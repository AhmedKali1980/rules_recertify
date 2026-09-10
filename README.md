# Rules Recertify

Rules Recertify will collect Illumio policy and rule-usage exports, retain a
rolling 180-day history, resolve labels and IP lists to concrete endpoints,
and generate a consolidated Excel recertification workbook for one logical
application (one or more application labels) in one environment.

The repository now contains the first executable implementation: Workloader
collection and polling, validated CSV adapters, SQLite history, endpoint reference
ingestion, on-demand Excel reporting, structured logs, and SMTP summaries.

## Design documents

- [Technical design](docs/technical-design.md): scope, processing model,
  proposed architecture, data model, Excel contract, operational controls,
  delivery phases, and open questions.
- [Repository assessment](docs/repository-assessment.md): verified Git and
  reusable-project visibility from the current workspace.
- [Integration and test guide](docs/integration-guide.md): offline installation,
  configuration, cron, collection, backfill, reporting, and acceptance tests.

## Proposed implementation stack

- Python 3.9.25 for validation, transformation, persistence, and Excel creation
  on the production RHEL 8 host.
- Thin POSIX shell wrappers for `workloader` invocation and scheduler entrypoints.
- SQLite as the default single-host historical store, with raw immutable CSV
  artifacts retained for audit and replay.
- Standard-library processing plus `openpyxl` for the final `.xlsx` workbook.

The confirmed functional and operational decisions are recorded in the
[requirements decision record](docs/requirements-decisions.md).

No PCE credentials, Workloader binary, generated exports, databases, logs, or
produced workbooks should be committed to Git.

## Quick start

```bash
cp config/example.json config/local.json
cp .env.example .env
chmod 600 .env
./scripts/rules-recertify --config config/local.json validate-config
./scripts/rules-recertify --config config/local.json init-db
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

See the integration guide before contacting a PCE or enabling cron.

## Import des workloads et IP Lists

La commande `collect` importe désormais les référentiels avant les exports de
règles. Workloader doit être installé et les variables `EXECUTABLE` (binaire)
et `CFG` (`pce.yaml`) doivent être définies dans l'environnement ou dans le
`.env` du projet. Les credentials sont lus par Workloader dans `CFG` : aucune
copie de clé API dans `.env` n'est requise.

Les profils peuvent être sélectionnés explicitement avec `PCE_L1_NAME` et
`PCE_L3SM_NAME`. À défaut, `PCE_L1_FQDN` et `PCE_L3SM_FQDN` permettent de
retrouver la clé du profil dans `CFG` à partir du hostname. L1 peut utiliser le
profil Workloader par défaut ; L3SM échoue si aucun profil sûr n'est déterminé.

L'ordre live est strict : (1) tous les workloads L1, (2) workloads managés
L3SM, (3) fusion CSV, (4) IP Lists L1, (5) dérivations. Le répertoire raw de
l'exécution contient `export_wkld.csv`, `export_wkld.l3sm.m.csv`,
`export_iplists.csv`, `export_wkld.derived.csv` et
`export_iplists.derived.csv`. La fusion conserve toutes les lignes sans
déduplication et exige des en-têtes strictement identiques.

```bash
EXECUTABLE=/opt/workloader CFG=/secure/pce.yaml \
PCE_L1_NAME=l1 PCE_L3SM_NAME=l3sm \
./scripts/rules-recertify --config config/local.json collect
```

Le mode stub ne contacte jamais Workloader. Son répertoire exige
`export_wkld.csv` et `export_iplists.csv`; un
`export_wkld.l3sm.m.csv` non vide est facultatif et est fusionné avec les mêmes
contrôles que le mode live. On peut employer l'option ou la variable :

```bash
./scripts/rules-recertify --config config/local.json collect \
  --pce-stub-dir '/tmp/reference stubs'
# équivalent : PCE_STUB_DIR='/tmp/reference stubs' ... collect
```

`--skip-pce-import` conserve explicitement le comportement de collecte sans
actualisation du référentiel (utile pour une reprise contrôlée).

Les dérivations préservent les colonnes source, insèrent `short_hostname`
(préfixe DNS en majuscules) après `hostname`, puis ajoutent
`ocs_name_from_IP`, `IPLIST` et `SUBNET`. `ocs_name_from_IP` utilise l'IP de
passerelle pour un workload managé (préfixe `IP-`, sauf Windows), la première
IPv4 d'interface pour une source non managée `AUTOMATION GEN2`, et reste vide
sinon. Seules les IP Lists `NZ3_*` et leurs réseaux IPv4 valides sont corrélés.
La priorité est **première IPv4, puis première IP List/réseau dans l'ordre
source**. Le fichier IP Lists dérivé ne conserve que `name` et `include`.

The standard production installation root is:

```text
/DATA/mco/illumio-mco/rules_recertify
```

Deploy a reviewed checkout with:

```bash
sudo RULES_RECERTIFY_OWNER=illumio-mco \
  RULES_RECERTIFY_GROUP=illumio-mco \
  ./scripts/install-prod.sh
```

Replace the example owner/group with the actual production service account.

RHEL 8 pip 20.2.4 and offline setuptools 50.3.2 are supported through `setup.py`.
The project deliberately avoids `pyproject.toml`, which would trigger an offline
PEP 517 build-dependency download. If editable installation is unavailable, the
supplied launcher runs directly from the deployed source tree without pip.
