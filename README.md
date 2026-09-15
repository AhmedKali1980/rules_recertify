# Rules Recertify

Rules Recertify will collect Illumio policy and rule-usage exports, retain a
rolling 180-day history, resolve labels and IP lists to concrete endpoints,
and generate a consolidated Excel recertification workbook for one logical
application from one or more explicit application/environment pairs.

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
règles. Le binaire et son fichier de configuration proviennent respectivement
des clés `workloader_dir` et `workloader_config_file` de `config/local.json`.
L'orchestrateur les transmet aux wrappers sous les noms internes `EXECUTABLE`
et `CFG`; il n'est donc pas nécessaire de les dupliquer dans `.env`. Les FQDN,
utilisateurs, clés et autres paramètres d'accès restent exclusivement dans
`pce.yaml`, que Workloader lit via `--config-file`.

Pour L1, le wrapper lit `default_pce_name` dans `pce.yaml`. Pour L3SM, il
recherche une clé de profil de premier niveau suivant la convention
`pce-l3-sm`/`pce_l3sm`. Les surcharges historiques `PCE_L1_NAME`,
`PCE_L3SM_NAME`, `PCE_L1_FQDN` et `PCE_L3SM_FQDN` restent acceptées pour un
diagnostic exceptionnel, mais ne font pas partie de la configuration normale
et ne doivent pas dupliquer les accès dans `.env`. Si L3SM ne peut pas être
déterminé sans ambiguïté, l'export échoue avant tout appel PCE.

L'ordre live est strict : (1) tous les workloads L1, (2) workloads managés
L3SM, (3) fusion CSV, (4) IP Lists L1, (5) services L1 compressés, (6) dérivations. Le répertoire raw de
l'exécution contient `export_wkld.csv`, `export_wkld.l3sm.m.csv`,
`export_iplists.csv`, `export_services.csv`, `export_wkld.derived.csv` et
`export_iplists.derived.csv`. La fusion conserve toutes les lignes sans
déduplication et exige des en-têtes strictement identiques.

```bash
./scripts/rules-recertify --config config/local.json collect
```

Le mode stub ne contacte jamais Workloader. Son répertoire exige
`export_wkld.csv`, `export_iplists.csv` et `export_services.csv`; un
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

## Rapport Excel

Chaque `--application-label` doit être associé, dans le même ordre, à un
`--environment`. Cela permet de consolider plusieurs couples dans un seul
livrable sans appliquer un environnement global à toutes les applications :

```bash
./scripts/rules-recertify --config config/local.json report \
  --kear-id "12345678-abcd-4321-abcd-123456789012" \
  --logical-application-name "Paiements Internationaux" \
  --application-label APM_PAYMENT --environment PRD \
  --application-label APM_PAYMENT_LEGACY --environment UAT \
  --lookback-days 180 --as-of 2026-09-10
```

Un ruleset scopé doit correspondre exactement à un couple demandé. Un ruleset
sans scope est retenu si un même côté Source ou Destination contient ce couple,
ou contient seulement le label applicatif (tous les environnements demandés
pour cette application).

### Génération en masse depuis Microcosmos

La commande `report-batch` accepte un export Excel Microcosmos :

```bash
./scripts/rules-recertify --config config/local.json report-batch \
  --microcosmos-xlsx /chemin/export_microcosmos.xlsx \
  --lookback-days 180 --as-of 2026-09-10
```

La première feuille doit contenir les colonnes `Kear Id`, `Application Name`,
`Module`, `Account`, `Account Leader`, `Microsegmentation Solution`,
`Environment` et `Entity`. Seules les lignes dont `Kear Id` est renseigné sont
traitées. `Application Name` alimente le nom logique et `Environment` le scope.
Le module est rapproché des labels applicatifs connus en comparant sa valeur à
la partie située après le deuxième underscore : `APM_RBS_FACTOBOT` correspond
ainsi au module `FACTOBOT`. Un module sans label correspondant provoque une
ligne `SKIPPED`. Un label existant dans le dernier `labels.csv`, mais sans règle
correspondante dans SQLite pour l'environnement demandé, est également ignoré
sans interrompre les autres rapports.

Les fichiers sont écrits sous
`output/<timestamp>/{PRD,NONPRD}/<Entity>/`. Pour un même KEAR, les lignes PRD
sont réunies dans un rapport suffixé `PRD`; tous les autres environnements sont
réunis dans un second rapport suffixé `NONPRD`. Les noms d'entités sont assainis
pour rester des composants de chemin sûrs.
Une copie du fichier Microcosmos est créée directement sous
`output/<timestamp>/` avec le suffixe `.rules-recertify-status.xlsx`. La colonne
supplémentaire `Rules Recertify Status` indique pour chaque ligne le rapport
produit (`PROCESSED`) ou la raison précise du `SKIPPED`.

Dans `Expanded Rules`, les workloads sont résolus directement depuis le
`export_wkld.derived.csv` du sous-répertoire raw horodaté le plus récent, avec
fallback SQLite si cet export n'est pas disponible. Ils sont affichés comme
`short_hostname (ip1;ip2)`, avec
fallback sur `name`. Les IP Lists sont résolues depuis l'export complet
`export_iplists.csv`; le dérivé limité à `NZ3_*` sert uniquement à la
corrélation workload/subnet. Les commentaires `#...` sont retirés de chaque
membre. Lors de la génération, le rapport charge en priorité le
`export_iplists.csv` du sous-répertoire d'exécution horodaté le plus récent.
Le répertoire technique `raw/preflight` est explicitement exclu. Cela corrige
également les bases historiques qui avaient été alimentées uniquement avec les
IP Lists `NZ3_*`; SQLite reste le fallback si aucun export brut n'est disponible.
La feuille `Presentation` indique le fichier effectivement utilisé.

Les objets de service nommés Illumio sont résolus depuis le
`export_services.csv` du même type de sous-répertoire raw horodaté. Cet export
est produit par `svc-export --compressed`; sa colonne `service_ports` est
injectée après le nom du service dans `Expanded Rules`, puis reprise telle
quelle dans `Octoflow`. Les ports explicites présents à côté d'un service sont
conservés. Le comptage et la détection des ports dangereux utilisent cette
définition développée, et `Presentation` trace le fichier de services retenu.

Un sélecteur latéral qui fournit explicitement `app` et `env` est résolu selon
ses propres labels, auxquels peuvent s'ajouter `loc` et `role`, sans être filtré
une seconde fois par le couple du rapport. Cela couvre symétriquement Sources et
Destinations et évite d'écarter un workload valide comme
`app:APM_RBS_FACTOBOT.IAAS;env:PRD;role:DB.PCP`. Lorsqu'un sélecteur ne fournit
aucun label `app`, les couples du rapport continuent de borner l'expansion.
La combinaison des labels suit la sémantique Illumio : **ET entre dimensions
différentes**, **OU entre plusieurs valeurs d'une même dimension**. Ainsi,
`app:CSM_RBD_CYBERARK.STANDARD.FRA.BUSU;env:PRD;role:PSM;role:PSMP`
sélectionne les workloads PRD de cette application dont le rôle vaut `PSM` ou
`PSMP`. La règle est identique pour Sources et Destinations. Lorsqu'un
sélecteur contient `app` mais aucun label `env`, tous les environnements sont
acceptés : `app:A;role:X;role:Y` signifie `app=A AND (role=X OR role=Y)`, sans
filtre PRD/NONPRD implicite.

Les colonnes `nb_src_ips` et `nb_dst_ips` comptent la cardinalité de l'union des
IP, ranges et subnets IPv4 développés, sans double comptage. Dans ce périmètre
corporate IPv4, `Any` (`0.0.0.0/0` et `::/0`) vaut donc `2^32`, soit
`4294967296`. Dans `Expanded Rules`, `All Services` est rendu sous la forme
`0-65535 TCP;0-65535 UDP`; `nb_ports` vaut alors `131072`.

La colonne `dangerous_ports` contient l'intersection entre les ports autorisés
par la règle et les catalogues activés dans `config/local.json` :

```json
"dangerous_port_lists": ["PORTS_TO_CONTROL", "PORTS_TO_ERADICATE"]
```

La forme texte séparée par des virgules est également acceptée :
`"PORTS_TO_CONTROL,PORTS_TO_ERADICATE"`. Les valeurs possibles sont
`PORTS_TO_CONTROL`, `PORTS_TO_ERADICATE` et `PORTS_ADMIN`. Les résultats sont
affichés sans ambiguïté sous la forme `TCP/22`, `UDP/161` ou `TCP/5900-5906`.
Une règle `All Services` contient tous les ports des catalogues sélectionnés.
Les suffixes `/3` et `/14` visibles dans l'ancien modèle ne correspondent pas à
une notation réseau standard : ils semblent représenter un score ou identifiant
de criticité propre à ce modèle. Faute de référentiel permettant de les calculer,
ils ne sont volontairement pas inventés dans ce rapport.

La feuille `Octoflow` transpose chaque ligne enrichie vers le contrat attendu
par le consommateur : `device` vient de `pce`, les identifiants sont extraits du
`Rule Href`, les sources/destinations/services reprennent les expansions, et les
zones sont les IP Lists `NZ3_*` contenant intégralement les adresses ou subnets
du côté concerné (`Any` en absence de correspondance). `Disabled`,
`dangerous_rule`, puis `dangerous_ports` avec exactement la valeur calculée
dans `Expanded Rules`, les compteurs et le dernier hit sont également exposés.

Le seuil de permissivité se configure dans `config/local.json` :

```json
"permissive_rule_max_ips": 255
```

`permissive_rule` vaut `YES` lorsque `nb_src_ips` ou `nb_dst_ips` dépasse ce
seuil. `creation_time` correspond au premier import observé et `last_modified`
au premier import ayant détecté la version courante. Ce suivi commence après la
mise en place de la table d'historique ; les imports antérieurs ne peuvent pas
être reconstruits rétroactivement. `unused_since_18_months` vaut `YES` sans hit
connu ou lorsque le dernier hit date d'au moins 18 mois calendaires.

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
