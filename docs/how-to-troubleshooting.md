# Rules Recertify — How-to & Troubleshooting

Runbook court pour exploiter, superviser et diagnostiquer `rules_recertify`.
Toutes les commandes partent de la racine de production :

```bash
cd /DATA/mco/illumio-mco/rules_recertify
```

> **Règle d'or :** utiliser les wrappers `scripts/*.sh` pour les collectes de
> production. Ils chargent la configuration, activent le virtualenv, vérifient
> le snapshot et protègent les traitements avec un verrou commun.

## 1. Aide-mémoire

| Besoin | Commande |
|---|---|
| Vérifier la configuration | `./scripts/rules-recertify --config config/local.json --env-file .env validate-config` |
| Initialiser SQLite | `./scripts/rules-recertify --config config/local.json --env-file .env init-db` |
| Tester SMTP | `./scripts/rules-recertify --config config/local.json --env-file .env test-email` |
| Rafraîchir le snapshot policy | `./scripts/daily-policy-collect.sh` |
| Collecter le trafic hebdomadaire | `./scripts/weekly-traffic-collect.sh` |
| Exécuter une fenêtre de backfill | `./scripts/backfill-traffic.sh` |
| Forcer le backfill avant 47 h | `./scripts/backfill-traffic.sh --force` |
| Forcer exceptionnellement un dimanche | `./scripts/backfill-traffic.sh --force --allow-sunday` |
| Voir l'état global | `./scripts/check-collection.sh` |
| Voir le détail du backfill | `./scripts/rules-recertify --config config/local.json --env-file .env backfill-status --backfill-id traffic-92-days` |

## 2. Première mise en service

```bash
cp config/example.json config/local.json
cp .env.example .env
chmod 600 .env

./scripts/rules-recertify --config config/local.json --env-file .env validate-config
./scripts/rules-recertify --config config/local.json --env-file .env init-db
./scripts/rules-recertify --config config/local.json --env-file .env test-email
```

Avant le premier contact PCE, vérifier dans `config/local.json` :

- `pce`, `workloader_dir` et `workloader_config_file` ;
- les chemins `state_db`, `raw_dir`, `output_dir`, `log_dir` ;
- `traffic_environments` et `traffic_batch_size` ;
- la configuration SMTP dans `.env`.

## 3. Opérations courantes

### Rafraîchir le snapshot

Exporte workloads L1/L3SM, IP Lists, services, labels, rulesets et règles, puis
publie atomiquement `var/raw/snapshot` :

```bash
./scripts/daily-policy-collect.sh
```

### Collecter le trafic hebdomadaire

```bash
./scripts/weekly-traffic-collect.sh
```

Le wrapper utilise le curseur SQLite et ne rejoue pas une fenêtre déjà réussie.

### Initialiser puis poursuivre le backfill

L'initialisation est **unique** et fige une plage de 92 jours :

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  init-backfill-traffic --target-end 2026-09-20 \
  --backfill-id traffic-92-days

./scripts/backfill-traffic.sh
```

Chaque lancement traite au maximum une fenêtre de sept jours. En cas d'échec,
la relance reprend au premier batch non terminé lorsque les contrôles de reprise
sont satisfaits ; sinon elle rejoue prudemment la fenêtre.

### Snapshot puis backfill en arrière-plan

Les deux collectes partagent un verrou : les enchaîner, ne pas les paralléliser.

```bash
LOG="var/logs/snapshot-and-backfill-$(date +%Y%m%dT%H%M%S).log"

nohup bash -c '
  set -Eeuo pipefail
  echo "===== SNAPSHOT START $(date --iso-8601=seconds) ====="
  ./scripts/daily-policy-collect.sh
  echo "===== BACKFILL START $(date --iso-8601=seconds) ====="
  ./scripts/backfill-traffic.sh --force
' >"$LOG" 2>&1 </dev/null &

echo "PID=$!"
echo "LOG=$LOG"
```

### Générer un rapport

```bash
./scripts/rules-recertify --config config/local.json --env-file .env report \
  --kear-id "12345678-abcd-4321-abcd-123456789012" \
  --logical-application-name "Paiements" \
  --application-label APM_PAYMENT --environment PRD \
  --lookback-days 180
```

Recherche ponctuelle de règles :

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  search-rules --items /tmp/items.xlsx
```

## 4. Supervision rapide

### État synthétique

```bash
./scripts/check-collection.sh; echo "rc=$?"
```

| Code | Signification |
|---:|---|
| `0` | OK |
| `1` | WARNING : traitement actif ou backfill à reprendre |
| `2` | CRITICAL : snapshot, curseur, archive ou run en défaut |
| `3` | UNKNOWN : contrôle impossible |

### Suivre les journaux

```bash
tail -f var/logs/rules-recertify-$(date +%F).jsonl
```

Pour un job lancé avec `nohup` :

```bash
tail -f "$LOG"
ps -fp "$PID"
```

### Processus et verrou

```bash
pgrep -af 'rules-recertify|backfill-traffic|daily-policy-collect|workloader'
fuser var/state/collect.lock 2>/dev/null || true
```

Ne jamais supprimer le verrou tant qu'un processus de collecte existe.

## 5. Diagnostic en 5 minutes

Exécuter ce bloc et joindre sa sortie au ticket :

```bash
echo '=== HEALTH ==='
./scripts/check-collection.sh || true

echo '=== CONFIG ==='
./scripts/rules-recertify --config config/local.json --env-file .env \
  validate-config || true

echo '=== BACKFILL ==='
./scripts/rules-recertify --config config/local.json --env-file .env \
  backfill-status --backfill-id traffic-92-days || true

echo '=== PROCESSES ==='
pgrep -af 'rules-recertify|backfill|workloader' || true

echo '=== DISK ==='
df -h . var var/raw var/output 2>/dev/null

echo '=== RECENT ERRORS ==='
tail -n 200 "var/logs/rules-recertify-$(date +%F).jsonl" 2>/dev/null \
  | grep -Ei 'error|warning|failed|retry|exception' || true
```

## 6. Lire SQLite sans dépendre du client `sqlite3`

Les extraits suivants utilisent le chemin défini par la configuration.

### Dix derniers runs

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
from rules_recertify.config import load_settings
from rules_recertify.history.database import Database

s = load_settings(Path("config/local.json"), Path(".env"))
db = Database(Path(s.state_db)); db.initialize()
with db.connect() as c:
    for row in c.execute(
        "SELECT run_id,run_type,status,started_at,finished_at "
        "FROM runs ORDER BY started_at DESC LIMIT 10"
    ):
        print(*row, sep=" | ")
PY
```

### État du backfill et curseur hebdomadaire

```bash
PYTHONPATH=src python3 - <<'PY'
from pathlib import Path
from rules_recertify.config import load_settings
from rules_recertify.history.database import Database

s = load_settings(Path("config/local.json"), Path(".env"))
db = Database(Path(s.state_db)); db.initialize()
with db.connect() as c:
    print("BACKFILL")
    for row in c.execute("SELECT * FROM backfill_states"):
        print(dict(row))
    print("WEEKLY CURSOR")
    for row in c.execute("SELECT * FROM traffic_cursors"):
        print(dict(row))
PY
```

### Détails du dernier run en erreur

```bash
PYTHONPATH=src python3 - <<'PY'
import json
from pathlib import Path
from rules_recertify.config import load_settings
from rules_recertify.history.database import Database

s = load_settings(Path("config/local.json"), Path(".env"))
db = Database(Path(s.state_db)); db.initialize()
with db.connect() as c:
    row = c.execute(
        "SELECT run_id,details_json FROM runs WHERE status IN ('ERROR','WARNING') "
        "ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
if row:
    print("run_id:", row[0])
    print(json.dumps(json.loads(row[1]), indent=2, sort_keys=True))
else:
    print("Aucun run ERROR/WARNING")
PY
```

## 7. Incidents fréquents

### `Another Rules Recertify collection is running` / code 75

- une autre collecte détient le verrou ;
- vérifier les processus et attendre leur fin ;
- si aucun processus n'existe mais qu'un run reste `RUNNING`, conserver les
  éléments de diagnostic avant toute intervention SQLite.

### Le backfill ne démarre pas

Vérifier, dans cet ordre :

1. dimanche : utiliser exceptionnellement `--force --allow-sunday` ;
2. tentative datant de moins de 47 h : utiliser `--force` ;
3. état `COMPLETED` : aucune fenêtre ne reste à traiter ;
4. verrou détenu : une autre collecte tourne ;
5. snapshot manquant : le wrapper lance d'abord `collect-policy`.

### Workloader sort avec le statut 1

```bash
find var/logs/failed-runs -maxdepth 2 -type f -printf '%T@ %p\n' \
  | sort -nr | head -20
```

Consulter en priorité :

- `run-details.json` ;
- `workloader-output.log` ;
- les fichiers `batch_NNNN_*` du batch courant.

Les erreurs HTTP `429/500/502/503/504` et certaines erreurs de transport PCE
sont retentées automatiquement. Une erreur d'authentification, de configuration
ou de données reste bloquante.

### `INVALID_PORT_DETAILS`

Ouvrir `flows_by_port` dans la feuille **Problematic Rules** :

- `443 TCP (10)` : port TCP ;
- `0 ICMP (10)` ou `0 VRRP (1)` : protocole IP sans port ;
- `0 (1)` : protocole non spécifié produit par Workloader pour certains flux
  **All Services** ;
- toute autre forme réellement inconnue est conservée dans l'audit pour analyse.

### Lignes contenant seulement les entêtes dans `Problematic Rules`

Les versions récentes ignorent les entêtes CSV répétés par Workloader. Si elles
réapparaissent, conserver le fichier `batch_NNNN_usage_NNN.csv` concerné et le
`workloader-output.log` pour reproduire le format exact.

### `SUCCESS_WITH_EXCEPTIONS`

Le run est exploitable mais contient une exception documentée. Vérifier dans le
mail et le classeur : statuts async inconnus, résultat absent, query body ou port
invalide, ruleset hors limite. `PENDING` et `EXPIRED` restent bloquants.

### Snapshot absent ou trop ancien

```bash
./scripts/daily-policy-collect.sh
./scripts/check-collection.sh
```

Ne pas lancer le refresh snapshot en parallèle d'un trafic/backfill : le verrou
commun est volontaire.

### Disque plein

```bash
du -xhd1 var | sort -h
du -xhd1 var/raw var/output var/logs 2>/dev/null | sort -h
```

Ne pas supprimer directement la base SQLite, le snapshot courant ou une archive
référencée. Utiliser la commande de purge pour les archives expirées :

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  purge-archives --as-of "$(date +%F)"
```

## 8. Archives

Lister et vérifier visuellement :

```bash
find var/raw/archives -maxdepth 1 -type f -name '*.tar.gz' -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' | sort
```

Restaurer une archive sans toucher au snapshot courant :

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  restore-archive --archive var/raw/archives/<run_id>.tar.gz \
  --target-dir /tmp/rules-recertify-restore
```

## 9. Fichiers à joindre à un ticket

Ne jamais joindre `.env`, `pce.yaml`, clés ou secrets.

Joindre si disponibles :

1. sortie de `check-collection.sh` ;
2. sortie de `backfill-status` ;
3. `var/logs/failed-runs/<run_id>/run-details.json` ;
4. `workloader-output.log` du run en erreur ;
5. fichiers du batch fautif `batch_NNNN_*` ;
6. lignes JSON du run dans `var/logs/rules-recertify-YYYY-MM-DD.jsonl` ;
7. espace disque (`df -h`) et processus (`pgrep -af ...`).

## 10. Planification de référence

```text
00:10 tous les jours       snapshot policy
01:00 dimanche             trafic hebdomadaire
02:00 dimanche             retry trafic hebdomadaire
03:00 lundi à samedi       backfill si dernière tentative >= 47 h
```

La référence installable se trouve dans `config/rules-recertify.cron`.
