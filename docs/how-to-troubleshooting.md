# Rules Recertify — How-to & Troubleshooting

A concise runbook for operating, monitoring, and troubleshooting
`rules_recertify`. Run all commands from the production root:

```bash
cd /DATA/mco/illumio-mco/rules_recertify
```

> **Golden rule:** use the `scripts/*.sh` wrappers for production collections.
> They load the configuration and virtualenv, verify the policy snapshot, and
> protect collection jobs with a shared lock.

## 1. Quick reference

| Task | Command |
|---|---|
| Validate configuration | `./scripts/rules-recertify --config config/local.json --env-file .env validate-config` |
| Initialize SQLite | `./scripts/rules-recertify --config config/local.json --env-file .env init-db` |
| Test SMTP | `./scripts/rules-recertify --config config/local.json --env-file .env test-email` |
| Refresh the policy snapshot | `./scripts/daily-policy-collect.sh` |
| Collect weekly traffic | `./scripts/weekly-traffic-collect.sh` |
| Process one backfill window | `./scripts/backfill-traffic.sh` |
| Bypass the 47-hour backfill gate | `./scripts/backfill-traffic.sh --force` |
| Explicitly run a Sunday backfill | `./scripts/backfill-traffic.sh --force --allow-sunday` |
| Check overall health | `./scripts/check-collection.sh` |
| Inspect backfill details | `./scripts/rules-recertify --config config/local.json --env-file .env backfill-status --backfill-id traffic-92-days` |
| Search current rules for supplied items | `./scripts/rules-recertify --config config/local.json --env-file .env search-rules --items /tmp/items.xlsx` |

## 2. First-time setup

```bash
cp config/example.json config/local.json
cp .env.example .env
chmod 600 .env

./scripts/rules-recertify --config config/local.json --env-file .env validate-config
./scripts/rules-recertify --config config/local.json --env-file .env init-db
./scripts/rules-recertify --config config/local.json --env-file .env test-email
```

Before the first PCE connection, verify in `config/local.json`:

- `pce`, `workloader_dir`, and `workloader_config_file`;
- `state_db`, `raw_dir`, `output_dir`, and `log_dir`;
- `traffic_environments` and `traffic_batch_size`;
- SMTP variables in `.env`.

## 3. Routine operations

### Refresh the policy snapshot

Exports L1/L3SM workloads, IP Lists, services, labels, rulesets, and rules, then
atomically publishes `var/raw/snapshot`:

```bash
./scripts/daily-policy-collect.sh
```

### Collect weekly traffic

```bash
./scripts/weekly-traffic-collect.sh
```

The wrapper uses the persisted SQLite cursor and does not replay a successful
window.

### Initialize and continue a backfill

Initialization is a **one-time** operation that freezes a 92-day range:

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  init-backfill-traffic --target-end 2026-09-20 \
  --backfill-id traffic-92-days

./scripts/backfill-traffic.sh
```

Each invocation processes at most one seven-day window. After a failure, a retry
starts at the first unfinished batch when all resume safety checks pass;
otherwise, it safely replays the window.

### Extend an existing backfill target

Wait for the active window to finish, then move the exclusive target forward.
Completed windows and the current cursor are preserved:

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  extend-backfill-traffic --backfill-id traffic-92-days \
  --target-end 2026-10-11
```

For a cursor at `2026-09-20`, this creates three subsequent windows:
`[2026-09-20, 2026-09-27)`, `[2026-09-27, 2026-10-04)`, and
`[2026-10-04, 2026-10-11)`. Process them normally with
`./scripts/backfill-traffic.sh` (or `--force` for an approved immediate run).

The backfill cursor and weekly cursor are independent. Once coverage reaches
Sunday `2026-10-11`, the first weekly collection on Sunday `2026-10-18` can
collect `[2026-10-11, 2026-10-18)`; when no weekly cursor exists, the wrapper
automatically derives that seven-day start from its available end date.

### Refresh the snapshot, then backfill in the background

Both jobs use the same lock. Run them sequentially, never in parallel:

```bash
LOG="var/logs/snapshot-and-backfill-$(date +%Y%m%dT%H%M%S).log"

nohup bash -c '
  set -Eeuo pipefail
  echo "===== SNAPSHOT START $(date --iso-8601=seconds) ====="
  ./scripts/daily-policy-collect.sh
  echo "===== BACKFILL START $(date --iso-8601=seconds) ====="
  ./scripts/backfill-traffic.sh --force
' >"$LOG" 2>&1 </dev/null &

PID=$!
echo "PID=$PID"
echo "LOG=$LOG"
```

### Generate an application report

```bash
./scripts/rules-recertify --config config/local.json --env-file .env report \
  --kear-id "12345678-abcd-4321-abcd-123456789012" \
  --logical-application-name "Payments" \
  --application-label APM_PAYMENT --environment PRD \
  --lookback-days 180
```

In the generated **Octoflow** worksheet:

- `seq_number` contains only the ruleset identifier extracted from the rule
  href (for example `13173`);
- `rule_id` contains only the final rule identifier (for example `10499`),
  regardless of whether the href contains `sec_rules` or `deny_rules`;
- `sources` and `destinations` contain IPv4 values only;
- the PCE dual-stack Any selector is rendered as exactly
  `IP List: Any (0.0.0.0/0)`.

## 4. Search supplied items across the current rule snapshot

The former standalone CSV/Pandas search is still available as the integrated
`search-rules` command. It reads the latest successfully published policy
snapshot from SQLite and searches only rules currently marked as present.

The old `--rules <rules.csv>` argument is intentionally gone: the current
snapshot is now the authoritative rules source. The remaining options map as
follows:

| Former script | Integrated command |
|---|---|
| `--rules rules.csv` | Not required; reads the current SQLite snapshot |
| `--items items.csv` | `--items items.csv` (CSV, TXT, or XLSX) |
| `--out result.xlsx` | `--out result.xlsx` (optional) |
| `--case-sensitive` | `--case-sensitive` (optional) |

Compared with the former script, the integrated command also:

- accepts CSV, TXT, or XLSX input;
- searches scopes, descriptions, labels, label groups, exclusions, IP Lists,
  workloads, and services;
- expands named services from the snapshot service catalog;
- understands ports and ranges such as `TCP/22`, `3389`, or `UDP/160-162`;
- produces **Summary**, **Results**, and **Metadata** worksheets;
- emits `NOT_USED_IN_ANY_RULE` when an item has no match.

### Prepare the input

Use one item per row. A header named `item`, `search item`, or `searched item` is
optional. Blank rows and duplicates are ignored.

```text
item
APM_PAYMENT
PRODUCTION-WEB
DATABASE-NET
DATABASE-SVC
TCP/22
UDP/160-162
```

Save it as `/tmp/items.csv`, `/tmp/items.txt`, or `/tmp/items.xlsx`.

### Run the search

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  search-rules --items /tmp/items.csv
```

By default, the workbook is written under `output_dir` as
`rules_items_search_<UTC timestamp>.xlsx`. To choose the destination:

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  search-rules --items /tmp/items.xlsx \
  --out var/output/my-rule-search.xlsx
```

Text search is case-insensitive by default. Enable strict case matching with:

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  search-rules --items /tmp/items.csv --case-sensitive
```

### Read the output

- **Summary**: one line per input item, status, and matching-rule count.
- **Results**: one line per item/rule match, including `found as`, optional port
  intersection details, snapshot timestamp, and all original rule columns.
- **Metadata**: snapshot timestamp, input path, service-reference source,
  case-sensitivity mode, and generation time.

If the command reports `no rule snapshot is available in SQLite`, refresh the
snapshot first:

```bash
./scripts/daily-policy-collect.sh
```

## 5. Quick monitoring

### Overall health

```bash
./scripts/check-collection.sh; echo "rc=$?"
```

| Exit code | Meaning |
|---:|---|
| `0` | OK |
| `1` | WARNING: active job or backfill retry pending |
| `2` | CRITICAL: snapshot, cursor, archive, or run failure |
| `3` | UNKNOWN: health check could not run |

### Follow logs

```bash
tail -f var/logs/rules-recertify-$(date +%F).jsonl
```

For a `nohup` job:

```bash
tail -f "$LOG"
ps -fp "$PID"
```

### Processes and lock

```bash
pgrep -af 'rules-recertify|backfill-traffic|daily-policy-collect|workloader'
fuser var/state/collect.lock 2>/dev/null || true
```

Never remove or bypass the lock while a collection process is running.

## 6. Five-minute diagnostic bundle

Run this block and attach its output to the incident ticket:

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

## 7. Inspect SQLite without the `sqlite3` client

These snippets obtain the database path from the effective configuration.

### Last ten runs

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

### Backfill state and weekly cursor

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

### Most recent failed run details

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
    print("No ERROR/WARNING run found")
PY
```

## 8. Common incidents

### `Another Rules Recertify collection is running` / exit code 75

- another collection owns the shared lock;
- inspect processes and wait for it to finish;
- if no process exists but a run remains `RUNNING`, preserve diagnostics before
  making any SQLite change.

### Backfill does not start

Check in this order:

1. Sunday: use `--force --allow-sunday` only for an approved exception;
2. last attempt was less than 47 hours ago: use `--force`;
3. state is `COMPLETED`: no window remains;
4. lock is held: another collection is active;
5. snapshot is missing: the wrapper runs `collect-policy` first.

### Workloader exits with status 1

```bash
find var/logs/failed-runs -maxdepth 2 -type f -printf '%T@ %p\n' \
  | sort -nr | head -20
```

Inspect first:

- `run-details.json`;
- `workloader-output.log`;
- the current batch files matching `batch_NNNN_*`.

HTTP `429/500/502/503/504` and recognized PCE transport failures are retried
automatically. Authentication, configuration, and deterministic data errors
remain blocking.

### `INVALID_PORT_DETAILS`

Inspect `flows_by_port` in **Problematic Rules**:

- `443 TCP (10)`: TCP port;
- `0 ICMP (10)` or `0 VRRP (1)`: portless IP protocol;
- `0 (1)`: unspecified protocol emitted by Workloader for some **All Services**
  traffic;
- any genuinely unknown representation remains in the audit for investigation.

### Header-only rows in `Problematic Rules`

Current versions ignore CSV headers repeated by Workloader. If they reappear,
preserve the relevant `batch_NNNN_usage_NNN.csv` and `workloader-output.log` to
capture the exact source format.

### `SUCCESS_WITH_EXCEPTIONS`

The run is usable but contains a documented exception. Check the email and
workbook for unknown async statuses, missing results, invalid query/port data, or
oversized rulesets. `PENDING` and `EXPIRED` remain blocking.

### Snapshot is missing or stale

```bash
./scripts/daily-policy-collect.sh
./scripts/check-collection.sh
```

Do not refresh the snapshot in parallel with traffic/backfill collection. The
shared lock is intentional.

### Disk is full

```bash
du -xhd1 var | sort -h
du -xhd1 var/raw var/output var/logs 2>/dev/null | sort -h
```

Do not directly delete SQLite, the current snapshot, or a referenced archive.
Use the archive retention command:

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  purge-archives --as-of "$(date +%F)"
```

## 9. Archives

List archives:

```bash
find var/raw/archives -maxdepth 1 -type f -name '*.tar.gz' \
  -printf '%TY-%Tm-%Td %TH:%TM %s %p\n' | sort
```

Restore and verify an archive without changing the current snapshot:

```bash
./scripts/rules-recertify --config config/local.json --env-file .env \
  restore-archive --archive var/raw/archives/<run_id>.tar.gz \
  --target-dir /tmp/rules-recertify-restore
```

## 10. Evidence to attach to an incident

Never attach `.env`, `pce.yaml`, private keys, credentials, or other secrets.

Attach when available:

1. `check-collection.sh` output;
2. `backfill-status` output;
3. `var/logs/failed-runs/<run_id>/run-details.json`;
4. the failed run's `workloader-output.log`;
5. the failed `batch_NNNN_*` files;
6. relevant entries from `var/logs/rules-recertify-YYYY-MM-DD.jsonl`;
7. disk (`df -h`) and process (`pgrep -af ...`) output.

## 11. Reference schedule

```text
00:10 every day             policy snapshot
01:00 Sunday                weekly traffic
02:00 Sunday                weekly traffic retry
03:00 Monday to Saturday    backfill when last attempt is at least 47 hours old
```

The installable reference is `config/rules-recertify.cron`.
