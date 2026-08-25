# Integration and Test Guide

## 1. Delivered commands

The `scripts/rules-recertify` entrypoint exposes:

| Command | Purpose |
|---|---|
| `validate-config` | Validate configuration without contacting the PCE |
| `init-db` | Create/upgrade the local SQLite schema |
| `collect` | Export policy, submit/poll traffic queries, and persist usage |
| `ingest-usage` | Ingest an existing Workloader `rule-usage` CSV |
| `ingest-reference` | Ingest derived workload and IP-list CSVs |
| `report` | Generate an application workbook on demand |

Collection and report delivery are deliberately separate. Cron runs `collect`;
an operator or another system runs `report` only when a deliverable is needed.

## 2. RHEL 9 installation

### 2.1 Prerequisites

- Python 3.9.25 and `venv`.
- Workloader 12.0.20, default `/DATA/WORKLOADER/ver12/workloader`.
- SQLite 3.34 or newer.
- An approved offline `openpyxl` package for workbook generation.
- Network/PCE credentials already accepted by Workloader.

No online package lookup is required by collection, ingestion, SQLite, or tests.
`openpyxl` is imported only by `report`.

### 2.2 Install from the checkout

```bash
cd /path/to/rules_recertify
python3.9 -m venv .venv
. .venv/bin/activate
python -m pip install --no-index --no-deps -e .
# Use the approved internal wheel directory when openpyxl is not preinstalled:
python -m pip install --no-index --find-links /path/to/approved/wheels openpyxl
```

For a completely offline editable installation, the host must already contain a
compatible setuptools build backend. Otherwise use `PYTHONPATH=src` through the
provided script without installing the package.

## 3. Configuration

```bash
cp config/example.json config/local.json
cp .env.example .env
chmod 600 .env
```

Edit `config/local.json`. Important settings are:

- `workloader_dir`: directory containing the Workloader binary;
- `state_db`: durable local SQLite path;
- traffic batch/poll timing;
- `retention_days`, which cannot be lower than 200;
- `smtp_enabled`.

Edit `.env` for PCE/Workloader environment overrides and SMTP values. The parser
never evaluates shell syntax. Do not run `source .env`; do not commit it.

Validate and initialize:

```bash
./scripts/rules-recertify --config config/local.json validate-config
./scripts/rules-recertify --config config/local.json init-db
```

## 4. Reference-data ingestion

Produce `export_wkld.derived.csv` and `export_iplists.derived.csv` with the existing
approved extraction/derivation process, then run:

```bash
./scripts/rules-recertify --config config/local.json ingest-reference \
  --workloads /data/export_wkld.derived.csv \
  --ip-lists /data/export_iplists.derived.csv
```

The adapter accepts comma or semicolon CSV delimiters and UTF-8 with or without a
BOM. Workloads without a usable selected IP are excluded and recorded under Data
Quality. Repeat ingestion after every reference export; it atomically replaces the
current workload/IP-list snapshot.

## 5. Collection

### 5.1 One daily UTC window

Run after the previous UTC day has closed:

```bash
./scripts/rules-recertify --config config/local.json collect \
  --traffic-start 2026-08-23 \
  --traffic-end 2026-08-24
```

The collector:

1. exports all enabled and disabled rulesets;
2. inventories rules without traffic expansion;
3. counts and bin-packs whole rulesets into at most 500 rules;
4. submits sequential `rule-export --traffic-count --expand-svcs` batches;
5. polls `rule-usage` and logs completion progress;
6. never replaces a completed usage window with a later pending result;
7. commits usage and port observations to SQLite;
8. writes raw artifacts and `manifest.json` under `var/raw/<run_id>`;
9. sends one non-blocking SMTP summary.

If one ruleset alone exceeds 500 rules, collection stops with an explicit error.
Do not raise the limit until the PCE owner approves it.

### 5.2 Initial backfill

The PCE exposes about 90 days. Start with smaller windows to validate PCE load,
then increase cautiously. Each window must be non-overlapping. For example, run
sequential 7-day windows, newest first. Never sum overlapping counts.

### 5.3 Cron

Example for a daily launch at 03:15 server time (ensure the host timezone and
window-generation wrapper are reviewed):

```cron
15 3 * * * cd /opt/rules_recertify && /opt/rules_recertify/scripts/daily-collect.sh
```

Use the supplied wrapper template, which computes adjacent UTC dates, activates
the virtual environment, obtains a non-blocking lock, and preserves the collector
exit code.

## 6. On-demand report

```bash
./scripts/rules-recertify --config config/local.json report \
  --kear-id 51be4bf9-2080-432f-9d02-1c0cf0f251d7 \
  --logical-application-name "My Consolidated Application" \
  --application-label APP_A \
  --application-label APP_A_LEGACY \
  --environment PRD \
  --lookback-days 180
```

The output is written atomically below `output_dir`, with KEAR ID and Environment
in its filename. Inspect `Presentation`, `Raw Rules`, `Expanded Rules`,
`Rule Usage`, and `Data Quality`. The KEAR ID is present on every sheet.

## 7. Test procedure

### 7.1 Offline automated suite

```bash
PYTHONPATH=src python3.9 -m unittest discover -s tests -v
python3.9 -m compileall -q src tests
```

The suite includes a fake Workloader end-to-end collection test and does not
contact the PCE.

### 7.2 Development smoke test

```bash
cp config/example.json /tmp/rules-recertify-test.json
PYTHONPATH=src python3 -m rules_recertify.cli \
  --config /tmp/rules-recertify-test.json validate-config
```

### 7.3 PCE integration acceptance

Use a non-production/test PCE and a small ruleset set where possible. Confirm:

1. returned `query_body` exactly contains the requested adjacent UTC boundaries;
2. Workloader statuses progress from pending to completed;
3. the manifest counts equal the Workloader console output;
4. rerunning the same window does not duplicate database observations;
5. a completed result cannot be downgraded to pending;
6. `flows=0` becomes `NO_HIT`, positive flows become `HIT`, and missing data is
   `UNKNOWN`;
7. `+ N more` sets incomplete port detail without losing the positive hit;
8. failed SMTP is logged and does not change the collection business status;
9. generated workbooks open successfully and their filters, wrapped cells,
   dates, KEAR ID, and application selection are correct;
10. the downstream system accepts the workbook baseline.

### 7.4 Operational acceptance

Run shadow collection for at least one week. Validate disk growth, PCE load,
completion time, polling values, recovery after interruption, email summaries,
and gap/backfill handling before enabling the full cron schedule.

## 8. Runtime artifacts and recovery

- `var/raw/<run_id>`: immutable run CSVs, Workloader log, and manifest.
- `var/state/rules_recertify.sqlite`: durable canonical state.
- `var/logs`: structured JSON-line application logs.
- `var/output`: on-demand workbooks.

Back up SQLite and raw artifacts. To investigate a run, start with its manifest,
then the JSON-line log, then Workloader log. `ingest-usage` can recover a valid
existing usage result without re-querying the PCE:

```bash
./scripts/rules-recertify --config config/local.json ingest-usage \
  /data/workloader-rule-usage.csv
```
