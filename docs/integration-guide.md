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

## 2. Production RHEL 8 installation

### 2.1 Prerequisites

- Python 3.9.25 and `venv`.
- Workloader 12.0.20, default `/DATA/WORKLOADER/ver12/workloader`.
- SQLite 3.24 or newer. Production provides `3.26.0-20.el8_10`.
- An approved offline `openpyxl` package for workbook generation.
- Network/PCE credentials already accepted by Workloader.

No online package lookup is required by collection, ingestion, SQLite, or tests.
`openpyxl` is imported only by `report`.

The standard production installation root is:

```text
/DATA/mco/illumio-mco/rules_recertify
```

The code uses SQLite UPSERT syntax introduced in 3.24 and checks the linked
Python SQLite version before creating the schema. The production 3.26 release is
therefore supported. Verify the version used by Python—not only the RPM—with:

```bash
python3.9 -c 'import sqlite3; print(sqlite3.sqlite_version)'
```

### 2.2 Deploy the checkout under `/DATA`

From a reviewed checkout, run as the target service account or as root while
providing the intended owner/group:

```bash
cd /path/to/rules_recertify
sudo RULES_RECERTIFY_OWNER=illumio-mco \
  RULES_RECERTIFY_GROUP=illumio-mco \
  ./scripts/install-prod.sh
cd /DATA/mco/illumio-mco/rules_recertify
```

The installer creates the standard root and `var/state`, `var/raw`, `var/output`,
and `var/logs` with mode `0750`. On a first install it creates
`config/local.json` from the production example and `.env` with mode `0600`.
During an upgrade it preserves `.env`, `config/local.json`, `.venv`, and the entire
`var` tree. It does not install RPMs, credentials, cron, or Python wheels.
Set `workloader_config_file` in `config/local.json` to the absolute Workloader
`pce.yaml` path. Every managed Workloader invocation passes it with
`--config-file`, so execution does not depend on the cron working directory.

### 2.3 Create the Python environment

```bash
cd /DATA/mco/illumio-mco/rules_recertify
python3.9 -m venv .venv
. .venv/bin/activate
python -m pip --version
python -m pip install --no-index --no-deps -e .
# Use the approved internal wheel directory when openpyxl is not preinstalled:
python -m pip install --no-index --find-links /path/to/approved/wheels openpyxl
```

Production uses the checked-in `setup.py`, which is compatible with pip 20.2.4
and setuptools 50.3.2. The repository intentionally does not contain a
`pyproject.toml`: on this offline host it activates PEP 517 build isolation and
causes pip to search an unavailable package index for `setuptools>=61`. The
virtual environment must contain setuptools; verify it without contacting an
index:

```bash
python -c 'import setuptools; print(setuptools.__version__)'
```

If setuptools is unavailable, install an approved internal RPM/wheel, or skip the
editable installation. The supplied `scripts/rules-recertify` launcher sets
`PYTHONPATH` itself and works directly from the deployed source tree:

```bash
./scripts/rules-recertify --config config/local.json validate-config
./scripts/rules-recertify --config config/local.json init-db
```

Do not use the network to upgrade pip/setuptools on production.

### 2.4 Troubleshoot the legacy editable-mode error

The following messages are packaging-tool compatibility errors, unrelated to
SQLite, Workloader, PCE credentials, or the application configuration:

```text
File "setup.py" not found. Directory cannot be installed in editable mode.
A pyproject.toml file was found, but editable mode currently requires a
setup.py based build.

Installing build dependencies ... error
Could not find a version that satisfies the requirement setuptools>=61
```

The second error means pip 20.2.4 found `pyproject.toml`, created an isolated build
environment and attempted to download the declared build requirement. `--no-index`
correctly prevented that download. Deploy this revision: `install-prod.sh` removes
the obsolete deployed `pyproject.toml` and copies `setup.py`. Then reactivate the
virtualenv, confirm the files and retry the original command:

```bash
cd /DATA/mco/illumio-mco/rules_recertify
. .venv/bin/activate
test -f setup.py
test ! -e pyproject.toml
python -m pip --version
python -c 'import setuptools; print(setuptools.__version__)'
python -m pip install --no-index --no-deps -e .
```

If the approved production environment intentionally has no setuptools, do not
block initialization on editable installation. Use the source launcher directly.

## 3. Configuration

```bash
# install-prod.sh creates these on first installation. If provisioning manually:
cp config/production.example.json config/local.json
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

`PCE`, `WORKLOADER_DIR`, and `STATE_DB` in `.env` override values from
`config/local.json`. They are commented out in new installations to avoid an
accidental override. For an installation created from an earlier template, check
only these non-secret keys:

```bash
grep -E '^(PCE|WORKLOADER_DIR|STATE_DB)=' .env || true
```

Remove an unintended `STATE_DB=var/state/rules_recertify.sqlite` line, or replace
it with the absolute production path. `validate-config` prints all effective paths;
the displayed `state_db` is authoritative.

Validate and initialize:

```bash
./scripts/rules-recertify --config config/local.json validate-config
./scripts/rules-recertify --config config/local.json init-db
```

The second command creates
`/DATA/mco/illumio-mco/rules_recertify/var/state/rules_recertify.sqlite` and the
version-1 schema. `collect`, `ingest-reference`, `ingest-usage`, and `report` also
initialize the schema defensively. This is application setup, not an RPM install:
the installer does not execute `dnf` or modify the operating system.

Verify the created database:

```bash
sqlite3 /DATA/mco/illumio-mco/rules_recertify/var/state/rules_recertify.sqlite \
  'PRAGMA integrity_check; SELECT version FROM schema_version;'
sqlite3 /DATA/mco/illumio-mco/rules_recertify/var/state/rules_recertify.sqlite \
  '.tables'
```

Expected schema version is `1`; integrity must return `ok`.

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
2. exports labels and builds the authoritative set of `app` label values;
3. inventories rules without traffic expansion;
4. admits only rulesets whose complete scope is `app:<value>;env:<value>` and
   whose application value exists in the label export;
5. counts and bin-packs whole eligible rulesets up to the configured rule limit;
6. submits sequential `rule-export --traffic-count --expand-svcs` batches;
7. polls `rule-usage` and logs completion progress;
8. never replaces a completed usage window with a later pending result;
9. commits usage and port observations to SQLite;
10. writes raw artifacts and `manifest.json` under `var/raw/<run_id>`;
11. sends one non-blocking SMTP summary.

Check the latest collection with a single concise status line:

```bash
./scripts/check-collection.sh
```

Exit code `0` means a complete success, `1` means running or warning, `2` means
failure or inconsistency, and `3` means the status could not be determined.

Rulesets above `traffic_batch_size` are not submitted for traffic analysis. They
remain in the rule inventory, are listed in the manifest under
`skipped_oversized_rulesets`, create `RULESET_SKIPPED_OVERSIZED` data-quality
records, and force the collection status to `WARNING`. This makes deliberate
partial collection auditable instead of silently omitting policy.

Rulesets with an empty scope, a scope other than the strict
`app:<application_label>;env:<environment>` form, or an application value absent
from the current `label-export` are also excluded from traffic expansion. The
manifest records them in `excluded_scope_rulesets` with a reason, and the
collector writes a corresponding `RULESET_SKIPPED_*` data-quality entry. The
unexpanded inventory is still retained for audit.

The structured application log emits one `Traffic ruleset selected` or
`Traffic ruleset excluded` record per ruleset. Each record carries
`selection`, `ruleset_href`, `ruleset_name`, `ruleset_scope`, `rule_count`, and,
when applicable, `batch` or `reason`. For a concise post-run selection audit:

```bash
grep -E 'Traffic ruleset (selected|excluded)' var/logs/rules-recertify-*.jsonl
```

### 5.2 Initial backfill

The PCE exposes about 90 days. Start with smaller windows to validate PCE load,
then increase cautiously. Each window must be non-overlapping. For example, run
sequential 7-day windows, newest first. Never sum overlapping counts.

### 5.3 Cron

Example for a daily launch at 03:15 server time (ensure the host timezone and
window-generation wrapper are reviewed):

```cron
15 3 * * * cd /DATA/mco/illumio-mco/rules_recertify && /DATA/mco/illumio-mco/rules_recertify/scripts/daily-collect.sh
```

Use the supplied wrapper template, which computes adjacent UTC dates, activates
the virtual environment, obtains a non-blocking lock, and preserves the collector
exit code.

The repository does not modify crontab automatically. Install the reviewed line
under the service account only after the PCE integration test succeeds.

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

## 9. Production ownership and upgrade checklist

Before the first real collection, verify:

```bash
cd /DATA/mco/illumio-mco/rules_recertify
pwd
stat -c '%U:%G %a %n' . .env config/local.json var var/state var/raw var/output var/logs
python3.9 -c 'import sqlite3; print(sqlite3.sqlite_version)'
./scripts/rules-recertify --config config/local.json validate-config
./scripts/rules-recertify --config config/local.json init-db
```

The runtime owner needs read/execute access to application files and read/write
access to every `var` directory. Keep `.env` at `0600`. Review SELinux labels and
mount options with the RHEL administrators because the repository does not change
SELinux policy.

For an application upgrade, take a SQLite backup, stop/disable the cron launch,
deploy from the new reviewed checkout with `install-prod.sh`, run the offline test
suite and `init-db`, then re-enable cron. The installer preserves runtime state and
local configuration, but it is not a backup mechanism.

Because WAL mode can create `rules_recertify.sqlite-wal` and
`rules_recertify.sqlite-shm`, do not copy only the main database during active
writes. Use SQLite's backup mechanism or stop collection and checkpoint first.
