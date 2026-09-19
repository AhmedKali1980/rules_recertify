# Integration and Test Guide

## 1. Delivered commands

The `scripts/rules-recertify` entrypoint exposes:

| Command | Purpose |
|---|---|
| `validate-config` | Validate configuration without contacting the PCE |
| `init-db` | Create/upgrade the local SQLite schema |
| `collect` | Export policy, submit/poll traffic queries, and persist usage |
| `ingest-usage` | Ingest an existing Workloader `rule-usage` CSV |
| `ingest-reference` | Ingest derived workloads and the complete raw IP-list CSV |
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
`openpyxl` is imported only by commands that read or generate workbooks
(`report`, `report-batch`, and `search-rules`).

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
- `workloader_config_file`: Workloader `pce.yaml`, which owns PCE profiles,
  FQDNs and credentials;
- `state_db`: durable local SQLite path;
- traffic batch/poll timing;
- `retention_days`, which cannot be lower than 550;
- `smtp_enabled`.

Use `.env` primarily for optional SMTP secrets. Runtime paths and the normal PCE
selection belong in `config/local.json` and `pce.yaml`. The parser never
evaluates shell syntax. Do not run `source .env`; do not commit it.

Legacy `PCE`, `WORKLOADER_DIR`, and `STATE_DB` values in `.env` still override
`config/local.json`; new installations should not define them. For an
installation created from an earlier template, check these non-secret keys:

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
version-2 schema. Existing version-1 databases are migrated transactionally.
`collect-policy`, `collect`, `ingest-reference`, `ingest-usage`, and `report` also
initialize the schema defensively. This is application setup, not an RPM install:
the installer does not execute `dnf` or modify the operating system.

Verify the created database:

```bash
sqlite3 /DATA/mco/illumio-mco/rules_recertify/var/state/rules_recertify.sqlite \
  'PRAGMA integrity_check; SELECT version FROM schema_version;'
sqlite3 /DATA/mco/illumio-mco/rules_recertify/var/state/rules_recertify.sqlite \
  '.tables'
```

Expected schema version is `2`; integrity must return `ok`.

## 4. Reference-data ingestion

Produce the reference exports with the approved extraction/derivation process,
then ingest derived workloads and the complete IP-list export:

```bash
./scripts/rules-recertify --config config/local.json ingest-reference \
  --workloads /data/export_wkld.derived.csv \
  --ip-lists /data/export_iplists.csv
```

The adapter accepts comma or semicolon CSV delimiters and UTF-8 with or without a
BOM. Workloads without a usable selected IP are excluded and recorded under Data
Quality. Repeat ingestion after every reference export; it atomically replaces the
current workload/IP-list snapshot.

## 5. Collection

### 5.1 Daily complete policy inventory

Run the policy-only command daily. It exports L1 and L3SM workloads, IP Lists,
compressed services, labels, every ruleset, and every rule, then validates and
ingests them without submitting any Explorer or rule-usage query:

```bash
./scripts/rules-recertify --config config/local.json collect-policy
```

The run type is `POLICY_COLLECTION`. Current-rule membership is published only
after every required CSV has passed validation and reference ingestion has
completed. A failed run therefore leaves `rules.is_present` and the previous
`policy_snapshots` record untouched. On success, the complete validated run and
manifest are materialized atomically under `var/raw/snapshot`; reports and
`search-rules` read only rules with `is_present=1` and prefer snapshot reference
exports when timestamped raw runs are no longer available.

For an offline validation, `--pce-stub-dir` supplies workload, IP-list, and
service exports while rulesets, labels, and rules continue to come from the
configured fake/test Workloader. The production command does not use this flag.

### 5.2 Weekly traffic collection

The first invocation may seed the cursor explicitly. `--traffic-end` represents
the latest exclusive boundary currently available from the PCE:

```bash
./scripts/rules-recertify --config config/local.json collect-traffic \
  --traffic-start 2026-09-06 --traffic-end 2026-09-13
```

Subsequent invocations omit the start; it is read from SQLite:

```bash
./scripts/rules-recertify --config config/local.json collect-traffic \
  --traffic-end 2026-09-20
```

The command always requests one complete seven-day half-open window. Before
batching, it freshly exports rulesets, labels, and all rules, then applies the
existing traffic-only app/environment/scope and configured-exception filter.
That minimal inventory is retained as a run artifact but is never ingested into
the current policy snapshot and never changes `rules.is_present`.

The durable `weekly` cursor advances only when every submitted query is
terminal and valid and no ruleset was omitted. Pending, expired, unknown,
invalid, or oversized results mark the window failed. Its original start and
end remain stored, and the next invocation must replay that exact window.
Successful windows therefore meet exactly at their exclusive boundaries, with
neither overlap nor a missing day. Usage UPSERT keys preserve idempotence when a
failed window is replayed. Retention pruning uses the configured 550 days.

### 5.2.1 Raw storage and recovery

The current complete policy materialization is always
`var/raw/snapshot/`; successful policy staging directories are removed after
SQLite publication. A successful weekly traffic run whose exclusive end is a
Sunday is retained as `var/raw/archives/<run_id>.tar.gz`. Before the raw source
is removed, the archive is fully reopened and validated, hashed with SHA-256,
atomically published, and registered in `run_archives` in the same transaction
that advances the weekly cursor. Archive failure therefore prevents cursor
advancement. Failed runs and backfill runs are not archived.

Operators can validate disaster recovery without touching the live snapshot:

```bash
./scripts/rules-recertify --config config/local.json restore-archive \
  --archive var/raw/archives/<run_id>.tar.gz --target-dir /tmp/restore-test
./scripts/rules-recertify --config config/local.json purge-archives \
  --as-of 2028-03-23
```

The purge command removes verified archive records whose `retained_until` is
strictly before the supplied date. Reports prefer `var/raw/snapshot`; legacy
timestamped raw directories are accepted only as a migration fallback.

### 5.3 Initial 92-day traffic backfill

Freeze the target once. The command derives and persists `backfill_start` as
exactly 92 days before that target:

```bash
./scripts/rules-recertify --config config/local.json init-backfill-traffic \
  --target-end 2026-09-20 --backfill-id traffic-92-days
```

Run one window every two days until completion:

```bash
./scripts/rules-recertify --config config/local.json backfill-traffic \
  --backfill-id traffic-92-days
```

Each invocation processes at most one oldest-first window. Windows are capped at
seven days; a 92-day interval therefore produces thirteen full windows and one
one-day final window. Persistent states are `PENDING`, `RUNNING`, `FAILED`, and
`COMPLETED`. Failure retains `next_window_start`, so the exact same interval is
retried. Initialization is insert-only and refuses an existing identifier,
including a completed backfill. Once the target is reached, later invocations
return `COMPLETED` without creating a run. Backfill state and windows are
separate from the weekly cursor, while both modes call the same export,
selection, batching, polling, validation, and usage-ingestion engine.

### 5.4 Transitional combined collection

Run after the previous UTC day has closed:

```bash
./scripts/rules-recertify --config config/local.json collect \
  --traffic-start 2026-08-23 \
  --traffic-end 2026-08-24
```

The collector:

1. exports L1 workloads, managed L3SM workloads, and the complete L1 IP Lists,
   then produces and ingests the derived reference data;
2. exports all enabled and disabled rulesets;
3. exports labels and builds the authoritative set of `app` label values;
4. inventories rules without traffic expansion;
5. admits only rulesets whose complete scope contains exactly `app:<value>` and
   `env:<value>` (in either order) and whose application value exists in the
   label export;
6. counts and bin-packs whole eligible rulesets up to the configured rule limit;
7. submits sequential `rule-export --traffic-count --expand-svcs` batches;
8. polls `rule-usage` and logs completion progress;
9. never replaces a completed usage window with a later pending result;
10. commits usage and port observations to SQLite;
11. writes raw artifacts and `manifest.json` under `var/raw/<run_id>`;
12. sends one non-blocking SMTP summary.

This legacy `collect` command temporarily remains available while the traffic
workflow is split into its dedicated command. New daily scheduling must use
`collect-policy`; the legacy command is not the target production scheduler.

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

Workloader can occasionally count more rules than the metadata inventory. If a
traffic submission reports that `--traffic-rule-limit` was exceeded, the
collector splits a multi-ruleset batch to isolate the offending ruleset. A
ruleset that still exceeds the limit on its own is excluded with reason
`TRAFFIC_RULE_LIMIT_EXCEEDED`; the remaining batches continue and the run ends
with status `WARNING` rather than `ERROR`.

An HTTP 429, 500, 502, 503, or 504 returned after Workloader's own retries is
retried by the collector after `rate_limit_retry_delay_minutes` (10 minutes
minimum). The same Workloader command and input file are retried, so collection
resumes at the failed batch or poll instead of advancing past it or restarting
the batches already ingested. `rate_limit_max_retries` bounds this recovery (12
retries by default). Workloader accepts ruleset hrefs rather than individual
rule hrefs, so the safe submission recovery boundary is the current batch, not
the precise rule shown in its log.

Other failures are deliberately not retried automatically. Authentication and
authorization failures, invalid arguments, malformed exports, and local file or
configuration errors require correction; repeatedly issuing the same request
would hide the cause and may increase load on the PCE.

Workloader may summarize rate limiting as `received N 429 errors with ...`
instead of printing a final `status code: 429`. Both forms are recognized as the
same retryable HTTP 429 condition.

Some non-terminal or expired Workloader rows can lack a valid `query_body` and
therefore have no usable `start_date`/`end_date`. Such rows remain preserved in
the raw batch CSV, are skipped during SQLite ingestion, and create a
`USAGE_SKIPPED_INVALID_QUERY_BODY` Data Quality record. The collector continues
with subsequent batches and finishes with `WARNING`; a valid but unexpected
window remains a hard error to prevent data from being attributed to the wrong
day.

Portless IP protocols exported as `0 <PROTOCOL> (<flows>)`, including VRRP, are
stored with their protocol name and no port. If Workloader emits a genuinely
malformed `flows_by_port` item, only that usage row is skipped: the raw CSV is
retained, `USAGE_SKIPPED_INVALID_FLOWS_BY_PORT` identifies its `rule_href`, the
manifest increments `invalid_flows_by_port_count`, and later batches continue.

Rulesets with an empty scope, a scope other than exactly the
`app:<application_label>` and `env:<environment>` dimensions (in either order),
or an application value absent
from the current `label-export` are also excluded from traffic expansion. The
manifest records them in `excluded_scope_rulesets` with a reason, and the
collector writes a corresponding `RULESET_SKIPPED_*` data-quality entry. The
unexpanded inventory is still retained for audit.

Specific empty-scope rulesets can be admitted by a case-insensitive substring
match on `ruleset_name`. Configure one or more explicit sequences, for example:

```json
"empty_scope_ruleset_name_patterns": ["OUTBOUND2APA"]
```

Only empty scopes receive this exception. An empty list keeps the default strict
behavior, and additional name sequences can be added without changing code.

The structured application log emits one `Traffic ruleset selected` or
`Traffic ruleset excluded` record per ruleset. Each record carries
`selection`, `ruleset_href`, `ruleset_name`, `ruleset_scope`, `rule_count`, and,
when applicable, `batch` or `reason`. For a concise post-run selection audit:

```bash
grep -E 'Traffic ruleset (selected|excluded)' var/logs/rules-recertify-*.jsonl
```

### 5.2 Initial backfill

The frozen 92-day backfill described above is processed oldest first, one window
of at most seven days per eligible wrapper execution. Never create ad-hoc or
overlapping windows outside its persisted cursor.

### 5.3 Production schedule

The reviewed schedule is versioned in `config/rules-recertify.cron` and uses the
server local timezone:

```cron
10 0 * * * cd /DATA/mco/illumio-mco/rules_recertify && ./scripts/daily-policy-collect.sh
0 1 * * 0 cd /DATA/mco/illumio-mco/rules_recertify && ./scripts/weekly-traffic-collect.sh
0 2 * * 0 cd /DATA/mco/illumio-mco/rules_recertify && ./scripts/weekly-traffic-collect.sh
0 3 * * 1-6 cd /DATA/mco/illumio-mco/rules_recertify && ./scripts/backfill-traffic.sh
```

The 02:00 traffic entry is the one-hour retry. After a 01:00 success, the
wrapper reads the weekly cursor and exits successfully without collecting the
following window. The backfill wrapper is invoked Monday through Saturday and
uses SQLite run history as a persistent 47-hour gate, yielding at most one
attempt every two days and excluding Sunday.

All wrappers source `collection_common.sh`, activate the configured virtual
environment and acquire the same non-blocking lock. A collision exits with code
75 and never starts another PCE operation. The repository does not modify
crontab automatically: install it only after supervised manual acceptance.

## 6. On-demand report

```bash
./scripts/rules-recertify --config config/local.json report \
  --kear-id 51be4bf9-2080-432f-9d02-1c0cf0f251d7 \
  --logical-application-name "My Consolidated Application" \
  --application-label APP_A --environment PRD \
  --application-label APP_A_LEGACY --environment UAT \
  --lookback-days 180
```

The output is written atomically below `output_dir`, with KEAR ID and Environment
in its filename. Inspect `Presentation`, `Raw Rules`, `Expanded Rules`,
`Rule Usage`, and `Data Quality`. The KEAR ID is present on every sheet.
Each `--application-label` is paired by position with one `--environment`; the
two options must therefore occur the same number of times. Scoped rulesets must
match an exact pair. An unscoped ruleset is selected only when one source or
destination side contains that exact pair, or contains the application label
without an environment label (meaning every requested environment for that
application).

### 6.1 Bulk reports from Microcosmos

Use `report-batch --microcosmos-xlsx <file.xlsx>` to generate reports for every
non-empty `Kear Id` in the active sheet. The workbook must expose `Kear Id`,
`Application Name`, `Module`, `Account`, `Account Leader`,
`Microsegmentation Solution`, `Environment`, and `Entity`. The application name
becomes the logical report name. A Microcosmos module matches application labels
whose suffix after the second underscore equals that module, case-insensitively
(for example, `APM_RBS_FACTOBOT` maps to `FACTOBOT`). Unknown modules and
inconsistent application names are skipped and recorded in the audit workbook.

The batch root is `output_dir/<UTC timestamp>`. Reports are grouped below
`PRD/<sanitized Entity>` and `NONPRD/<sanitized Entity>`. Rows for the same KEAR
and category are consolidated into one report; NONPRD preserves each original
environment in its application/environment pairs while using `NONPRD` in the
filename. Labels are also discovered from the newest timestamped `labels.csv`.
A known label with no matching rule in SQLite is skipped rather than aborting
the batch.

The timestamp root contains a copy named
`<input>.rules-recertify-status.xlsx`. Its appended `Rules Recertify Status`
column records either the relative generated report path or the reason the row
was skipped (empty KEAR/environment, unknown module, missing rule, or
inconsistent application name).

In `Expanded Rules`, sources and destinations are resolved from the ingested
references, preferring the newest timestamped raw `export_wkld.derived.csv`
over the SQLite workload snapshot and using the complete `export_iplists.csv`.
Label,
explicit-workload, and `All Workloads` selectors render one entry as
`short_hostname (ip1;ip2)`; `name` is used when `short_hostname` is empty.
Managed workloads use `ip_with_default_gw`, while unmanaged workloads use the
ordered IPv4 values parsed from `interfaces`.
Selectors containing both `app` and `env` are matched directly against those
labels (plus any `loc`/`role`) on both source and destination sides. They are not
cross-filtered by a second report pair. Selectors without `app` remain
constrained by the requested report pairs.
Label selector dimensions use Illumio boolean semantics: different dimensions
are ANDed, while repeated values inside one dimension are ORed. For example,
`app:A;env:PRD;role:PSM;role:PSMP` means app A AND PRD AND (PSM OR PSMP), on
both source and destination sides.
When an application label is present but `env` is absent, the selector matches
all environments; report-level environment pairs must not add an implicit
filter. A selector without `app` remains constrained by the report pairs.

IP-list selectors render as `IP List: name (member1;member2)`. Members are
split on `;` during reference ingestion and inline `#comment` suffixes are
removed. An IP List that cannot be resolved remains visibly marked
`[unresolved]` rather than being silently discarded.
Reporting resolves these selectors from the complete raw `export_iplists.csv`;
the `NZ3_*`-only derived export remains dedicated to workload/subnet
correlation. At report time, the newest non-empty
`raw_dir/<YYYYMMDDTHHMMSSZ-8hex>/export_iplists.csv` is parsed directly and takes precedence
over the SQLite snapshot. This makes reports self-healing when SQLite was
populated by an older release that stored only `NZ3_*` members. SQLite remains
the fallback when no raw export exists. The `Presentation` sheet records the
selected file path or the SQLite fallback for auditability. Technical folders
such as `raw/preflight` are never eligible.

The `Expanded Rules` sheet also contains `nb_src_ips`, `nb_dst_ips`, and
`nb_ports`. Address counts represent the union cardinality of workload IPs,
IP-list addresses, ranges, and subnets rather than the number of displayed
items. Corporate rules are IPv4-only, so `Any` (`0.0.0.0/0` plus `::/0` in the
source selector) counts only `2^32`, or `4294967296`. The port count is the
number of distinct explicit TCP/UDP ports and expands inclusive ranges.
`All Services` is displayed as `0-65535 TCP;0-65535 UDP` in `Expanded Rules`
and therefore counts `131072` protocol/port pairs.

Named Illumio service objects are exported from L1 with
`svc-export --compressed` into `export_services.csv`. Reporting loads the
newest non-empty file under a timestamped raw run (never `raw/preflight`) and
resolves each name from the `name` and `service_ports` columns. Expanded Rules
keeps the service name followed by its compressed TCP/UDP definition; Octoflow,
port cardinality, and dangerous-port detection all consume that same expanded
value. Explicit ports combined with a named service remain present. The chosen
service reference path is recorded in `Presentation`.

`Expanded Rules.dangerous_ports` intersects each rule's TCP/UDP ports with the
catalogues selected by the `dangerous_port_lists` setting. Supported names are
`PORTS_TO_CONTROL`, `PORTS_TO_ERADICATE`, and `PORTS_ADMIN`; configuration may
use a JSON list or a comma-separated string. Output uses canonical values such
as `TCP/22` and `TCP/5900-5906`. The unexplained `/3` and `/14` suffixes from a
legacy spreadsheet are not protocol or port syntax and are not emitted without
an authoritative severity mapping.

The `Octoflow` sheet exposes the 25-column consumer contract. The
`dangerous_ports` column immediately follows `dangerous_rule` and contains the
exact value computed for `Expanded Rules.dangerous_ports`. Its NZ3 zones are
computed by full containment of expanded IPv4 addresses, ranges, or subnets;
unmatched sides become `Any`. `permissive_rule_max_ips` (default 255) controls
the strict-greater-than threshold for `permissive_rule`. Rule imports populate
`rule_history`: the first observation is `creation_time`, and the latest
content-changing observation is `last_modified`. Historical changes predating
this schema cannot be reconstructed. `last_hit` uses the latest positive,
completed usage window independently of the report lookback.

## 7. Rule-item search

`search-rules` reads one item per row from a one-column CSV, text, or XLSX file
and searches only rules explicitly marked present by the latest successful
complete policy snapshot. Searchable selectors include ruleset scopes, labels and exclusions,
label groups and exclusions, IP Lists, explicit workloads, and services.
Text matching is literal and case-insensitive unless `--case-sensitive` is
used.

Port inputs support slash or Workloader notation, single ports, and inclusive
ranges. A semicolon-separated port list uses intersection semantics: a rule is
reported when at least one requested interval overlaps an allowed TCP/UDP
interval. Named services are expanded from the newest timestamped
`export_services.csv` before matching. The output workbook contains `Summary`,
`Results`, and `Metadata`; unmatched inputs are explicitly retained as
`NOT_USED_IN_ANY_RULE`.

```bash
./scripts/rules-recertify --config config/local.json search-rules \
  --items /data/search_items.csv --out /data/rules_items_search.xlsx
```

## 8. Test procedure

### 8.1 Offline automated suite

```bash
PYTHONPATH=src python3.9 -m unittest discover -s tests -v
python3.9 -m compileall -q src tests
```

The suite includes a fake Workloader end-to-end collection test and does not
contact the PCE.

### 8.2 Development smoke test

```bash
cp config/example.json /tmp/rules-recertify-test.json
PYTHONPATH=src python3 -m rules_recertify.cli \
  --config /tmp/rules-recertify-test.json validate-config
```

### 8.3 PCE integration acceptance

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

### 8.4 Operational acceptance

Run shadow collection for at least one week. Validate disk growth, PCE load,
completion time, polling values, recovery after interruption, email summaries,
and gap/backfill handling before enabling the full cron schedule.

## 8. Production runbook

### 8.1 Start and supervised acceptance

Keep cron disabled for the first execution. Run `validate-config`, `init-db`,
`daily-policy-collect.sh`, `weekly-traffic-collect.sh`, and
`check-collection.sh` manually under the service account. Initialize the
historical process once with `init-backfill-traffic`, then test
`backfill-traffic.sh`. Confirm PCE load, snapshot contents, cursor boundary,
Sunday archive restoration, logs and monitoring before installing
`config/rules-recertify.cron`. Finally inspect `crontab -l` and the system cron
log after the first scheduled executions.

### 8.2 Stop and resume

To stop, comment or remove the four crontab entries. Do not kill a healthy
collector unless required; the shared lock identifies an active run. To resume,
run `check-collection.sh`, reconcile an interrupted `RUNNING` state, and rerun
the failed wrapper manually. Traffic and backfill cursors retain failed window
boundaries, so recovery replays the same window without a silent gap.

### 8.3 Incident handling and supervision

`check-collection.sh` emits one Nagios-compatible line and checks policy and
traffic status, interrupted runs, snapshot age (26 hours by default), cursor age
(192 hours), backfill progress, expected Sunday archive, lock and disk usage.
Exit codes are 0/1/2/3 for OK/WARNING/CRITICAL/UNKNOWN. Override freshness with
`RULES_RECERTIFY_SNAPSHOT_MAX_HOURS` and
`RULES_RECERTIFY_TRAFFIC_MAX_HOURS`. Disk utilization is reported to the server
monitoring platform; the application does not impose a second disk threshold.

For failed policy, fix the cause and rerun `daily-policy-collect.sh`; the prior
snapshot remains current. For traffic or backfill, rerun the same wrapper and
never manually move its cursor. A held lock with an active run is a warning. A
database `RUNNING` row while the lock is free is critical and must be examined
in structured and Workloader logs before recovery.

### 8.4 Archive restoration

Restore into an isolated directory and never overwrite the live snapshot:

```bash
./scripts/rules-recertify --config config/local.json restore-archive \
  --archive var/raw/archives/<run_id>.tar.gz \
  --target-dir /tmp/rules-recertify-restore
```

Compare the restored manifest and the SHA stored in `run_archives` before using
its contents for investigation or recovery.

### 8.5 Backfill completion

When `next_window_start` reaches the frozen target, the monitor reports
`COMPLETED` and `backfill-traffic.sh` becomes a successful no-op. Remove only
the backfill cron entry after verifying all 92 days; retain daily policy and
Sunday traffic schedules.

### 8.6 Rollback

Before upgrade, disable cron, reconcile the shared lock, checkpoint and back up
SQLite, and retain the current release and snapshot. Deploy with
`install-prod.sh`, run migrations/tests and a supervised policy collection. To
roll back, disable cron again, restore the previous application tree and its
matching SQLite backup, restore the matching snapshot backup when necessary,
run `check-collection.sh`, and only then re-enable cron. Never combine newer
SQLite state with an older binary without a tested migration path.

## 9. Runtime artifacts and recovery

- `var/raw/snapshot`: current materialized policy references and manifest.
- `var/raw/archives/<run_id>.tar.gz`: verified retained Sunday traffic runs.
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

## 10. Production ownership and upgrade checklist

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
