# Rules Recertify — Technical Design

**Status:** design baseline for review  
**Date:** 2026-08-22 (UTC)  
**Language:** English  

## 1. Purpose

Rules Recertify will produce an auditable Excel view of Illumio microsegmentation
rules for a logical application. A logical application is selected with one or
more `app` label values plus exactly one `env` label value. The workbook will
consolidate all selected application labels, replace the Local/Remote convention
with explicit Source/Destination columns, resolve policy selectors to IPs and
subnets, and show whether and when each rule was used over a rolling period of up
to 180 days.

The workbook is both a human-readable recertification deliverable and a machine
input to another system. Its schema must therefore be versioned and deterministic.

## 2. Scope

### 2.1 In scope

- Orchestrate Workloader exports for rulesets, rules with traffic queries,
  rule usage, IP lists, labels, and managed/unmanaged workloads.
- Ingest the enriched `export_wkld.derived.csv` and, when confirmed,
  `export_iplists.derived.csv`.
- Select all rules relevant to the requested application-label set and
  environment.
- Preserve Illumio rule identity using `rule_href`, not mutable names or row
  positions.
- Expand labels, label groups, explicit workloads, IP lists, Any, and workload
  subnet selectors while respecting ruleset scope and exclusions.
- Accumulate windowed traffic observations, calculate first/last hit and days
  since last hit, and retain 180 days.
- Generate a formatted, validated Excel workbook and a machine-readable run
  manifest.

### 2.2 Out of scope for the first release

- Changing or provisioning Illumio policy.
- Making an automated approve/delete recommendation.
- Replacing Workloader with direct PCE API calls.
- Multi-PCE aggregation, unless a stable `pce_id` is added to every key.
- Treating a failed, pending, expired, or truncated query as zero traffic.

## 3. Required inputs and outputs

### 3.1 Runtime inputs

```yaml
pce: pce-prd-l3.wr
application_labels:
  - APP_A
  - APP_A_LEGACY
environment_label: PRD
window_days: 1
query_initial_delay_minutes: 30
query_poll_interval_minutes: 10
query_deadline_minutes: 1380
traffic_batch_size: 500
retention_days: 180
timezone: UTC
```

Secrets must come from the established Workloader/PCE credential mechanism or a
secret manager, never from this file or command logs. CLI values should override
configuration values and the effective redacted configuration should be stored
in the run manifest.

### 3.2 Source datasets

| Dataset | Purpose | Minimum identity |
|---|---|---|
| Rulesets | Enabled state, description, scope, href | `href` |
| Rules | Source/destination selectors, services, flags | `rule_href` |
| Rule usage | status, total flows, flows by port, query | `rule_href`, query window |
| Labels | Resolve hrefs and label values/types | label `href` |
| IP lists | Resolve named members, CIDRs and exclusions | IP-list `href` |
| Workloads | Resolve label combinations to interfaces/IPs | workload `href` |
| Derived workloads | Organisation-specific enrichment | stable workload identity |

Every adapter must validate required headers and record the Workloader version,
command, file checksum, row count, and extraction time before transformation.

### 3.3 Outputs

- `rules_recertify_<logical-app>_<env>_<as-of>.xlsx`
- `manifest.json` with run identity, effective filters, source checksums, coverage,
  warnings, counts, software versions, and workbook schema version
- immutable raw CSV exports and logs in a run-specific artifact directory
- a local historical database (SQLite by default), not committed to Git

## 4. End-to-end processing design

### 4.1 Run lifecycle

1. Acquire a single-instance lock and create a unique `run_id`.
2. Validate configuration, dates, binary version, credentials, disk space, and
   output paths.
3. Export rulesets and retain enabled rows. Preserve the full raw file.
4. Determine relevant rulesets/rules for the requested app labels and environment.
5. Export labels, IP lists, and managed/unmanaged workloads; ingest derived data.
6. Submit rule traffic queries in bounded batches.
7. Poll with `rule-usage` after the initial delay and until every query reaches a
   terminal state or the deadline approaches the 24-hour expiry.
8. Validate and atomically ingest only completed usage results.
9. Resolve and explode the policy snapshot.
10. Calculate coverage and 180-day usage metrics.
11. Generate the workbook to a temporary path, validate it, then atomically rename.
12. Finalize the manifest and prune data strictly older than the retention policy.

A rerun with the same PCE, rule, window, and usage granularity must be idempotent.
Partial runs remain resumable and must never overwrite a successful run.

### 4.2 Date-window semantics

Use half-open UTC intervals: `[traffic_start, traffic_end)`. For a daily run at
2026-08-22 00:00 UTC, query `2026-08-21T00:00:00Z` through
`2026-08-22T00:00:00Z`. Passing the same date as both start and end, as in the
sample command, may represent a zero-length interval and must not be relied on
until the installed Workloader behavior is confirmed.

`window_days` controls the interval length; it should not silently use “now minus
N days,” because scheduler delays would create gaps or overlaps. The next window
starts at the last successfully covered boundary. Daily windows are recommended:
they give exact day-level last-hit reporting and make recovery inexpensive.

### 4.3 Rule selection semantics

The phrase “rules for an application” is ambiguous and must become an explicit
policy. The recommended default is **touching application**: include an enabled
rule when, after applying ruleset scope, its effective source or destination can
select a workload carrying one requested `app` label and the requested `env`
label. Include rules scoped directly to that app/environment even when an endpoint
uses Any. The workbook must state the selection mode.

Do not filter only on `ruleset_scope`: rules can reference the application from a
differently scoped ruleset. Conversely, simple string matching can include rules
whose label conjunction is impossible. Selection and explosion must evaluate
selectors as Boolean expressions: OR between include groups, AND within a group,
then exclusions and scope constraints.

The treatment of disabled rules and rulesets should be configurable; the default
deliverable contains enabled rules only, while recording excluded counts.

### 4.4 Safe traffic batching

The observed 500-rule limit is a traffic-query safety limit, not proof that
raising it is safe. Setting `--traffic-rule-limit 700` bypasses the guard and may
increase PCE load. A ruleset-href batch is not necessarily a 500-rule batch,
because one ruleset may contain many rules.

Recommended algorithm:

1. Obtain a metadata-only rule inventory (without `--traffic-count`) if supported.
2. Count rules per ruleset and bin-pack ruleset hrefs so each input file contains
   no more than 500 rules.
3. If a single ruleset exceeds 500 and Workloader cannot accept rule hrefs, stop
   with an actionable error; agree either a lower-scope approach, direct API
   fallback, or an explicitly approved higher limit.
4. Submit batches sequentially by default, with configurable cooldown; do not run
   concurrent traffic batches without PCE-owner approval.
5. Keep one rule-export and rule-usage file per batch. Consolidate only after all
   files pass schema, uniqueness, window, and terminal-status checks.

This is safer than concatenating CSV blindly: quoted JSON in `query_body`, headers,
duplicate rules, and differing statuses require CSV-aware parsing.

### 4.5 Asynchronous completion

Prefer status-driven polling over a fixed sleep. The `rule-usage` output already
distinguishes `completed`, `pending`, and `expired`; invoke it repeatedly using
the latest output file as documented by the installed Workloader version. Use a
configurable initial delay, capped exponential or fixed polling, and a hard
deadline before 24 hours. Fixed delay remains a fallback, not the primary signal.

Only `async_query_status=completed` is eligible for usage aggregation. `pending`,
`expired`, parse errors, transport failures, and missing rows are **Unknown**, not
zero. A completed query with `flows=0` is a valid observed zero. The run manifest
and workbook must expose completion percentage and incomplete rules.

### 4.6 Selector explosion

Normalize each rule into explicit Source and Destination selector expressions.
Resolve:

- labels against workload label sets, including managed and unmanaged workloads;
- label groups recursively, with cycle detection;
- explicit workloads and virtual objects when source data supports them;
- IP lists into individual addresses/CIDRs while retaining list name and member;
- workload-subnet semantics from workload interfaces/subnets;
- Any as `0.0.0.0/0` and `::/0`, without enumerating the address space;
- inclusions and exclusions without discarding their provenance.

Ruleset scope constrains effective consumers/providers and must be applied before
claiming a label matches a workload. The resolver should output endpoint records
(`type`, `name`, `hostname`, `ip_or_cidr`, `managed_state`, provenance) rather than
creating a full Source × Destination Cartesian product. If pairwise rows are
required by the downstream system, make that a separate bounded output mode with
row-count guards, because Excel is limited to 1,048,576 rows per sheet.

The exact columns and delimiter rules of `export_wkld.derived.csv` are currently
unknown, so its adapter cannot be finalized.

## 5. Historical accumulation and 180-day guarantee

### 5.1 Recommended persistence

Use SQLite in WAL mode on a single execution host, plus immutable compressed raw
artifacts. CSV-only accumulation is possible but is fragile for deduplication,
transactions, schema evolution, overlapping windows, and concurrent scheduler
runs. PostgreSQL should replace SQLite if multiple workers/hosts are introduced.

Core tables:

| Table | Key / purpose |
|---|---|
| `runs` | `run_id`; state, version, timestamps, configuration |
| `artifacts` | checksum and lineage for every source/output file |
| `policy_snapshots` | snapshot time and PCE identity |
| `rules` | snapshot + `rule_href`; current policy attributes |
| `usage_windows` | PCE + `rule_href` + start + end; status and total flows |
| `usage_ports` | usage window + protocol + port/range; flow count |
| `coverage_intervals` | completed observation intervals, including observed zero |
| `endpoint_snapshots` | time-aware workload/IP-list/label resolution |

Store atomic port observations when `flows_by_port` provides them. Never infer an
exact hit timestamp from a window aggregate: a positive seven-day window proves
only that a hit occurred somewhere in that interval. Therefore report
`first_hit_window_start/end` and `last_hit_window_start/end`; daily collection
narrows uncertainty to one day. “Days since last hit” should use the end of the
last positive completed window and be labelled conservative/interval-based.

### 5.2 Overlaps, gaps, and corrections

- Unique constraints make reingestion idempotent.
- Same-window reruns replace data only when the new result is completed and its
  lineage is retained.
- Overlapping windows must not have their counts summed: traffic would be double
  counted. Prefer non-overlapping canonical daily windows. If overlaps exist,
  counts are reported per window and only coverage intervals are unioned.
- A zero-hit classification is valid only when the complete requested lookback is
  covered by successful queries. Otherwise report `NO_HIT_IN_OBSERVED_PERIOD` or
  `UNKNOWN_INCOMPLETE_COVERAGE`, never simply “unused.”
- Deleted rules retain history and are marked absent from the latest snapshot;
  re-created rules are distinct when their `rule_href` changes.

### 5.3 Retention and assurance

Retain at least 180 completed UTC days plus a configurable safety margin (default
7 days). Prune by window end only after a successful backup/checkpoint. Run a daily
coverage check that detects gaps, schedules backfill while PCE history permits,
and alerts before the asynchronous query's 24-hour lifetime expires.

The application can claim 180-day assurance only when:

1. all canonical daily intervals in the requested period are covered;
2. all selected rules have terminal completed observations for applicable days;
3. no required result was truncated (the sample query has `max_results=10000`,
   which needs explicit validation); and
4. retention and backup checks pass.

Weekly seven-day runs reduce calls but increase hit-time uncertainty and make a
failed/expired run create a seven-day gap. Daily collection is therefore the
recommended default even if weekly reporting is desired.

## 6. Canonical presentation model

### 6.1 Raw Rules

One row per `rule_href` in the current snapshot, with stable ordering:

- Module (`ruleset_name`)
- Environment (derived from effective scope/input, with conflicts flagged)
- Source (readable selectors, includes/excludes preserved)
- Destination (readable selectors, includes/excludes preserved)
- Services (protocol and port/range, plus service name when available)
- Description
- Rule Type, Rule Enabled, Ruleset Enabled
- Rule Href and Ruleset Href
- Hit Status, Total Flows, First Hit Window, Last Hit Window, Days Since Last Hit
- Observation Coverage Start/End/Percent and Data Quality Status

“Module” is assumed to mean ruleset name; this requires confirmation.

### 6.2 Exploded Rules

Use one row per rule-side-endpoint (not Source × Destination pair) with:

- rule/module/environment identity;
- side (`SOURCE` or `DESTINATION`);
- selector expression and inclusion/exclusion flag;
- resolved object type and original object name/href;
- hostname/workload name, IP or CIDR, managed state;
- applied scope and resolution warning;
- services and usage summary repeated for filterability.

If consumers require pairwise rows, define an additional `Rule Matrix` sheet or a
separate CSV after confirming maximum volume.

### 6.3 Recommended workbook sheets

The three requested sheets are mandatory; additional sheets improve auditability:

1. **Presentation** — title, logical application, requested labels/environment,
   modules/scopes, extraction time/timezone, traffic period, coverage, schema and
   tool versions, warnings, and definitions.
2. **Raw Rules** — canonical non-exploded rule view.
3. **Exploded Rules** — resolved endpoint view.
4. **Rule Usage** — per-rule/per-window/per-protocol-port observations and status.
5. **Data Quality** — pending/expired/missing/truncated queries, unresolved
   selectors, gaps, duplicates, and counts.

Use frozen header rows, filters, Excel tables, wrapped text, sensible widths,
consistent UTC date formats, conditional formatting for hit/unknown status, and a
documented color legend. Sheet and column names, types, null representation, and
enumerations belong to a versioned workbook contract; cosmetic changes must not
silently break the downstream ingestion system.

## 7. Proposed repository structure

```text
rules_recertify/
├── README.md
├── pyproject.toml
├── config/
│   ├── example.yaml
│   └── logging.yaml
├── docs/
│   ├── technical-design.md
│   ├── repository-assessment.md
│   └── workbook-contract.md
├── scripts/
│   ├── rules-recertify
│   └── scheduler-entrypoint.sh
├── src/rules_recertify/
│   ├── cli.py
│   ├── config.py
│   ├── domain.py
│   ├── orchestrator.py
│   ├── workloader/
│   │   ├── runner.py
│   │   ├── commands.py
│   │   ├── batching.py
│   │   └── parsers.py
│   ├── selection/
│   │   ├── scopes.py
│   │   └── rules.py
│   ├── resolution/
│   │   ├── labels.py
│   │   ├── ip_lists.py
│   │   └── workloads.py
│   ├── history/
│   │   ├── schema.py
│   │   ├── repository.py
│   │   ├── coverage.py
│   │   └── metrics.py
│   ├── reporting/
│   │   ├── workbook.py
│   │   └── quality.py
│   └── validation/
│       ├── inputs.py
│       └── outputs.py
├── migrations/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── contract/
│   └── fixtures/synthetic/
└── var/                 # gitignored runtime data
    ├── raw/<run_id>/
    ├── state/
    ├── output/
    └── logs/
```

Python owns CSV parsing and business logic; shell remains a minimal scheduler and
binary adapter. This avoids reproducing complex CSV/JSON, date, database, and
Excel logic in shell while still allowing reviewed scripts from existing projects
to inform command construction.

## 8. Reliability, security, and observability

- Invoke commands as argument arrays; never interpolate untrusted labels into a
  shell command.
- Redact credentials and sensitive query bodies from normal logs; restrict file
  permissions because workload names and IPs are sensitive.
- Check Workloader exit codes **and** semantic output status.
- Use checksums, atomic writes, database transactions, locks, structured logs,
  and deterministic run identifiers.
- Emit metrics for submission/completion/expiry counts, PCE request duration,
  rules, unresolved objects, coverage gaps, workbook rows, and run duration.
- Apply retry with backoff only to retryable failures. Do not automatically
  resubmit traffic queries indefinitely.
- Test with synthetic fixtures; production exports and query bodies must not enter
  Git. CSV contract tests must include commas, quotes, empty values, IPv6, ranges,
  exclusions, label conjunctions, and changed/deleted rules.

## 9. Logic assessment

The proposed pipeline is coherent: policy exports supply rule structure, inventory
exports resolve selectors, and asynchronous usage exports supply traffic evidence.
Consolidating multiple application labels into one logical deliverable is sound.
Separating readable Raw Rules from resolution-heavy Exploded Rules is also sound.

The following corrections are essential:

1. Do not assume a fixed delay proves completion; poll terminal statuses.
2. Do not increase the 500-rule limit by default; batch based on actual rule count.
3. Do not concatenate batch CSV files without semantic validation.
4. Do not equate non-completed/missing usage with zero hits.
5. Do not sum overlapping observation windows.
6. Do not claim exact first/last hit timestamps from aggregated windows.
7. Do not expand Any or blindly create endpoint Cartesian products.
8. Do not use label names as durable rule identity; use href plus PCE identity.
9. Confirm `traffic-end` inclusivity and timestamp support before production.
10. Validate query result truncation before using counts for certification.

## 10. Missing decisions and information

Implementation is blocked from being contract-complete until the following are
answered or samples are supplied:

### Selection and policy semantics

1. Does “application rules” mean rules whose ruleset scope contains the app,
   rules whose source/destination selects it, or both (recommended)?
2. How should multiple environments, `env:NULL`, missing env labels, and ruleset
   scopes without an environment be treated?
3. Include disabled rules/rulesets, deny rules, custom iptables rules, unscoped
   consumers, and inherited/shared rules?
4. Required semantics for label groups, exclusions, virtual services/servers,
   user groups, explicit workloads, `all_workloads`, and `use_workload_subnets`?
5. Is “Module” exactly the ruleset name, a naming-derived value, or derived data?

### Usage semantics

6. Installed Workloader version and exact help/output for all commands, including
   whether rule export can filter by individual rule href?
7. Are start/end values dates or timestamps, is end inclusive, and what timezone
   does the PCE/Workloader apply?
8. Exact grammar and meaning of `flows_by_port`; is `flows` a session, record,
   connection, or aggregate count, and are denied flows included?
9. Does `max_results=10000` truncate counts or port detail, and how is truncation
   signalled?
10. Required definition of “first hit,” “last hit,” and “days without a hit” when
    only a multi-day aggregate is available?
11. PCE-approved request rate, concurrency, cooldown, batch limit, retry policy,
    and historical traffic availability for backfill?

### Data and output contracts

12. Representative, sanitized full exports for labels, IP lists, workloads,
    derived workloads/IP lists, rules with non-zero `flows_by_port`, and all async
    statuses?
13. Derived CSV column definitions, key, delimiter/encoding, producer, refresh
    schedule, and conflict precedence versus Workloader?
14. Required exact Excel column names/order/types/enumerations, locale, maximum
    size, downstream schema validation, and whether extra sheets are accepted?
15. Should Exploded Rules be side-endpoint rows (recommended) or every
    source/destination pair?
16. Required protocol rendering, service expansion, IPv4/IPv6 handling, IP-list
    exclusions, hostname/interface selection, and duplicate-IP behavior?
17. Logical application display name when several app labels are supplied?

### Operations and governance

18. Scheduler/orchestrator, runtime OS/Python, installation constraints, storage,
    backup, monitoring, alert destinations, service account, and secret source?
19. One PCE or several, and draft versus active policy expectations? The sample
    hrefs are under `sec_policy/draft`, despite the requirement referring to active
    enabled rulesets; this must be reconciled.
20. Retention requirements for raw exports and workbooks beyond the 180-day
    analytical store, including encryption and access controls?
21. Access to the two reusable repositories/files listed in the repository
    assessment, plus their licensing/ownership and expected reuse level?

## 11. Delivery plan and acceptance gates

1. **Contract discovery:** collect samples/help/version and resolve the questions
   above; approve workbook contract and selection truth table.
2. **Extraction foundation:** implement command runner, manifest, ruleset filter,
   bounded batches, polling, resume, and synthetic command tests.
3. **Normalization:** implement validated parsers and canonical policy/usage model.
4. **History:** add migrations, idempotent ingestion, coverage, retention, and
   first/last-hit interval metrics.
5. **Resolution:** implement scoped label/IP-list/workload expansion and quality
   warnings with controlled row growth.
6. **Reporting:** build and contract-test the workbook, including downstream test
   ingestion.
7. **Operational pilot:** shadow daily runs, prove gap detection/recovery, validate
   load with the PCE owner, then begin the 180-day assurance clock.

Acceptance requires reproducible outputs from the same inputs, no duplicate usage
after rerun, explicit incomplete coverage, correct selector truth-table fixtures,
validated Excel schema, recovery from pending/expired batches, and documented
operational ownership.
