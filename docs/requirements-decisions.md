# Requirements Decision Record

**Status:** confirmed unless explicitly marked open  
**Last updated:** 2026-08-24 (UTC)

This record turns the product owner's clarifications into an implementation
contract. It takes precedence over earlier proposals in the technical design.

## 1. Selection and module semantics

### DEC-001 — Application rule selection

Use the **touching application** model. Include a rule when its effective source
or destination selects at least one requested Application label in the requested
Environment, or when its ruleset scope directly names a requested Application
label and applies to the requested Environment. Both Source and Destination are
considered.

The command accepts a subset of Application labels and one Environment. Extraction
and reporting are restricted to that requested set. Consolidation does not erase
module provenance.

### DEC-002 — Module

`Module` is the requested Application label to which the rule is attributed. If a
rule is relevant to more than one requested Application label, its `Module` cell
contains the matching labels in deterministic input order, separated by an
in-cell newline. A stable rule row is not duplicated per module.

### DEC-003 — Included policy objects

Include enabled and disabled rules, `allow` and `deny` rules, rules containing
custom iptables, rules with `unscoped_consumers=true`, and rules with an empty
description. Also include rules belonging to disabled rulesets. Preserve
`ruleset_enabled` and `rule_enabled` as separate columns so consumers can filter
without losing policy inventory.

### DEC-004 — Environment behavior

- `env:NULL` in ruleset scope applies to every requested Environment.
- A ruleset scope without `env` applies to every requested Environment.
- A shared/multi-environment rule applies when it covers the requested Environment.
- A workload without an Environment label does not match an environment-scoped
  application selection.
- Multiple Environment labels on one workload are invalid input and must be
  reported as a data-quality error.
- The ruleset scope wins over any environment-looking token in its name.

## 2. Workloader contract

### DEC-005 — Supported version and commands

Target Workloader version is `12.0.20`. `rule-export` supports
`--ruleset-hrefs`, `--policy-version active|draft`, `--expand-svcs`,
`--traffic-count`, `--traffic-max-results`, `--traffic-rule-limit`, date-only
traffic boundaries, and an output file. It does not expose a `--rule-hrefs`
option. `rule-usage` accepts a suitably shaped prior CSV and may be run repeatedly
within 24 hours.

Run metadata-only `rule-export` first, without `--traffic-count` and without
`--expand-svcs`, to inventory and count rules. Run traffic submissions separately
with both `--traffic-count` and `--expand-svcs`.

### DEC-006 — Traffic windows

Use one-day windows and invoke Workloader with adjacent date-only boundaries, for
example `--traffic-start 2026-08-20 --traffic-end 2026-08-21`. The generated query
body confirms midnight UTC timestamps for the supplied examples. Internally
represent the window as `[start_date 00:00:00Z, end_date 00:00:00Z)` and validate
the returned `query_body` boundaries before ingestion.

This exclusive-end convention is the project contract. An integration test must
still verify that Workloader 12.0.20 produces the expected query boundaries before
production ingestion is enabled.

The PCE exposes approximately 90 days of traffic. Gaps should be backfilled before
they age out. The initial backfill requests up to the available 90 days, but it
must be split into configurable windows if a single long query proves too costly
or approaches result limits.

### DEC-007 — Batching and polling defaults

- Maximum traffic batch: 100 rules.
- Submission: sequential, no concurrent batches.
- Cooldown: configurable.
- Initial result delay: 30 minutes.
- Poll interval: 10 minutes.
- Deadline: 23 hours after submission.
- Completion is status-driven, not sleep-driven.
- Each poll logs total, completed, pending, expired, failed/unknown, completion
  percentage, batch number, elapsed time, and next poll time.
- Either the original rule-export file or a later compatible rule-usage file may
  be supplied to the next poll.

Because Workloader cannot accept rule hrefs, rulesets are bin-packed using the
metadata inventory. Rulesets above the configured limit are excluded and audited
rather than partially submitted.

If Workloader's submission-time count exceeds the inventory count, recursively
split the batch. Exclude a ruleset that exceeds `--traffic-rule-limit` when
submitted alone, record `TRAFFIC_RULE_LIMIT_EXCEEDED`, and continue the run.

If Workloader exits after HTTP 429, 500, 502, 503, or 504, retry the identical
command rather than aborting the collection. Enforce at least ten minutes
between collector-level attempts and cap the retry count through configuration.
Previously completed batches remain committed; rule-level resume is unavailable
because Workloader's selection interface accepts ruleset hrefs, not rule hrefs.
Do not retry deterministic failures such as invalid input, authentication,
authorization, or local configuration errors.

Skip and audit individual usage rows whose `query_body` has no parseable
`start_date`/`end_date`, while continuing the collection and retaining the raw
CSV. Continue to reject parseable windows that differ from the requested period.

Accept named IP protocols in Workloader's portless `0 NAME (flows)` form, not
only ICMP/IGMP. Skip and audit an individual row if its expanded port detail is
still malformed rather than rolling back ingestion for the entire batch.

Before bin-packing, export labels and admit only rulesets with one consistent
scope containing exactly `app:<application_label>` and `env:<environment>` (in
either order), where the application value exists under `key=app` in that label
export. Empty, malformed, label-group,
unknown-application, and inconsistent scopes remain in the raw inventory but are
excluded from traffic expansion and recorded in the manifest and Data Quality.
Named exceptions may admit empty-scope rulesets when `ruleset_name` contains a
configured `empty_scope_ruleset_name_patterns` value (case-insensitive). This
exception does not admit malformed non-empty scopes.

### DEC-008 — Service representation

Traffic submission uses `--expand-svcs`. Preserve the Illumio service name and
parse the expanded protocol/port list in parentheses. Reports display both:

- service object name; and
- resolved protocol/port or range, one item per in-cell line.

`All Services`, ICMP, IGMP, TCP/UDP single ports, and TCP/UDP ranges must be
supported.

## 3. Hit semantics

### DEC-009 — Certification-oriented hit model

The primary question is whether traffic was observed, not the exact flow volume.
For each completed daily usage window:

- `HIT` when numeric `flows > 0`;
- `NO_HIT` when numeric `flows = 0`;
- `UNKNOWN` for pending, expired, failed, missing, malformed, or unverified data.

Across the requested lookback:

- `HAS_HIT`: at least one completed positive window;
- `NO_HIT_IN_COVERED_PERIOD`: all applicable windows completed and all are zero;
- `UNKNOWN_INCOMPLETE_COVERAGE`: no positive window and at least one applicable
  window is absent or not completed.

First and last hit are the first and last positive daily **windows**, not precise
packet timestamps. `days_since_last_hit` is measured from the report as-of date to
the end date of the latest positive window. If no positive window exists, the
field is null rather than a fabricated number.

The meaning of Workloader's raw `flows` counter at the network-record level remains
unconfirmed. Store it as an opaque Workloader count. The supplied examples show
that `flows_by_port` has grammar `PORT PROTOCOL (COUNT)` separated by semicolons,
with `0 ICMP` and `0 IGMP` representing protocols without a port. The suffix
`+ N more` means the textual per-port summary is incomplete; it does not invalidate
the binary hit/no-hit conclusion from total `flows`, but sets
`port_breakdown_complete=false`.

`--traffic-max-results 10000` remains configurable. Since truncation behavior is
not known, any detected truncation affects count/detail quality, while a positive
total still proves a hit. It must never turn a positive hit into `NO_HIT`.
When `flows_by_port` ends with `+ N more`, set
`port_breakdown_complete=false`, store `N` as `port_details_omitted_count`, add a
Data Quality warning, and never attempt to infer the omitted ports.

## 4. Endpoint expansion

### DEC-010 — Supported selectors for release 1

Support labels, IP Lists, explicit workloads, `all_workloads`, and `Any`. Unsupported
non-empty selector types cause a visible Data Quality warning and prevent the
affected rule from being marked fully resolved.

Label expressions use AND within a selector group, OR between groups, then apply
exclusions and ruleset scope.

Expand `All Workloads` against the ruleset scope rather than displaying the
literal selector. Apply every supported dimension present in `ruleset_scope`
(`app`, `env`, `loc`, and `role`) to the workload reference. Format one workload
as `short_hostname (ip1;ip2)`, falling back to `name` when `short_hostname` is
empty. For `env:NULL`, use the environment paired with the selected application.

### DEC-011 — Workload address selection

- Managed workload (`managed=TRUE`): use `ip_with_default_gw`.
- Unmanaged workload (`managed=FALSE`): use every address in `interfaces`.
- Workload with no selected IP: exclude it from expanded endpoints and count it in
  Data Quality.
- More than one Environment label: invalid; exclude from resolution and report.
- `use_workload_subnets` is expected to be false in the corporate data. Do not
  expand it in release 1; a true value is an unsupported-data warning.

`ip_with_default_gw` is a plain IP such as `10.20.30.40`. `interfaces` is not
JSON: it is a semicolon-separated list of `interface_name:address` entries. A
managed example is `eth0:175.128.12.115/21; <any ipv6>`; an unmanaged example is
`aut0:192.18.18.247; aut0:175.128.12.115`. Trim whitespace, ignore empty or
malformed entries with a Data Quality warning, parse IPv4/IPv6 with an optional
prefix, and deduplicate selected IP addresses while preserving first-seen order.
IPv6 is expected only on managed workloads but must be parsed rather than rejected.

### DEC-012 — IP Lists and Any

Resolve report IP Lists from the complete `export_iplists.csv`, not from the
`NZ3_*`-only derived file. Split `include` on `;`, remove each inline `#comment`,
and retain the IP-list name in the human report. Preserve address/CIDR/range
text in normalized storage. Represent Any as `0.0.0.0/0` and `::/0`; its address
count is `2^32 + 2^128`, stored as exact decimal text in Excel.

## 5. Derived data contracts

### DEC-013 — Derived IP-list CSV

`export_iplists.derived.csv` is retained as a normalized derived artifact with:

```text
name
include
```

The raw source is produced by Workloader `ipl-export`. This derived file is
limited to `NZ3_*` and supports workload/subnet correlation. Report selector
resolution deliberately uses the complete raw export instead.
The report prefers the newest non-empty timestamped run-specific raw export,
explicitly excluding technical directories such as `preflight`, and records
its path in `Presentation`; the normalized SQLite table is a fallback for
manual or legacy runs without an available raw file.

### DEC-014 — Derived workload CSV

`export_wkld.derived.csv` has these ordered columns:

```text
href
hostname
short_hostname
name
external_data_set
created_at
interfaces
public_ip
ip_with_default_gw
app
env
loc
role
managed
enforcement
external_data_reference
OS
os_id
ocs_name_from_IP
IPLIST
SUBNET
```

The Workloader extraction wrapper initially requests:
`href,hostname,name,external_data_set,created_at,interfaces,public_ip,` followed by
`ip_with_default_gw,app,env,loc,role,managed,enforcement,` followed by
`external_data_reference,OS,os_id`. The derivation stage adds and/or normalizes the
remaining columns. Derive the enriched fields as follows:

- `short_hostname`: the substring of `hostname` before the first dot. Preserve an
  already-short hostname. If `hostname` is empty, use the literal
  `[hostname_empty]`; never fall back to workload `name`.
- `ocs_name_from_IP`: replace every `.` in the selected IPv4 address with `-`, for
  example `10.20.30.40` becomes `10-20-30-40`. IPv6 has no confirmed equivalent;
  leave it empty and emit a Data Quality notice in release 1.
- `IPLIST`: the name of the IP List whose name starts with `NZ3_` and whose member
  contains the workload IP (or at least one workload IP at workload summary
  level).
- `SUBNET`: the precise member subnet from that matching `NZ3_` IP List which
  contains the selected IP address.

If several `NZ3_` lists or subnets contain an address, use the first workload IP
and then the first matching IP-list/network in source order. Boolean spelling
and source encoding remain adapter-validation details.

## 6. Workbook contract baseline

### DEC-015 — Workbook grain and sheets

Use one row per rule. Multi-valued Sources, Destinations, ports/ranges, services,
and Modules are stored as in-cell newline-separated values. The required sheets
are:

1. `Presentation`
2. `Raw Rules`
3. `Expanded Rules`
4. `Rule Usage`
5. `Data Quality`

Additional validation sheets are permitted. A later derivation may emit only the
consumer-required sheet.

`Expanded Rules` replaces the earlier proposed name `Exploded Rules`. Its first
version contains the useful canonical columns; exact target column order and
types will evolve after downstream ingestion testing.

It also contains `nb_src_ips`, `nb_dst_ips`, and `nb_ports`. Address counts are
the cardinality of the union represented by expanded IPs, CIDRs, and ranges;
overlaps are not counted twice and IPv6 is ignored for this corporate IPv4
scope. Port counts include distinct explicit TCP/UDP ports and expand inclusive
ranges. `All Services` expands to `0-65535 TCP` and `0-65535 UDP`, for 131072
protocol/port pairs; portless protocols do not add a numeric count.

### DEC-016 — Required application arguments

The command requires:

- `kear_consolidated_application`: UID-format application identifier;
- `logical_application_name`: mandatory display name, passed as one quoted shell
  argument when it contains whitespace or apostrophes;
- one or more Application label values;
- exactly one Environment value per Application value, paired by CLI order.

For a scoped ruleset, `ruleset_scope` must match an exact requested pair. For an
unscoped ruleset, one Source or Destination side must contain the pair, or the
Application label alone (meaning every requested environment for that
application). Labels split across opposite sides do not form a pair.

Never use shell `eval`; pass arguments as an array so quotes and apostrophes are
data rather than command syntax.

The representative KEAR identifier format is a hyphenated UUID such as
`51be4bf9-2080-432f-9d02-1c0cf0f251d7`, without a `KEAR-` prefix. Input validation
only requires a non-empty value; normalize it to lowercase. The mandatory KEAR ID
appears in every workbook sheet and, together with the ordered distinct
environments, in the workbook filename. A safe pattern is
`rules_recertify_<kear_id>_<env1-env2>_<as-of>.xlsx`.

## 7. Persistence and operations

### DEC-017 — History

Use SQL compatible with SQLite 3.24 or newer for the single-host deployment. The
production SQLite version is `3.26.0-20.el8_10`, which meets this requirement.
Keep auditable raw artifacts alongside the database and consider external
storage later. The analytical retention minimum and default are **550 days**;
the default report lookback is **548 days**. This provides an operational margin
over the required 18 months.

The initial backfill covers the 92 PCE days fixed at initialization. Persistent
weekly and backfill cursors advance only after a complete successful window.
Coverage is always reported honestly; no-hit certification requires complete
coverage for the claimed lookback.

### DEC-018 — Runtime

- Scheduler: cron.
- Production OS: RHEL 8.
- Production installation root: `/DATA/mco/illumio-mco/rules_recertify`.
- Python: 3.9.25 in a virtual environment.
- PyPI: unavailable; dependencies must come from approved installed packages or
  offline artifacts with hashes.
- Workloader default directory: `/DATA/WORKLOADER/ver12`, configurable.
- Production SQLite RPM: `3.26.0-20.el8_10`.
- SQLite is accessed through Python's standard `sqlite3` module; `openpyxl` is
  required for reporting.
- Alerts: email, with potential reuse of `smtp_utils.py` after source review.
- PCE/Workloader credentials: `.env` file.

The `.env` path is configurable, excluded from Git, permissioned `0600`, never
logged, and loaded without `source`/shell evaluation. Startup validation reports
missing variable names but never values.

SMTP settings are also stored in `.env`. Send exactly one summary email at the end
of each scheduled collection batch, whether it succeeds, partially succeeds, or
fails. The message uses `SUCCESS`, `WARNING`, or `ERROR` and summarizes every
export and processing stage, traffic-query totals/statuses, coverage, warnings,
and local artifact/log locations. All operations are logged locally. SMTP failure
is logged but never changes the collection's business status or exit outcome.

Scheduled collection persists exports and usage history; it does **not** generate
or email an application workbook every day. A separate on-demand report command
reads the stored snapshots/history and generates a workbook for the requested
KEAR ID, logical application name, Application labels, Environment, and lookback.
Collection must therefore retain the complete PCE policy/inventory scope required
for arbitrary later application selections rather than discarding non-requested
applications during ingestion.

### DEC-019 — Policy version

Use the policy representation returned by the established Workloader export
workflow. `draft` hrefs are expected in this context and do not require a separate
active/draft comparison in release 1. Record `--policy-version` and the href in
the manifest for traceability.

### DEC-020 — Daily policy-only publication

Use `collect-policy` for the daily complete policy inventory. It exports all
references, labels, rulesets, and rules without requesting traffic. Rule
presence changes only when the entire inventory and every required CSV have
been validated and the complete snapshot is committed successfully. Failed or
partial runs never mark a rule absent. The successful run is materialized under
`var/raw/snapshot`; the historical combined `collect` command remains available
only as a transitional compatibility path until traffic collection is split.

### DEC-021 — Weekly cursor-controlled traffic collection

Use `collect-traffic` for one seven-day half-open window per invocation. A fresh
minimal ruleset/label/rule export determines traffic eligibility but never
replaces the current policy inventory. SQLite is authoritative for continuity:
the next start equals the previous successful end, and an incomplete or failed
window retains its original boundaries for an identical retry. Only complete
success advances the cursor; retention pruning remains 550 days.

## 8. Residual implementation discoveries

No product-owner decision remains open from the R1–R8 clarification round. The
following behaviors must be discovered or contract-tested during implementation,
without blocking the approved design:

1. Whether PCE/Workloader exposes a truncation signal beyond the visible
   `+ N more` port-summary marker.
2. Confirmation through an integration test that Workloader 12.0.20 applies the
   agreed exclusive traffic-end convention.
3. The exact boolean spelling and source encoding of production workload CSVs.
4. The existing `smtp_utils.py` interface and `.env` variable names, after the
   referenced repository becomes accessible.
