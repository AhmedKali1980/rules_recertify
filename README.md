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
  on the target RHEL 9 host.
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
