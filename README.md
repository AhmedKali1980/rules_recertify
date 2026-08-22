# Rules Recertify

Rules Recertify will collect Illumio policy and rule-usage exports, retain a
rolling 180-day history, resolve labels and IP lists to concrete endpoints,
and generate a consolidated Excel recertification workbook for one logical
application (one or more application labels) in one environment.

This repository currently contains the approved design baseline; implementation
has not started yet.

## Design documents

- [Technical design](docs/technical-design.md): scope, processing model,
  proposed architecture, data model, Excel contract, operational controls,
  delivery phases, and open questions.
- [Repository assessment](docs/repository-assessment.md): verified Git and
  reusable-project visibility from the current workspace.

## Proposed implementation stack

- Python 3.11+ for validation, transformation, persistence, and Excel creation.
- Thin POSIX shell wrappers for `workloader` invocation and scheduler entrypoints.
- SQLite as the default single-host historical store, with raw immutable CSV
  artifacts retained for audit and replay.
- `pandas`/`openpyxl` (or `xlsxwriter`) for the final `.xlsx` workbook.

No PCE credentials, Workloader binary, generated exports, databases, logs, or
produced workbooks should be committed to Git.
