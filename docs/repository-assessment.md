# Repository and Reuse Visibility Assessment

Assessment date: 2026-08-22 (UTC).

## `rules_recertify` repository

The repository is accessible at `/workspace/rules_recertify`. It is a valid Git
working tree on branch `work`, with initial commit `f0c6aa8`. At assessment time
it contained only `README.md`. No Git remote is configured in the checked-out
repository.

This confirms that the project can be built here, but publishing or opening a
remote pull request requires the execution environment to provide a PR tool or
a Git remote independently of the source tree.

## Other projects

The requested reusable assets are known by name:

### `carto-create-rules`

- `workloader_common.sh`
- `workloader_ipl_export.sh`
- `workloader_label.sh`
- `workloader_ruleset.sh`

### `kpi-steerco`

- `cron_job.sh`
- `workloader_wkld_export.sh`
- `export_wkld.derived.csv`
- `export_iplists.derived.csv`

Neither sibling repository nor any of these files is present under the visible
`/workspace` or `/root` trees. Consequently, their content has **not** been
reviewed and reuse compatibility cannot yet be asserted. They must be cloned,
mounted, or supplied before implementation. Reuse should be selective after a
review of licensing, configuration conventions, secret handling, exit-code
handling, quoting, retries, and compatibility with the installed Workloader
version. Derived CSV files should be treated as sample schemas/fixtures unless
their generation and ownership are explicitly defined.
