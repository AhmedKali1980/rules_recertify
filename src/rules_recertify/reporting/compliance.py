"""Generate rule-compliance workbooks from the materialized policy snapshot."""
from __future__ import annotations

import csv
import importlib.util
import logging
import re
from collections import Counter, defaultdict
from datetime import date, datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Dict, List, Mapping, Optional, Sequence, Tuple
from zipfile import ZIP_DEFLATED, ZipFile

from ..history.database import Database
from ..workloader.csvio import parse_bool, read_rows
from .app_server_scope import (
    IMPACTED_APP_SERVERS, AppServerScopeIndex, AppServerSelection, RoleSelection,
    load_app_server_scope_index, normalized_label,
)
from .dangerous_ports import PORT_CATALOGS, _catalog_interval, dangerous_ports
from .compliance_layout import CONFIGURATION_SHEET, DETAIL_SHEETS, ComplianceLayout, load_compliance_layout
from .compliance_references import ComplianceReferences
from .compliance_schema import (
    COLUMN_GROUPS, DEFAULT_HEADERS, REFERENCE_HEADERS, RULE_ID, RULE_STATUS,
    available_headers, canonical_header, output_row,
)
from .microcosmos import _safe_component
from .workbook import _expand_services, _load_report_services


RULE_FIELDS = (
    "ruleset_name", "ruleset_scope", "ruleset_enabled", "rule_type",
    "rule_description", "rule_enabled", "unscoped_consumers", "src_all_workloads",
    "src_labels", "src_labels_exclusions", "src_label_groups",
    "src_label_groups_exclusions", "src_iplists", "src_workloads", "dst_all_workloads", "dst_labels",
    "dst_labels_exclusions", "dst_label_groups", "dst_label_groups_exclusions",
    "dst_iplists", "dst_workloads", "services", "rule_href",
)
OPTIONAL_RULE_FIELDS = ("src_workloads", "dst_workloads")
REQUIRED_RULE_FIELDS = tuple(field for field in RULE_FIELDS if field not in OPTIONAL_RULE_FIELDS)
LABEL_GROUP_FIELDS = (
    "name", "key", "description", "member_labels", "member_label_groups",
    "fully_expanded_members", "href",
)
MICROCOSMOS_COLUMNS = (
    "Kear Id", "Application Name", "Module", "Account", "Account Leader",
    "Microsegmentation Solution", "Environment", "Entity", "Program (MIO)",
)
MICROCOSMOS_REQUIRED_COLUMNS = MICROCOSMOS_COLUMNS[:-1]
KEAR_NOT_ONBOARDED = "KEAR_NOT_ONBOARDED_IN_MICROCOSMOS"
LOG = logging.getLogger(__name__)


def generate_compliance_workbook(
    raw_dir: Path, output: Path, dangerous_port_lists: Sequence[str],
    input_path: Optional[Path] = None, database: Optional[Database] = None,
    custom_headers_path: Optional[Path] = None,
    split_by_kear_id: bool = False, timestamp: Optional[str] = None,
    debug: bool = False,
) -> Path:
    """Evaluate matching snapshot rules for optional app/environment input rows."""
    if importlib.util.find_spec("openpyxl") is None:
        raise RuntimeError("openpyxl is required for compliance report generation")
    if debug and custom_headers_path is not None:
        raise ValueError("--debug and --custom-headers are mutually exclusive")
    if split_by_kear_id:
        if input_path is None:
            raise ValueError("--split-by-kear-id requires --input with a Kear Id column")
        if output.suffix.casefold() != ".zip":
            raise ValueError("--split-by-kear-id requires a .zip output path")
    snapshot = raw_dir / "snapshot"
    required = [snapshot / "rules_inventory.csv", snapshot / "export_labelgroups.csv"]
    if input_path is None:
        required.append(snapshot / "labels.csv")
    missing = [str(path) for path in required if not path.is_file() or not path.stat().st_size]
    if missing:
        raise ValueError("compliance snapshot file is missing or empty: " + ", ".join(missing))
    input_rows, input_columns = _load_scope_input(input_path, snapshot / "labels.csv")
    if split_by_kear_id and not any(name.casefold() == "kear id" for name in input_columns):
        raise ValueError("--split-by-kear-id requires input with a Kear Id column")
    microcosmos_input = "Program (MIO)" in input_columns
    microcosmos_lookup = _microcosmos_kear_lookup(input_rows) if microcosmos_input else {}
    rules = [
        {**dict.fromkeys(OPTIONAL_RULE_FIELDS, ""), **row}
        for row in read_rows(snapshot / "rules_inventory.csv", REQUIRED_RULE_FIELDS)
    ]
    groups = list(read_rows(snapshot / "export_labelgroups.csv", LABEL_GROUP_FIELDS))
    group_index = _label_group_index(groups)
    app_servers = load_app_server_scope_index(snapshot)
    services, _ = _load_report_services(raw_dir)
    report_catalogs = tuple(dict.fromkeys((*dangerous_port_lists, *PORT_CATALOGS)))
    usage_by_rule = database.compliance_usage() if database is not None else {}
    intra_zone_rulesets = {
        _ruleset_identity(row) for row in rules
        if _has_intra_zone_iplist(row.get("src_iplists", ""))
        or _has_intra_zone_iplist(row.get("dst_iplists", ""))
    }

    rows: List[Dict[str, object]] = []
    for input_row in input_rows:
        app = _get_case_insensitive(input_row, "app").strip()
        env = str(input_row.get("__compliance_env", _get_case_insensitive(input_row, "env"))).strip()
        programs = _programs_for_app(app, groups)
        matched = [
            row for row in rules if _rule_matches_scope(row, app, env, group_index)
        ]
        primary_columns = (
            [*MICROCOSMOS_COLUMNS, "app"]
            if "Program (MIO)" in input_columns else input_columns
        )
        reserved = {IMPACTED_APP_SERVERS, RULE_ID, RULE_STATUS}
        input_values = {column: input_row.get(column, "") for column in primary_columns
                        if canonical_header(column) not in reserved}
        extra_values = {
            column: input_row.get(column, "")
            for column in input_columns if column not in primary_columns
            and canonical_header(column) not in reserved
        }
        if not matched:
            rows.append({
                **_with_rule_enrichment_columns(input_values), "Program (KPI)": programs,
                "env": env, RULE_STATUS: "", RULE_ID: "",
                "Match status": "APP_NOT_FOUND" if not app else "NO_MATCH",
                "Warning": "",
                "Global Consumer in use": "FALSE",
                **{field: "" for field in (
                    "ruleset_name", "ruleset_scope", "ruleset_enabled", "rule_type",
                    "rule_description", "rule_enabled", "rule_href",
                )},
                "Source": "", "Destination": "",
                IMPACTED_APP_SERVERS: None,
                "Source contains User": "FALSE",
                "Destination contains User": "FALSE",
                "services": "",
                **{catalog: "" for catalog in report_catalogs},
                "Protection type": "",
                **_empty_usage_columns(report_catalogs),
                **extra_values,
            })
            continue
        for rule in matched:
            source, source_kind = _factor_side(rule, "src", group_index)
            destination, destination_kind = _factor_side(rule, "dst", group_index)
            expanded_services = _expand_services(rule["services"], services)
            enrichment = _rule_relationship(
                rule, input_row, microcosmos_lookup if microcosmos_input else None,
                group_index,
            )
            usage = _usage_columns(
                usage_by_rule.get(rule["rule_href"]), report_catalogs,
            )
            app_server_count = _impacted_app_server_count(rule, enrichment, app_servers, group_index)
            rows.append({
                **_with_rule_enrichment_columns(input_values, enrichment),
                "env": env,
                "Program (KPI)": programs,
                "Match status": "MATCHED",
                "Warning": _join_warnings(_extrascope_warning(rule), enrichment["warning"]),
                "Global Consumer in use": str(_global_consumer_in_use(rule)).upper(),
                "ruleset_name": rule["ruleset_name"],
                "ruleset_scope": _format_ruleset_scope(rule["ruleset_scope"], group_index),
                "ruleset_enabled": rule["ruleset_enabled"],
                "rule_type": rule["rule_type"],
                "rule_description": rule["rule_description"],
                "rule_enabled": rule["rule_enabled"],
                "rule_href": rule["rule_href"],
                RULE_STATUS: (
                    "Disabled" if any(rule[name].strip().casefold() == "false" for name in ("ruleset_enabled", "rule_enabled"))
                    else "Enabled"
                ),
                RULE_ID: _rule_id(rule["rule_href"]),
                "Source": source,
                "Destination": destination,
                IMPACTED_APP_SERVERS: (
                    "undefined" if app_server_count is None
                    and enrichment["rule_category"] in {"business_rule", "strategic_rule"}
                    else app_server_count
                ),
                "Source contains User": str(
                    source_kind == "iplist" and _contains_user_iplist(source)
                ).upper(),
                "Destination contains User": str(
                    destination_kind == "iplist" and _contains_user_iplist(destination)
                ).upper(),
                "services": _expand_services(rule["services"], services, expand_all_services=False),
                **{
                    catalog: dangerous_ports(expanded_services, [catalog])
                    for catalog in report_catalogs
                },
                "Protection type": (
                    "Intra-zone" if _ruleset_identity(rule) in intra_zone_rulesets else ""
                ),
                **usage,
                **extra_values,
            })

    headers = available_headers(list(dict.fromkeys(name for row in rows for name in row)))
    layout = (
        load_compliance_layout(custom_headers_path, headers, (*MICROCOSMOS_COLUMNS, "env"))
        if custom_headers_path is not None else None
    )
    selected_headers = headers if debug or layout is not None else DEFAULT_HEADERS
    reference_sheets = [name for name in REFERENCE_HEADERS if layout is None or layout.sheet_visible(name)]
    references = ComplianceReferences(snapshot, rules, group_index, reference_sheets) if reference_sheets else None
    if split_by_kear_id:
        return _write_split_compliance_archive(rows, selected_headers, report_catalogs, output, layout, timestamp, references)
    return _write_compliance_workbook(rows, selected_headers, report_catalogs, output, layout, references)


def _rule_id(href: str) -> str:
    match = re.search(r"(?:^|/)rule_sets/(\d+)/sec_rules/(\d+)/?$", href.strip())
    return "-".join(match.groups()) if match else ""


def _write_compliance_workbook(
    rows: Sequence[Mapping[str, object]], headers: Sequence[str], catalogs: Sequence[str],
    output: Path, layout: Optional[ComplianceLayout] = None,
    references: Optional[ComplianceReferences] = None,
) -> Path:
    from openpyxl import Workbook
    workbook = Workbook()
    workbook.remove(workbook.active)
    visible = layout.sheet_visible if layout is not None else lambda name: True
    selected_headers = layout.headers if layout is not None else headers
    if visible("Summary"):
        _write_summary_sheet(workbook, rows, catalogs)
    business_rows, infra_rows, data_quality_rows = _partition_compliance_rows(rows)
    for sheet, table, data in (
        ("Business Rules", "BusinessRules", business_rows),
        ("Infra Rules", "InfraRules", infra_rows),
        ("Data Quality", "DataQuality", data_quality_rows),
    ):
        if visible(sheet):
            presented = [output_row(row) for row in data]
            if sheet in ("Business Rules", "Infra Rules"):
                presented.sort(key=lambda row: tuple(str(row.get(name) or "").casefold() for name in
                                                    ("Kear Id (Scope)", "Module (Scope)", "illumio label env (Scope)")))
            _write_compliance_sheet(workbook, presented, sheet, table, selected_headers)
    if references is not None:
        dictionaries = references.for_rows(rows)
        for sheet, data in dictionaries.items():
            if visible(sheet):
                columns = layout.reference_headers(sheet) if layout is not None else REFERENCE_HEADERS[sheet]
                _write_compliance_sheet(workbook, data, sheet, "Compliance" + sheet.title(), columns)
    if layout is not None and visible(CONFIGURATION_SHEET):
        _write_compliance_sheet(workbook, layout.configuration_rows(), CONFIGURATION_SHEET, "ReportConfiguration")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    try:
        workbook.save(temporary)
        temporary.replace(output)
    finally:
        workbook.close()
        temporary.unlink(missing_ok=True)
    return output


def _write_split_compliance_archive(
    rows: Sequence[Mapping[str, object]], headers: Sequence[str], catalogs: Sequence[str],
    output: Path, layout: Optional[ComplianceLayout], timestamp: Optional[str],
    references: Optional[ComplianceReferences] = None,
) -> Path:
    stamp = timestamp or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    if not re.fullmatch(r"\d{8}T\d{6}Z", stamp):
        raise ValueError("Invalid compliance report timestamp; expected YYYYMMDDTHHMMSSZ")
    groups: Dict[Tuple[str, str], List[Mapping[str, object]]] = defaultdict(list)
    skipped = 0
    for row in rows:
        kear = _get_case_insensitive(row, "Kear Id").strip()
        if not kear:
            skipped += 1
            continue
        entity = _get_case_insensitive(row, "Entity").strip() or "UNSPECIFIED"
        groups[(entity, kear)].append(row)
    if skipped:
        LOG.warning("Skipped %s compliance report rows without Kear Id", skipped)
    if not groups:
        raise ValueError("No non-empty Kear Id is available for --split-by-kear-id")

    members = []
    names = set()
    for (entity, kear), data in sorted(groups.items()):
        member = Path(_safe_component(entity)) / f"compliance_{_safe_component(kear)}_{stamp}.xlsx"
        key = member.as_posix().casefold()
        if key in names:
            raise ValueError(f"Split report filenames collide after sanitization: {member}")
        names.add(key)
        members.append((member, data))
    output.parent.mkdir(parents=True, exist_ok=True)
    # Stage complete workbooks and ZIP in the output filesystem, inheriting
    # its shared group; publish only after every member is successfully written.
    with TemporaryDirectory(prefix=".compliance-", dir=output.parent) as directory:
        staging = Path(directory)
        temporary = staging / "reports.zip"
        with ZipFile(temporary, "w", compression=ZIP_DEFLATED) as archive:
            for member, data in members:
                target = _write_compliance_workbook(data, headers, catalogs, staging / "workbooks" / member, layout, references)
                archive.write(target, arcname=member.as_posix())
        temporary.replace(output)
    return output


def _scope_server_group_values(
    group: Mapping[str, object], dimension: str, group_index: Mapping[str, Mapping[str, object]],
    seen: frozenset[str] = frozenset(),
) -> Optional[frozenset[str]]:
    name = str(group["name"]).casefold()
    if name in seen or group.get("key") != dimension:
        return None
    values = set(_group_member_values(name, dimension, group_index))
    if not str(group.get("fully_expanded_members", "")).strip():
        for reference in _parts(group.get("member_label_groups", "")):
            child = group_index.get(_clean_label_group_reference(reference).casefold())
            if child is None:
                return None
            members = _scope_server_group_values(child, dimension, group_index, seen | {name})
            if members is None:
                return None
            values.update(members)
    return frozenset(normalized_label(value, dimension) for value in values)


def _scope_server_values(
    labels_value: object, group_references: object, dimension: str,
    group_index: Mapping[str, Mapping[str, object]],
) -> Optional[Tuple[frozenset[str], bool]]:
    """Resolve only the requested dimension, preserving an explicit empty set."""
    labels = _labels(labels_value)
    specified = bool(labels.get(dimension) or labels.get(dimension + "group"))
    referenced_groups = []
    for key in (dimension, dimension + "group"):
        for value in labels.get(key, set()):
            group = group_index.get(_clean_label_group_reference(value).casefold())
            if key.endswith("group") and (not group or group.get("key") != dimension):
                return None
            if group and group.get("key") == dimension:
                referenced_groups.append(group)
    for reference in _parts(group_references):
        group = group_index.get(_clean_label_group_reference(reference).casefold())
        if group is None:
            key = reference.partition(":")[0].strip().casefold()
            if key in {"app", "appgroup", "env", "envgroup", "role", "rolegroup", "loc", "locgroup"}:
                if key in {dimension, dimension + "group"}:
                    return None
            else:
                return None
        elif group.get("key") == dimension:
            specified = True
            referenced_groups.append(group)
    expanded = _expanded_selector_labels(labels_value, group_references, group_index)
    values = {normalized_label(value, dimension) for value in expanded.get(dimension, set())}
    for group in referenced_groups:
        members = _scope_server_group_values(group, dimension, group_index)
        if members is None:
            return None
        values.update(members)
    return frozenset(values), specified


def _scope_server_roles(
    rule: Mapping[str, str], prefix: str, group_index: Mapping[str, Mapping[str, object]],
) -> Optional[RoleSelection]:
    excluded = _scope_server_values(rule.get(f"{prefix}_labels_exclusions", ""),
                                    rule.get(f"{prefix}_label_groups_exclusions", ""), "role", group_index)
    if excluded is None:
        return None
    if parse_bool(rule.get(f"{prefix}_all_workloads", "")):
        return RoleSelection(None, excluded[0])
    included = _scope_server_values(rule.get(f"{prefix}_labels", ""),
                                    rule.get(f"{prefix}_label_groups", ""), "role", group_index)
    if included is None:
        return None
    return RoleSelection(included[0] if included[1] else None, excluded[0])


def _outbound2apa_app_server_count(
    rule: Mapping[str, str], servers: AppServerScopeIndex,
    group_index: Mapping[str, Mapping[str, object]],
) -> Optional[int]:
    selections = []
    for prefix in ("src", "dst"):
        labels = rule.get(f"{prefix}_labels", "")
        groups = rule.get(f"{prefix}_label_groups", "")
        apps = _scope_server_values(labels, groups, "app", group_index)
        if apps is None:
            return None
        if not apps[1]:
            # IP Lists or a side without an application cannot supply an app
            # scope. Do not extrapolate it to every managed workload.
            continue
        envs = _scope_server_values(labels, groups, "env", group_index)
        excluded_labels = rule.get(f"{prefix}_labels_exclusions", "")
        excluded_groups = rule.get(f"{prefix}_label_groups_exclusions", "")
        excluded_apps = _scope_server_values(excluded_labels, excluded_groups, "app", group_index)
        excluded_envs = _scope_server_values(excluded_labels, excluded_groups, "env", group_index)
        roles = _scope_server_roles(rule, prefix, group_index)
        if (envs is None or not envs[1] or "null" in apps[0] or "null" in envs[0]
                or excluded_apps is None or excluded_envs is None or roles is None):
            return None
        selections.append(AppServerSelection(apps[0] - excluded_apps[0], envs[0] - excluded_envs[0], roles))
    return servers.count_union(selections) if selections else None


def _impacted_app_server_count(
    rule: Mapping[str, str], enrichment: Mapping[str, str], servers: Optional[AppServerScopeIndex],
    group_index: Mapping[str, Mapping[str, object]],
) -> Optional[int]:
    if servers is None or enrichment["rule_category"] not in {"business_rule", "strategic_rule"}:
        return None
    scope = rule.get("ruleset_scope", "").strip()
    if not scope and "OUTBOUND2APA" in rule.get("ruleset_name", "").upper():
        return _outbound2apa_app_server_count(rule, servers, group_index)
    prefixes = {"incoming": ("dst",), "outgoing": ("src",), "intra-app": ("src", "dst")}.get(
        enrichment["direction"]
    )
    if prefixes is None:
        return None
    apps = _scope_server_values(scope, "", "app", group_index)
    envs = _scope_server_values(scope, "", "env", group_index)
    # A nonempty scope without an env selector covers every environment.
    # An explicit but unresolved env must not silently broaden the selection.
    any_env = bool(scope) and not any(
        component.partition(":")[0].strip().casefold() in {"env", "envgroup"}
        for component in _parts(scope)
    )
    if (apps is None or envs is None or not apps[1] or (not envs[1] and not any_env)
            or "null" in apps[0] or "null" in envs[0]):
        return None
    environments = None if any_env else envs[0]
    selections = [_scope_server_roles(rule, prefix, group_index) for prefix in prefixes]
    if any(selection is not None and selection.included is None and not selection.excluded
           for selection in selections):
        # Union with an unrestricted local side covers the complete app/env scope.
        return servers.count(apps[0], environments, [RoleSelection()])
    if any(selection is None for selection in selections):
        return None
    return servers.count(apps[0], environments, [selection for selection in selections if selection is not None])


def _empty_usage_columns(catalogs: Sequence[str]) -> Dict[str, object]:
    output: Dict[str, object] = {
        "Usage Status": "NO_DATA", "Last Hit": "", "Days Since Last Hit": "",
        "Total Hit Flows": 0, "Observed Windows": 0, "First Observed": "",
        "Last Observed": "", "Port Breakdown Complete": "NO_DATA",
    }
    for catalog in catalogs:
        output[f"{catalog} Hit Ports"] = ""
        output[f"{catalog} Hit Flows"] = 0
        output[f"{catalog} Last Hit"] = ""
    return output


def _usage_columns(
    usage: Optional[Mapping[str, object]], catalogs: Sequence[str],
    as_of: Optional[date] = None,
) -> Dict[str, object]:
    """Render rule usage and dangerous-port hits as analysis-ready columns."""
    output = _empty_usage_columns(catalogs)
    if not usage:
        return output
    total_flows = int(usage.get("total_flows", 0) or 0)
    last_hit = str(usage.get("last_hit", "") or "")
    last_hit_date = _iso_date(last_hit)
    output.update({
        "Usage Status": "HIT" if total_flows > 0 else "NO_HIT",
        "Last Hit": last_hit,
        "Days Since Last Hit": (
            ((as_of or datetime.now(timezone.utc).date()) - last_hit_date).days
            if last_hit_date else ""
        ),
        "Total Hit Flows": total_flows,
        "Observed Windows": int(usage.get("observed_windows", 0) or 0),
        "First Observed": str(usage.get("first_observed", "") or ""),
        "Last Observed": str(usage.get("last_observed", "") or ""),
        "Port Breakdown Complete": (
            "FALSE" if int(usage.get("incomplete_windows", 0) or 0) else "TRUE"
        ),
    })
    ports = list(usage.get("ports", []) or [])
    for catalog in catalogs:
        matched = []
        for port in ports:
            protocol = str(port.get("protocol", "")).upper()
            number = int(port.get("port", -1))
            if number < 0 or not any(
                protocol == expected_protocol and start <= number <= end
                for expected_protocol, start, end in (
                    _catalog_interval(definition) for definition in PORT_CATALOGS[catalog]
                )
            ):
                continue
            matched.append(port)
        matched.sort(key=lambda item: (str(item.get("protocol", "")), int(item.get("port", -1))))
        output[f"{catalog} Hit Ports"] = ", ".join(
            f"{str(item['protocol']).upper()}/{item['port']} ({item['flows']} flows)"
            for item in matched
        )
        output[f"{catalog} Hit Flows"] = sum(int(item.get("flows", 0)) for item in matched)
        output[f"{catalog} Last Hit"] = max(
            (str(item.get("last_hit", "")) for item in matched), default="",
        )
    return output


def _iso_date(value: object) -> Optional[date]:
    """Read a database ISO date or timestamp, including the common UTC ``Z`` suffix."""
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def _excel_safe(value: object) -> object:
    if value is None:
        return ""
    if isinstance(value, (bool, int, float, datetime, date)):
        return value
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", " ", str(value))
    if len(cleaned) > 32767:
        cleaned = cleaned[:32740] + " ... [TRUNCATED FOR EXCEL]"
    return "'" + cleaned if cleaned.startswith("=") else cleaned


def _write_summary_sheet(
    workbook: object, rows: Sequence[Mapping[str, object]], catalogs: Sequence[str],
) -> None:
    from openpyxl.chart import BarChart, Reference
    from openpyxl.styles import Alignment, Font, PatternFill

    navy, dark, blue, teal = "10233B", "172D48", "0B6B8B", "057D79"
    white, pale, light = "FFFFFF", "E9F5F6", "F0F4F9"
    green, red, amber = "087443", "B42318", "B35D0A"
    sheet = workbook.create_sheet("Summary")
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 85
    sheet.freeze_panes = "A4"
    sheet.sheet_properties.tabColor = teal
    for column in range(1, 14):
        sheet.column_dimensions[sheet.cell(1, column).column_letter].width = 14

    def box(cell_range: str, value: object, background: str, color: str,
            size: int = 11, bold: bool = False, centered: bool = False) -> None:
        sheet.merge_cells(cell_range)
        cell = sheet[cell_range.split(":")[0]]
        cell.value = _excel_safe(value)
        cell.fill = PatternFill("solid", fgColor=background)
        cell.font = Font(
            name="Aptos Display" if size >= 19 else "Aptos",
            size=size, bold=bold, color=color,
        )
        cell.alignment = Alignment(
            vertical="center", horizontal="center" if centered else "left",
            indent=0 if centered else 1, wrap_text=True,
        )

    box("A1:M2", "RULE COMPLIANCE & RECERTIFICATION REPORT", navy, white, 20, True)
    box(
        "A3:M3",
        "Policy scope, Microcosmos ownership, rule classification and observed traffic usage",
        pale, dark, 10, True,
    )
    sheet.row_dimensions[1].height = 30
    sheet.row_dimensions[2].height = 26
    sheet.row_dimensions[3].height = 30

    matched = [row for row in rows if row.get("Match status") == "MATCHED"]
    usage = Counter(str(row.get("Usage Status", "")) for row in matched)
    cards = (
        ("A5:C5", "A6:C7", "Report rows", len(rows), teal),
        ("D5:F5", "D6:F7", "Matched rules", len(matched), green),
        ("G5:I5", "G6:I7", "Rules with hits", usage["HIT"], blue),
        ("J5:M5", "J6:M7", "Rules without usage data", usage["NO_DATA"], amber),
        ("A9:C9", "A10:C11", "Remote Kear not onboarded", sum(
            row.get("Kear Remote") == KEAR_NOT_ONBOARDED for row in matched
        ), red),
        ("D9:F9", "D10:F11", "Undetermined direction", sum(
            row.get("Direction") == "undetermined" for row in matched
        ), amber),
        ("G9:I9", "G10:I11", "Strategic rules", sum(
            row.get("Rule Category") == "strategic_rule" for row in matched
        ), red),
        ("J9:M9", "J10:M11", "Infrastructure rules", sum(
            row.get("Rule Category") == "infra_rule" for row in matched
        ), blue),
    )
    for label_range, value_range, label, metric, accent in cards:
        box(label_range, label, dark, white, 10, True, True)
        box(value_range, metric, light, accent, 24, True, True)

    box("A14:M14", "CALCULATION RULES & INTERPRETATION", navy, white, 11, True)
    explanations = [
        ("Kear Remote", "Resolved from the opposite application's labels or ruleset scope using Microcosmos Module and Environment. Kear Id and other identity columns remain those of the evaluated input application. A unique Kear shared across environments is accepted. Missing or ambiguous mappings are marked KEAR_NOT_ONBOARDED_IN_MICROCOSMOS."),
        ("Direction", "For infra_rule, one explicit appgroup identifies the local side: Source outgoing, Destination incoming. Otherwise direction follows the identified local app/Kear, with equal peer Kears intra-app. Role-only, exclusion-only EXCEPT selectors and All workloads inherit scope. Unknown remote Kears do not hide a known direction; without a local side it stays undetermined."),
        ("OUTBOUND2APA validation", "OUTBOUND2APA is intended for a managed source and unmanaged destination. A managed destination receives OUTBOUND2APA_DESTINATION_MANAGED, while its row stays incoming. The naming convention never reverses endpoints or replaces the evaluated application's identity."),
        ("Rule Category", "BOUQUETS_*, GLOBAL_*, and LUIGI_* rulesets are infra_rule. Other deny rules, rules using a ZNOT_* IP List, or descriptions beginning with [+srule] or [+drule] are strategic_rule. Remaining rules are business_rule."),
        ("Label groups & exclusions", "Scope, Source and Destination display labels in role, app, env order, including groups and EXCEPT exclusions. Explicit workloads appear as workload:<name> in Source and Destination; a name alone does not identify a Kear. Confirmed groups use <key>group:<name> (for example appgroup:PAYMENTS)."),
        ("Usage Status", "HIT means at least one completed usage window has flows; NO_HIT means completed observations exist with zero flows; NO_DATA means no completed usage window is stored for the rule href."),
        ("Last Hit", "Latest end date of a completed usage window with at least one flow. Days Since Last Hit is calculated in UTC on report generation."),
        ("Dangerous-port hits", "Observed per-port flows are intersected with the configured To Control, To Eradicate and Admin catalogues. Exposure columns describe allowed rule services; Hit columns describe observed traffic."),
        ("Port Breakdown Complete", "FALSE means at least one completed usage window omitted or could not fully parse per-port details; aggregate hit flows can still be available."),
        ("Global Consumer", "TRUE only when unscoped_consumers and src_all_workloads are both true, which applies an Extrascope consumer rule to all managed PCE workloads."),
    ]
    row_number = 15
    for subject, explanation in explanations:
        box(f"A{row_number}:C{row_number}", subject, light, dark, 10, True)
        box(f"D{row_number}:M{row_number}", explanation, light, dark, 10)
        sheet.row_dimensions[row_number].height = 42
        row_number += 1

    box("A25:M25", "TRAFFIC USAGE DISTRIBUTION", navy, white, 11, True)
    sheet["A27"], sheet["B27"] = "STATUS", "RULE ROWS"
    for cell in sheet[27][:2]:
        cell.fill = PatternFill("solid", fgColor=navy)
        cell.font = Font(name="Aptos", size=10, bold=True, color=white)
    for offset, status in enumerate(("HIT", "NO_HIT", "NO_DATA"), 28):
        sheet.cell(offset, 1, status)
        sheet.cell(offset, 2, usage[status])
    chart = BarChart()
    chart.type = "col"
    chart.style = 10
    chart.title = "Rule usage status"
    chart.y_axis.title = "Report rows"
    chart.add_data(Reference(sheet, min_col=2, min_row=27, max_row=30), titles_from_data=True)
    chart.set_categories(Reference(sheet, min_col=1, min_row=28, max_row=30))
    chart.legend = None
    chart.width, chart.height = 20, 8
    sheet.add_chart(chart, "D27")

    box("A38:M38", "DANGEROUS-PORT CATALOGUES", navy, white, 11, True)
    row_number = 39
    for catalog in catalogs:
        box(f"A{row_number}:C{row_number}", catalog, light, dark, 10, True)
        box(f"D{row_number}:M{row_number}", ", ".join(PORT_CATALOGS[catalog]), light, dark, 10)
        sheet.row_dimensions[row_number].height = 32
        row_number += 1

    row_number += 1
    box(f"A{row_number}:M{row_number}", "APP SERVER IMPACT (SCOPE)", navy, white, 11, True)
    row_number += 1
    box(f"A{row_number}:C{row_number}", IMPACTED_APP_SERVERS, light, dark, 10, True)
    box(f"D{row_number}:M{row_number}",
        "Business and strategic rules: count managed workload rows matching the ruleset scope app/env. "
        "A scope with app but no env covers all environments. "
        "Empty-scope OUTBOUND2APA unions Source and Destination app/env/roles. "
        "Otherwise incoming uses Destination roles; "
        "outgoing uses Source roles; intra-app uses their union, "
        "counting each row once. All workloads or no included role allows the full scope on that side; "
        "role exclusions still apply. Zero means no matching rows; undefined means the calculation is "
        "unavailable. Blank means not applicable (Infra Rules or Data Quality).",
        light, dark, 10)
    sheet.row_dimensions[row_number].height = 80

    row_number += 2
    box(f"A{row_number}:M{row_number}", "REPORT COLUMN DEFINITIONS", navy, white, 11, True)
    for subject, explanation in (
        (RULE_STATUS, "Disabled if either ruleset_enabled or rule_enabled is false; otherwise Enabled. Unmatched inputs have no rule status."),
        (RULE_ID, "Text identifier <ruleset id>-<security rule id>, extracted from rule_href. It is right-aligned and preserves leading zeros."),
        ("Reference sheets", "iplists lists the IP Lists used by this workbook's rules. workloads lists matching managed workloads only, including explicit workload selectors. Scope fills omitted label dimensions; unscoped consumers do not inherit scope. Missing references are logged."),
    ):
        row_number += 1
        box(f"A{row_number}:C{row_number}", subject, light, dark, 10, True)
        box(f"D{row_number}:M{row_number}", explanation, light, dark, 10)
        sheet.row_dimensions[row_number].height = 42


def _write_compliance_sheet(
    workbook: object, rows: Sequence[Mapping[str, object]],
    sheet_name: str = "Compliance", table_name: str = "ComplianceResults",
    headers: Optional[Sequence[str]] = None,
) -> None:
    from openpyxl.formatting.rule import CellIsRule, FormulaRule
    from openpyxl.utils import get_column_letter
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.table import Table, TableStyleInfo

    navy, white, dark = "10233B", "FFFFFF", "172D48"
    pale_green, green = "E0F4EA", "087443"
    pale_red, red = "FCE8E6", "B42318"
    pale_amber, amber = "FFF2DA", "B35D0A"
    pale_blue, blue = "E2EDF7", "0B6B8B"
    grey = "ECECEC"
    header_blues = ("1E4669", "255477", "2C6185", "336D93", "3B799F", "235B82")
    body_blues = ("EDF3F9", "E6EFF7", "F1F6FB", "E8F1FA", "DFEBF7", "EAF2FB")
    grey_fill = PatternFill("solid", fgColor=grey)
    body_fills = {color: PatternFill("solid", fgColor=color) for color in body_blues}
    group_colors = {name: (heading, body) for group, heading, body in zip(COLUMN_GROUPS, header_blues, body_blues)
                    for name in group} if sheet_name in DETAIL_SHEETS else {}
    disabled_rows = [index for index, row in enumerate(rows, 2) if row.get(RULE_STATUS) == "Disabled"]
    disabled_set = set(disabled_rows)
    sheet = workbook.create_sheet(sheet_name)
    headers = list(headers or (list(rows[0]) if rows else ["Match status"]))
    sheet.append(headers)
    for row in rows:
        sheet.append([_excel_safe(row.get(header, "")) for header in headers])
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 85
    sheet.freeze_panes = "C2"
    sheet.sheet_properties.tabColor = (
        "B42318" if sheet_name == "Data Quality"
        else "0B6B8B" if sheet_name == "Infra Rules"
        else "057D79"
    )
    sheet.row_dimensions[1].height = 34
    vertical_side = Side(style="thin", color="D5DEE9")
    vertical_border = Border(left=vertical_side, right=vertical_side)
    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor=group_colors.get(cell.value, (navy, ""))[0])
        cell.font = Font(name="Aptos", size=10, bold=True, color=white)
        cell.alignment = Alignment(vertical="center", wrap_text=True, indent=1)
        cell.border = vertical_border
    for row_number in range(2, sheet.max_row + 1):
        for cell in sheet[row_number]:
            cell.font = Font(name="Aptos", size=10, color=dark)
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            cell.border = vertical_border
            if row_number in disabled_set:
                cell.fill = grey_fill
            elif headers[cell.column - 1] in group_colors:
                cell.fill = body_fills[group_colors[headers[cell.column - 1]][1]]
            if headers[cell.column - 1] == RULE_ID:
                cell.number_format = "@"
                cell.alignment = Alignment(horizontal="right", vertical="center", wrap_text=True)
        sheet.row_dimensions[row_number].height = 30
    if rows:
        table = Table(displayName=table_name, ref=sheet.dimensions)
        table.tableStyleInfo = TableStyleInfo(
            name="TableStyleMedium2", showFirstColumn=False, showLastColumn=False,
            showRowStripes=True, showColumnStripes=False,
        )
        sheet.add_table(table)
    else:
        sheet.auto_filter.ref = sheet.dimensions

    preferred_widths = {
        "rule_description": 55, "Source": 50, "Destination": 50, "services": 45,
        "Warning": 55, "ruleset_scope": 45, "rule_href": 48,
        IMPACTED_APP_SERVERS: 24,
    }
    for index, header in enumerate(headers, 1):
        values = [len(str(row.get(header, "") or "")) for row in rows[:250]]
        width = preferred_widths.get(header, min(max([len(header), *values]) + 2, 36))
        sheet.column_dimensions[sheet.cell(1, index).column_letter].width = width

    if sheet_name == "iplists":
        for name in ("name", "include", "exclude"):
            if name in headers:
                sheet.column_dimensions[get_column_letter(headers.index(name) + 1)].width = 52
        for index in range(2, sheet.max_row + 1):
            lines = max((sum(max(1, (len(line) + 51) // 52) for line in str(cell.value or "").split("\n"))
                         for cell in sheet[index]), default=1)
            sheet.row_dimensions[index].height = min(409, max(30, 14 * lines + 6))

    if disabled_rows:
        last_column = get_column_letter(len(headers))
        if RULE_STATUS in headers:
            status_column = get_column_letter(headers.index(RULE_STATUS) + 1)
            ranges = f"A2:{last_column}{sheet.max_row}"
            formula = f'${status_column}2="Disabled"'
        else:
            # No hidden helper columns: keep the generated row status when the
            # profile omits the status field. Coalesce adjacent disabled rows.
            blocks = []
            start = end = disabled_rows[0]
            for index in disabled_rows[1:]:
                if index == end + 1:
                    end = index
                else:
                    blocks.append(f"A{start}:{last_column}{end}")
                    start = end = index
            blocks.append(f"A{start}:{last_column}{end}")
            ranges, formula = " ".join(blocks), "TRUE"
        # First priority preserves the full grey row over status-cell fills.
        sheet.conditional_formatting.add(ranges, FormulaRule(
            formula=[formula], fill=grey_fill, stopIfTrue=True,
        ))

    formats = {
        "MATCHED": (pale_green, green), "HIT": (pale_green, green),
        "intra-app": (pale_green, green), "business_rule": (pale_green, green),
        "NO_MATCH": (pale_red, red), "APP_NOT_FOUND": (pale_red, red),
        KEAR_NOT_ONBOARDED: (pale_amber, amber), "undetermined": (pale_amber, amber),
        "NO_HIT": (pale_amber, amber), "strategic_rule": (pale_amber, amber),
        "NO_DATA": (pale_blue, blue), "incoming": (pale_blue, blue),
        "outgoing": (pale_blue, blue), "infra_rule": (pale_blue, blue),
    }
    for header in (
        "Match status", "Kear Remote", "Direction", "Rule Category", "Usage Status",
        "Port Breakdown Complete", "Global Consumer in use",
    ):
        if header not in headers or sheet.max_row < 2:
            continue
        letter = sheet.cell(1, headers.index(header) + 1).column_letter
        cell_range = f"{letter}2:{letter}{sheet.max_row}"
        column_formats = dict(formats)
        if header == "Port Breakdown Complete":
            column_formats.update({
                "TRUE": (pale_green, green), "FALSE": (pale_red, red),
            })
        elif header == "Global Consumer in use":
            column_formats.update({
                "TRUE": (pale_red, red), "FALSE": (pale_green, green),
            })
        for status, (background, foreground) in column_formats.items():
            sheet.conditional_formatting.add(
                cell_range,
                CellIsRule(
                    operator="equal", formula=[f'"{status}"'],
                    fill=PatternFill("solid", fgColor=background),
                    font=Font(name="Aptos", bold=True, color=foreground),
                ),
            )
    sheet.print_title_rows = "1:1"
    sheet.sheet_properties.pageSetUpPr.fitToPage = True
    sheet.page_setup.fitToWidth = 1
    sheet.page_setup.fitToHeight = 0


def _partition_compliance_rows(
    rows: Sequence[Mapping[str, object]],
) -> Tuple[List[Mapping[str, object]], List[Mapping[str, object]], List[Mapping[str, object]]]:
    """Split report rows into business, infrastructure, and data-quality tabs."""
    data_quality_statuses = {"APP_NOT_FOUND", "NO_MATCH"}
    data_quality = [
        row for row in rows if str(row.get("Match status", "")) in data_quality_statuses
    ]
    infra = [
        row for row in rows
        if str(row.get("Match status", "")) not in data_quality_statuses
        and row.get("Rule Category") == "infra_rule"
    ]
    business = [
        row for row in rows
        if str(row.get("Match status", "")) not in data_quality_statuses
        and row.get("Rule Category") in {"business_rule", "strategic_rule"}
    ]
    return business, infra, data_quality


def _write_metadata_sheet(workbook: object, rows: Sequence[Mapping[str, object]]) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill

    sheet = workbook.create_sheet("Metadata")
    sheet.sheet_view.showGridLines = False
    sheet.sheet_view.zoomScale = 85
    sheet.append(["PROPERTY", "VALUE"])
    for key, value in rows[0].items():
        sheet.append([key, _excel_safe(value)])
    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor="10233B")
        cell.font = Font(name="Aptos", size=10, bold=True, color="FFFFFF")
    for row in sheet.iter_rows(min_row=2):
        for cell in row:
            cell.font = Font(name="Aptos", size=10, color="172D48")
            cell.alignment = Alignment(vertical="center", wrap_text=True)
    sheet.column_dimensions["A"].width = 28
    sheet.column_dimensions["B"].width = 100
    sheet.freeze_panes = "A2"


def _load_scope_input(input_path: Optional[Path], labels_path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if input_path is None:
        rows = [
            {"app": row["value"]}
            for row in read_rows(labels_path, ("key", "value"))
            if row["key"].strip().casefold() == "app" and row["value"].strip()
        ]
        return _deduplicate_inputs(rows, ("app",)), ["app"]
    if not input_path.is_file():
        raise ValueError(f"compliance input file not found: {input_path}")
    if input_path.suffix.casefold() == ".xlsx":
        if importlib.util.find_spec("openpyxl") is None:
            raise RuntimeError("openpyxl is required to read an XLSX compliance input")
        from openpyxl import load_workbook
        workbook = load_workbook(input_path, read_only=True, data_only=True)
        iterator = workbook.active.iter_rows(values_only=True)
        headers = [str(value or "").strip() for value in next(iterator, ())]
        second_row = next(iterator, ())
        microcosmos_input = _is_microcosmos_headers(headers)
        # Microcosmos exports use two header rows.  The second row contains
        # sub-headings for unrelated grouped columns and is never application data.
        values = list(iterator) if microcosmos_input else [second_row, *iterator]
        workbook.close()
        rows = [
            {header: str(row[index] or "").strip() if index < len(row) else ""
             for index, header in enumerate(headers) if header}
            for row in values if any(str(value or "").strip() for value in row)
        ]
    elif input_path.suffix.casefold() == ".csv":
        with input_path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            raw_headers = list(reader.fieldnames or [])
            headers = [str(value or "").strip() for value in raw_headers]
            rows = [
                {
                    header: str(row.get(raw_header, "") or "").strip()
                    for raw_header, header in zip(raw_headers, headers)
                }
                for row in reader
            ]
    else:
        raise ValueError("compliance input must be a CSV or XLSX file")
    if input_path.suffix.casefold() == ".xlsx" and _is_microcosmos_headers(headers):
        return _prepare_microcosmos_input(rows, headers, labels_path)
    if any(not header for header in headers):
        raise ValueError("compliance input contains an empty column header")
    if len({header.casefold() for header in headers}) != len(headers):
        raise ValueError("compliance input contains duplicate column headers")
    header_names = {header.casefold(): header for header in headers}
    if "app" not in header_names:
        raise ValueError(
            "compliance input must contain an app column, or be a Microcosmos XLSX "
            "with Kear Id, Application Name, Module, Account, Account Leader, "
            "Microsegmentation Solution, Environment, and Entity columns"
        )
    rows = [row for row in rows if _get_case_insensitive(row, "app").strip()]
    if not rows:
        raise ValueError("compliance input contains no non-empty app value")
    return rows, headers


def _prepare_microcosmos_input(
    rows: Sequence[Mapping[str, str]], headers: Sequence[str], labels_path: Path,
) -> Tuple[List[Dict[str, str]], List[str]]:
    """Translate Microcosmos Module/Environment rows into compliance app/env scopes."""
    if not labels_path.is_file() or not labels_path.stat().st_size:
        raise ValueError(f"compliance snapshot file is missing or empty: {labels_path}")
    labels = list(read_rows(labels_path, ("key", "value")))
    apps_by_module: Dict[str, List[str]] = {}
    environments: Dict[str, str] = {}
    for label in labels:
        key, value = label["key"].strip().casefold(), label["value"].strip()
        if not value:
            continue
        if key == "app":
            module = _module_from_app(value)
            if module:
                apps_by_module.setdefault(module.casefold(), []).append(value)
        elif key == "env":
            environments.setdefault(value.casefold(), value)

    source_by_name = {header.casefold(): header for header in headers}
    output_columns = [*MICROCOSMOS_COLUMNS, "app"]
    prepared: List[Dict[str, str]] = []
    for source in rows:
        module = _get_case_insensitive(source, "Module").strip()
        environment = _get_case_insensitive(source, "Environment").strip()
        apps = list(dict.fromkeys(apps_by_module.get(module.casefold(), []))) or [""]
        for app in apps:
            output: Dict[str, str] = {}
            for column in MICROCOSMOS_COLUMNS:
                source_name = source_by_name.get(column.casefold())
                if column == "Program (MIO)" and source_name is None:
                    source_name = source_by_name.get("program")
                output[column] = str(source.get(source_name, "") or "") if source_name else ""
            output["app"] = app
            output["__compliance_env"] = environments.get(environment.casefold(), environment)
            prepared.append(output)
    if not prepared:
        raise ValueError("compliance input contains no non-empty Microcosmos row")
    return prepared, output_columns


def _is_microcosmos_headers(headers: Sequence[str]) -> bool:
    """Recognize the first of the two header rows in a Microcosmos workbook."""
    available = {header.casefold() for header in headers if header}
    return {name.casefold() for name in MICROCOSMOS_REQUIRED_COLUMNS}.issubset(available)


def _module_from_app(app: str) -> str:
    """Return the part after the second underscore in an application label."""
    components = app.split("_", 2)
    return components[2].strip() if len(components) == 3 else ""


def _microcosmos_kear_lookup(
    rows: Sequence[Mapping[str, str]],
) -> Dict[str, Dict[str, set[str]]]:
    """Index Microcosmos Kear IDs by module and environment."""
    lookup: Dict[str, Dict[str, set[str]]] = {}
    for row in rows:
        module = _get_case_insensitive(row, "Module").strip().casefold()
        environment = str(
            row.get("__compliance_env", _get_case_insensitive(row, "Environment"))
        ).strip().casefold()
        kear = _get_case_insensitive(row, "Kear Id").strip()
        if module and kear:
            lookup.setdefault(module, {}).setdefault(environment, set()).add(kear)
    return lookup


def _resolve_remote_kear(
    app: str, environment: str, lookup: Mapping[str, Mapping[str, set[str]]],
) -> Tuple[str, str]:
    """Resolve a remote app, preferring its environment without guessing."""
    module = _module_from_app(app).casefold()
    by_environment = lookup.get(module, {})
    if not by_environment:
        return "", "REMOTE_KEAR_NOT_FOUND"
    exact = by_environment.get(environment.casefold(), set())
    if len(exact) == 1:
        return next(iter(exact)), ""
    if len(exact) > 1:
        return "", "REMOTE_KEAR_AMBIGUOUS"
    all_kears = {kear for kears in by_environment.values() for kear in kears}
    if len(all_kears) == 1:
        # A single application Kear may legitimately cover PRD and DEV modules.
        return next(iter(all_kears)), ""
    return "", "REMOTE_KEAR_AMBIGUOUS"


def _side_applications(
    rule: Mapping[str, str], prefix: str,
    group_index: Mapping[str, Mapping[str, object]],
) -> set[str]:
    """Expand included applications without retaining excluded group members."""
    included = _expanded_selector_labels(
        rule.get(f"{prefix}_labels", ""),
        rule.get(f"{prefix}_label_groups", ""), group_index,
    ).get("app", set())
    excluded = _expanded_selector_labels(
        rule.get(f"{prefix}_labels_exclusions", ""),
        rule.get(f"{prefix}_label_groups_exclusions", ""), group_index,
    ).get("app", set())
    applications = included - excluded
    if prefix == "src" and parse_bool(rule.get("unscoped_consumers", "")) is False:
        scope_apps = _expanded_selector_labels(
            rule.get("ruleset_scope", ""), "", group_index,
        ).get("app", set())
        if scope_apps:
            applications &= scope_apps
    return applications


def _has_application_group(
    rule: Mapping[str, str], prefix: str,
    group_index: Mapping[str, Mapping[str, object]],
) -> bool:
    labels = _format_ruleset_scope(rule.get(f"{prefix}_labels", ""), group_index)
    if _labels(labels).get("appgroup"):
        return True
    for reference in _parts(rule.get(f"{prefix}_label_groups", "")):
        name = _clean_label_group_reference(reference)
        if str(group_index.get(name.casefold(), {}).get("key", "")).casefold() == "app":
            return True
        if re.match(r"^(?:appgroup|app)\s*:", reference, flags=re.I):
            return True
    return False


def _side_relationship(
    rule: Mapping[str, str], prefix: str, local_app: str,
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> Tuple[str, set[str]]:
    """Classify one rule side relative to the application ruleset scope."""
    all_workloads = parse_bool(rule.get(f"{prefix}_all_workloads", ""))
    has_iplist = bool(_iplist_names(rule.get(f"{prefix}_iplists", "")))
    has_workloads = bool(_parts(rule.get(f"{prefix}_workloads", "")))
    explicit_apps = _side_applications(rule, prefix, group_index or {})
    has_app_group = _has_application_group(rule, prefix, group_index or {})
    has_exclusions = bool(
        _parts(rule.get(f"{prefix}_labels_exclusions", ""))
        or _parts(rule.get(f"{prefix}_label_groups_exclusions", ""))
    )
    local = local_app.casefold()
    remote_apps = {app for app in explicit_apps if app != local}
    has_local_app = local in explicit_apps

    kinds = sum((
        bool(all_workloads), has_iplist, has_workloads, has_local_app, bool(remote_apps), has_exclusions,
    ))
    if has_workloads and kinds > 1:
        return "ambiguous", remote_apps
    if has_iplist and kinds > 1:
        return "ambiguous", remote_apps
    if all_workloads and remote_apps:
        return "ambiguous", remote_apps
    if has_local_app and remote_apps:
        return ("app_group" if has_app_group else "ambiguous"), remote_apps
    if has_iplist:
        return "iplist", set()
    if has_workloads:
        return "workload", set()
    if remote_apps:
        return "remote_app", remote_apps
    if has_app_group and not explicit_apps:
        return "app_group", set()
    if all_workloads or has_local_app or any(
        rule.get(f"{prefix}_{field}", "").strip()
        for field in ("labels", "label_groups", "labels_exclusions", "label_groups_exclusions")
    ):
        return "local", set()
    return "empty", set()


def _side_has_local_kear(
    rule: Mapping[str, str], prefix: str, local_kear: str, environment: str,
    lookup: Optional[Mapping[str, Mapping[str, set[str]]]],
    group_index: Mapping[str, Mapping[str, object]],
) -> bool:
    """Recognize app-label aliases only through an unambiguous Microcosmos Kear."""
    if not local_kear or lookup is None:
        return False
    # A known application does not identify every member of a mixed endpoint.
    if (
        _iplist_names(rule.get(f"{prefix}_iplists", ""))
        or _parts(rule.get(f"{prefix}_workloads", ""))
        or parse_bool(rule.get(f"{prefix}_all_workloads", ""))
    ):
        return False
    applications = _side_applications(rule, prefix, group_index)
    if not applications:
        return False
    labels = _expanded_selector_labels(
        rule.get(f"{prefix}_labels", ""), rule.get(f"{prefix}_label_groups", ""), group_index,
    )
    environments = labels.get("env", set())
    if len(environments) > 1:
        return False
    peer_environment = next(iter(environments), environment)
    for application in applications:
        kear, warning = _resolve_remote_kear(application, peer_environment, lookup)
        if warning or not kear or kear.casefold() != local_kear.casefold():
            return False
    return True


def _rule_relationship(
    rule: Mapping[str, str], input_row: Mapping[str, str],
    lookup: Optional[Mapping[str, Mapping[str, set[str]]]],
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> Dict[str, str]:
    """Calculate Kear Remote, Direction, Rule Category, and diagnostics."""
    group_index = group_index or {}
    input_app = _get_case_insensitive(input_row, "app").strip().casefold()
    scope = _expanded_selector_labels(rule.get("ruleset_scope", ""), "", group_index)
    local_apps = scope.get("app", set())
    local_app = (
        input_app if input_app in local_apps
        else next(iter(local_apps)) if len(local_apps) == 1
        else ""
    )
    local_kear = _get_case_insensitive(input_row, "Kear Id").strip()
    environment = next(
        iter(scope.get("env", set())),
        str(input_row.get(
            "__compliance_env", _get_case_insensitive(input_row, "Environment"),
        )).strip(),
    )
    source_kind, source_apps = _side_relationship(rule, "src", local_app, group_index)
    destination_kind, destination_apps = _side_relationship(
        rule, "dst", local_app, group_index,
    )
    # Distinct app labels (for example AGENTLESS and IAAS modules) can belong
    # to the same Kear. Use that confirmed identity when neither label side
    # directly identifies the local application; keep the input row unchanged.
    if source_kind != "local" and destination_kind != "local":
        if _side_has_local_kear(rule, "src", local_kear, environment, lookup, group_index):
            source_kind = "local"
        if _side_has_local_kear(rule, "dst", local_kear, environment, lookup, group_index):
            destination_kind = "local"
    category = _rule_category(rule)

    if category == "infra_rule":
        source_group = _has_application_group(rule, "src", group_index)
        destination_group = _has_application_group(rule, "dst", group_index)
        if source_group != destination_group:
            # Infrastructure convention: the sole explicit application-group
            # side is local, even without a usable application ruleset scope.
            remote_prefix = "dst" if source_group else "src"
            direction = "outgoing" if source_group else "incoming"
            remote_kind = destination_kind if source_group else source_kind
            remote_apps = _side_applications(rule, remote_prefix, group_index)
            remote_labels = _expanded_selector_labels(
                rule.get(f"{remote_prefix}_labels", ""),
                rule.get(f"{remote_prefix}_label_groups", ""), group_index,
            )
            remote_environments = remote_labels.get("env", set())
            remote_environment = (
                next(iter(remote_environments)) if len(remote_environments) == 1
                else "" if remote_environments
                else environment or _get_case_insensitive(input_row, "env").strip()
            )
            result = _relationship_to_endpoint(
                direction, remote_kind, remote_apps, remote_environment,
                lookup, local_kear, category,
            )
            # The convention determines Direction independently of whether
            # the opposite application's Kear happens to equal the row's.
            result["direction"] = direction
            if (
                not rule.get("ruleset_scope", "").strip()
                and "OUTBOUND2APA" in rule.get("ruleset_name", "").upper()
                and _side_applications(rule, "dst", group_index)
            ):
                result["warning"] = _join_warnings("OUTBOUND2APA_DESTINATION_MANAGED", result["warning"])
            return result

    source_input_match = input_app in _side_applications(rule, "src", group_index)
    destination_input_match = input_app in _side_applications(rule, "dst", group_index)
    scope_uses_app_group = bool(
        _labels(_format_ruleset_scope(rule.get("ruleset_scope", ""), group_index)).get(
            "appgroup", set()
        )
    )

    # A ruleset scoped by an application group can be discovered through an
    # explicit application on the opposite side.  In that case direction is
    # relative to the Microcosmos input application which caused the match;
    # All workloads represents the (remote) ruleset scope.
    if (
        source_input_match
        and not destination_input_match
        and bool(parse_bool(rule.get("dst_all_workloads", "")))
        and scope_uses_app_group
    ):
        return {"kear_remote": "", "direction": "outgoing",
                "rule_category": category, "warning": ""}
    if (
        destination_input_match
        and not source_input_match
        and bool(parse_bool(rule.get("src_all_workloads", "")))
        and scope_uses_app_group
    ):
        return {"kear_remote": "", "direction": "incoming",
                "rule_category": category, "warning": ""}

    # The naming convention describes intended usage; direction follows the
    # actual selected endpoint, including managed OUTBOUND2APA destinations.
    if (
        not rule.get("ruleset_scope", "").strip()
        and "OUTBOUND2APA" in rule.get("ruleset_name", "").upper()
    ):
        destination_apps = _side_applications(rule, "dst", group_index)
        warning = "OUTBOUND2APA_DESTINATION_MANAGED" if destination_apps else ""
        if source_input_match != destination_input_match:
            other_prefix = "dst" if source_input_match else "src"
            other_apps = _side_applications(rule, other_prefix, group_index)
            other_labels = _expanded_selector_labels(
                rule.get(f"{other_prefix}_labels", ""),
                rule.get(f"{other_prefix}_label_groups", ""), group_index,
            )
            other_environment = next(iter(other_labels.get("env", set())), environment)
            result = _relationship_to_apps(
                "outgoing" if source_input_match else "incoming",
                other_apps, other_environment, lookup, local_kear, category,
            )
            if not other_apps and _has_application_group(rule, other_prefix, group_index):
                result["warning"] = _join_warnings(result["warning"], "REMOTE_KEAR_UNAVAILABLE")
            result["warning"] = _join_warnings(warning, result["warning"])
            return result
        if (
            source_input_match and destination_input_match
            and _side_applications(rule, "src", group_index) == destination_apps == {input_app}
        ):
            return {"kear_remote": local_kear, "direction": "intra-app",
                    "rule_category": category, "warning": warning}
        return {"kear_remote": "", "direction": "undetermined", "rule_category": category,
                "warning": _join_warnings(warning, "DIRECTION_UNDETERMINED")}

    # Explicit endpoints anchor the row's perspective even when the ruleset
    # names another application. Implicit role/All workloads peers inherit
    # that scope; explicit peers retain their own application and environment.
    if input_app and local_apps and input_app not in local_apps:
        if source_input_match != destination_input_match:
            other_prefix = "dst" if source_input_match else "src"
            other_kind = destination_kind if source_input_match else source_kind
            if other_kind != "empty":
                other_apps = (
                    local_apps if other_kind == "local"
                    else _side_applications(rule, other_prefix, group_index)
                )
                other_labels = _expanded_selector_labels(
                    rule.get(f"{other_prefix}_labels", ""),
                    rule.get(f"{other_prefix}_label_groups", ""), group_index,
                )
                other_environment = next(iter(other_labels.get("env", set())), environment)
                return _relationship_to_endpoint(
                    "outgoing" if source_input_match else "incoming",
                    other_kind, other_apps, other_environment, lookup, local_kear, category,
                )
        return {"kear_remote": "", "direction": "undetermined",
                "rule_category": category, "warning": "DIRECTION_UNDETERMINED"}

    if not local_app:
        return {"kear_remote": "", "direction": "undetermined",
                "rule_category": category, "warning": "LOCAL_SCOPE_UNDETERMINED"}
    if source_kind == destination_kind == "local":
        return {"kear_remote": local_kear, "direction": "intra-app",
                "rule_category": category, "warning": ""}

    remote_apps: set[str] = set()
    remote_kinds = {"remote_app", "app_group", "iplist", "workload", "ambiguous"}
    if source_kind in remote_kinds and destination_kind == "local":
        direction, remote_kind, remote_apps = "incoming", source_kind, source_apps
    elif source_kind == "local" and destination_kind in remote_kinds:
        direction, remote_kind, remote_apps = "outgoing", destination_kind, destination_apps
    else:
        return {"kear_remote": "", "direction": "undetermined",
                "rule_category": category, "warning": "DIRECTION_UNDETERMINED"}

    return _relationship_to_endpoint(
        direction, remote_kind, remote_apps, environment, lookup, local_kear, category,
    )


def _relationship_to_endpoint(
    direction: str, kind: str, applications: set[str], environment: str,
    lookup: Optional[Mapping[str, Mapping[str, set[str]]]],
    local_kear: str, category: str,
) -> Dict[str, str]:
    """Separate a known flow direction from incomplete peer identification."""
    if kind == "ambiguous":
        return {"kear_remote": "", "direction": direction,
                "rule_category": category, "warning": "REMOTE_KEAR_AMBIGUOUS"}
    result = _relationship_to_apps(
        direction, applications, environment, lookup, local_kear, category,
    )
    if not applications and kind in {"app_group", "workload"}:
        result["warning"] = _join_warnings(result["warning"], "REMOTE_KEAR_UNAVAILABLE")
    return result


def _relationship_to_apps(
    direction: str, remote_apps: set[str], environment: str,
    lookup: Optional[Mapping[str, Mapping[str, set[str]]]],
    local_kear: str, category: str,
) -> Dict[str, str]:
    """Resolve the opposite Kear without mixing it with the report row's Kear."""
    if not remote_apps:
        return {"kear_remote": "", "direction": direction,
                "rule_category": category, "warning": ""}
    if len(remote_apps) != 1 or lookup is None:
        warning = (
            "REMOTE_KEAR_AMBIGUOUS"
            if len(remote_apps) != 1 else "REMOTE_KEAR_UNAVAILABLE"
        )
        return {"kear_remote": "", "direction": direction,
                "rule_category": category, "warning": warning}
    remote_kear, warning = _resolve_remote_kear(next(iter(remote_apps)), environment, lookup)
    if remote_kear and local_kear and remote_kear.casefold() == local_kear.casefold():
        direction = "intra-app"
    return {"kear_remote": remote_kear, "direction": direction,
            "rule_category": category, "warning": warning}


def _rule_category(rule: Mapping[str, str]) -> str:
    """Apply the approved infrastructure/strategic/business precedence."""
    name = rule.get("ruleset_name", "").strip().upper()
    if name.startswith(("BOUQUETS_", "GLOBAL_", "LUIGI_")):
        return "infra_rule"
    description = rule.get("rule_description", "").lstrip().casefold()
    iplist_names = _iplist_names(rule.get("src_iplists", ""))
    iplist_names.extend(_iplist_names(rule.get("dst_iplists", "")))
    strategic_description = description.startswith(("[+srule]", "[+drule]"))
    deny_rule = rule.get("rule_type", "").strip().casefold() == "deny"
    strategic_iplist = any(name.upper().startswith("ZNOT_") for name in iplist_names)
    if strategic_description or deny_rule or strategic_iplist:
        return "strategic_rule"
    return "business_rule"


def _with_rule_enrichment_columns(
    values: Mapping[str, object], enrichment: Optional[Mapping[str, str]] = None,
) -> Dict[str, object]:
    """Insert relationship columns after Kear Id (or app for standard input)."""
    enrichment = enrichment or {}
    output: Dict[str, object] = {}
    inserted = False
    for key, value in values.items():
        output[key] = value
        insertion_point = key.casefold() == "kear id" or (
            key.casefold() == "app" and "Kear Id" not in values
        )
        if insertion_point:
            output["Kear Remote"] = enrichment.get("kear_remote", "") or KEAR_NOT_ONBOARDED
            output["Direction"] = enrichment.get("direction", "")
            output["Rule Category"] = enrichment.get("rule_category", "")
            inserted = True
    if not inserted:
        output.update({"Kear Remote": enrichment.get("kear_remote", "") or KEAR_NOT_ONBOARDED,
                       "Direction": enrichment.get("direction", ""),
                       "Rule Category": enrichment.get("rule_category", "")})
    return output


def _join_warnings(*warnings: str) -> str:
    return "; ".join(dict.fromkeys(warning for warning in warnings if warning))


def _deduplicate_inputs(rows: Sequence[Dict[str, str]], keys: Sequence[str]) -> List[Dict[str, str]]:
    output: List[Dict[str, str]] = []
    seen = set()
    for row in rows:
        identity = tuple(row.get(key, "").casefold() for key in keys)
        if identity not in seen:
            output.append(row)
            seen.add(identity)
    return output


def _get_case_insensitive(row: Mapping[str, object], name: str) -> str:
    wanted = name.casefold()
    return next((str(value or "") for key, value in row.items() if key.casefold() == wanted), "")


def _labels(value: object) -> Dict[str, set[str]]:
    output: Dict[str, set[str]] = {}
    for component in re.split(r"[;\n]", str(value or "")):
        key, separator, item = component.strip().partition(":")
        if separator and key.strip() and item.strip():
            normalized_item = re.sub(r"\s*\(/[^)]*\)\s*$", "", item).strip()
            if normalized_item:
                output.setdefault(key.strip().casefold(), set()).add(
                    normalized_item.casefold()
                )
    return output


def _parts(value: object) -> List[str]:
    return [part.strip() for part in re.split(r"[;\n]", str(value or "")) if part.strip()]


def _clean_label_group_reference(value: object) -> str:
    text = re.sub(r"^Label\s*Group\s*:\s*", "", str(value or "").strip(), flags=re.I)
    text = re.sub(r"^(?:app|env|role|loc)(?:group)?\s*:\s*", "", text, flags=re.I)
    return re.sub(r"\s*\(/[^)]*\)\s*$", "", text).strip()


def _label_group_index(
    groups: Sequence[Mapping[str, str]],
) -> Dict[str, Mapping[str, object]]:
    """Index only the label groups confirmed by the snapshot export."""
    output: Dict[str, Mapping[str, object]] = {}
    for group in groups:
        name = str(group.get("name", "")).strip()
        key = str(group.get("key", "")).strip().casefold()
        if name and key:
            output[name.casefold()] = {
                **group, "name": name, "key": key,
            }
    return output


def _group_member_values(
    references: object, key: str,
    group_index: Mapping[str, Mapping[str, object]],
) -> set[str]:
    values: set[str] = set()
    for reference in _parts(references):
        name = _clean_label_group_reference(reference)
        group = group_index.get(name.casefold())
        if not group or str(group.get("key", "")).casefold() != key.casefold():
            continue
        members = ";".join((
            str(group.get("member_labels", "")),
            str(group.get("fully_expanded_members", "")),
        ))
        for member in _parts(members):
            member_key, separator, member_value = member.partition(":")
            if separator and member_key.strip().casefold() == key.casefold():
                values.add(member_value.strip().casefold())
            elif not separator:
                bare_member = re.sub(r"\s*\(/[^)]*\)\s*$", "", member).strip()
                if bare_member:
                    values.add(bare_member.casefold())
    return values


def _display_label_groups(
    references: object, group_index: Mapping[str, Mapping[str, object]],
) -> List[str]:
    output = []
    for reference in _parts(references):
        name = _clean_label_group_reference(reference)
        group = group_index.get(name.casefold())
        prefix = f"{group['key']}group" if group else "labelgroup"
        output.append(f"{prefix}:{name}")
    return output


def _expanded_selector_labels(
    labels_value: object, group_references: object,
    group_index: Mapping[str, Mapping[str, object]],
) -> Dict[str, set[str]]:
    labels = _labels(labels_value)
    for key, values in tuple(labels.items()):
        for value in tuple(values):
            name = _clean_label_group_reference(value)
            group = group_index.get(name.casefold())
            group_key = str(group.get("key", "")).casefold() if group else ""
            selector_key = key[:-5] if key.endswith("group") else key
            if group and group_key == selector_key:
                labels[key].discard(value)
                labels.setdefault(selector_key, set()).update(
                    _group_member_values(name, selector_key, group_index)
                )
    for reference in _parts(group_references):
        name = _clean_label_group_reference(reference)
        group = group_index.get(name.casefold())
        if not group:
            continue
        key = str(group.get("key", "")).casefold()
        labels.setdefault(key, set()).update(_group_member_values(name, key, group_index))
    return labels


def _format_ruleset_scope(
    scope: object, group_index: Mapping[str, Mapping[str, object]],
) -> str:
    """Render confirmed scope label groups as e.g. ``appgroup:GROUP``."""
    output = []
    for component in _parts(scope):
        key, separator, value = component.partition(":")
        normalized_key = key.strip().casefold()
        selector_key = normalized_key[:-5] if normalized_key.endswith("group") else normalized_key
        name = _clean_label_group_reference(value)
        group = group_index.get(name.casefold()) if separator else None
        if group and str(group.get("key", "")).casefold() == selector_key:
            output.append(f"{selector_key}group:{group['name']}")
        else:
            output.append(component)
    return "; ".join(_ordered_selectors(output))


def _ordered_selectors(selectors: Sequence[str]) -> List[str]:
    """Keep values intact while ordering label families, including exclusions."""
    def order(selector: str) -> int:
        value = selector.strip()
        if value.startswith("EXCEPT(") and value.endswith(")"):
            value = value[7:-1]
        key = value.partition(":")[0].strip().casefold()
        if key.endswith("group"):
            key = key[:-5]
        return {"role": 0, "app": 1, "env": 2, "loc": 3}.get(key, 4)

    return sorted(dict.fromkeys(selectors), key=order)


def _rule_matches_scope(
    rule: Mapping[str, str], app: str, env: str,
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> bool:
    wanted_app, wanted_env = app.casefold(), env.casefold()
    group_index = group_index or {}
    for field, group_field in (
        ("ruleset_scope", ""),
        ("src_labels", "src_label_groups"),
        ("dst_labels", "dst_label_groups"),
    ):
        labels = _expanded_selector_labels(
            rule.get(field, ""), rule.get(group_field, "") if group_field else "",
            group_index,
        )
        applications = (
            labels.get("app", set()) if field == "ruleset_scope"
            else _side_applications(rule, field.split("_", 1)[0], group_index)
        )
        if wanted_app not in applications:
            continue
        if not wanted_env or wanted_env in labels.get("env", set()):
            return True
    return False


def _programs_for_app(app: str, groups: Sequence[Mapping[str, str]]) -> str:
    programs = []
    for group in groups:
        name = str(group.get("name", "")).strip()
        if not name.upper().startswith("KPI_PROGRAM_"):
            continue
        members = ";".join((
            str(group.get("member_labels", "")),
            str(group.get("fully_expanded_members", "")),
        ))
        if re.search(rf"(?<![A-Za-z0-9_]){re.escape(app)}(?![A-Za-z0-9_])", members, re.I):
            programs.append(name)
    return ";".join(dict.fromkeys(programs))


def _factor_side(
    rule: Mapping[str, str], prefix: str,
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> Tuple[str, str]:
    group_index = group_index or {}
    selectors: List[str] = []
    all_workloads = parse_bool(rule.get(f"{prefix}_all_workloads", ""))
    iplists = rule.get(f"{prefix}_iplists", "").strip()
    if all_workloads:
        context = _ruleset_scope_context(rule.get("ruleset_scope", ""), group_index)
        selectors.append(f"All workloads ({context})" if context else "All workloads")
    if iplists:
        selectors.append(iplists)
    labels = rule.get(f"{prefix}_labels", "").strip()
    label_selectors = _parts(_format_ruleset_scope(labels, group_index))
    label_selectors.extend(_display_label_groups(
        rule.get(f"{prefix}_label_groups", ""), group_index,
    ))
    excluded = [
        *_parts(_format_ruleset_scope(
            rule.get(f"{prefix}_labels_exclusions", ""), group_index,
        )),
        *_display_label_groups(
            rule.get(f"{prefix}_label_groups_exclusions", ""), group_index,
        ),
    ]
    label_selectors.extend(f"EXCEPT({value})" for value in excluded)
    selectors.extend(_ordered_selectors(label_selectors))
    workloads = _parts(rule.get(f"{prefix}_workloads", ""))
    selectors.extend(
        name if name.casefold().startswith("workload:") else f"workload:{name}"
        for name in workloads
    )
    kind = (
        "all_workloads" if all_workloads else "iplist" if iplists
        else "labels" if label_selectors else "workload" if workloads else ""
    )
    return "; ".join(dict.fromkeys(selectors)), kind


def _ruleset_scope_context(
    scope: object,
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> str:
    """Render scope labels in role/app/env order without losing other dimensions."""
    values: Dict[str, List[str]] = {
        "role": [], "rolegroup": [], "app": [], "appgroup": [],
        "env": [], "envgroup": [], "loc": [], "locgroup": [],
    }
    formatted_scope = _format_ruleset_scope(scope, group_index or {})
    for component in re.split(r"[;\n]", formatted_scope):
        key, separator, value = component.strip().partition(":")
        normalized_key = key.strip().casefold()
        value = value.strip()
        if separator and normalized_key in values and value and value not in values[normalized_key]:
            values[normalized_key].append(value)
    return "; ".join(
        f"{key}:{', '.join(values[key])}"
        for key in values if values[key]
    )


def _extrascope_warning(rule: Mapping[str, str]) -> str:
    """Explain the critical Global Consumer condition when it is detected."""
    if _global_consumer_in_use(rule):
        return "WARNING: Global Consumer applies the rule to all managed workloads in the PCE"
    return ""


def _global_consumer_in_use(rule: Mapping[str, str]) -> bool:
    """Return whether an Extrascope rule consumes every managed PCE workload."""
    return bool(
        parse_bool(rule.get("unscoped_consumers", ""))
        and parse_bool(rule.get("src_all_workloads", ""))
    )


def _iplist_names(value: str) -> List[str]:
    names = []
    for part in re.split(r"[;\n]", value):
        name = re.sub(r"\s+\(/orgs/\d+/(?:sec_policy/[^/)]+/)?ip_lists/\d+\)\s*$", "", part).strip()
        if name.casefold().startswith("ip list:"):
            name = name.partition(":")[2].strip()
        if name:
            names.append(name)
    return names


def _contains_user_iplist(value: str) -> bool:
    return any(name.upper().startswith(("U_", "USR_")) for name in _iplist_names(value))


def _has_intra_zone_iplist(value: str) -> bool:
    return any(name.upper().startswith(("NZ3_", "ZNOT_NZ3")) for name in _iplist_names(value))


def _ruleset_identity(rule: Mapping[str, str]) -> str:
    return rule.get("ruleset_href", "").strip() or rule.get("ruleset_name", "").strip()
