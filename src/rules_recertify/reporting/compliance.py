"""Generate rule-compliance workbooks from the materialized policy snapshot."""
from __future__ import annotations

import csv
import importlib.util
import re
from collections import Counter
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from ..history.database import Database
from ..workloader.csvio import parse_bool, read_rows
from .dangerous_ports import PORT_CATALOGS, _catalog_interval, dangerous_ports
from .workbook import _expand_services, _load_report_services


RULE_FIELDS = (
    "ruleset_name", "ruleset_scope", "ruleset_enabled", "rule_type",
    "rule_description", "rule_enabled", "unscoped_consumers", "src_all_workloads",
    "src_labels", "src_labels_exclusions", "src_label_groups",
    "src_label_groups_exclusions", "src_iplists", "dst_all_workloads", "dst_labels",
    "dst_labels_exclusions", "dst_label_groups", "dst_label_groups_exclusions",
    "dst_iplists", "services", "rule_href",
)
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


def generate_compliance_workbook(
    raw_dir: Path, output: Path, dangerous_port_lists: Sequence[str],
    input_path: Optional[Path] = None, database: Optional[Database] = None,
) -> Path:
    """Evaluate matching snapshot rules for optional app/environment input rows."""
    if importlib.util.find_spec("openpyxl") is None:
        raise RuntimeError("openpyxl is required for compliance report generation")
    snapshot = raw_dir / "snapshot"
    required = [snapshot / "rules_inventory.csv", snapshot / "export_labelgroups.csv"]
    if input_path is None:
        required.append(snapshot / "labels.csv")
    missing = [str(path) for path in required if not path.is_file() or not path.stat().st_size]
    if missing:
        raise ValueError("compliance snapshot file is missing or empty: " + ", ".join(missing))
    input_rows, input_columns = _load_scope_input(input_path, snapshot / "labels.csv")
    microcosmos_input = "Program (MIO)" in input_columns
    microcosmos_lookup = _microcosmos_kear_lookup(input_rows) if microcosmos_input else {}
    rules = list(read_rows(snapshot / "rules_inventory.csv", RULE_FIELDS))
    groups = list(read_rows(snapshot / "export_labelgroups.csv", LABEL_GROUP_FIELDS))
    group_index = _label_group_index(groups)
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
        input_values = {column: input_row.get(column, "") for column in primary_columns}
        extra_values = {
            column: input_row.get(column, "")
            for column in input_columns if column not in primary_columns
        }
        if not matched:
            rows.append({
                **_with_rule_enrichment_columns(input_values), "Program (KPI)": programs,
                "Match status": "APP_NOT_FOUND" if not app else "NO_MATCH",
                "Warning": "",
                "Global Consumer in use": "FALSE",
                **{field: "" for field in (
                    "ruleset_name", "ruleset_scope", "ruleset_enabled", "rule_type",
                    "rule_description", "rule_enabled", "rule_href",
                )},
                "Source": "", "Destination": "", "Source contains User": "FALSE",
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
            rows.append({
                **_with_rule_enrichment_columns(input_values, enrichment),
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
                "Source": source,
                "Destination": destination,
                "Source contains User": str(
                    source_kind == "iplist" and _contains_user_iplist(source)
                ).upper(),
                "Destination contains User": str(
                    destination_kind == "iplist" and _contains_user_iplist(destination)
                ).upper(),
                "services": rule["services"],
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

    from openpyxl import Workbook
    workbook = Workbook()
    workbook.remove(workbook.active)
    _write_summary_sheet(workbook, rows, report_catalogs)
    business_rows, infra_rows, data_quality_rows = _partition_compliance_rows(rows)
    headers = list(rows[0]) if rows else ["Match status"]
    _write_compliance_sheet(
        workbook, business_rows, "Business Rules", "BusinessRules", headers,
    )
    _write_compliance_sheet(
        workbook, infra_rows, "Infra Rules", "InfraRules", headers,
    )
    _write_compliance_sheet(
        workbook, data_quality_rows, "Data Quality", "DataQuality", headers,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    workbook.save(temporary)
    temporary.replace(output)
    return output


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
        ("Kear Remote", "Resolved from the explicit remote app label using Microcosmos Module and Environment. A unique Kear shared across environments is accepted. Missing or ambiguous mappings are marked KEAR_NOT_ONBOARDED_IN_MICROCOSMOS."),
        ("Direction", "The ruleset_scope app is normally local. When an app-group-scoped rule is discovered through an explicit app on one side and All workloads on the other, direction is relative to that matched input app (source = outgoing, destination = incoming). Otherwise role-only selectors and All workloads inherit the local scope. Remote → local is incoming; local → remote is outgoing; equal local/remote Kears are intra-app; ambiguous topologies are undetermined. Unscoped OUTBOUND2APA rules whose source explicitly selects the input app are outgoing."),
        ("Rule Category", "BOUQUETS_* and GLOBAL_* rulesets are infra_rule. Other deny rules, rules using a ZNOT_* IP List, or descriptions beginning with [+srule] or [+drule] are strategic_rule. Remaining rules are business_rule."),
        ("Label groups & exclusions", "Label groups confirmed in export_labelgroups.csv are rendered in the existing scope, Source, and Destination columns as <key>group:<name> (for example appgroup:PAYMENTS). Excluded labels and groups are rendered as ALL EXCEPT(<selector>)."),
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


def _write_compliance_sheet(
    workbook: object, rows: Sequence[Mapping[str, object]],
    sheet_name: str = "Compliance", table_name: str = "ComplianceResults",
    headers: Optional[Sequence[str]] = None,
) -> None:
    from openpyxl.formatting.rule import CellIsRule
    from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
    from openpyxl.worksheet.table import Table, TableStyleInfo

    navy, white, dark = "10233B", "FFFFFF", "172D48"
    pale_green, green = "E0F4EA", "087443"
    pale_red, red = "FCE8E6", "B42318"
    pale_amber, amber = "FFF2DA", "B35D0A"
    pale_blue, blue = "E2EDF7", "0B6B8B"
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
        cell.fill = PatternFill("solid", fgColor=navy)
        cell.font = Font(name="Aptos", size=10, bold=True, color=white)
        cell.alignment = Alignment(vertical="center", wrap_text=True, indent=1)
        cell.border = vertical_border
    for row_number in range(2, sheet.max_row + 1):
        for cell in sheet[row_number]:
            cell.font = Font(name="Aptos", size=10, color=dark)
            cell.alignment = Alignment(vertical="center", wrap_text=True)
            cell.border = vertical_border
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
    }
    for index, header in enumerate(headers, 1):
        values = [len(str(row.get(header, "") or "")) for row in rows[:250]]
        width = preferred_widths.get(header, min(max([len(header), *values]) + 2, 36))
        sheet.column_dimensions[sheet.cell(1, index).column_letter].width = width

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


def _side_relationship(
    rule: Mapping[str, str], prefix: str, local_app: str,
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> Tuple[str, set[str]]:
    """Classify one rule side relative to the application ruleset scope."""
    all_workloads = parse_bool(rule.get(f"{prefix}_all_workloads", ""))
    has_iplist = bool(_iplist_names(rule.get(f"{prefix}_iplists", "")))
    explicit_apps = set(
        _labels(rule.get(f"{prefix}_labels", "")).get("app", set())
    )
    explicit_apps.update(_group_member_values(
        rule.get(f"{prefix}_label_groups", ""), "app", group_index or {},
    ))
    local = local_app.casefold()
    remote_apps = {app for app in explicit_apps if app != local}
    has_local_app = local in explicit_apps

    kinds = sum((bool(all_workloads), has_iplist, has_local_app, bool(remote_apps)))
    if has_iplist and kinds > 1:
        return "ambiguous", remote_apps
    if all_workloads and remote_apps:
        return "ambiguous", remote_apps
    if has_local_app and remote_apps:
        return "ambiguous", remote_apps
    if has_iplist:
        return "iplist", set()
    if remote_apps:
        return "remote_app", remote_apps
    if all_workloads or has_local_app or rule.get(f"{prefix}_labels", "").strip():
        return "local", set()
    return "empty", set()


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
    environment = next(iter(scope.get("env", set())), "")
    source_kind, source_apps = _side_relationship(rule, "src", local_app, group_index)
    destination_kind, destination_apps = _side_relationship(
        rule, "dst", local_app, group_index,
    )
    category = _rule_category(rule)

    source_input_match = input_app in _expanded_selector_labels(
        rule.get("src_labels", ""), rule.get("src_label_groups", ""), group_index,
    ).get("app", set())
    destination_input_match = input_app in _expanded_selector_labels(
        rule.get("dst_labels", ""), rule.get("dst_label_groups", ""), group_index,
    ).get("app", set())
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

    # OUTBOUND2APA is a tactical, unscoped construct: the explicitly selected
    # source application is the local endpoint and the destination is unmanaged.
    # The input application remains the authoritative local identity/Kear.
    tactical_outbound = (
        not local_app
        and "OUTBOUND2APA" in rule.get("ruleset_name", "").upper()
        and input_app
        and input_app in _expanded_selector_labels(
            rule.get("src_labels", ""), rule.get("src_label_groups", ""), group_index,
        ).get("app", set())
    )
    if tactical_outbound:
        return {"kear_remote": "", "direction": "outgoing",
                "rule_category": category, "warning": ""}
    if not local_app:
        return {"kear_remote": "", "direction": "undetermined",
                "rule_category": category, "warning": "LOCAL_SCOPE_UNDETERMINED"}
    if source_kind == destination_kind == "local":
        return {"kear_remote": local_kear, "direction": "intra-app",
                "rule_category": category, "warning": ""}

    remote_apps: set[str] = set()
    if source_kind in {"remote_app", "iplist"} and destination_kind == "local":
        direction, remote_apps = "incoming", source_apps
    elif source_kind == "local" and destination_kind in {"remote_app", "iplist"}:
        direction, remote_apps = "outgoing", destination_apps
    else:
        return {"kear_remote": "", "direction": "undetermined",
                "rule_category": category, "warning": "DIRECTION_UNDETERMINED"}

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
    if name.startswith(("BOUQUETS_", "GLOBAL_")):
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
    return ";".join(output)


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
        if wanted_app not in labels.get("app", set()):
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
    if parse_bool(rule.get(f"{prefix}_all_workloads", "")):
        context = _ruleset_scope_context(rule.get("ruleset_scope", ""), group_index)
        selectors.append(f"All workloads ({context})" if context else "All workloads")
        kind = "all_workloads"
    elif rule.get(f"{prefix}_iplists", "").strip():
        selectors.append(rule[f"{prefix}_iplists"].strip())
        kind = "iplist"
    else:
        labels = rule.get(f"{prefix}_labels", "").strip()
        if labels:
            selectors.append(labels)
        selectors.extend(_display_label_groups(
            rule.get(f"{prefix}_label_groups", ""), group_index,
        ))
        kind = "labels" if selectors else ""

    excluded = [
        *_parts(rule.get(f"{prefix}_labels_exclusions", "")),
        *_display_label_groups(
            rule.get(f"{prefix}_label_groups_exclusions", ""), group_index,
        ),
    ]
    selectors.extend(f"ALL EXCEPT({value})" for value in excluded)
    return "; ".join(dict.fromkeys(selectors)), kind or ("labels" if excluded else "")


def _ruleset_scope_context(
    scope: object,
    group_index: Optional[Mapping[str, Mapping[str, object]]] = None,
) -> str:
    """Render app/env labels from a ruleset scope in a stable readable order."""
    values: Dict[str, List[str]] = {
        "app": [], "appgroup": [], "env": [], "envgroup": [],
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
        for key in ("app", "appgroup", "env", "envgroup") if values[key]
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
        name = part.strip().split(" (", 1)[0].strip()
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
