"""Generate rule-compliance workbooks from the materialized policy snapshot."""
from __future__ import annotations

import csv
import importlib.util
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from ..workloader.csvio import parse_bool, read_rows
from .dangerous_ports import dangerous_ports
from .rule_search import _write_sheet
from .workbook import _expand_services, _load_report_services


RULE_FIELDS = (
    "ruleset_name", "ruleset_scope", "ruleset_enabled", "rule_type", "rule_enabled",
    "src_all_workloads", "src_labels", "src_iplists", "dst_all_workloads",
    "dst_labels", "dst_iplists", "services",
)
LABEL_GROUP_FIELDS = (
    "name", "key", "description", "member_labels", "member_label_groups",
    "fully_expanded_members", "href",
)


def generate_compliance_workbook(
    raw_dir: Path, output: Path, dangerous_port_lists: Sequence[str],
    input_path: Optional[Path] = None,
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
    input_rows, _input_columns = _load_scope_input(input_path, snapshot / "labels.csv")
    rules = list(read_rows(snapshot / "rules_inventory.csv", RULE_FIELDS))
    groups = list(read_rows(snapshot / "export_labelgroups.csv", LABEL_GROUP_FIELDS))
    services, service_reference = _load_report_services(raw_dir)
    intra_zone_rulesets = {
        _ruleset_identity(row) for row in rules
        if _has_intra_zone_iplist(row.get("src_iplists", ""))
        or _has_intra_zone_iplist(row.get("dst_iplists", ""))
    }

    rows: List[Dict[str, object]] = []
    for input_row in input_rows:
        app = _get_case_insensitive(input_row, "app").strip()
        env = _get_case_insensitive(input_row, "env").strip()
        programs = _programs_for_app(app, groups)
        matched = [row for row in rules if _rule_matches_scope(row, app, env)]
        if not matched:
            rows.append({
                **input_row, "Program": programs, "Match status": "NO_MATCH",
                **{field: "" for field in RULE_FIELDS[:5]},
                "Source": "", "Destination": "", "Source contains User": "FALSE",
                "Destination contains User": "FALSE",
                "services": "",
                **{catalog: "" for catalog in dangerous_port_lists},
                "Protection type": "",
            })
            continue
        for rule in matched:
            source, source_kind = _factor_side(rule, "src")
            destination, destination_kind = _factor_side(rule, "dst")
            expanded_services = _expand_services(rule["services"], services)
            rows.append({
                **input_row,
                "Program": programs,
                "Match status": "MATCHED",
                "ruleset_name": rule["ruleset_name"],
                "ruleset_scope": rule["ruleset_scope"],
                "ruleset_enabled": rule["ruleset_enabled"],
                "rule_type": rule["rule_type"],
                "rule_enabled": rule["rule_enabled"],
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
                    for catalog in dangerous_port_lists
                },
                "Protection type": (
                    "Intra-zone" if _ruleset_identity(rule) in intra_zone_rulesets else ""
                ),
            })

    from openpyxl import Workbook
    workbook = Workbook()
    workbook.remove(workbook.active)
    _write_sheet(workbook, "Compliance", rows)
    _write_sheet(workbook, "Metadata", [{
        "rules inventory": str(snapshot / "rules_inventory.csv"),
        "input": str(input_path) if input_path else str(snapshot / "labels.csv"),
        "service reference": service_reference,
        "dangerous port lists": ";".join(dangerous_port_lists),
        "generated at UTC": datetime.now(timezone.utc).isoformat(),
    }])
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    workbook.save(temporary)
    temporary.replace(output)
    return output


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
        values = list(iterator)
        workbook.close()
        rows = [
            {header: str(row[index] or "").strip() if index < len(row) else ""
             for index, header in enumerate(headers)}
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
    if not headers or not any(header.casefold() == "app" for header in headers):
        raise ValueError("compliance input must contain an app column")
    if any(not header for header in headers):
        raise ValueError("compliance input contains an empty column header")
    if len({header.casefold() for header in headers}) != len(headers):
        raise ValueError("compliance input contains duplicate column headers")
    rows = [row for row in rows if _get_case_insensitive(row, "app").strip()]
    if not rows:
        raise ValueError("compliance input contains no non-empty app value")
    return rows, headers


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
    return next((str(value or "") for key, value in row.items() if key.casefold() == name), "")


def _labels(value: object) -> Dict[str, set[str]]:
    output: Dict[str, set[str]] = {}
    for component in re.split(r"[;\n]", str(value or "")):
        key, separator, item = component.strip().partition(":")
        if separator and key.strip() and item.strip():
            output.setdefault(key.strip().casefold(), set()).add(item.strip().casefold())
    return output


def _rule_matches_scope(rule: Mapping[str, str], app: str, env: str) -> bool:
    wanted_app, wanted_env = app.casefold(), env.casefold()
    for field in ("ruleset_scope", "src_labels", "dst_labels"):
        labels = _labels(rule.get(field, ""))
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


def _factor_side(rule: Mapping[str, str], prefix: str) -> Tuple[str, str]:
    if parse_bool(rule.get(f"{prefix}_all_workloads", "")):
        return "All workloads", "all_workloads"
    if rule.get(f"{prefix}_iplists", "").strip():
        return rule[f"{prefix}_iplists"], "iplist"
    if rule.get(f"{prefix}_labels", "").strip():
        return rule[f"{prefix}_labels"], "labels"
    return "", ""


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
