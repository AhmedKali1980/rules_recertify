"""Search the latest ingested rule snapshot from a user-supplied item list."""
from __future__ import annotations

import csv
import importlib.util
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from ..history.database import Database
from .workbook import _expand_services, _load_report_services


SEARCH_FIELDS = (
    "ruleset_name", "ruleset_scope", "rule_type", "rule_description",
    "src_all_workloads",
    "src_labels", "src_labels_exclusions", "src_label_groups",
    "src_label_groups_exclusions", "src_iplists", "src_workloads",
    "dst_all_workloads", "dst_labels", "dst_labels_exclusions", "dst_label_groups",
    "dst_label_groups_exclusions", "dst_iplists", "dst_workloads", "services",
)

_PORT_TOKEN = re.compile(
    r"^\s*(?:(TCP|UDP)\s*/\s*)?(\d{1,5})(?:\s*-\s*(\d{1,5}))?"
    r"(?:\s+(TCP|UDP))?\s*$", re.IGNORECASE,
)
_RULE_PORT = re.compile(
    r"\b(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s+(TCP|UDP)\b", re.IGNORECASE,
)


def load_search_items(path: Path) -> List[str]:
    """Load one non-empty item per CSV/TXT row or XLSX row."""
    if not path.is_file():
        raise ValueError(f"items file not found: {path}")
    if path.suffix.lower() == ".xlsx":
        if importlib.util.find_spec("openpyxl") is None:
            raise RuntimeError("openpyxl is required to read an XLSX items file")
        from openpyxl import load_workbook
        sheet = load_workbook(path, read_only=True, data_only=True).active
        rows = [[cell for cell in row if cell is not None and str(cell).strip()] for row in sheet.iter_rows(values_only=True)]
    else:
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.reader(handle))
    items: List[str] = []
    for number, row in enumerate(rows, 1):
        values = [str(value).strip() for value in row if str(value).strip()]
        if not values:
            continue
        if len(values) != 1:
            raise ValueError(f"{path}:{number}: expected exactly one non-empty column")
        if number == 1 and values[0].casefold() in {"item", "search item", "searched item"}:
            continue
        if values[0] not in items:
            items.append(values[0])
    if not items:
        raise ValueError("items file is empty or contains only blank values")
    return items


def latest_rules(db: Database) -> Tuple[List[Dict[str, object]], str]:
    """Return only rules explicitly present in the current policy inventory."""
    with db.connect() as connection:
        latest = connection.execute(
            "SELECT MAX(snapshot_at) FROM rules WHERE is_present=1"
        ).fetchone()[0]
        if not latest:
            return [], ""
        rows = [dict(row) for row in connection.execute(
            "SELECT * FROM rules WHERE is_present=1 ORDER BY ruleset_name,rule_href",
        )]
    return rows, str(latest)


def _port_query(item: str) -> Optional[List[Tuple[Optional[str], int, int]]]:
    tokens = [token.strip() for token in re.split(r"[;,]", item) if token.strip()]
    parsed: List[Tuple[Optional[str], int, int]] = []
    if not tokens:
        return None
    for token in tokens:
        match = _PORT_TOKEN.fullmatch(token)
        if not match:
            return None
        protocol = (match.group(1) or match.group(4) or "").upper() or None
        start, end = int(match.group(2)), int(match.group(3) or match.group(2))
        if start > end or end > 65535:
            raise ValueError(f"invalid port or range: {token}")
        parsed.append((protocol, start, end))
    return parsed


def _service_intersections(
    expanded_services: str, query: Sequence[Tuple[Optional[str], int, int]],
) -> List[str]:
    rule_intervals: List[Tuple[str, int, int]] = []
    for match in _RULE_PORT.finditer(expanded_services):
        start, end = int(match.group(1)), int(match.group(2) or match.group(1))
        if start <= end <= 65535:
            rule_intervals.append((match.group(3).upper(), start, end))
    matches: List[str] = []
    for query_protocol, query_start, query_end in query:
        for rule_protocol, rule_start, rule_end in rule_intervals:
            if query_protocol and query_protocol != rule_protocol:
                continue
            start, end = max(query_start, rule_start), min(query_end, rule_end)
            if start <= end:
                value = f"{rule_protocol}/{start}" if start == end else f"{rule_protocol}/{start}-{end}"
                if value not in matches:
                    matches.append(value)
    return matches


def search_latest_rules(
    rules: Iterable[Mapping[str, object]], items: Sequence[str],
    service_catalog: Mapping[str, Tuple[str, str]], case_sensitive: bool = False,
) -> Tuple[List[Dict[str, object]], List[Dict[str, object]]]:
    """Return result and summary rows, one result per searched item/rule."""
    prepared = []
    raw_headers: List[str] = []
    for rule in rules:
        raw = json.loads(str(rule["raw_json"]))
        for key in raw:
            if key not in raw_headers:
                raw_headers.append(key)
        prepared.append((rule, raw))
    results: List[Dict[str, object]] = []
    summary: List[Dict[str, object]] = []
    for item in items:
        port_query = _port_query(item)
        matched_count = 0
        for rule, raw in prepared:
            found_fields: List[str] = []
            details: List[str] = []
            if port_query is not None:
                expanded = _expand_services(str(raw.get("services", rule.get("services", ""))), service_catalog)
                intersections = _service_intersections(expanded, port_query)
                if intersections:
                    found_fields.append("services")
                    details.extend(intersections)
            else:
                needle = item if case_sensitive else item.casefold()
                for field in SEARCH_FIELDS:
                    value = str(raw.get(field, rule.get(field, "")) or "")
                    haystack = value if case_sensitive else value.casefold()
                    if needle in haystack:
                        found_fields.append(field)
            if found_fields:
                matched_count += 1
                results.append({
                    "searched item": item,
                    "status": "FOUND",
                    "found as": ";".join(found_fields),
                    "match details": ";".join(details),
                    "rule snapshot": rule["snapshot_at"],
                    **{header: raw.get(header, "") for header in raw_headers},
                })
        if not matched_count:
            results.append({
                "searched item": item, "status": "NOT_USED_IN_ANY_RULE",
                "found as": "", "match details": "", "rule snapshot": "",
                **{header: "" for header in raw_headers},
            })
        summary.append({
            "searched item": item,
            "status": "FOUND" if matched_count else "NOT_USED_IN_ANY_RULE",
            "matching rules": matched_count,
        })
    results.sort(key=lambda row: (0 if row["status"] == "NOT_USED_IN_ANY_RULE" else 1,
                                  str(row["searched item"]).casefold(), str(row.get("rule_href", ""))))
    return results, summary


def _write_sheet(workbook: object, name: str, rows: Sequence[Mapping[str, object]]) -> None:
    sheet = workbook.create_sheet(name)
    headers = list(rows[0]) if rows else ["searched item", "status"]
    sheet.append(headers)
    for row in rows:
        sheet.append([_excel_value(row.get(header, "")) for header in headers])
    sheet.freeze_panes = "A2"
    sheet.auto_filter.ref = sheet.dimensions
    for index, header in enumerate(headers, 1):
        lengths = [len(str(header))] + [len(str(row.get(header, "") or "")) for row in rows]
        sheet.column_dimensions[sheet.cell(1, index).column_letter].width = min(max(lengths) + 2, 80)


def _excel_value(value: object) -> object:
    if isinstance(value, (dict, list, tuple, set)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def generate_rule_search_workbook(
    db: Database, items_path: Path, output: Path, raw_dir: Optional[Path] = None,
    case_sensitive: bool = False,
) -> Path:
    if importlib.util.find_spec("openpyxl") is None:
        raise RuntimeError("openpyxl is required for rule-search Excel generation")
    from openpyxl import Workbook
    items = load_search_items(items_path)
    rules, snapshot = latest_rules(db)
    if not snapshot:
        raise ValueError("no rule snapshot is available in SQLite")
    service_catalog, service_reference = _load_report_services(raw_dir)
    results, summary = search_latest_rules(rules, items, service_catalog, case_sensitive)
    workbook = Workbook(); workbook.remove(workbook.active)
    _write_sheet(workbook, "Summary", summary)
    _write_sheet(workbook, "Results", results)
    _write_sheet(workbook, "Metadata", [{
        "rule snapshot": snapshot,
        "items file": str(items_path),
        "service reference": service_reference,
        "case sensitive": str(case_sensitive).upper(),
        "generated at UTC": datetime.now(timezone.utc).isoformat(),
    }])
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    workbook.save(temporary); temporary.replace(output)
    return output
