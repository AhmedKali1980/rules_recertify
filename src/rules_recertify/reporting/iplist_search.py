"""Search materialized IP Lists for user-supplied IP addresses and subnets."""
from __future__ import annotations

import csv
import importlib.util
import ipaddress
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from ..resolution.workloads import normalize_ip_list_member
from ..workloader.csvio import read_rows
from .rule_search import _write_sheet


INPUT_COLUMNS = ("ip/subnet", "ip", "subnet")
IPLIST_FIELDS = ("name", "include")
AddressSpan = Tuple[int, int, int]


def generate_iplist_search_workbook(raw_dir: Path, input_path: Path, output: Path) -> Path:
    """Find IP Lists that fully contain each input IP address or subnet."""
    if importlib.util.find_spec("openpyxl") is None:
        raise RuntimeError("openpyxl is required for IP List search workbook generation")
    input_rows, input_columns = _load_search_input(input_path)
    snapshot = raw_dir / "snapshot"
    references = [
        path for path in (
            snapshot / "export_iplists.csv",
            snapshot / "export_iplists.derived.csv",
        )
        if path.is_file()
    ]
    if not references:
        raise ValueError(
            "IP List snapshot export is missing: expected export_iplists.csv "
            "or export_iplists.derived.csv"
        )
    loaded_references: List[Path] = []
    skipped_references: List[Tuple[Path, str]] = []
    ip_lists = _load_ip_lists(
        references, loaded_paths=loaded_references, skipped_paths=skipped_references,
    )
    if not loaded_references:
        details = "; ".join(
            f"{path}: {reason}" for path, reason in skipped_references
        )
        raise ValueError(
            "No readable IP List snapshot export is available"
            + (f" ({details})" if details else "")
        )

    result_rows: List[Dict[str, object]] = []
    for input_row in input_rows:
        searched = _input_value(input_row)
        try:
            query = _parse_query(searched)
        except ValueError:
            result_rows.append({
                **input_row, "searched_ip_or_subnet": searched,
                "normalized_ip_or_subnet": "", "match_status": "INVALID_INPUT",
                "iplist_name": "", "matched_iplist_members": "",
                "iplist_reference": "",
            })
            continue
        matches = _matching_ip_lists(query, ip_lists)
        if not matches:
            result_rows.append({
                **input_row, "searched_ip_or_subnet": searched,
                "normalized_ip_or_subnet": _format_query(searched, query),
                "match_status": "NO_MATCH", "iplist_name": "",
                "matched_iplist_members": "", "iplist_reference": "",
            })
            continue
        for match in matches:
            result_rows.append({
                **input_row, "searched_ip_or_subnet": searched,
                "normalized_ip_or_subnet": _format_query(searched, query),
                "match_status": "MATCHED", "iplist_name": match["name"],
                "matched_iplist_members": "\n".join(match["members"]),
                "iplist_reference": ";".join(match["references"]),
            })

    from openpyxl import Workbook
    workbook = Workbook()
    workbook.remove(workbook.active)
    _write_sheet(workbook, "IP List Matches", result_rows)
    _format_results_sheet(workbook["IP List Matches"])
    _write_sheet(workbook, "Metadata", [{
        "input": str(input_path),
        "input columns": ";".join(input_columns),
        "IP List references": ";".join(str(path) for path in loaded_references),
        "unreadable references skipped": ";".join(
            f"{path} ({reason})" for path, reason in skipped_references
        ),
        "Any members ignored": "0.0.0.0/0;::/0",
        "generated at UTC": datetime.now(timezone.utc).isoformat(),
    }])
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    workbook.save(temporary)
    temporary.replace(output)
    return output


def _format_results_sheet(sheet: object) -> None:
    """Apply report-specific wrapping and status highlighting."""
    from openpyxl.styles import Alignment, Font, PatternFill

    headers = {str(cell.value): cell.column for cell in sheet[1]}
    wrapped_columns = {
        headers[name] for name in ("matched_iplist_members",)
        if name in headers
    }
    for row_number in range(2, sheet.max_row + 1):
        for column_number in range(1, sheet.max_column + 1):
            cell = sheet.cell(row_number, column_number)
            cell.alignment = Alignment(
                vertical="top", wrap_text=column_number in wrapped_columns,
            )
        status = sheet.cell(row_number, headers["match_status"])
        status.font = Font(bold=True)
        status.fill = PatternFill(
            fill_type="solid",
            fgColor={
                "MATCHED": "C6E0B4",
                "NO_MATCH": "FFF2CC",
                "INVALID_INPUT": "F4CCCC",
            }.get(str(status.value), "FFFFFF"),
        )
        member_lines = str(
            sheet.cell(row_number, headers["matched_iplist_members"]).value or ""
        ).count("\n") + 1
        sheet.row_dimensions[row_number].height = min(max(15, 15 * member_lines), 120)


def _load_search_input(path: Path) -> Tuple[List[Dict[str, str]], List[str]]:
    if not path.is_file():
        raise ValueError(f"IP List search input file not found: {path}")
    if path.suffix.casefold() == ".xlsx":
        if importlib.util.find_spec("openpyxl") is None:
            raise RuntimeError("openpyxl is required to read an XLSX IP List search input")
        from openpyxl import load_workbook
        workbook = load_workbook(path, read_only=True, data_only=True)
        iterator = workbook.active.iter_rows(values_only=True)
        headers = [str(value or "").strip() for value in next(iterator, ())]
        rows = [
            {header: str(row[index] or "").strip() if index < len(row) else ""
             for index, header in enumerate(headers)}
            for row in iterator if any(str(value or "").strip() for value in row)
        ]
        workbook.close()
    elif path.suffix.casefold() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            raw_headers = list(reader.fieldnames or [])
            headers = [str(value or "").strip() for value in raw_headers]
            rows = [{
                header: str(row.get(raw_header, "") or "").strip()
                for raw_header, header in zip(raw_headers, headers)
            } for row in reader]
    else:
        raise ValueError("IP List search input must be a CSV or XLSX file")
    if not headers or any(not header for header in headers):
        raise ValueError("IP List search input contains an empty column header")
    if len({header.casefold() for header in headers}) != len(headers):
        raise ValueError("IP List search input contains duplicate column headers")
    available = {header.casefold() for header in headers}
    if not available.intersection(INPUT_COLUMNS):
        raise ValueError("IP List search input must contain an ip, subnet, or ip/subnet column")
    rows = [row for row in rows if any(str(value).strip() for value in row.values())]
    if not rows:
        raise ValueError("IP List search input contains no data rows")
    return rows, headers


def _input_value(row: Mapping[str, object]) -> str:
    values = {key.casefold(): str(value or "").strip() for key, value in row.items()}
    return next((values[name] for name in INPUT_COLUMNS if values.get(name)), "")


def _parse_query(value: str) -> AddressSpan:
    if not value.strip():
        raise ValueError("empty IP/subnet")
    try:
        if "/" in value:
            network = ipaddress.ip_network(value.strip(), strict=False)
            return network.version, int(network.network_address), int(network.broadcast_address)
        address = ipaddress.ip_address(value.strip())
        return address.version, int(address), int(address)
    except ValueError as exc:
        raise ValueError(f"invalid IP/subnet: {value}") from exc


def _member_span(value: str) -> Optional[AddressSpan]:
    cleaned = normalize_ip_list_member(value)
    if not cleaned:
        return None
    try:
        if "/" in cleaned:
            network = ipaddress.ip_network(cleaned, strict=False)
            return network.version, int(network.network_address), int(network.broadcast_address)
        start_text, separator, end_text = cleaned.partition("-")
        start = ipaddress.ip_address(start_text.strip())
        end = ipaddress.ip_address(end_text.strip()) if separator else start
        if start.version != end.version or int(start) > int(end):
            return None
        return start.version, int(start), int(end)
    except ValueError:
        return None


def _is_any_span(span: AddressSpan) -> bool:
    version, start, end = span
    return start == 0 and end == (2 ** (32 if version == 4 else 128)) - 1


def _load_ip_lists(
    paths: Sequence[Path], loaded_paths: Optional[List[Path]] = None,
    skipped_paths: Optional[List[Tuple[Path, str]]] = None,
) -> List[Dict[str, object]]:
    """Load every readable reference, tolerating an inaccessible alternative.

    The complete and derived exports are alternative sources for this report.
    Production snapshots can contain one file with stricter ownership, so a
    permission problem on one export must not hide usable data from the other.
    """
    combined: Dict[str, Dict[str, object]] = {}
    for path in paths:
        try:
            rows = list(read_rows(path, IPLIST_FIELDS))
        except OSError as exc:
            if skipped_paths is not None:
                skipped_paths.append((path, str(exc)))
            continue
        if loaded_paths is not None:
            loaded_paths.append(path)
        for row in rows:
            name = row["name"].strip()
            if not name:
                continue
            entry = combined.setdefault(name.casefold(), {
                "name": name, "members": [], "references": [],
            })
            if path.name not in entry["references"]:
                entry["references"].append(path.name)
            for raw_member in row["include"].split(";"):
                member = normalize_ip_list_member(raw_member)
                span = _member_span(member)
                if span is None or _is_any_span(span):
                    continue
                identity = (member.casefold(), span)
                if identity not in [(item[0].casefold(), item[1]) for item in entry["members"]]:
                    entry["members"].append((member, span))
    return list(combined.values())


def _matching_ip_lists(
    query: AddressSpan, ip_lists: Sequence[Mapping[str, object]],
) -> List[Dict[str, object]]:
    matches: List[Dict[str, object]] = []
    query_version, query_start, query_end = query
    for ip_list in ip_lists:
        members = [
            member for member, span in ip_list["members"]
            if span[0] == query_version and span[1] <= query_start and query_end <= span[2]
        ]
        if members:
            matches.append({
                "name": ip_list["name"], "members": members,
                "references": list(ip_list["references"]),
            })
    return sorted(matches, key=lambda row: str(row["name"]).casefold())


def _format_query(raw: str, span: AddressSpan) -> str:
    version, start, end = span
    if start == end:
        return str(ipaddress.ip_address(start))
    network = ipaddress.ip_network(raw.strip(), strict=False)
    return str(network) if network.version == version else raw.strip()
