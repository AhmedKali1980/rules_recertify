"""CSV adapters tolerant of comma/semicolon exports and BOMs."""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Tuple


class CsvContractError(ValueError):
    pass


# Workloader query bodies and expanded service definitions can exceed Python's
# conservative 128 KiB CSV field default. Keep a finite ceiling so malformed
# inputs cannot request unbounded memory while accepting realistic exports.
MAX_CSV_FIELD_SIZE = 16 * 1024 * 1024


def detect_delimiter(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;").delimiter
    except csv.Error:
        first = sample.splitlines()[0] if sample else ""
        return ";" if first.count(";") > first.count(",") else ","


def read_rows(path: Path, required: Iterable[str] = ()) -> Iterator[Dict[str, str]]:
    csv.field_size_limit(MAX_CSV_FIELD_SIZE)
    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        sample = handle.read(8192)
        handle.seek(0)
        reader = csv.DictReader(handle, delimiter=detect_delimiter(sample))
        headers = reader.fieldnames or []
        missing = set(required) - set(headers)
        if missing:
            raise CsvContractError(f"{path}: missing columns: {', '.join(sorted(missing))}")
        for number, row in enumerate(reader, 2):
            if None in row:
                raise CsvContractError(f"{path}:{number}: excess unquoted fields")
            yield {str(key): (value or "").strip() for key, value in row.items()}


def write_rows(path: Path, headers: List[str], rows: Iterable[Mapping[str, object]], delimiter: str = ",") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headers, delimiter=delimiter, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)
    temporary.replace(path)


def parse_bool(value: str) -> Optional[bool]:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes", "y"}:
        return True
    if normalized in {"false", "0", "no", "n"}:
        return False
    if not normalized:
        return None
    raise CsvContractError(f"Invalid boolean: {value!r}")


_PORT = re.compile(r"^\s*(\d+)\s+(TCP|UDP)\s+\((\d+)\)\s*$", re.I)
_PROTOCOL = re.compile(r"^\s*0\s+(ICMP|IGMP)\s+\((\d+)\)\s*$", re.I)
_MORE = re.compile(r"^\s*\+\s*(\d+)\s+more\s*$", re.I)


def parse_flows_by_port(value: str) -> Tuple[List[Dict[str, object]], bool, int]:
    observations: List[Dict[str, object]] = []
    complete, omitted = True, 0
    if not value.strip():
        return observations, complete, omitted
    for item in value.split(";"):
        item = item.strip()
        if not item:
            continue
        match = _MORE.match(item)
        if match:
            complete, omitted = False, int(match.group(1))
            continue
        match = _PORT.match(item)
        if match:
            observations.append({"port": int(match.group(1)), "protocol": match.group(2).upper(), "flows": int(match.group(3))})
            continue
        match = _PROTOCOL.match(item)
        if match:
            observations.append({"port": None, "protocol": match.group(1).upper(), "flows": int(match.group(2))})
            continue
        raise CsvContractError(f"Unsupported flows_by_port item: {item!r}")
    return observations, complete, omitted


def query_window(query_body: str) -> Tuple[str, str]:
    try:
        body = json.loads(query_body)
        return str(body["start_date"]), str(body["end_date"])
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise CsvContractError("query_body does not contain valid start_date/end_date") from exc
