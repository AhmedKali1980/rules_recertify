"""CSV consolidation and deterministic workload/IP-list enrichment."""
from __future__ import annotations

import csv
import ipaddress
import os
import re
import tempfile
from pathlib import Path
from typing import Iterable, List, Mapping, Sequence, Tuple

WORKLOAD_REQUIRED = ("hostname", "interfaces", "ip_with_default_gw", "os_id", "managed")
IPLIST_REQUIRED = ("name", "include")
IPV4_RE = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![0-9.])")


class ExportContractError(ValueError):
    """An input export does not satisfy the expected CSV contract."""


def parse_ipv4_interfaces(value: str) -> List[str]:
    """Return valid IPv4 interface addresses, stably deduplicated."""
    result: List[str] = []
    for match in IPV4_RE.finditer(value or ""):
        try:
            parsed = ipaddress.ip_interface(match.group()).ip
        except ValueError:
            continue
        if parsed.version == 4 and str(parsed) not in result:
            result.append(str(parsed))
    return result


def parse_subnets(value: str) -> List[ipaddress.IPv4Network]:
    result: List[ipaddress.IPv4Network] = []
    for item in (value or "").split(";"):
        candidate = item.partition("#")[0].strip()
        if not candidate:
            continue
        try:
            network = ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            continue
        if network.version == 4:
            result.append(network)
    return result


def short_hostname(value: str) -> str:
    value = (value or "").strip()
    return value.split(".", 1)[0].upper() if value else ""


def ocs_name_from_ip(row: Mapping[str, str], interface_ips: Sequence[str] | None = None) -> str:
    if row.get("managed", "").strip().upper() == "TRUE":
        address = row.get("ip_with_default_gw", "").strip()
        if not address:
            return ""
        rendered = address.replace(".", "-")
        return rendered if "win" in row.get("os_id", "").lower() else "IP-" + rendered
    if row.get("external_data_set", "").strip().upper() == "AUTOMATION GEN2":
        addresses = list(interface_ips) if interface_ips is not None else parse_ipv4_interfaces(row.get("interfaces", ""))
        return "IP-" + addresses[0].replace(".", "-") if addresses else ""
    return ""


def prepare_ip_lists(rows: Iterable[Mapping[str, str]]) -> List[Tuple[str, ipaddress.IPv4Network]]:
    prepared: List[Tuple[str, ipaddress.IPv4Network]] = []
    for row in rows:
        name = row.get("name", "")
        if name.startswith("NZ3_"):
            prepared.extend((name, network) for network in parse_subnets(row.get("include", "")))
    return prepared


def first_ip_list_match(addresses: Iterable[str], prepared: Iterable[Tuple[str, ipaddress.IPv4Network]]) -> Tuple[str, str]:
    members = list(prepared)
    for address in addresses:
        parsed = ipaddress.ip_address(address)
        for name, network in members:
            if parsed in network:
                return name, str(network)
    return "", ""


def _read(path: Path, required: Sequence[str]) -> Tuple[List[str], List[dict]]:
    if not path.is_file() or path.stat().st_size == 0:
        raise ExportContractError(f"CSV file is missing or empty: {path}")
    with path.open(newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        header = reader.fieldnames
        if not header:
            raise ExportContractError(f"CSV file has no header: {path}")
        missing = [column for column in required if column not in header]
        if missing:
            raise ExportContractError(f"Missing required columns in {path}: {', '.join(missing)}")
        return list(header), list(reader)


def _atomic_write(path: Path, header: Sequence[str], rows: Iterable[Mapping[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=header, extrasaction="ignore")
            writer.writeheader(); writer.writerows(rows)
        os.replace(temporary, path)
    except BaseException:
        try: os.unlink(temporary)
        except FileNotFoundError: pass
        raise


def merge_workloads(primary: Path, additional: Path) -> int:
    header, rows = _read(primary, ())
    other_header, other_rows = _read(additional, ())
    if header != other_header:
        raise ExportContractError("Workload CSV headers are not strictly identical")
    additions = [row for row in other_rows if any((value or "").strip() for value in row.values())]
    _atomic_write(primary, header, [*rows, *additions])
    return len(additions)


def derive_exports(raw_dir: Path) -> Tuple[Path, Path]:
    workload_header, workloads = _read(raw_dir / "export_wkld.csv", WORKLOAD_REQUIRED)
    _, ip_lists = _read(raw_dir / "export_iplists.csv", IPLIST_REQUIRED)
    filtered = [row for row in ip_lists if row.get("name", "").startswith("NZ3_")]
    ip_output = raw_dir / "export_iplists.derived.csv"
    _atomic_write(ip_output, ["name", "include"], ({"name": r["name"], "include": r["include"]} for r in filtered))
    prepared = prepare_ip_lists(filtered)
    output_header = list(workload_header)
    output_header.insert(output_header.index("hostname") + 1, "short_hostname")
    output_header.extend(("ocs_name_from_IP", "IPLIST", "SUBNET"))
    enriched = []
    for row in workloads:
        addresses = parse_ipv4_interfaces(row.get("interfaces", ""))
        ip_list, subnet = first_ip_list_match(addresses, prepared)
        item = dict(row)
        item["short_hostname"] = short_hostname(row.get("hostname", ""))
        item["ocs_name_from_IP"] = ocs_name_from_ip(row, addresses)
        item["IPLIST"], item["SUBNET"] = ip_list, subnet
        enriched.append(item)
    workload_output = raw_dir / "export_wkld.derived.csv"
    _atomic_write(workload_output, output_header, enriched)
    return workload_output, ip_output
