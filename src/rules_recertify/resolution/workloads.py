from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple

HOSTNAME_EMPTY = "[hostname_empty]"


def parse_interfaces(value: str) -> Tuple[List[str], List[str]]:
    addresses, warnings = [], []
    for raw in value.split(";"):
        item = raw.strip()
        if not item:
            continue
        if ":" not in item:
            warnings.append(f"Malformed interface entry: {item}")
            continue
        _, address = item.split(":", 1)
        address = address.strip()
        try:
            parsed = ipaddress.ip_interface(address)
        except ValueError:
            warnings.append(f"Malformed interface address: {address}")
            continue
        normalized = str(parsed.ip)
        if normalized not in addresses:
            addresses.append(normalized)
    return addresses, warnings


def select_addresses(row: Mapping[str, str]) -> Tuple[List[str], List[str]]:
    managed = row.get("managed", "").strip().lower() in {"true", "1", "yes"}
    if managed:
        value = row.get("ip_with_default_gw", "").strip()
        if not value:
            return [], ["Managed workload has no ip_with_default_gw"]
        try:
            return [str(ipaddress.ip_address(value))], []
        except ValueError:
            return [], [f"Invalid ip_with_default_gw: {value}"]
    return parse_interfaces(row.get("interfaces", ""))


def short_hostname(hostname: str) -> str:
    value = hostname.strip()
    return value.split(".", 1)[0] if value else HOSTNAME_EMPTY


def ocs_name_from_ip(address: str) -> str:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return ""
    return str(parsed).replace(".", "-") if parsed.version == 4 else ""


def matching_nz3(address: str, ip_lists: Iterable[Mapping[str, str]]) -> List[Tuple[str, str]]:
    parsed = ipaddress.ip_address(address)
    matches: List[Tuple[str, str]] = []
    for row in ip_lists:
        name, member = row.get("name", ""), row.get("include", row.get("member", ""))
        if not name.startswith("NZ3_"):
            continue
        try:
            network = ipaddress.ip_network(member, strict=False)
        except ValueError:
            continue
        value = (name, str(network))
        if parsed in network and value not in matches:
            matches.append(value)
    return sorted(matches)
