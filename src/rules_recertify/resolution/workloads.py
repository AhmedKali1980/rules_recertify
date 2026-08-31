from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple, Union

HOSTNAME_EMPTY = "[hostname_empty]"
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
PreparedNz3Member = Tuple[str, str, IPAddress, IPAddress]


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


def normalize_ip_list_member(value: str) -> str:
    """Remove an Illumio inline comment from an IP-list member.

    Illumio comments start with ``#``. Workloader 12 exports the same delimiter
    as ``$`` in some PCE data, so both representations are accepted.
    """
    normalized = value.strip()
    for delimiter in ("#", "$"):
        normalized = normalized.partition(delimiter)[0].strip()
    return normalized


def prepare_nz3_members(ip_lists: Iterable[Mapping[str, str]]) -> List[PreparedNz3Member]:
    prepared: List[PreparedNz3Member] = []
    for row in ip_lists:
        name = row.get("name", "")
        member = normalize_ip_list_member(row.get("include", row.get("member", "")))
        if not name.startswith("NZ3_"):
            continue
        try:
            network = ipaddress.ip_network(member, strict=False)
        except ValueError:
            start_text, separator, end_text = member.partition("-")
            if not separator:
                continue
            try:
                start = ipaddress.ip_address(start_text.strip())
                end = ipaddress.ip_address(end_text.strip())
            except ValueError:
                continue
            if start.version != end.version or int(start) > int(end):
                continue
            prepared.append((name, member, start, end))
        else:
            prepared.append((name, str(network), network.network_address, network.broadcast_address))
    return prepared


def matching_prepared_nz3(address: str, prepared: Iterable[PreparedNz3Member]) -> List[Tuple[str, str]]:
    parsed = ipaddress.ip_address(address)
    matches: List[Tuple[str, str]] = []
    for name, member, start, end in prepared:
        if parsed.version != start.version:
            continue
        value = (name, member)
        if int(start) <= int(parsed) <= int(end) and value not in matches:
            matches.append(value)
    return sorted(matches)


def matching_nz3(address: str, ip_lists: Iterable[Mapping[str, str]]) -> List[Tuple[str, str]]:
    return matching_prepared_nz3(address, prepare_nz3_members(ip_lists))
