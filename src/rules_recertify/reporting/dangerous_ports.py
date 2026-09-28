"""Configured dangerous-port catalogues and rule intersection helpers."""
from __future__ import annotations

import re
from typing import Dict, List, Sequence, Tuple

PORT_CATALOGS: Dict[str, Tuple[str, ...]] = {
    "PORTS_TO_CONTROL": (
        "TCP/22", "TCP/135", "TCP/137-138", "TCP/389", "TCP/445",
        "TCP/3268", "TCP/3389", "UDP/69", "UDP/161",
    ),
    "PORTS_TO_ERADICATE": (
        "TCP/13", "TCP/19", "TCP/21", "TCP/23", "TCP/37", "TCP/139",
        "UDP/177", "TCP/512", "TCP/513", "TCP/514", "UDP/1701",
        "TCP/1723", "TCP/5900-5906", "TCP/6000-6063",
    ),
    "PORTS_ADMIN": (
        "TCP/12200-12220", "TCP/1521-1569", "UDP/1434", "TCP/1435",
        "TCP/12400", "TCP/1434", "TCP/14001", "TCP/11020", "TCP/22",
        "TCP/33089", "TCP/3389",
    ),
}


def dangerous_ports(services: str, selected_catalogs: Sequence[str]) -> str:
    """Return dangerous protocol/port intersections in catalogue order."""
    allowed = _service_intervals(services)
    matches: List[str] = []
    for catalog in selected_catalogs:
        for definition in PORT_CATALOGS[catalog]:
            protocol, start, end = _catalog_interval(definition)
            for allowed_start, allowed_end in allowed.get(protocol, ()):
                overlap_start = max(start, allowed_start)
                overlap_end = min(end, allowed_end)
                if overlap_start <= overlap_end:
                    rendered = _render(protocol, overlap_start, overlap_end)
                    if rendered not in matches:
                        matches.append(rendered)
    return ", ".join(matches)


def _service_intervals(services: str) -> Dict[str, List[Tuple[int, int]]]:
    if re.search(r"\bAll Services\b", services, re.I):
        return {"TCP": [(0, 65535)], "UDP": [(0, 65535)]}
    intervals: Dict[str, List[Tuple[int, int]]] = {"TCP": [], "UDP": []}
    patterns = (
        r"\b(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s+(TCP|UDP)\b",
        r"\b(TCP|UDP)/(\d{1,5})(?:\s*-\s*(\d{1,5}))?\b",
    )
    for pattern_number, pattern in enumerate(patterns):
        for match in re.finditer(pattern, services, re.I):
            if pattern_number == 0:
                start, end, protocol = int(match.group(1)), int(match.group(2) or match.group(1)), match.group(3)
            else:
                protocol, start, end = match.group(1), int(match.group(2)), int(match.group(3) or match.group(2))
            if 0 <= start <= end <= 65535:
                intervals[protocol.upper()].append((start, end))
    return intervals


def _catalog_interval(value: str) -> Tuple[str, int, int]:
    protocol, ports = value.split("/", 1)
    start_text, separator, end_text = ports.partition("-")
    start = int(start_text)
    return protocol, start, int(end_text) if separator else start


def _render(protocol: str, start: int, end: int) -> str:
    return f"{protocol}/{start}" if start == end else f"{protocol}/{start}-{end}"
