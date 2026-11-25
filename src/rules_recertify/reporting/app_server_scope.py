"""Managed workload row counts indexed by application, environment and role."""
from __future__ import annotations

import csv
import logging
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

from ..workloader.csvio import parse_bool, read_rows


IMPACTED_APP_SERVERS = "Number of impacted App servers (scope)"
LOG = logging.getLogger(__name__)


def normalized_label(value: str, dimension: str) -> str:
    value = re.sub(r"\s*\(/[^)]*\)\s*$", "", value).strip()
    prefix, separator, name = value.partition(":")
    if separator and prefix.strip().casefold() == dimension:
        value = name.strip()
    return value.casefold()


@dataclass(frozen=True)
class RoleSelection:
    included: Optional[FrozenSet[str]] = None
    excluded: FrozenSet[str] = frozenset()

    def matches(self, role: str) -> bool:
        return (self.included is None or role in self.included) and role not in self.excluded


class AppServerScopeIndex:
    def __init__(self, counts: Mapping[Tuple[str, str], Counter[str]]):
        self.counts = counts
        self.cache: Dict[Tuple[FrozenSet[str], FrozenSet[str], Tuple[RoleSelection, ...]], int] = {}

    def count(self, apps: Iterable[str], envs: Iterable[str], selections: Sequence[RoleSelection]) -> int:
        key = (frozenset(apps), frozenset(envs), tuple(selections))
        if key not in self.cache:
            self.cache[key] = sum(
                number for app in key[0] for env in key[1]
                for role, number in self.counts.get((app, env), {}).items()
                if any(selection.matches(role) for selection in selections)
            )
        return self.cache[key]


def load_app_server_scope_index(snapshot: Path) -> Optional[AppServerScopeIndex]:
    """Prefer the requested plural filename, with the deployed singular alias."""
    source = None
    try:
        source = next((snapshot / name for name in ("export_wklds.csv", "export_wkld.csv")
                       if (snapshot / name).is_file()), None)
        if source is None:
            LOG.warning("App server scope counts unavailable: no workload snapshot export")
            return None
        counts: Dict[Tuple[str, str], Counter[str]] = defaultdict(Counter)
        for row in read_rows(source, ("app", "env", "role", "managed")):
            if parse_bool(row["managed"]) is not True:
                continue
            app = normalized_label(row["app"], "app")
            env = normalized_label(row["env"], "env")
            if app and env:
                counts[(app, env)][normalized_label(row["role"], "role")] += 1
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        LOG.warning("App server scope counts unavailable from %s: %s", source or snapshot, exc)
        return None
    LOG.info("Using workload scope count reference: %s (%s managed rows)",
             source, sum(sum(roles.values()) for roles in counts.values()))
    return AppServerScopeIndex(counts)
