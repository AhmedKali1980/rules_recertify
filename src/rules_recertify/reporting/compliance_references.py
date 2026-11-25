"""Per-workbook IP List and managed workload dictionaries for compliance."""
from __future__ import annotations

import csv
import logging
from collections import defaultdict
from pathlib import Path
from typing import Mapping, Sequence

from ..workloader.csvio import parse_bool, read_rows
from .app_server_scope import normalized_label
from .compliance_schema import REFERENCE_HEADERS


LOG = logging.getLogger(__name__)
DIMENSIONS = ("app", "env", "role", "loc")


def _read_reference(snapshot: Path, names: Sequence[str], required: Sequence[str]) -> list[dict[str, str]]:
    source = None
    try:
        source = next((snapshot / name for name in names if (snapshot / name).is_file()), None)
        if source is None:
            LOG.warning("Compliance reference unavailable: %s", snapshot / names[0])
            return []
        return list(read_rows(source, required))
    except (OSError, ValueError, UnicodeError, csv.Error) as exc:
        LOG.warning("Compliance reference unavailable from %s: %s", source or snapshot / names[0], exc)
        return []


class ComplianceReferences:
    def __init__(self, snapshot: Path, rules: Sequence[Mapping[str, str]],
                 group_index: Mapping[str, Mapping[str, object]], enabled: Sequence[str]):
        self.rules: dict[str, list[Mapping[str, str]]] = defaultdict(list)
        for rule in rules:
            self.rules[rule["rule_href"]].append(rule)
        self.groups = group_index
        self.enabled = set(enabled)
        self.iplists = _read_reference(snapshot, ("export_iplists.csv",), ("name", "include")) if "iplists" in enabled else []
        self.workloads = []
        if "workloads" in enabled:
            rows = _read_reference(snapshot, ("export_wkld.csv", "export_wklds.csv"), ("app", "env", "role", "managed"))
            try:
                self.workloads = [row for row in rows if parse_bool(row["managed"]) is True]
            except ValueError as exc:
                LOG.warning("Compliance workload reference unavailable: %s", exc)
        self.index: dict[str, dict[str, set[int]]] = {name: defaultdict(set) for name in DIMENSIONS}
        self.names: dict[str, set[int]] = defaultdict(set)
        for number, row in enumerate(self.workloads):
            for dimension in DIMENSIONS:
                self.index[dimension][normalized_label(row.get(dimension, ""), dimension)].add(number)
            for name in ("name", "hostname", "href"):
                if row.get(name):
                    self.names[row[name].casefold()].add(number)
        self.all_workloads = set(range(len(self.workloads)))
        self.rule_cache: dict[tuple[tuple[str, str], ...], set[int]] = {}

    def _workload_ids(self, rule: Mapping[str, str]) -> set[int]:
        # Import at evaluation time: compliance owns the shared policy selectors.
        from .compliance import _parts, _scope_server_values
        fields = ("ruleset_scope", "unscoped_consumers", *(f"{prefix}_{suffix}" for prefix in ("src", "dst")
                  for suffix in ("labels", "label_groups", "labels_exclusions", "label_groups_exclusions",
                                 "all_workloads", "workloads")))
        key = tuple((name, rule.get(name, "")) for name in fields)
        if key in self.rule_cache:
            return self.rule_cache[key]
        result: set[int] = set()
        for prefix in ("src", "dst"):
            for name in _parts(rule.get(f"{prefix}_workloads", "")):
                clean = normalized_label(name, "workload")
                result.update(self.names.get(clean, set()))
            labels = rule.get(f"{prefix}_labels", "")
            groups = rule.get(f"{prefix}_label_groups", "")
            excluded_labels = rule.get(f"{prefix}_labels_exclusions", "")
            excluded_groups = rule.get(f"{prefix}_label_groups_exclusions", "")
            all_workloads = parse_bool(rule.get(f"{prefix}_all_workloads", "")) is True
            if not (labels or groups or excluded_labels or excluded_groups or all_workloads):
                continue
            scope = "" if prefix == "src" and parse_bool(rule.get("unscoped_consumers", "")) is True else rule.get("ruleset_scope", "")
            selected = None
            for dimension in DIMENSIONS:
                included = _scope_server_values(scope if all_workloads else labels,
                                               "" if all_workloads else groups, dimension, self.groups)
                if (all_workloads and included is not None and not included[1]
                        and dimension in ("app", "env") and not rule.get("ruleset_scope", "").strip()):
                    included = _scope_server_values(labels, groups, dimension, self.groups)
                excluded = _scope_server_values(excluded_labels, excluded_groups, dimension, self.groups)
                if included is None or excluded is None:
                    selected = set()
                    LOG.warning("Unresolved %s workload selector in %s (%s)", dimension, rule["rule_href"], prefix)
                    break
                if not all_workloads and not included[1]:
                    inherited = _scope_server_values(scope, "", dimension, self.groups)
                    if inherited is None:
                        selected = set()
                        break
                    included = inherited
                if dimension == "app" and prefix == "src" and parse_bool(rule.get("unscoped_consumers", "")) is False:
                    scope_apps = _scope_server_values(scope, "", "app", self.groups)
                    if scope_apps is None:
                        selected = set()
                        break
                    if scope_apps[1]:
                        included = (included[0] & scope_apps[0] if included[1] else scope_apps[0], True)
                if included[1]:
                    candidates: set[int] = set()
                    for value in included[0]:
                        candidates.update(self.index[dimension].get(value, set()))
                    selected = candidates if selected is None else selected.intersection(candidates)
                for value in excluded[0]:
                    if selected is None:
                        selected = self.all_workloads.copy()
                    selected.difference_update(self.index[dimension].get(value, set()))
            result.update(self.all_workloads if selected is None else selected)
        self.rule_cache[key] = result
        return result

    def for_rows(self, rows: Sequence[Mapping[str, object]]) -> dict[str, list[dict[str, str]]]:
        from .compliance import _iplist_names
        rules = {tuple(sorted(rule.items())): rule for row in rows if row.get("Match status") == "MATCHED"
                 for rule in self.rules.get(str(row.get("rule_href", "")), [])}
        used_ip_lists = {name.casefold(): name for rule in rules.values() for prefix in ("src", "dst")
                         for name in _iplist_names(rule.get(f"{prefix}_iplists", ""))} if "iplists" in self.enabled else {}
        ip_rows = [{name: row.get(name, "") for name in REFERENCE_HEADERS["iplists"]}
                   for row in self.iplists if row["name"].casefold() in used_ip_lists]
        found = {row["name"].casefold() for row in ip_rows}
        for name in sorted(used_ip_lists.keys() - found):
            LOG.warning("IP List missing from compliance reference: %s", used_ip_lists[name])
            ip_rows.append({"name": used_ip_lists[name], "include": "", "exclude": "", "fqdns": ""})
        ids: set[int] = set()
        if self.workloads:
            for rule in rules.values():
                ids.update(self._workload_ids(rule))
        workload_rows = []
        for number in sorted(ids):
            row = self.workloads[number]
            workload_rows.append({**{name: row.get(name, "") for name in REFERENCE_HEADERS["workloads"]},
                                  "OS": row.get("OS") or row.get("os") or row.get("os_id", "")})
        return {"iplists": ip_rows, "workloads": workload_rows}
