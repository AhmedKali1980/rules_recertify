from __future__ import annotations

import json
import importlib.util
import re
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Mapping, Sequence, Tuple

from ..history.database import Database
from ..history.metrics import summarize_usage


class ReportingDependencyError(RuntimeError):
    pass


def generate_workbook(db: Database, output_dir: Path, kear_id: str, logical_name: str,
                      application_labels: Sequence[str], environments: Sequence[str],
                      lookback_days: int, as_of: date) -> Path:
    scope_pairs = _scope_pairs(application_labels, environments)
    if not kear_id.strip():
        raise ValueError("kear_id must not be empty")
    if not logical_name.strip() or not scope_pairs:
        raise ValueError("logical name, application labels, and environment are required")
    if importlib.util.find_spec("openpyxl") is None:
        raise ReportingDependencyError("openpyxl is required for report generation; install the approved offline package")
    from openpyxl import Workbook
    kear = kear_id.lower()
    cutoff = (as_of - timedelta(days=lookback_days)).isoformat()
    with db.connect() as connection:
        rule_rows = [dict(row) for row in connection.execute("SELECT * FROM rules ORDER BY ruleset_name,rule_href")]
        selected = [row for row in rule_rows if _rule_matches(row, scope_pairs)]
        usage_by_rule: Dict[str, List[Mapping[str, object]]] = defaultdict(list)
        for row in connection.execute("SELECT * FROM usage_windows WHERE window_end>? AND window_start<? ORDER BY window_start", (cutoff, as_of.isoformat())):
            usage_by_rule[row["rule_href"]].append(dict(row))
        workloads = [dict(row) for row in connection.execute("SELECT * FROM workloads")]
        ip_lists = [dict(row) for row in connection.execute("SELECT * FROM ip_lists ORDER BY rowid")]
        quality = [dict(row) for row in connection.execute("SELECT * FROM data_quality ORDER BY category,object_id")]
    raw_rows, expanded_rows, usage_rows = [], [], []
    for rule in selected:
        raw = json.loads(rule["raw_json"])
        rule_pairs = _matching_rule_pairs(raw, scope_pairs)
        modules = list(dict.fromkeys(label for label, _ in rule_pairs))
        rule_environments = list(dict.fromkeys(environment for _, environment in rule_pairs))
        metrics = summarize_usage(usage_by_rule[rule["rule_href"]], as_of, lookback_days)
        base = {
            "KEAR ID": kear, "Logical Application": logical_name, "Module": "\n".join(modules),
            "Environment": "\n".join(rule_environments), "Ruleset": rule["ruleset_name"], "Rule Href": rule["rule_href"],
            "Ruleset Enabled": _display_bool(rule["ruleset_enabled"]), "Rule Enabled": _display_bool(rule["rule_enabled"]),
            "Rule Type": rule["rule_type"], "Source": rule["source_text"], "Destination": rule["destination_text"],
            "Service Name / Definition": rule["services"], "Description": rule["rule_description"],
            "Hit Status": metrics["hit_status"], "Total Flows": metrics["total_flows"],
            "First Hit Window": _window(metrics["first_hit_window_start"], metrics["first_hit_window_end"]),
            "Last Hit Window": _window(metrics["last_hit_window_start"], metrics["last_hit_window_end"]),
            "Days Since Last Hit": metrics["days_since_last_hit"], "Coverage %": metrics["coverage_percent"],
        }
        raw_rows.append(base)
        expanded = dict(base)
        expanded_sources, source_addresses = _expand_side_details(raw, "src", workloads, rule_pairs, ip_lists)
        expanded_destinations, destination_addresses = _expand_side_details(raw, "dst", workloads, rule_pairs, ip_lists)
        expanded["Expanded Sources"] = expanded_sources
        expanded["Expanded Destinations"] = expanded_destinations
        expanded["nb_src_ips"] = len(source_addresses)
        expanded["nb_dst_ip"] = len(destination_addresses)
        expanded["nb_ports"] = _count_ports(str(rule["services"]))
        expanded_rows.append(expanded)
        for usage in usage_by_rule[rule["rule_href"]]:
            usage_rows.append({"KEAR ID": kear, "Rule Href": rule["rule_href"], "Window Start": usage["window_start"],
                               "Window End": usage["window_end"], "Status": usage["status"], "Flows": usage["flows"],
                               "Port Breakdown Complete": _display_bool(usage["port_breakdown_complete"]),
                               "Omitted Port Details": usage["port_details_omitted_count"]})
    workbook = Workbook(); workbook.remove(workbook.active)
    presentation = [{"Field": key, "Value": value} for key, value in (
        ("KEAR ID", kear), ("Logical Application", logical_name),
        ("Application Scopes", "\n".join(f"{app} / {env}" for app, env in scope_pairs)),
        ("As Of", as_of.isoformat()), ("Lookback Days", lookback_days),
        ("Rules", len(selected)), ("Generated At UTC", datetime.now(timezone.utc).isoformat()))]
    _sheet(workbook, "Presentation", presentation)
    _sheet(workbook, "Raw Rules", raw_rows)
    _sheet(workbook, "Expanded Rules", expanded_rows)
    _sheet(workbook, "Rule Usage", usage_rows)
    quality_rows = [{"KEAR ID": kear, **row} for row in quality]
    _sheet(workbook, "Data Quality", quality_rows)
    output_dir.mkdir(parents=True, exist_ok=True)
    safe_env = re.sub(r"[^A-Za-z0-9_.-]+", "_", "-".join(dict.fromkeys(env for _, env in scope_pairs)))
    target = output_dir / f"rules_recertify_{kear}_{safe_env}_{as_of.strftime('%Y%m%d')}.xlsx"
    temporary = target.with_suffix(".xlsx.tmp")
    workbook.save(temporary); temporary.replace(target)
    return target


def _scope_pairs(labels: Sequence[str], environments: Sequence[str]) -> List[Tuple[str, str]]:
    if isinstance(environments, str):
        environments = [environments]
    if len(labels) != len(environments):
        raise ValueError("application labels and environments must form one-to-one pairs")
    pairs = [(label.strip(), environment.strip()) for label, environment in zip(labels, environments)]
    if any(not label or not environment for label, environment in pairs):
        raise ValueError("application labels and environments must not be empty")
    return list(dict.fromkeys(pairs))


def _rule_matches(rule: Mapping[str, object], scope_pairs: Sequence[Tuple[str, str]]) -> bool:
    raw = json.loads(str(rule["raw_json"]))
    return bool(_matching_rule_pairs(raw, scope_pairs))


def _matching_rule_pairs(raw: Mapping[str, object], scope_pairs: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    scope_text = str(raw.get("ruleset_scope", "")).strip()
    if scope_text:
        scope = _scope_dimensions(scope_text)
        app, env = scope.get("app", ""), scope.get("env", "")
        if not app or not env:
            return []
        return [pair for pair in scope_pairs if pair[0].casefold() == app.casefold()
                and (env.casefold() == "null" or pair[1].casefold() == env.casefold())]
    matches: List[Tuple[str, str]] = []
    for pair in scope_pairs:
        if any(_side_matches_pair(raw, side, pair) for side in ("src", "dst")):
            matches.append(pair)
    return matches


def _side_matches_pair(raw: Mapping[str, object], side: str, pair: Tuple[str, str]) -> bool:
    labels = _label_dimensions(str(raw.get(f"{side}_labels", "")))
    apps, environments = labels.get("app", set()), labels.get("env", set())
    return pair[0].casefold() in apps and (not environments or pair[1].casefold() in environments)


def _contains_app(raw: Mapping[str, object], label: str) -> bool:
    needle = f"app:{label}".lower()
    fields = ("ruleset_scope", "src_labels", "dst_labels", "src_labels_exclusions", "dst_labels_exclusions")
    for field in fields:
        tokens = {token.strip().lower() for token in str(raw.get(field, "")).split(";")}
        if needle in tokens:
            return True
    return False


def _expand_side(raw: Mapping[str, object], side: str, workloads: Sequence[Mapping[str, object]],
                 environment: object, ip_lists: Sequence[Mapping[str, object]] = ()) -> str:
    return _expand_side_details(raw, side, workloads, environment, ip_lists)[0]


def _expand_side_details(raw: Mapping[str, object], side: str,
                         workloads: Sequence[Mapping[str, object]], environment: object,
                         ip_lists: Sequence[Mapping[str, object]] = ()) -> Tuple[str, List[str]]:
    scope_pairs = _coerce_expansion_pairs(raw, environment)
    values: List[str] = []
    addresses: List[str] = []
    if str(raw.get(f"{side}_all_workloads", "")).lower() == "true":
        scope = _scope_dimensions(str(raw.get("ruleset_scope", "")))
        if scope:
            scoped = _matching_workloads(
                workloads,
                lambda workload: _matches_scope(workload, scope, scope_pairs),
            )
            _append_workloads(values, addresses, scoped)
        else:
            values.append("All Workloads")
    ip_list_selectors = str(raw.get(f"{side}_iplists", ""))
    if ip_list_selectors:
        ip_list_entries, ip_list_members = _ip_list_entries(ip_list_selectors, ip_lists)
        values.extend(ip_list_entries); addresses.extend(ip_list_members)
    explicit = str(raw.get(f"{side}_workloads", ""));
    if explicit:
        selectors = {item.strip().casefold() for item in explicit.split(";") if item.strip()}
        matched = _matching_workloads(workloads, lambda workload: bool(selectors & _workload_identities(workload)))
        _append_workloads(values, addresses, matched)
    labels = str(raw.get(f"{side}_labels", ""))
    if labels:
        wanted = {part.strip().casefold() for part in labels.split(";") if part.strip()}
        matched = _matching_workloads(
            workloads,
            lambda workload: (
                _workload_matches_pairs(workload, scope_pairs)
                and wanted.issubset(_workload_tags(workload))
            ),
        )
        _append_workloads(values, addresses, matched)
    if "Any (0.0.0.0/0 and ::/0)" in ip_list_selectors:
        values.extend(["0.0.0.0/0", "::/0"]); addresses.extend(["0.0.0.0/0", "::/0"])
    return "\n".join(dict.fromkeys(values)), list(dict.fromkeys(addresses))


def _scope_dimensions(scope: str) -> Dict[str, str]:
    dimensions: Dict[str, str] = {}
    for component in scope.split(";"):
        key, separator, value = component.partition(":")
        if separator and key.strip() and value.strip():
            dimensions[key.strip().casefold()] = value.strip()
    return dimensions


def _label_dimensions(labels: str) -> Dict[str, set[str]]:
    dimensions: Dict[str, set[str]] = defaultdict(set)
    for component in labels.split(";"):
        key, separator, value = component.partition(":")
        if separator and key.strip() and value.strip():
            dimensions[key.strip().casefold()].add(value.strip().casefold())
    return dimensions


def _coerce_expansion_pairs(raw: Mapping[str, object], environment: object) -> List[Tuple[str, str]]:
    if isinstance(environment, str):
        apps = _label_dimensions(str(raw.get("ruleset_scope", ""))).get("app", set())
        if not apps:
            apps = _label_dimensions(str(raw.get("src_labels", "")) + ";" + str(raw.get("dst_labels", ""))).get("app", set())
        return [(app, environment) for app in apps] or [("", environment)]
    return [(str(app), str(env)) for app, env in environment]


def _workload_entries(
    workloads: Sequence[Mapping[str, object]],
    predicate: Callable[[Mapping[str, object]], bool],
) -> List[str]:
    entries: List[str] = []
    for workload in workloads:
        if not predicate(workload):
            continue
        display_name = str(workload.get("short_hostname") or workload.get("name") or "").strip()
        addresses = [str(address) for address in json.loads(str(workload.get("addresses_json", "[]"))) if address]
        if display_name and addresses:
            entries.append(f"{display_name} ({';'.join(addresses)})")
    return entries


def _matching_workloads(workloads: Sequence[Mapping[str, object]],
                        predicate: Callable[[Mapping[str, object]], bool]) -> List[Mapping[str, object]]:
    return [workload for workload in workloads if predicate(workload)]


def _append_workloads(values: List[str], addresses: List[str],
                      workloads: Sequence[Mapping[str, object]]) -> None:
    values.extend(_workload_entries(workloads, lambda workload: True))
    for workload in workloads:
        addresses.extend(
            str(address) for address in json.loads(str(workload.get("addresses_json", "[]"))) if address
        )


def _matches_scope(workload: Mapping[str, object], scope: Mapping[str, str],
                   scope_pairs: Sequence[Tuple[str, str]]) -> bool:
    for dimension in ("app", "env", "loc", "role"):
        wanted = scope.get(dimension)
        if not wanted:
            continue
        if dimension == "env" and wanted.casefold() == "null":
            if not _workload_matches_pairs(workload, scope_pairs):
                return False
            continue
        if str(workload.get(dimension, "")).casefold() != wanted.casefold():
            return False
    return True


def _workload_matches_pairs(workload: Mapping[str, object],
                            scope_pairs: Sequence[Tuple[str, str]]) -> bool:
    app = str(workload.get("app", "")).casefold()
    environment = str(workload.get("env", "")).casefold()
    return any((not pair_app or pair_app.casefold() == app) and pair_env.casefold() == environment
               for pair_app, pair_env in scope_pairs)


def _workload_tags(workload: Mapping[str, object]) -> set[str]:
    return {
        f"app:{workload.get('app', '')}".casefold(),
        f"env:{workload.get('env', '')}".casefold(),
        f"loc:{workload.get('loc', '')}".casefold(),
        f"role:{workload.get('role', '')}".casefold(),
    }


def _workload_identities(workload: Mapping[str, object]) -> set[str]:
    return {
        str(workload.get(field, "")).strip().casefold()
        for field in ("href", "hostname", "short_hostname", "name")
        if str(workload.get(field, "")).strip()
    }


def _ip_list_entries(selectors: str, ip_lists: Sequence[Mapping[str, object]]) -> Tuple[List[str], List[str]]:
    members: Dict[str, Tuple[str, List[str]]] = {}
    for row in ip_lists:
        name = str(row.get("name", "")).strip()
        for raw_member in str(row.get("member", row.get("include", ""))).split(";"):
            member = raw_member.partition("#")[0].strip()
            if name and member:
                key = name.casefold()
                members.setdefault(key, (name, []))[1].append(member)
    entries: List[str] = []
    addresses: List[str] = []
    for selector in (item.strip() for item in re.split(r"[;\n]", selectors) if item.strip()):
        selector_name = _ip_list_selector_name(selector)
        match = members.get(selector_name.casefold())
        if match:
            entries.append(f"IP List: {match[0]} ({';'.join(dict.fromkeys(match[1]))})")
            addresses.extend(match[1])
        elif selector_name != "Any (0.0.0.0/0 and ::/0)":
            entries.append(f"IP List: {selector_name} [unresolved]")
    return entries, addresses


def _ip_list_selector_name(selector: str) -> str:
    value = re.sub(r"^IP\s*List\s*:\s*", "", selector.strip(), flags=re.IGNORECASE)
    value = re.sub(r"\s*(?:[\[(]|:\s*)?/orgs/.*$", "", value)
    return value.strip()


def _count_ports(services: str) -> int:
    """Count distinct explicit TCP/UDP ports, expanding inclusive ranges."""
    ports = set()
    for match in re.finditer(r"\b(\d{1,5})(?:\s*-\s*(\d{1,5}))?\s+(TCP|UDP)\b", services, re.IGNORECASE):
        start = int(match.group(1)); end = int(match.group(2) or start)
        if 0 <= start <= end <= 65535:
            ports.update((match.group(3).upper(), port) for port in range(start, end + 1))
    return len(ports)


def _sheet(workbook: object, name: str, rows: List[Mapping[str, object]]) -> None:
    from openpyxl.styles import Alignment, Font, PatternFill
    sheet = workbook.create_sheet(name)
    headers = list(rows[0]) if rows else ["KEAR ID", "Message"]
    sheet.append(headers)
    for row in rows: sheet.append([row.get(header) for header in headers])
    for cell in sheet[1]:
        cell.fill = PatternFill("solid", fgColor="1F4E78"); cell.font = Font(color="FFFFFF", bold=True)
    sheet.freeze_panes = "A2"; sheet.auto_filter.ref = sheet.dimensions
    for column in sheet.columns:
        letter = column[0].column_letter
        width = min(60, max(12, max(len(str(cell.value or "")) for cell in column) + 2))
        sheet.column_dimensions[letter].width = width
        for cell in column: cell.alignment = Alignment(vertical="top", wrap_text=True)


def _display_bool(value: object) -> str:
    return "TRUE" if value == 1 else "FALSE" if value == 0 else ""


def _window(start: object, end: object) -> str:
    return f"{start} / {end}" if start and end else ""
