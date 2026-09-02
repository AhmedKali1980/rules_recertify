from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple


class OversizedRulesetError(ValueError):
    pass


@dataclass(frozen=True)
class RulesetCount:
    href: str
    count: int


@dataclass(frozen=True)
class ExcludedRuleset:
    href: str
    count: int
    scope: str
    reason: str


_APPLICATION_SCOPE = re.compile(r"^app:([^;]+);env:([^;]+)$")


def count_rules_by_ruleset(rows: Iterable[Mapping[str, str]]) -> List[RulesetCount]:
    counts: Dict[str, int] = {}
    for row in rows:
        href = row.get("ruleset_href", "").strip()
        if not href:
            raise ValueError("Rule inventory row has no ruleset_href")
        counts[href] = counts.get(href, 0) + 1
    return [RulesetCount(href, count) for href, count in sorted(counts.items())]


def select_application_scoped_rulesets(
    rows: Iterable[Mapping[str, str]], application_labels: Iterable[str]
) -> Tuple[List[RulesetCount], List[ExcludedRuleset]]:
    """Select whole rulesets with a strict app/value;env/value scope."""
    known_apps = {value.strip() for value in application_labels if value.strip()}
    rulesets: Dict[str, List[str]] = {}
    for row in rows:
        href = row.get("ruleset_href", "").strip()
        if not href:
            raise ValueError("Rule inventory row has no ruleset_href")
        rulesets.setdefault(href, []).append(row.get("ruleset_scope", "").strip())

    eligible: List[RulesetCount] = []
    excluded: List[ExcludedRuleset] = []
    for href, scopes in sorted(rulesets.items()):
        unique_scopes = set(scopes)
        scope = scopes[0] if len(unique_scopes) == 1 else " | ".join(sorted(unique_scopes))
        reason = ""
        if len(unique_scopes) != 1:
            reason = "INCONSISTENT_SCOPE"
        elif not scope:
            reason = "EMPTY_SCOPE"
        else:
            match = _APPLICATION_SCOPE.fullmatch(scope)
            if match is None:
                reason = "INVALID_SCOPE_FORMAT"
            elif match.group(1).strip() not in known_apps:
                reason = "UNKNOWN_APPLICATION_LABEL"
        if reason:
            excluded.append(ExcludedRuleset(href, len(scopes), scope, reason))
        else:
            eligible.append(RulesetCount(href, len(scopes)))
    return eligible, excluded


def bin_pack_rulesets(items: Sequence[RulesetCount], limit: int = 500) -> List[List[RulesetCount]]:
    if limit < 1:
        raise ValueError("limit must be positive")
    oversized = [item for item in items if item.count > limit]
    if oversized:
        item = oversized[0]
        raise OversizedRulesetError(f"Ruleset {item.href} has {item.count} rules, above batch limit {limit}")
    bins: List[Tuple[int, List[RulesetCount]]] = []
    for item in sorted(items, key=lambda value: (-value.count, value.href)):
        for index, (used, values) in enumerate(bins):
            if used + item.count <= limit:
                values.append(item)
                bins[index] = (used + item.count, values)
                break
        else:
            bins.append((item.count, [item]))
    return [values for _, values in bins]


def partition_and_pack_rulesets(
    items: Sequence[RulesetCount], limit: int
) -> Tuple[List[List[RulesetCount]], List[RulesetCount]]:
    """Pack eligible whole rulesets and return oversized ones for audit."""
    eligible = [item for item in items if item.count <= limit]
    oversized = sorted(
        (item for item in items if item.count > limit),
        key=lambda item: item.href,
    )
    return bin_pack_rulesets(eligible, limit), oversized
