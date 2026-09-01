from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple


class OversizedRulesetError(ValueError):
    pass


@dataclass(frozen=True)
class RulesetCount:
    href: str
    count: int


def count_rules_by_ruleset(rows: Iterable[Mapping[str, str]]) -> List[RulesetCount]:
    counts: Dict[str, int] = {}
    for row in rows:
        href = row.get("ruleset_href", "").strip()
        if not href:
            raise ValueError("Rule inventory row has no ruleset_href")
        counts[href] = counts.get(href, 0) + 1
    return [RulesetCount(href, count) for href, count in sorted(counts.items())]


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
