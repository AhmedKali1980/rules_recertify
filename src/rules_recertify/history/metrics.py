from __future__ import annotations

from datetime import date, datetime, timedelta
from typing import Dict, Iterable, Mapping, Optional


def summarize_usage(rows: Iterable[Mapping[str, object]], as_of: date, lookback_days: int) -> Dict[str, object]:
    values = list(rows)
    completed = [row for row in values if str(row.get("status", "")).lower() == "completed"]
    positives = [row for row in completed if row.get("flows") is not None and int(row["flows"]) > 0]
    expected = lookback_days
    coverage_start = as_of - timedelta(days=lookback_days)
    intervals = sorted(
        (max(coverage_start, _date(row["window_start"])), min(as_of, _date(row["window_end"])))
        for row in completed
    )
    merged = []
    for start, end in intervals:
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    covered = sum((end - start).days for start, end in merged)
    if positives:
        status = "HAS_HIT"
        first = min(positives, key=lambda row: str(row["window_start"]))
        last = max(positives, key=lambda row: str(row["window_end"]))
        last_end = _date(last["window_end"])
        days_since = max(0, (as_of - last_end).days)
        first_start, first_end = first["window_start"], first["window_end"]
        last_start, last_finish = last["window_start"], last["window_end"]
    else:
        status = "NO_HIT_IN_COVERED_PERIOD" if covered >= expected else "UNKNOWN_INCOMPLETE_COVERAGE"
        first_start = first_end = last_start = last_finish = None
        days_since = None
    return {
        "hit_status": status, "first_hit_window_start": first_start,
        "first_hit_window_end": first_end, "last_hit_window_start": last_start,
        "last_hit_window_end": last_finish, "days_since_last_hit": days_since,
        "coverage_days": covered, "coverage_percent": round(100 * covered / expected, 2) if expected else 100.0,
        "total_flows": sum(int(row["flows"]) for row in completed if row.get("flows") is not None),
    }


def _date(value: object) -> date:
    return datetime.fromisoformat(str(value).replace("Z", "+00:00")).date()
