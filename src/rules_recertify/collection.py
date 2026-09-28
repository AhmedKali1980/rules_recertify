"""Compatibility imports for the collection engine.

The implementation lives in :mod:`rules_recertify.collection_engine`.  Keeping
this small module preserves the historical Python import path for integrations.
"""
from .collection_engine import (
    _initial_traffic_run_details,
    _send_and_record_summary,
    _validated_usage_rows,
    backfill_traffic,
    collect,
    collect_policy,
    collect_traffic,
    initialize_backfill_traffic,
)

__all__ = [
    "backfill_traffic",
    "collect",
    "collect_policy",
    "collect_traffic",
    "initialize_backfill_traffic",
]
