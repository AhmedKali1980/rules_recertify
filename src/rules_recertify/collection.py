from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence

from .config import Settings
from .history.database import Database
from .notifications import send_summary
from .workloader.batching import (
    partition_and_pack_rulesets,
    select_application_scoped_rulesets,
)
from .workloader.csvio import query_window, read_rows, write_rows
from .workloader.runner import WorkloaderRunner, sha256_file

LOG = logging.getLogger(__name__)
RULE_REQUIRED = ("ruleset_href", "rule_href")
USAGE_REQUIRED = (*RULE_REQUIRED, "async_query_status", "flows", "flows_by_port", "query_body")
LABEL_REQUIRED = ("key", "value")


def collect(settings: Settings, traffic_start: date, traffic_end: date, no_wait: bool = False) -> Dict[str, object]:
    if traffic_end <= traffic_start:
        raise ValueError("traffic_end must be after traffic_start")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = Path(settings.raw_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    db = Database(Path(settings.state_db)); db.initialize()
    details: Dict[str, object] = {"run_id": run_id, "traffic_start": traffic_start.isoformat(), "traffic_end": traffic_end.isoformat(), "batches": [], "current_stage": "EXPORTING_RULESETS"}
    db.begin_run(run_id, "COLLECTION", details)
    config_file = Path(settings.workloader_config_file) if settings.workloader_config_file else None
    runner = WorkloaderRunner(settings.workloader, settings.pce, run_dir / "workloader.log", config_file)
    status = "ERROR"
    try:
        rulesets_file = run_dir / "rulesets.csv"
        runner.run(["ruleset-export", "--output-file", str(rulesets_file)])
        rulesets = list(read_rows(rulesets_file, ("href", "enabled")))
        all_hrefs = [{"href": row["href"]} for row in rulesets if row["href"]]
        href_file = run_dir / "ruleset_hrefs_all.csv"
        write_rows(href_file, ["href"], all_hrefs)

        details["current_stage"] = "EXPORTING_LABELS"
        db.update_run_details(run_id, details)
        labels_file = run_dir / "labels.csv"
        runner.run(["label-export", "--output-file", str(labels_file)])
        labels = list(read_rows(labels_file, LABEL_REQUIRED))
        application_labels = {
            row["value"] for row in labels if row["key"].strip().lower() == "app"
        }
        details["application_label_count"] = len(application_labels)

        details["current_stage"] = "EXPORTING_RULE_INVENTORY"
        db.update_run_details(run_id, details)
        inventory_file = run_dir / "rules_inventory.csv"
        runner.run(["rule-export", "--ruleset-hrefs", str(href_file), "--policy-version", settings.policy_version, "--output-file", str(inventory_file)])
        inventory = list(read_rows(inventory_file, RULE_REQUIRED))
        ruleset_metadata = _ruleset_metadata(inventory)
        details["rules"] = db.upsert_rules(inventory, datetime.now(timezone.utc).isoformat())
        scoped_rulesets, scope_exclusions = select_application_scoped_rulesets(
            inventory, application_labels
        )
        details["excluded_scope_rulesets"] = [asdict(item) for item in scope_exclusions]
        details["excluded_scope_ruleset_count"] = len(scope_exclusions)
        details["excluded_scope_rule_count"] = sum(
            item.count for item in scope_exclusions
        )
        for item in scope_exclusions:
            metadata = ruleset_metadata[item.href]
            db.add_quality(
                run_id,
                f"RULESET_SKIPPED_{item.reason}",
                item.href,
                f"Ruleset excluded from traffic collection: scope={item.scope!r}",
            )
            LOG.info(
                "Traffic ruleset excluded",
                extra={
                    "selection": "EXCLUDED",
                    "reason": item.reason,
                    "ruleset_href": item.href,
                    "ruleset_name": metadata["name"],
                    "ruleset_scope": item.scope,
                    "rule_count": item.count,
                },
            )
        if scope_exclusions:
            LOG.info(
                "Excluded rulesets without a valid application scope",
                extra={
                    "excluded_rulesets": len(scope_exclusions),
                    "excluded_rules": details["excluded_scope_rule_count"],
                },
            )
        batches, oversized = partition_and_pack_rulesets(
            scoped_rulesets, settings.traffic_batch_size
        )
        details["skipped_oversized_rulesets"] = [
            {"ruleset_href": item.href, "rule_count": item.count}
            for item in oversized
        ]
        details["skipped_oversized_ruleset_count"] = len(oversized)
        details["skipped_oversized_rule_count"] = sum(item.count for item in oversized)
        if oversized:
            LOG.warning(
                "Skipping rulesets above the traffic batch limit",
                extra={
                    "traffic_batch_size": settings.traffic_batch_size,
                    "skipped_rulesets": len(oversized),
                    "skipped_rules": details["skipped_oversized_rule_count"],
                },
            )
        for item in oversized:
            metadata = ruleset_metadata[item.href]
            db.add_quality(
                run_id,
                "RULESET_SKIPPED_OVERSIZED",
                item.href,
                f"Ruleset has {item.count} rules, above traffic batch limit "
                f"{settings.traffic_batch_size}",
            )
            LOG.info(
                "Traffic ruleset excluded",
                extra={
                    "selection": "EXCLUDED",
                    "reason": "OVERSIZED",
                    "ruleset_href": item.href,
                    "ruleset_name": metadata["name"],
                    "ruleset_scope": metadata["scope"],
                    "rule_count": item.count,
                },
            )
        for index, batch in enumerate(batches, 1):
            details["current_batch"] = index
            details["current_stage"] = "SUBMITTING"
            details["batch_count"] = len(batches)
            db.update_run_details(run_id, details)
            hrefs = run_dir / f"batch_{index:04d}_hrefs.csv"
            write_rows(hrefs, ["href"], ({"href": item.href} for item in batch))
            for item in batch:
                metadata = ruleset_metadata[item.href]
                LOG.info(
                    "Traffic ruleset selected",
                    extra={
                        "selection": "SELECTED",
                        "batch": index,
                        "ruleset_href": item.href,
                        "ruleset_name": metadata["name"],
                        "ruleset_scope": metadata["scope"],
                        "rule_count": item.count,
                    },
                )
            submitted = run_dir / f"batch_{index:04d}_submitted.csv"
            runner.run(["rule-export", "--ruleset-hrefs", str(hrefs), "--policy-version", settings.policy_version,
                        "--expand-svcs", "--traffic-count", "--traffic-start", traffic_start.isoformat(),
                        "--traffic-end", traffic_end.isoformat(), "--traffic-max-results", str(settings.traffic_max_results),
                        "--traffic-rule-limit", str(settings.traffic_batch_size), "--output-file", str(submitted)])
            details["current_stage"] = "POLLING"
            db.update_run_details(run_id, details)
            batch_result = _poll_batch(runner, submitted, run_dir, index, settings, no_wait)
            cast_batches = details["batches"]
            assert isinstance(cast_batches, list)
            cast_batches.append(batch_result)
            if batch_result["output"]:
                usage_rows = list(read_rows(Path(str(batch_result["output"])), USAGE_REQUIRED))
                _validate_windows(usage_rows, traffic_start, traffic_end)
                details["current_stage"] = "INGESTING"
                db.update_run_details(run_id, details)
                db.upsert_usage(run_id, usage_rows)
            db.update_run_details(run_id, details)
            if settings.batch_cooldown_seconds and index < len(batches):
                time.sleep(settings.batch_cooldown_seconds)
        details.pop("current_batch", None)
        details.pop("current_stage", None)
        summary = _summarize_batches(details["batches"])
        details.update(summary)
        artifacts = []
        for path in sorted(run_dir.iterdir()):
            if path.is_file() and path.name != "manifest.json":
                record = {"path": str(path), "sha256": sha256_file(path)}
                artifacts.append(record)
                db.add_artifact(run_id, path.suffix.lstrip(".") or "file", str(path), record["sha256"])
        details["artifacts"] = artifacts
        status = "SUCCESS" if (
            not oversized
            and summary["total"] > 0
            and not summary["pending"]
            and not summary["expired"]
            and not summary["unknown"]
        ) else "WARNING"
        details["pruned_usage_windows"] = db.prune(settings.retention_days)
    except Exception as exc:
        details["error"] = str(exc)
        LOG.exception("Collection failed")
        raise
    finally:
        details["status"] = status
        manifest = run_dir / "manifest.json"
        manifest.write_text(json.dumps(details, indent=2, sort_keys=True), encoding="utf-8")
        db.finish_run(run_id, status, details)
        try:
            send_summary(settings, details)
        except Exception:
            LOG.exception("SMTP summary failed without changing collection status")
    return details


def _poll_batch(runner: WorkloaderRunner, original: Path, run_dir: Path, index: int, settings: Settings, no_wait: bool) -> Dict[str, object]:
    started = time.monotonic()
    current = original
    iteration = 0
    if not no_wait and settings.query_initial_delay_minutes:
        time.sleep(settings.query_initial_delay_minutes * 60)
    while True:
        iteration += 1
        output = run_dir / f"batch_{index:04d}_usage_{iteration:03d}.csv"
        runner.run(["rule-usage", str(current), "--output-file", str(output)])
        rows = list(read_rows(output, USAGE_REQUIRED))
        counts = {"completed": 0, "pending": 0, "expired": 0, "unknown": 0}
        for row in rows:
            value = row["async_query_status"].lower()
            counts[value if value in counts else "unknown"] += 1
        total = len(rows); percent = round(100 * counts["completed"] / total, 2) if total else 0
        LOG.info("Traffic query progress", extra={"batch": index, "completed": counts["completed"],
                 "pending": counts["pending"], "expired": counts["expired"],
                 "unknown": counts["unknown"], "total": total, "percent": percent})
        terminal = counts["pending"] == 0
        deadline = time.monotonic() - started >= settings.query_deadline_minutes * 60
        if terminal or no_wait or deadline:
            return {"batch": index, "output": str(output), "total": total, "percent": percent, **counts, "deadline_reached": deadline}
        current = output
        time.sleep(settings.query_poll_interval_minutes * 60)


def _summarize_batches(batches: object) -> Dict[str, int]:
    values = batches if isinstance(batches, list) else []
    return {key: sum(int(batch.get(key, 0)) for batch in values) for key in ("total", "completed", "pending", "expired", "unknown")}


def _ruleset_metadata(rows: Sequence[Mapping[str, str]]) -> Dict[str, Dict[str, str]]:
    metadata: Dict[str, Dict[str, str]] = {}
    for row in rows:
        href = row["ruleset_href"].strip()
        metadata.setdefault(
            href,
            {
                "name": row.get("ruleset_name", "").strip(),
                "scope": row.get("ruleset_scope", "").strip(),
            },
        )
    return metadata


def _validate_windows(rows: Sequence[Mapping[str, str]], expected_start: date, expected_end: date) -> None:
    for row in rows:
        start, end = query_window(row["query_body"])
        actual_start = datetime.fromisoformat(start.replace("Z", "+00:00")).date()
        actual_end = datetime.fromisoformat(end.replace("Z", "+00:00")).date()
        if (actual_start, actual_end) != (expected_start, expected_end):
            raise ValueError(
                f"Workloader query window {actual_start}/{actual_end} does not match "
                f"requested {expected_start}/{expected_end}"
            )
