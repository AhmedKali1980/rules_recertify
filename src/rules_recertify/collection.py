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
from .workloader.batching import bin_pack_rulesets, count_rules_by_ruleset
from .workloader.csvio import query_window, read_rows, write_rows
from .workloader.runner import WorkloaderRunner, sha256_file

LOG = logging.getLogger(__name__)
RULE_REQUIRED = ("ruleset_href", "rule_href")
USAGE_REQUIRED = (*RULE_REQUIRED, "async_query_status", "flows", "flows_by_port", "query_body")


def collect(settings: Settings, traffic_start: date, traffic_end: date, no_wait: bool = False) -> Dict[str, object]:
    if traffic_end <= traffic_start:
        raise ValueError("traffic_end must be after traffic_start")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = Path(settings.raw_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    db = Database(Path(settings.state_db)); db.initialize()
    details: Dict[str, object] = {"run_id": run_id, "traffic_start": traffic_start.isoformat(), "traffic_end": traffic_end.isoformat(), "batches": []}
    db.begin_run(run_id, "COLLECTION", details)
    runner = WorkloaderRunner(settings.workloader, settings.pce, run_dir / "workloader.log")
    status = "ERROR"
    try:
        rulesets_file = run_dir / "rulesets.csv"
        runner.run(["ruleset-export", "--output-file", str(rulesets_file)])
        rulesets = list(read_rows(rulesets_file, ("href", "enabled")))
        all_hrefs = [{"href": row["href"]} for row in rulesets if row["href"]]
        href_file = run_dir / "ruleset_hrefs_all.csv"
        write_rows(href_file, ["href"], all_hrefs)

        inventory_file = run_dir / "rules_inventory.csv"
        runner.run(["rule-export", "--ruleset-hrefs", str(href_file), "--policy-version", settings.policy_version, "--output-file", str(inventory_file)])
        inventory = list(read_rows(inventory_file, RULE_REQUIRED))
        details["rules"] = db.upsert_rules(inventory, datetime.now(timezone.utc).isoformat())
        batches = bin_pack_rulesets(count_rules_by_ruleset(inventory), settings.traffic_batch_size)
        for index, batch in enumerate(batches, 1):
            hrefs = run_dir / f"batch_{index:04d}_hrefs.csv"
            write_rows(hrefs, ["href"], ({"href": item.href} for item in batch))
            submitted = run_dir / f"batch_{index:04d}_submitted.csv"
            runner.run(["rule-export", "--ruleset-hrefs", str(hrefs), "--policy-version", settings.policy_version,
                        "--expand-svcs", "--traffic-count", "--traffic-start", traffic_start.isoformat(),
                        "--traffic-end", traffic_end.isoformat(), "--traffic-max-results", str(settings.traffic_max_results),
                        "--traffic-rule-limit", str(settings.traffic_batch_size), "--output-file", str(submitted)])
            batch_result = _poll_batch(runner, submitted, run_dir, index, settings, no_wait)
            cast_batches = details["batches"]
            assert isinstance(cast_batches, list)
            cast_batches.append(batch_result)
            if batch_result["output"]:
                usage_rows = list(read_rows(Path(str(batch_result["output"])), USAGE_REQUIRED))
                _validate_windows(usage_rows, traffic_start, traffic_end)
                db.upsert_usage(run_id, usage_rows)
            if settings.batch_cooldown_seconds and index < len(batches):
                time.sleep(settings.batch_cooldown_seconds)
        summary = _summarize_batches(details["batches"])
        details.update(summary)
        artifacts = []
        for path in sorted(run_dir.iterdir()):
            if path.is_file() and path.name != "manifest.json":
                record = {"path": str(path), "sha256": sha256_file(path)}
                artifacts.append(record)
                db.add_artifact(run_id, path.suffix.lstrip(".") or "file", str(path), record["sha256"])
        details["artifacts"] = artifacts
        status = "SUCCESS" if not summary["pending"] and not summary["expired"] and not summary["unknown"] else "WARNING"
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
