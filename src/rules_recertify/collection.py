from __future__ import annotations

import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import asdict
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from .archives import discard_prepared_archive, prepare_run_archive, purge_expired_archives
from .config import Settings
from .history.database import (
    Database, RUN_TYPE_BACKFILL, RUN_TYPE_POLICY, RUN_TYPE_TRAFFIC,
)
from .notifications import send_summary
from .pce_import import import_pce_exports
from .reference import ingest_reference
from .workloader.batching import (
    partition_and_pack_rulesets,
    select_application_scoped_rulesets,
)
from .workloader.csvio import (
    CsvContractError,
    parse_flows_by_port,
    query_window,
    read_rows,
    write_rows,
)
from .workloader.runner import WorkloaderError, WorkloaderRunner, sha256_file

LOG = logging.getLogger(__name__)
RULE_REQUIRED = ("ruleset_href", "rule_href")
USAGE_REQUIRED = (*RULE_REQUIRED, "async_query_status", "flows", "flows_by_port", "query_body")
LABEL_REQUIRED = ("key", "value")
POLICY_REFERENCE_EXPORTS = (
    "export_wkld.csv", "export_iplists.csv", "export_services.csv",
    "export_wkld.derived.csv", "export_iplists.derived.csv",
)


def collect_policy(settings: Settings, pce_stub_dir: Optional[Path] = None) -> Dict[str, object]:
    """Export and atomically publish one complete policy inventory."""
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    raw_root = Path(settings.raw_dir)
    run_dir = raw_root / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    db = Database(Path(settings.state_db)); db.initialize()
    details: Dict[str, object] = {
        "run_id": run_id,
        "run_type": RUN_TYPE_POLICY,
        "current_stage": "IMPORTING_PCE_REFERENCE",
    }
    db.begin_run(run_id, RUN_TYPE_POLICY, details)
    config_file = Path(settings.workloader_config_file) if settings.workloader_config_file else None
    runner = WorkloaderRunner(
        settings.workloader, settings.pce, run_dir / "workloader.log", config_file,
        rate_limit_retry_delay_minutes=settings.rate_limit_retry_delay_minutes,
        rate_limit_max_retries=settings.rate_limit_max_retries,
    )
    status = "ERROR"
    snapshot_backup: Optional[Path] = None
    snapshot_published = False
    try:
        import_pce_exports(run_dir, pce_stub_dir, _pce_import_environment(settings))

        details["current_stage"] = "EXPORTING_RULESETS"
        db.update_run_details(run_id, details)
        rulesets_file = run_dir / "rulesets.csv"
        runner.run(["ruleset-export", "--output-file", str(rulesets_file)])
        rulesets = list(read_rows(rulesets_file, ("href", "enabled")))
        if not rulesets or not any(row["href"] for row in rulesets):
            raise RuntimeError("Complete policy export contains no ruleset")
        href_file = run_dir / "ruleset_hrefs_all.csv"
        write_rows(href_file, ["href"], ({"href": row["href"]} for row in rulesets if row["href"]))

        details["current_stage"] = "EXPORTING_LABELS"
        db.update_run_details(run_id, details)
        labels_file = run_dir / "labels.csv"
        runner.run(["label-export", "--output-file", str(labels_file)])
        labels = list(read_rows(labels_file, LABEL_REQUIRED))

        details["current_stage"] = "EXPORTING_RULE_INVENTORY"
        db.update_run_details(run_id, details)
        inventory_file = run_dir / "rules_inventory.csv"
        runner.run([
            "rule-export", "--ruleset-hrefs", str(href_file),
            "--policy-version", settings.policy_version, "--output-file", str(inventory_file),
        ])
        inventory = list(read_rows(inventory_file, RULE_REQUIRED))
        if not inventory:
            raise RuntimeError("Complete policy export contains no rule")
        # Re-read every contract before publishing any current-rule state.
        _validate_policy_exports(run_dir)

        details["current_stage"] = "INGESTING_REFERENCES"
        db.update_run_details(run_id, details)
        details["reference_ingest"] = ingest_reference(
            db, run_dir / "export_wkld.derived.csv", run_dir / "export_iplists.csv", run_id,
        )
        details.update({
            "ruleset_count": len(rulesets),
            "label_count": len(labels),
            "rule_count": len(inventory),
            "reference_exports": [
                name for name in (*POLICY_REFERENCE_EXPORTS, "export_wkld.l3sm.m.csv")
                if (run_dir / name).is_file()
            ],
        })
        details["artifacts"] = _record_artifacts(db, run_id, run_dir)
        details.pop("current_stage", None)
        details["status"] = "SUCCESS"
        manifest = run_dir / "manifest.json"
        manifest.write_text(json.dumps(details, indent=2, sort_keys=True), encoding="utf-8")

        snapshot_backup = _publish_materialized_snapshot(run_dir, raw_root / "snapshot")
        snapshot_published = True
        db.complete_policy_snapshot(
            run_id, run_id, inventory,
            snapshot_path=str(raw_root / "snapshot"),
            manifest_path=str(raw_root / "snapshot" / "manifest.json"),
            run_details=details,
        )
        status = "SUCCESS"
        if snapshot_backup and snapshot_backup.exists():
            shutil.rmtree(snapshot_backup, ignore_errors=True)
            snapshot_backup = None
    except Exception as exc:
        details["error"] = str(exc)
        LOG.exception("Policy collection failed")
        if snapshot_published:
            _restore_materialized_snapshot(raw_root / "snapshot", snapshot_backup)
            snapshot_published = False
        raise
    finally:
        details["status"] = status
        if status != "SUCCESS":
            manifest = run_dir / "manifest.json"
            manifest.write_text(json.dumps(details, indent=2, sort_keys=True), encoding="utf-8")
            db.finish_run(run_id, status, details)
        if snapshot_backup and snapshot_backup.exists():
            shutil.rmtree(snapshot_backup, ignore_errors=True)
        try:
            send_summary(settings, details)
        except Exception:
            LOG.exception("SMTP summary failed without changing policy collection status")
        shutil.rmtree(run_dir, ignore_errors=True)
    return details


def collect(settings: Settings, traffic_start: date, traffic_end: date, no_wait: bool = False,
            import_references: bool = False, pce_stub_dir: Optional[Path] = None) -> Dict[str, object]:
    """Transitional combined policy/reference/traffic collection."""
    return _collect_traffic_run(
        settings, traffic_start, traffic_end, no_wait,
        import_references=import_references, pce_stub_dir=pce_stub_dir,
        run_type="COLLECTION", publish_policy_inventory=True,
    )


def collect_traffic(settings: Settings, available_end: date, initial_start: Optional[date] = None,
                    no_wait: bool = False) -> Dict[str, object]:
    """Collect the next durable, non-overlapping seven-day traffic window."""
    db = Database(Path(settings.state_db)); db.initialize()
    cursor = db.traffic_cursor("weekly")
    cursor_start: Optional[date] = None
    if cursor:
        raw_start = (
            cursor.get("in_progress_start")
            if cursor.get("last_status") == "FAILED"
            else cursor.get("last_successful_end")
        )
        if raw_start:
            cursor_start = date.fromisoformat(str(raw_start))
    if cursor_start and initial_start and cursor_start != initial_start:
        raise ValueError(
            f"traffic cursor requires start {cursor_start.isoformat()}, got {initial_start.isoformat()}"
        )
    traffic_start = cursor_start or initial_start or (
        available_end - timedelta(days=settings.traffic_window_days)
    )
    traffic_end = traffic_start + timedelta(days=settings.traffic_window_days)
    if traffic_end > available_end:
        raise ValueError(
            f"complete traffic window [{traffic_start},{traffic_end}) is not available at {available_end}"
        )
    result = _collect_traffic_run(
        settings, traffic_start, traffic_end, no_wait,
        run_type=RUN_TYPE_TRAFFIC, publish_policy_inventory=False,
        cursor_name="weekly",
    )
    if result["status"] != "SUCCESS":
        raise RuntimeError(
            f"Traffic window [{traffic_start},{traffic_end}) incomplete; cursor was not advanced"
        )
    return result


def initialize_backfill_traffic(settings: Settings, target_end: date,
                                backfill_id: str = "traffic-92-days") -> Dict[str, object]:
    """Freeze the 92-day historical target and its oldest-first cursor."""
    if not backfill_id.strip():
        raise ValueError("backfill_id must not be empty")
    start = target_end - timedelta(days=92)
    db = Database(Path(settings.state_db)); db.initialize()
    db.initialize_backfill(backfill_id, start.isoformat(), target_end.isoformat())
    return dict(db.backfill_state(backfill_id) or {})


def backfill_traffic(settings: Settings, backfill_id: str = "traffic-92-days",
                     no_wait: bool = False) -> Dict[str, object]:
    """Process at most one oldest-first backfill window."""
    db = Database(Path(settings.state_db)); db.initialize()
    state = db.backfill_state(backfill_id)
    if state is None:
        raise ValueError(f"unknown backfill: {backfill_id}; initialize it first")
    if state["status"] == "COMPLETED":
        return {"backfill_id": backfill_id, "status": "COMPLETED", "window_processed": False}
    traffic_start = date.fromisoformat(str(state["next_window_start"]))
    target_end = date.fromisoformat(str(state["backfill_target_end"]))
    traffic_end = min(
        traffic_start + timedelta(days=settings.traffic_window_days), target_end,
    )
    result = _collect_traffic_run(
        settings, traffic_start, traffic_end, no_wait,
        run_type=RUN_TYPE_BACKFILL, publish_policy_inventory=False,
        backfill_id=backfill_id,
    )
    if result["status"] != "SUCCESS":
        raise RuntimeError(
            f"Backfill window [{traffic_start},{traffic_end}) incomplete; cursor was not advanced"
        )
    result["backfill_status"] = str(
        (db.backfill_state(backfill_id) or {}).get("status", "")
    )
    return result


def _collect_traffic_run(
    settings: Settings, traffic_start: date, traffic_end: date, no_wait: bool = False,
    import_references: bool = False, pce_stub_dir: Optional[Path] = None,
    run_type: str = "COLLECTION", publish_policy_inventory: bool = True,
    cursor_name: Optional[str] = None, backfill_id: Optional[str] = None,
) -> Dict[str, object]:
    if traffic_end <= traffic_start:
        raise ValueError("traffic_end must be after traffic_start")
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    run_dir = Path(settings.raw_dir) / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    db = Database(Path(settings.state_db)); db.initialize()
    details: Dict[str, object] = {"run_id": run_id, "traffic_start": traffic_start.isoformat(), "traffic_end": traffic_end.isoformat(), "batches": [], "current_stage": "EXPORTING_RULESETS"}
    details["run_type"] = run_type
    db.begin_run(run_id, run_type, details)
    config_file = Path(settings.workloader_config_file) if settings.workloader_config_file else None
    runner = WorkloaderRunner(
        settings.workloader,
        settings.pce,
        run_dir / "workloader.log",
        config_file,
        rate_limit_retry_delay_minutes=settings.rate_limit_retry_delay_minutes,
        rate_limit_max_retries=settings.rate_limit_max_retries,
    )
    status = "ERROR"
    cursor_started = False
    backfill_started = False
    try:
        if cursor_name:
            db.begin_traffic_window(
                cursor_name, run_type, run_id,
                traffic_start.isoformat(), traffic_end.isoformat(),
            )
            cursor_started = True
        if backfill_id:
            lease = db.begin_backfill_window(
                backfill_id, run_id, settings.traffic_window_days,
            )
            backfill_started = True
            if (
                lease["window_start"] != traffic_start.isoformat()
                or lease["window_end"] != traffic_end.isoformat()
            ):
                raise ValueError("backfill window provider changed during collection startup")
        if import_references:
            details["current_stage"] = "IMPORTING_PCE_REFERENCE"
            db.update_run_details(run_id, details)
            import_pce_exports(run_dir, pce_stub_dir, _pce_import_environment(settings))
            details["reference_ingest"] = ingest_reference(
                db, run_dir / "export_wkld.derived.csv",
                run_dir / "export_iplists.csv", run_id,
            )
            details["reference_exports"] = [
                "export_wkld.csv", "export_iplists.csv", "export_services.csv",
                "export_wkld.derived.csv", "export_iplists.derived.csv",
            ]
            details["current_stage"] = "EXPORTING_RULESETS"
            db.update_run_details(run_id, details)
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
        if publish_policy_inventory:
            details["rules"] = db.upsert_rules(inventory, datetime.now(timezone.utc).isoformat())
        else:
            details["rules"] = len(inventory)
            details["policy_snapshot_updated"] = False
        scoped_rulesets, scope_exclusions = select_application_scoped_rulesets(
            inventory,
            application_labels,
            settings.empty_scope_ruleset_name_patterns,
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
        pending_batches = list(batches)
        runtime_oversized = []
        index = 0
        while pending_batches:
            batch = pending_batches.pop(0)
            index += 1
            details["current_batch"] = index
            details["current_stage"] = "SUBMITTING"
            details["batch_count"] = index + len(pending_batches)
            db.update_run_details(run_id, details)
            hrefs = run_dir / f"batch_{index:04d}_hrefs.csv"
            write_rows(hrefs, ["href"], ({"href": item.href} for item in batch))
            submitted = run_dir / f"batch_{index:04d}_submitted.csv"
            try:
                runner.run(["rule-export", "--ruleset-hrefs", str(hrefs), "--policy-version", settings.policy_version,
                            "--expand-svcs", "--traffic-count", "--traffic-start", traffic_start.isoformat(),
                            "--traffic-end", traffic_end.isoformat(), "--traffic-max-results", str(settings.traffic_max_results),
                            "--traffic-rule-limit", str(settings.traffic_batch_size), "--output-file", str(submitted)])
            except WorkloaderError as exc:
                reported_rule_count = _traffic_rule_limit_count(exc)
                if reported_rule_count is None:
                    raise
                if len(batch) > 1:
                    midpoint = len(batch) // 2
                    pending_batches[0:0] = [batch[:midpoint], batch[midpoint:]]
                    LOG.warning(
                        "Workloader counted more rules than the inventory; splitting batch",
                        extra={"batch": index, "rulesets": len(batch)},
                    )
                    continue
                item = batch[0]
                metadata = ruleset_metadata[item.href]
                runtime_oversized.append((item, reported_rule_count))
                db.add_quality(
                    run_id,
                    "RULESET_SKIPPED_TRAFFIC_RULE_LIMIT_EXCEEDED",
                    item.href,
                    f"Workloader counted {reported_rule_count} rules, above the configured "
                    f"traffic rule limit {settings.traffic_batch_size}",
                )
                LOG.warning(
                    "Traffic ruleset excluded",
                    extra={
                        "selection": "EXCLUDED",
                        "reason": "TRAFFIC_RULE_LIMIT_EXCEEDED",
                        "ruleset_href": item.href,
                        "ruleset_name": metadata["name"],
                        "ruleset_scope": metadata["scope"],
                        "rule_count": item.count,
                        "reported_rule_count": reported_rule_count,
                        "traffic_rule_limit": settings.traffic_batch_size,
                    },
                )
                continue
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
            details["current_stage"] = "POLLING"
            db.update_run_details(run_id, details)
            batch_result = _poll_batch(runner, submitted, run_dir, index, settings, no_wait)
            cast_batches = details["batches"]
            assert isinstance(cast_batches, list)
            cast_batches.append(batch_result)
            if batch_result["output"]:
                usage_rows = list(read_rows(Path(str(batch_result["output"])), USAGE_REQUIRED))
                valid_usage_rows, invalid_usage_rows, invalid_port_rows = _validated_usage_rows(
                    usage_rows, traffic_start, traffic_end
                )
                batch_result["invalid_query_body"] = len(invalid_usage_rows)
                batch_result["invalid_flows_by_port"] = len(invalid_port_rows)
                for row in invalid_usage_rows:
                    rule_href = row.get("rule_href", "")
                    db.add_quality(
                        run_id,
                        "USAGE_SKIPPED_INVALID_QUERY_BODY",
                        rule_href,
                        "Workloader usage row has no valid start_date/end_date",
                    )
                    LOG.warning(
                        "Skipping Workloader usage row with invalid query_body",
                        extra={
                            "batch": index,
                            "ruleset_href": row.get("ruleset_href", ""),
                            "rule_href": rule_href,
                            "async_query_status": row.get("async_query_status", ""),
                        },
                    )
                for row in invalid_port_rows:
                    rule_href = row.get("rule_href", "")
                    db.add_quality(
                        run_id,
                        "USAGE_SKIPPED_INVALID_FLOWS_BY_PORT",
                        rule_href,
                        f"Unsupported flows_by_port value: {row.get('flows_by_port', '')!r}",
                    )
                    LOG.warning(
                        "Skipping Workloader usage row with invalid flows_by_port",
                        extra={
                            "batch": index,
                            "ruleset_href": row.get("ruleset_href", ""),
                            "rule_href": rule_href,
                            "flows_by_port": row.get("flows_by_port", ""),
                        },
                    )
                details["current_stage"] = "INGESTING"
                db.update_run_details(run_id, details)
                db.upsert_usage(run_id, valid_usage_rows)
            db.update_run_details(run_id, details)
            if settings.batch_cooldown_seconds and pending_batches:
                time.sleep(settings.batch_cooldown_seconds)
        details["runtime_oversized_rulesets"] = [
            {
                "ruleset_href": item.href,
                "inventory_rule_count": item.count,
                "reported_rule_count": reported_rule_count,
                "reason": "TRAFFIC_RULE_LIMIT_EXCEEDED",
            }
            for item, reported_rule_count in runtime_oversized
        ]
        details["runtime_oversized_ruleset_count"] = len(runtime_oversized)
        details.pop("current_batch", None)
        details.pop("current_stage", None)
        summary = _summarize_batches(details["batches"])
        details.update(summary)
        details["invalid_query_body_count"] = sum(
            int(batch.get("invalid_query_body", 0)) for batch in details["batches"]
        )
        details["invalid_flows_by_port_count"] = sum(
            int(batch.get("invalid_flows_by_port", 0)) for batch in details["batches"]
        )
        details["artifacts"] = _record_artifacts(db, run_id, run_dir)
        status = "SUCCESS" if (
            not oversized
            and not runtime_oversized
            and (summary["total"] > 0 or run_type == RUN_TYPE_TRAFFIC)
            and not summary["pending"]
            and not summary["expired"]
            and not summary["unknown"]
            and not details["invalid_query_body_count"]
            and not details["invalid_flows_by_port_count"]
        ) else "WARNING"
        details["pruned_usage_windows"] = db.prune(settings.retention_days)
    except Exception as exc:
        details["error"] = str(exc)
        LOG.exception("Collection failed")
        raise
    finally:
        details["status"] = status
        archive_record: Optional[Dict[str, object]] = None
        prepared_archive = None
        should_archive = status == "SUCCESS" and (
            run_type == RUN_TYPE_TRAFFIC and traffic_end.weekday() == 6
        )
        if should_archive:
            retained_until = (date.today() + timedelta(days=settings.retention_days)).isoformat()
            expected_archive = Path(settings.raw_dir) / "archives" / f"{run_id}.tar.gz"
            details["archive"] = {
                "path": str(expected_archive), "retained_until": retained_until,
            }
        elif run_type in {RUN_TYPE_TRAFFIC, RUN_TYPE_BACKFILL}:
            details["raw_disposition"] = "DELETE_AFTER_FINALIZATION"
        manifest = run_dir / "manifest.json"
        manifest.write_text(json.dumps(details, indent=2, sort_keys=True), encoding="utf-8")
        if should_archive:
            try:
                prepared_archive = prepare_run_archive(
                    run_dir, Path(settings.raw_dir) / "archives",
                )
                archive_record = {
                    "archive_kind": "TRAFFIC",
                    "archive_path": str(prepared_archive.path),
                    "sha256": prepared_archive.sha256,
                    "size_bytes": prepared_archive.size_bytes,
                    "retained_until": details["archive"]["retained_until"],
                }
            except Exception as exc:
                status = "ERROR"
                details["status"] = status
                details["error"] = f"Archive creation failed: {exc}"
                manifest.write_text(json.dumps(details, indent=2, sort_keys=True), encoding="utf-8")
        if backfill_id and backfill_started:
            try:
                db.update_backfill_window(
                    backfill_id, run_id, traffic_end.isoformat(), status == "SUCCESS",
                    run_details=details, run_status=status,
                    error=str(details.get("error", "")), archive=archive_record,
                )
            except Exception:
                if prepared_archive:
                    discard_prepared_archive(prepared_archive)
                raise
        elif cursor_name and cursor_started:
            try:
                db.finish_traffic_window(
                    cursor_name, run_type, run_id,
                    traffic_start.isoformat(), traffic_end.isoformat(),
                    status == "SUCCESS", str(details.get("error", "")),
                    run_details=details, run_status=status, archive=archive_record,
                )
            except Exception:
                if prepared_archive:
                    discard_prepared_archive(prepared_archive)
                raise
        else:
            db.finish_run(run_id, status, details)
        try:
            send_summary(settings, details)
        except Exception:
            LOG.exception("SMTP summary failed without changing collection status")
        if run_type in {RUN_TYPE_TRAFFIC, RUN_TYPE_BACKFILL}:
            shutil.rmtree(run_dir, ignore_errors=True)
        if status == "SUCCESS":
            try:
                details["purged_archives"] = purge_expired_archives(db, date.today())
            except Exception:
                LOG.exception("Archive purge failed without changing collection status")
    return details


def _pce_import_environment(settings: Settings) -> Dict[str, str]:
    import_keys = {
        "PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "PYTHONPATH",
        "EXECUTABLE", "CFG", "PCE_L1_NAME", "PCE_L3SM_NAME",
        "PCE_L1_FQDN", "PCE_L3SM_FQDN", "RULES_RECERTIFY_ENV_FILE",
        "BASE_SLEEP", "BACKOFF", "MAX_SLEEP", "JITTER", "TIMEOUT_SEC",
        "MAX_ATTEMPTS", "POST_SUCCESS_PAUSE_SEC", "POST_FAILURE_PAUSE_SEC",
        "VERIFY_OUTPUT_FILE",
    }
    environment = {key: value for key, value in os.environ.items() if key in import_keys}
    environment.setdefault("EXECUTABLE", str(settings.workloader))
    if settings.workloader_config_file:
        environment.setdefault("CFG", settings.workloader_config_file)
    return environment


def _validate_policy_exports(run_dir: Path) -> None:
    for name in POLICY_REFERENCE_EXPORTS:
        path = run_dir / name
        if not path.is_file() or path.stat().st_size == 0:
            raise RuntimeError(f"Policy export is missing or empty: {path}")
    list(read_rows(run_dir / "export_wkld.derived.csv", (
        "href", "hostname", "interfaces", "ip_with_default_gw", "app", "env", "managed",
    )))
    list(read_rows(run_dir / "export_iplists.csv", ("name", "include")))
    list(read_rows(run_dir / "export_services.csv", ("name", "service_ports")))
    list(read_rows(run_dir / "labels.csv", LABEL_REQUIRED))
    list(read_rows(run_dir / "rulesets.csv", ("href", "enabled")))
    list(read_rows(run_dir / "rules_inventory.csv", RULE_REQUIRED))


def _record_artifacts(db: Database, run_id: str, run_dir: Path) -> List[Dict[str, str]]:
    artifacts: List[Dict[str, str]] = []
    for path in sorted(run_dir.iterdir()):
        if not path.is_file() or path.name == "manifest.json":
            continue
        record = {"path": str(path), "sha256": sha256_file(path)}
        artifacts.append(record)
        db.add_artifact(run_id, path.suffix.lstrip(".") or "file", str(path), record["sha256"])
    return artifacts


def _publish_materialized_snapshot(run_dir: Path, snapshot_dir: Path) -> Optional[Path]:
    """Copy a validated run and atomically replace raw/snapshot, retaining a rollback copy."""
    temporary = snapshot_dir.parent / f".{snapshot_dir.name}-{run_dir.name}.tmp"
    backup = snapshot_dir.parent / f".{snapshot_dir.name}-{run_dir.name}.backup"
    if temporary.exists() or backup.exists():
        raise RuntimeError(f"Stale snapshot staging path exists for run {run_dir.name}")
    shutil.copytree(run_dir, temporary)
    for source in run_dir.iterdir():
        if source.is_file():
            target = temporary / source.name
            if not target.is_file() or sha256_file(source) != sha256_file(target):
                shutil.rmtree(temporary, ignore_errors=True)
                raise RuntimeError(f"Snapshot verification failed for {source.name}")
    previous: Optional[Path] = None
    if snapshot_dir.exists():
        snapshot_dir.replace(backup)
        previous = backup
    try:
        temporary.replace(snapshot_dir)
    except Exception:
        if previous and previous.exists():
            previous.replace(snapshot_dir)
        raise
    return previous


def _restore_materialized_snapshot(snapshot_dir: Path, backup: Optional[Path]) -> None:
    if snapshot_dir.exists():
        shutil.rmtree(snapshot_dir)
    if backup and backup.exists():
        backup.replace(snapshot_dir)


def _traffic_rule_limit_count(exc: WorkloaderError) -> Optional[int]:
    match = re.search(
        r"traffic-rule-limit.*?total rules is\s+(\d+)", str(exc), re.IGNORECASE | re.DOTALL
    )
    return int(match.group(1)) if match else None


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


def _validated_usage_rows(
    rows: Sequence[Mapping[str, str]], expected_start: date, expected_end: date
) -> Tuple[
    List[Mapping[str, str]],
    List[Mapping[str, str]],
    List[Mapping[str, str]],
]:
    valid: List[Mapping[str, str]] = []
    invalid: List[Mapping[str, str]] = []
    invalid_ports: List[Mapping[str, str]] = []
    for row in rows:
        try:
            start, end = query_window(row["query_body"])
            actual_start = datetime.fromisoformat(start.replace("Z", "+00:00")).date()
            actual_end = datetime.fromisoformat(end.replace("Z", "+00:00")).date()
        except (CsvContractError, ValueError):
            invalid.append(row)
            continue
        if (actual_start, actual_end) != (expected_start, expected_end):
            raise ValueError(
                f"Workloader query window {actual_start}/{actual_end} does not match "
                f"requested {expected_start}/{expected_end}"
            )
        try:
            parse_flows_by_port(row.get("flows_by_port", ""))
        except CsvContractError:
            invalid_ports.append(row)
            continue
        valid.append(row)
    return valid, invalid, invalid_ports
