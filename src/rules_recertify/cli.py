from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from .archives import purge_expired_archives, restore_archive
from .collection_engine import (
    backfill_traffic, collect, collect_policy, collect_traffic,
    initialize_backfill_traffic,
)
from .config import ConfigurationError, load_settings
from .history.database import Database
from .logging_utils import configure_logging
from .notifications import send_summary
from .reference import ingest_reference
from .reporting.workbook import generate_workbook
from .reporting.microcosmos import generate_microcosmos_reports
from .reporting.rule_search import generate_rule_search_workbook
from .workloader.csvio import read_rows

LOG = logging.getLogger(__name__)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="rules-recertify")
    root.add_argument("--config", type=Path, default=Path("config/local.json"))
    root.add_argument("--env-file", type=Path, default=Path(".env"))
    root.add_argument("--verbose", action="store_true")
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("validate-config")
    commands.add_parser("init-db")
    commands.add_parser("test-email", help="Send a standalone SMTP configuration test")
    collect_p = commands.add_parser("collect")
    collect_p.add_argument("--traffic-start", type=_date)
    collect_p.add_argument("--traffic-end", type=_date)
    collect_p.add_argument("--no-wait", action="store_true", help="Poll once; intended for integration testing")
    collect_p.add_argument("--pce-stub-dir", type=Path, help="Use local reference CSVs; never contact a PCE")
    collect_p.add_argument("--skip-pce-import", action="store_true", help="Skip workload/IP-list reference import")
    policy = commands.add_parser(
        "collect-policy", help="Export and publish the complete policy inventory without traffic queries",
    )
    policy.add_argument("--pce-stub-dir", type=Path,
                        help="Use local workload/IP-list/service CSVs; never contact those PCEs")
    traffic = commands.add_parser(
        "collect-traffic", help="Collect the next cursor-controlled seven-day traffic window",
    )
    traffic.add_argument(
        "--traffic-start", type=_date,
        help="Seed for the first window only; later runs always use the persisted cursor",
    )
    traffic.add_argument(
        "--traffic-end", type=_date, default=date.today(),
        help="Latest available exclusive boundary (default: server-local current date)",
    )
    traffic.add_argument("--no-wait", action="store_true", help="Poll once; intended for integration testing")
    init_backfill = commands.add_parser(
        "init-backfill-traffic", help="Freeze and initialize the 92-day traffic backfill",
    )
    init_backfill.add_argument(
        "--target-end", type=_date, default=date.today(),
        help="Frozen exclusive target; start is computed as target minus 92 days",
    )
    init_backfill.add_argument(
        "--backfill-id", default="traffic-92-days",
        help="Persistent identifier; an existing identifier cannot be reinitialized",
    )
    backfill = commands.add_parser(
        "backfill-traffic", help="Process at most one oldest-first backfill window",
    )
    backfill.add_argument(
        "--backfill-id", default="traffic-92-days",
        help="Identifier previously created by init-backfill-traffic",
    )
    backfill.add_argument("--no-wait", action="store_true", help="Poll once; intended for integration testing")
    backfill_status = commands.add_parser(
        "backfill-status", help="Show persisted backfill state and recent backfill runs",
    )
    backfill_status.add_argument("--backfill-id", default="traffic-92-days")
    restore = commands.add_parser("restore-archive", help="Restore and verify one raw tar.gz archive")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--target-dir", type=Path,
                         help="Parent directory for restored run (default: raw_dir/restored)")
    purge = commands.add_parser("purge-archives", help="Delete archives past retained_until")
    purge.add_argument("--as-of", type=_date, default=date.today())
    ingest = commands.add_parser("ingest-usage")
    ingest.add_argument("csv", type=Path)
    reference = commands.add_parser("ingest-reference")
    reference.add_argument("--workloads", type=Path, required=True)
    reference.add_argument("--ip-lists", type=Path, required=True)
    report = commands.add_parser("report")
    report.add_argument("--kear-id", required=True)
    report.add_argument("--logical-application-name", required=True)
    report.add_argument("--application-label", action="append", required=True)
    report.add_argument("--environment", action="append", required=True)
    report.add_argument("--lookback-days", type=int)
    report.add_argument("--as-of", type=_date, default=date.today())
    batch_report = commands.add_parser("report-batch", help="Generate reports from a Microcosmos XLSX export")
    batch_report.add_argument("--microcosmos-xlsx", type=Path, required=True,
                              help="Microcosmos XLSX used to generate all non-empty Kear Id rows")
    batch_report.add_argument("--lookback-days", type=int)
    batch_report.add_argument("--as-of", type=_date, default=date.today())
    search = commands.add_parser(
        "search-rules", help="Find items in the latest SQLite rule snapshot",
    )
    search.add_argument("--items", type=Path, required=True,
                        help="One-column CSV, TXT, or XLSX file containing search items")
    search.add_argument("--out", type=Path,
                        help="Output XLSX path (default: output_dir/rules_items_search_<UTC timestamp>.xlsx)")
    search.add_argument("--case-sensitive", action="store_true",
                        help="Use case-sensitive text matching (ports are unaffected)")
    return root


def main(argv: Optional[List[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        settings = load_settings(args.config, args.env_file)
        log_path = Path(settings.log_dir) / f"rules-recertify-{date.today().isoformat()}.jsonl"
        configure_logging(log_path, args.verbose)
        db = Database(Path(settings.state_db))
        if args.command == "validate-config":
            print(json.dumps({
                "status": "ok",
                "pce": settings.pce,
                "workloader": str(settings.workloader),
                "workloader_config_file": settings.workloader_config_file,
                "state_db": settings.state_db,
                "raw_dir": settings.raw_dir,
                "output_dir": settings.output_dir,
                "log_dir": settings.log_dir,
                "traffic_batch_size": settings.traffic_batch_size,
                "batch_cooldown_seconds": settings.batch_cooldown_seconds,
                "rate_limit_retry_delay_minutes": settings.rate_limit_retry_delay_minutes,
                "rate_limit_max_retries": settings.rate_limit_max_retries,
                "transport_retry_delay_minutes": settings.transport_retry_delay_minutes,
                "transport_max_retries": settings.transport_max_retries,
                "empty_scope_ruleset_name_patterns": settings.empty_scope_ruleset_name_patterns,
                "traffic_environments": settings.traffic_environments,
                "dangerous_port_lists": settings.dangerous_port_lists,
                "permissive_rule_max_ips": settings.permissive_rule_max_ips,
                "smtp_enabled": settings.smtp_enabled,
            }, indent=2)); return 0
        if args.command == "init-db":
            db.initialize(); print(settings.state_db); return 0
        if args.command == "test-email":
            if not settings.smtp_enabled:
                raise ConfigurationError("smtp_enabled must be true to send a test email")
            test_id = "smtp-test-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            sent = send_summary(settings, {
                "run_id": test_id, "run_type": "SMTP_TEST", "status": "SUCCESS",
            })
            if not sent:
                raise RuntimeError("SMTP test message was not sent")
            print(json.dumps({"status": "sent", "run_id": test_id}, indent=2))
            return 0
        if args.command == "collect":
            end = args.traffic_end or date.today()
            start = args.traffic_start or end - timedelta(days=settings.traffic_window_days)
            print(json.dumps(collect(settings, start, end, args.no_wait,
                                     import_references=not args.skip_pce_import,
                                     pce_stub_dir=args.pce_stub_dir), indent=2, sort_keys=True)); return 0
        if args.command == "collect-policy":
            print(json.dumps(
                collect_policy(settings, pce_stub_dir=args.pce_stub_dir),
                indent=2, sort_keys=True,
            )); return 0
        if args.command == "collect-traffic":
            print(json.dumps(
                collect_traffic(settings, args.traffic_end, args.traffic_start, args.no_wait),
                indent=2, sort_keys=True,
            )); return 0
        if args.command == "init-backfill-traffic":
            print(json.dumps(
                initialize_backfill_traffic(settings, args.target_end, args.backfill_id),
                indent=2, sort_keys=True,
            )); return 0
        if args.command == "backfill-traffic":
            print(json.dumps(
                backfill_traffic(settings, args.backfill_id, args.no_wait),
                indent=2, sort_keys=True,
            )); return 0
        if args.command == "backfill-status":
            db.initialize()
            state = db.backfill_state(args.backfill_id)
            if state is None:
                raise ValueError(f"unknown backfill: {args.backfill_id}")
            with db.connect() as connection:
                rows = connection.execute(
                    "SELECT run_id,status,started_at,finished_at,details_json "
                    "FROM runs WHERE run_type='TRAFFIC_BACKFILL' "
                    "ORDER BY started_at DESC LIMIT 5"
                ).fetchall()
            recent = []
            for row in rows:
                details = json.loads(str(row[4] or "{}"))
                started = datetime.fromisoformat(str(row[2]))
                finished = (
                    datetime.fromisoformat(str(row[3]))
                    if row[3] else datetime.now(timezone.utc)
                )
                if started.tzinfo is None:
                    started = started.replace(tzinfo=timezone.utc)
                if finished.tzinfo is None:
                    finished = finished.replace(tzinfo=timezone.utc)
                elapsed_seconds = max(0.0, (finished - started).total_seconds())
                batches = details.get("batches", [])
                current_batch_elapsed_seconds = None
                current_batch_started_at = details.get("current_batch_started_at")
                if current_batch_started_at and not row[3]:
                    batch_started = datetime.fromisoformat(str(current_batch_started_at))
                    if batch_started.tzinfo is None:
                        batch_started = batch_started.replace(tzinfo=timezone.utc)
                    current_batch_elapsed_seconds = max(
                        0.0, (datetime.now(timezone.utc) - batch_started).total_seconds(),
                    )
                recent.append({
                    "run_id": row[0], "status": row[1],
                    "started_at": row[2], "finished_at": row[3],
                    "traffic_start": details.get("traffic_start"),
                    "traffic_end": details.get("traffic_end"),
                    "current_stage": details.get("current_stage"),
                    "current_batch": details.get("current_batch"),
                    "batch_count": details.get("batch_count"),
                    "batch_attempt_count": details.get("batch_attempt_count"),
                    "resumed_from_run_id": details.get("resumed_from_run_id"),
                    "resumed_completed_batches": details.get("resumed_completed_batches"),
                    "resume_batch": details.get("resume_batch"),
                    "resume_ignored_reason": details.get("resume_ignored_reason"),
                    "error": details.get("error"),
                    "blocking_reasons": details.get("blocking_reasons", []),
                    "failed_diagnostics_dir": details.get("failed_diagnostics_dir"),
                    "notification_status": details.get("notification_status"),
                    "notification_error": details.get("notification_error"),
                    "current_batch_elapsed_hours": (
                        round(current_batch_elapsed_seconds / 3600, 3)
                        if current_batch_elapsed_seconds is not None else None
                    ),
                    "elapsed_seconds": round(elapsed_seconds, 1),
                    "elapsed_hours": round(elapsed_seconds / 3600, 3),
                    "batch_durations": [
                        {
                            "batch": batch.get("batch"),
                            "duration_seconds": batch.get("duration_seconds"),
                            "duration_hours": batch.get("duration_hours"),
                        }
                        for batch in batches if isinstance(batch, dict)
                    ],
                })
            print(json.dumps({
                "backfill": dict(state),
                "active_run": next(
                    (run for run in recent if run["status"] == "RUNNING"), None,
                ),
                "recent_runs": recent,
            }, indent=2, sort_keys=True))
            return 0
        if args.command == "restore-archive":
            target_dir = args.target_dir or Path(settings.raw_dir) / "restored"
            print(restore_archive(args.archive, target_dir)); return 0
        if args.command == "purge-archives":
            db.initialize()
            print(json.dumps(purge_expired_archives(db, args.as_of), indent=2)); return 0
        if args.command == "ingest-usage":
            db.initialize(); run_id = "manual-" + uuid.uuid4().hex
            db.begin_run(run_id, "MANUAL_USAGE", {"csv": str(args.csv)})
            rows = list(read_rows(args.csv, ("rule_href", "async_query_status", "flows", "flows_by_port", "query_body")))
            count = db.upsert_usage(run_id, rows); db.finish_run(run_id, "SUCCESS", {"rows": count})
            print(count); return 0
        if args.command == "ingest-reference":
            db.initialize(); run_id = "reference-" + uuid.uuid4().hex
            db.begin_run(run_id, "REFERENCE", {"workloads": str(args.workloads), "ip_lists": str(args.ip_lists)})
            result = ingest_reference(db, args.workloads, args.ip_lists, run_id)
            db.finish_run(run_id, "SUCCESS", result); print(json.dumps(result, indent=2)); return 0
        if args.command == "report":
            db.initialize(); lookback = args.lookback_days or settings.default_lookback_days
            if not 1 <= lookback <= settings.retention_days:
                raise ValueError("lookback-days must be between 1 and retention_days")
            if len(args.application_label) != len(args.environment):
                raise ValueError("each --application-label must have one corresponding --environment")
            target = generate_workbook(db, Path(settings.output_dir), args.kear_id, args.logical_application_name,
                                       args.application_label, args.environment, lookback, args.as_of,
                                       raw_dir=Path(settings.raw_dir),
                                       dangerous_port_lists=settings.dangerous_port_lists,
                                       device=settings.pce,
                                       permissive_rule_max_ips=settings.permissive_rule_max_ips)
            print(target); return 0
        if args.command == "report-batch":
            db.initialize(); lookback = args.lookback_days or settings.default_lookback_days
            if not 1 <= lookback <= settings.retention_days:
                raise ValueError("lookback-days must be between 1 and retention_days")
            targets = generate_microcosmos_reports(
                db, args.microcosmos_xlsx, Path(settings.output_dir), Path(settings.raw_dir),
                lookback, args.as_of,
                dangerous_port_lists=settings.dangerous_port_lists,
                device=settings.pce,
                permissive_rule_max_ips=settings.permissive_rule_max_ips,
            )
            print("\n".join(str(target) for target in targets)); return 0
        if args.command == "search-rules":
            db.initialize()
            target = args.out or Path(settings.output_dir) / (
                "rules_items_search_" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + ".xlsx"
            )
            print(generate_rule_search_workbook(
                db, args.items, target, raw_dir=Path(settings.raw_dir),
                case_sensitive=args.case_sensitive,
            ))
            return 0
        raise AssertionError("unhandled command")
    except (ConfigurationError, ValueError, RuntimeError) as exc:
        LOG.error("%s", exc)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _date(value: str) -> date:
    try: return date.fromisoformat(value)
    except ValueError as exc: raise argparse.ArgumentTypeError("expected YYYY-MM-DD") from exc


if __name__ == "__main__":
    raise SystemExit(main())
