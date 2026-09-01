from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from .collection import collect
from .config import ConfigurationError, load_settings
from .history.database import Database
from .logging_utils import configure_logging
from .reference import ingest_reference
from .reporting.workbook import generate_workbook
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
    collect_p = commands.add_parser("collect")
    collect_p.add_argument("--traffic-start", type=_date)
    collect_p.add_argument("--traffic-end", type=_date)
    collect_p.add_argument("--no-wait", action="store_true", help="Poll once; intended for integration testing")
    ingest = commands.add_parser("ingest-usage")
    ingest.add_argument("csv", type=Path)
    reference = commands.add_parser("ingest-reference")
    reference.add_argument("--workloads", type=Path, required=True)
    reference.add_argument("--ip-lists", type=Path, required=True)
    report = commands.add_parser("report")
    report.add_argument("--kear-id", required=True)
    report.add_argument("--logical-application-name", required=True)
    report.add_argument("--application-label", action="append", required=True)
    report.add_argument("--environment", required=True)
    report.add_argument("--lookback-days", type=int)
    report.add_argument("--as-of", type=_date, default=date.today())
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
                "smtp_enabled": settings.smtp_enabled,
            }, indent=2)); return 0
        if args.command == "init-db":
            db.initialize(); print(settings.state_db); return 0
        if args.command == "collect":
            end = args.traffic_end or date.today()
            start = args.traffic_start or end - timedelta(days=settings.traffic_window_days)
            print(json.dumps(collect(settings, start, end, args.no_wait), indent=2, sort_keys=True)); return 0
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
            target = generate_workbook(db, Path(settings.output_dir), args.kear_id, args.logical_application_name,
                                       args.application_label, args.environment, lookback, args.as_of)
            print(target); return 0
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
