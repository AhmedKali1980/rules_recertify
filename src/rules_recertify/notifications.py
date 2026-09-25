from __future__ import annotations

import html
import logging
import os
from pathlib import Path
from typing import Mapping

from .config import Settings
from .email_utils import parse_recipients, send_email

LOG = logging.getLogger(__name__)


def _summary_lines(summary: Mapping[str, object]) -> list[tuple[str, object]]:
    return [
        ("Run ID", summary.get("run_id", "")),
        ("Run type", summary.get("run_type", "")),
        ("Final status", summary.get("status", "UNKNOWN")),
        ("Run duration", f"{summary.get('execution_duration_seconds', 0)} seconds"),
        ("Certifiable traffic coverage", f"{summary.get('certifiable_days', 0)} days"),
        ("Successful traffic windows", summary.get("successful_window_count", 0)),
        ("SQLite database size", summary.get("sqlite_database_size_human", "0 B")),
        ("SQLite database size (bytes)", summary.get("sqlite_database_size_bytes", 0)),
        ("Traffic window", f"[{summary.get('traffic_start', '')}, {summary.get('traffic_end', '')})"),
        ("Total async results", summary.get("total", 0)),
        ("Completed", summary.get("completed", 0)),
        ("Pending", summary.get("pending", 0)),
        ("Expired", summary.get("expired", 0)),
        ("Unknown / empty", summary.get("unknown", 0)),
        ("Invalid query bodies", summary.get("invalid_query_body_count", 0)),
        ("Invalid port details", summary.get("invalid_flows_by_port_count", 0)),
        ("Processed rules", summary.get("processed_rule_count", 0)),
        ("Not in filtered scope", summary.get("not_in_scope_rule_count", 0)),
        ("Documented exceptions", summary.get("documented_exception_rule_count", 0)),
        ("Blocking problems", summary.get("blocking_rule_count", 0)),
        ("Blocking reasons", "; ".join(summary.get("blocking_reasons", []))),
        ("Exception reasons", "; ".join(summary.get("documented_exception_reasons", []))),
        ("Audit workbook", summary.get("traffic_audit_workbook", "")),
    ]


def send_summary(
    settings: Settings, summary: Mapping[str, object], attachment_path: Path | None = None,
) -> bool:
    if not settings.smtp_enabled:
        LOG.info("SMTP disabled; summary retained in local manifest")
        return False
    missing = []
    if not (os.getenv("SMTP_HOST") or os.getenv("SMTP_SERVER")):
        missing.append("SMTP_HOST/SMTP_SERVER")
    if not os.getenv("SMTP_TO"):
        missing.append("SMTP_TO")
    if missing:
        raise RuntimeError("Missing SMTP variables: " + ", ".join(missing))
    rows = _summary_lines(summary)
    body_text = "Rules Recertify final execution state\n\n" + "\n".join(
        f"{name}: {value}" for name, value in rows
    )
    body_html = (
        "<h2>Rules Recertify final execution state</h2>"
        "<table border='1' cellpadding='6' cellspacing='0'>"
        + "".join(
            f"<tr><th>{html.escape(str(name))}</th><td>{html.escape(str(value))}</td></tr>"
            for name, value in rows
        )
        + "</table>"
    )
    conf = {name: value for name, value in os.environ.items() if name.startswith("SMTP_")}
    send_email(
        conf, parse_recipients(os.environ["SMTP_TO"]),
        f"[{summary.get('status', 'UNKNOWN')}] Rules Recertify {summary.get('run_id', '')}",
        body_text, body_html, attachment_path,
    )
    return True
