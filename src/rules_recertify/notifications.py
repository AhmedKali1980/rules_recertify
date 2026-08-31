from __future__ import annotations

import json
import logging
import os
import smtplib
from email.message import EmailMessage
from typing import Mapping

from .config import Settings

LOG = logging.getLogger(__name__)


def send_summary(settings: Settings, summary: Mapping[str, object]) -> bool:
    if not settings.smtp_enabled:
        LOG.info("SMTP disabled; summary retained in local manifest")
        return False
    required = ("SMTP_HOST", "SMTP_FROM", "SMTP_TO")
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError("Missing SMTP variables: " + ", ".join(missing))
    message = EmailMessage()
    message["Subject"] = f"[{summary.get('status', 'UNKNOWN')}] Rules Recertify {summary.get('run_id', '')}"
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = os.environ["SMTP_TO"]
    message.set_content(json.dumps(dict(summary), indent=2, sort_keys=True))
    host, port = os.environ["SMTP_HOST"], int(os.getenv("SMTP_PORT", "25"))
    with smtplib.SMTP(host, port, timeout=30) as smtp:
        if os.getenv("SMTP_USE_TLS", "false").lower() in {"1", "true", "yes"}:
            smtp.starttls()
        if os.getenv("SMTP_USERNAME"):
            smtp.login(os.environ["SMTP_USERNAME"], os.getenv("SMTP_PASSWORD", ""))
        smtp.send_message(message)
    return True
