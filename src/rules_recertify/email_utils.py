from __future__ import annotations

import mimetypes
import smtplib
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable, Mapping


def is_truthy(value: str) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "y"}


def parse_recipients(value: str) -> list[str]:
    return [
        token.strip()
        for token in str(value or "").replace(";", ",").split(",")
        if token.strip()
    ]


def send_email(
    conf: Mapping[str, str], recipients: Iterable[str], subject: str,
    body_text: str, body_html: str = "", attachment_path: Path | None = None,
) -> None:
    recipients = [recipient for recipient in recipients if recipient]
    if not recipients:
        raise ValueError("No email recipients provided")
    host = (conf.get("SMTP_HOST", "") or conf.get("SMTP_SERVER", "")).strip()
    if not host:
        raise ValueError("Missing SMTP_HOST (or SMTP_SERVER)")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = conf.get("SMTP_FROM", "").strip() or recipients[0]
    message["To"] = ", ".join(recipients)
    if conf.get("SMTP_REPLY_TO", "").strip():
        message["Reply-To"] = conf["SMTP_REPLY_TO"].strip()
    message.set_content(body_text)
    if body_html:
        message.add_alternative(body_html, subtype="html")

    if attachment_path and attachment_path.is_file():
        mime, _encoding = mimetypes.guess_type(attachment_path.name)
        maintype, subtype = (mime or "application/octet-stream").split("/", 1)
        message.add_attachment(
            attachment_path.read_bytes(), maintype=maintype, subtype=subtype,
            filename=attachment_path.name,
        )

    port = int(conf.get("SMTP_PORT", "25") or 25)
    timeout = float(conf.get("SMTP_TIMEOUT", "30") or 30)
    use_ssl = is_truthy(conf.get("SMTP_USE_SSL", ""))
    connection = smtplib.SMTP_SSL if use_ssl else smtplib.SMTP
    with connection(host, port, timeout=timeout) as smtp:
        if is_truthy(conf.get("SMTP_USE_TLS", "")) and not use_ssl:
            smtp.starttls()
        username = (conf.get("SMTP_USERNAME", "") or conf.get("SMTP_USER", "")).strip()
        if username:
            smtp.login(username, conf.get("SMTP_PASSWORD", ""))
        smtp.send_message(message)
