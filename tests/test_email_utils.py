import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rules_recertify.email_utils import parse_recipients, send_email
from rules_recertify.notifications import _summary_lines


class _SMTP:
    instance = None

    def __init__(self, host, port, timeout):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.message = None
        _SMTP.instance = self

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def starttls(self):
        self.tls = True

    def login(self, username, password):
        self.credentials = (username, password)

    def send_message(self, message):
        self.message = message


class EmailUtilsTest(unittest.TestCase):
    def test_summary_contains_operational_metrics_in_english(self):
        rows = dict(_summary_lines({
            "execution_duration_seconds": 123.4,
            "certifiable_days": 91,
            "successful_window_count": 13,
            "sqlite_database_size_human": "12.50 MiB",
            "sqlite_database_size_bytes": 13107200,
        }))
        self.assertEqual(rows["Run duration"], "123.4 seconds")
        self.assertEqual(rows["Certifiable traffic coverage"], "91 days")
        self.assertEqual(rows["Successful traffic windows"], 13)
        self.assertEqual(rows["SQLite database size"], "12.50 MiB")
    def test_recipient_parser_accepts_commas_and_semicolons(self):
        self.assertEqual(parse_recipients("a@example; b@example,c@example"), [
            "a@example", "b@example", "c@example",
        ])

    def test_send_email_supports_aliases_and_xlsx_attachment(self):
        with tempfile.TemporaryDirectory() as directory:
            attachment = Path(directory) / "audit.xlsx"
            attachment.write_bytes(b"xlsx")
            with patch("rules_recertify.email_utils.smtplib.SMTP", _SMTP):
                send_email({
                    "SMTP_SERVER": "mail.internal",
                    "SMTP_USER": "service",
                    "SMTP_PASSWORD": "secret",
                }, ["ops@example"], "subject", "text", "<b>html</b>", attachment)
        smtp = _SMTP.instance
        self.assertEqual(smtp.host, "mail.internal")
        self.assertEqual(smtp.credentials, ("service", "secret"))
        self.assertIn("audit.xlsx", smtp.message.as_string())


if __name__ == "__main__":
    unittest.main()
