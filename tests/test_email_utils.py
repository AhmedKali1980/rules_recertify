import tempfile
import unittest
import json
from pathlib import Path
from unittest.mock import patch

from rules_recertify.collection_engine import _send_and_record_summary
from rules_recertify.config import Settings
from rules_recertify.email_utils import parse_recipients, send_email
from rules_recertify.history.database import Database
from rules_recertify.notifications import _policy_summary_lines, _summary_lines, send_summary


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
        self.assertEqual(rows["Run duration"], "0.03 hours")
        self.assertEqual(rows["Certifiable traffic coverage"], "91 days")
        self.assertEqual(rows["Successful traffic windows"], 13)
        self.assertEqual(rows["SQLite database size"], "12.50 MiB")

    def test_policy_summary_uses_export_metrics_and_specific_subject(self):
        summary = {
            "run_id": "policy-1", "run_type": "POLICY_COLLECTION", "status": "SUCCESS",
            "execution_duration_seconds": 3600, "snapshot_path": "/raw/snapshot",
            "ruleset_count": 2, "label_count": 3, "rule_count": 4,
            "reference_ingest": {"workloads": 5, "ip_list_members": 6},
            "reference_exports": ["export_wkld.csv", "export_labelgroups.csv"],
        }
        rows = dict(_policy_summary_lines(summary))
        self.assertEqual(rows["Rules exported"], 4)
        self.assertEqual(rows["Workloads imported"], 5)
        with patch.dict("os.environ", {
            "SMTP_HOST": "mail.internal", "SMTP_TO": "ops@example",
        }, clear=True), patch("rules_recertify.notifications.send_email") as mocked:
            self.assertTrue(send_summary(Settings(pce="pce", smtp_enabled=True), summary))
        args = mocked.call_args.args
        self.assertEqual(args[2], "[SUCCESS] Rules Recertify Policy Collection policy-1")
        self.assertIn("Rules Recertify policy collection summary", args[3])
        self.assertIn("Reference exports: export_wkld.csv; export_labelgroups.csv", args[3])
        self.assertNotIn("Traffic window", args[3])
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

    def test_notification_failure_is_persisted_without_changing_run_status(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Database(Path(directory) / "state.sqlite")
            database.initialize()
            details = {"run_id": "run", "status": "WARNING"}
            database.begin_run("run", "TRAFFIC_BACKFILL", details)
            database.finish_run("run", "WARNING", details)
            with patch(
                "rules_recertify.collection_engine.send_summary",
                side_effect=RuntimeError("SMTP unavailable"),
            ):
                _send_and_record_summary(
                    database, "run", Settings(pce="pce", smtp_enabled=True), details,
                )
            with database.connect() as connection:
                row = connection.execute(
                    "SELECT status,details_json FROM runs WHERE run_id='run'"
                ).fetchone()
            stored = json.loads(row[1])
            self.assertEqual(row[0], "WARNING")
            self.assertEqual(stored["notification_status"], "FAILED")
            self.assertEqual(stored["notification_error"], "SMTP unavailable")


if __name__ == "__main__":
    unittest.main()
