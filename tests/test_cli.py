import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rules_recertify.cli import main, parser


class CliTest(unittest.TestCase):
    def test_collect_policy_accepts_reference_stub_without_traffic_options(self):
        args = parser().parse_args([
            "collect-policy", "--pce-stub-dir", "reference stubs",
        ])
        self.assertEqual(args.command, "collect-policy")
        self.assertEqual(args.pce_stub_dir, Path("reference stubs"))
        self.assertFalse(hasattr(args, "traffic_start"))

    def test_collect_traffic_accepts_initial_window_seed_and_available_boundary(self):
        args = parser().parse_args([
            "collect-traffic", "--traffic-start", "2026-08-20",
            "--traffic-end", "2026-08-27", "--no-wait",
        ])
        self.assertEqual(args.command, "collect-traffic")
        self.assertEqual(args.traffic_start.isoformat(), "2026-08-20")
        self.assertEqual(args.traffic_end.isoformat(), "2026-08-27")
        self.assertTrue(args.no_wait)

    def test_rule_search_accepts_items_output_and_case_mode(self):
        args = parser().parse_args([
            "search-rules", "--items", "items.csv", "--out", "result.xlsx",
            "--case-sensitive",
        ])
        self.assertEqual(args.items, Path("items.csv"))
        self.assertEqual(args.out, Path("result.xlsx"))
        self.assertTrue(args.case_sensitive)

    def test_batch_report_accepts_microcosmos_workbook(self):
        args = parser().parse_args([
            "report-batch", "--microcosmos-xlsx", "microcosmos.xlsx",
            "--lookback-days", "180", "--as-of", "2026-09-10",
        ])
        self.assertEqual(args.microcosmos_xlsx, Path("microcosmos.xlsx"))
        self.assertEqual(args.as_of.isoformat(), "2026-09-10")

    def test_report_options_form_ordered_application_environment_pairs(self):
        args = parser().parse_args([
            "report", "--kear-id", "k", "--logical-application-name", "app",
            "--application-label", "APP_PRD", "--environment", "PRD",
            "--application-label", "APP_UAT", "--environment", "UAT",
        ])
        self.assertEqual(args.application_label, ["APP_PRD", "APP_UAT"])
        self.assertEqual(args.environment, ["PRD", "UAT"])

    def test_validate_config_displays_effective_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = root / "config.json"
            env_file = root / "missing.env"
            expected_db = str(root / "state.sqlite")
            config.write_text(json.dumps({
                "pce": "pce-test",
                "state_db": expected_db,
                "raw_dir": str(root / "raw"),
                "output_dir": str(root / "output"),
                "log_dir": str(root / "logs"),
            }), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = main(["--config", str(config), "--env-file", str(env_file), "validate-config"])
            self.assertEqual(result, 0)
            payload = json.loads(output.getvalue())
            self.assertEqual(payload["state_db"], expected_db)
            self.assertEqual(payload["raw_dir"], str(root / "raw"))
            self.assertIn("traffic_batch_size", payload)
