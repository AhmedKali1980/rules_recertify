import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from rules_recertify.cli import main, parser


class CliTest(unittest.TestCase):
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
