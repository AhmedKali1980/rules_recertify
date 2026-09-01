import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rules_recertify.workloader.runner import WorkloaderError, WorkloaderRunner


class WorkloaderRunnerTest(unittest.TestCase):
    def test_config_file_is_passed_as_global_option(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = WorkloaderRunner(
                root / "workloader",
                "pce-prd-l3.wr",
                root / "workloader.log",
                root / "pce.yaml",
            )
            completed = subprocess.CompletedProcess([], 0, "", "")
            with patch("subprocess.run", return_value=completed) as run:
                runner.run(["ruleset-export", "--output-file", "rulesets.csv"])

        command = run.call_args.args[0]
        self.assertEqual(command[1:3], ["--config-file", str(root / "pce.yaml")])
        self.assertIn("pce-prd-l3.wr", command)
        self.assertNotIn("capture_output", run.call_args.kwargs)
        self.assertIs(run.call_args.kwargs["stderr"], subprocess.STDOUT)

    def test_sigkill_has_actionable_bounded_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = WorkloaderRunner(root / "workloader", "pce", root / "workloader.log")
            completed = subprocess.CompletedProcess([], -9, None, None)

            def killed(*args, **kwargs):
                kwargs["stdout"].write(b"x" * 20000)
                return completed

            with patch("subprocess.run", side_effect=killed):
                with self.assertRaises(WorkloaderError) as raised:
                    runner.run(["rule-export"])

        message = str(raised.exception)
        self.assertIn("SIGKILL", message)
        self.assertIn("kernel OOM log", message)
        self.assertIn("bytes omitted", message)
        self.assertIn("workloader-output.log", message)
        self.assertLess(len(message), 13000)

    def test_http_429_has_rate_limit_hint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runner = WorkloaderRunner(root / "workloader", "pce", root / "workloader.log")
            completed = subprocess.CompletedProcess([], 1, None, None)

            def rate_limited(*args, **kwargs):
                kwargs["stdout"].write(
                    b"GetTrafficAnalysisAPI response status code: 429\n"
                    b"received a 429. pause between attempts\n"
                )
                return completed

            with patch("subprocess.run", side_effect=rate_limited):
                with self.assertRaises(WorkloaderError) as raised:
                    runner.run(["rule-export"])

        self.assertIn("PCE/API rate limit HTTP 429", str(raised.exception))
        self.assertIn("wait before submitting more queries", str(raised.exception))
