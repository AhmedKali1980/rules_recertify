import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from rules_recertify.workloader.runner import WorkloaderRunner


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

