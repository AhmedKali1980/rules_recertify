import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from rules_recertify.history.database import Database


class CheckCollectionTest(unittest.TestCase):
    def test_success_is_reported_on_one_line(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite"
            raw_dir = root / "raw"
            config = root / "config.json"
            env_file = root / ".env"
            lock = root / "collect.lock"
            config.write_text(json.dumps({
                "pce": "pce",
                "state_db": str(database_path),
                "raw_dir": str(raw_dir),
            }), encoding="utf-8")
            env_file.write_text("", encoding="utf-8")
            env_file.chmod(0o600)

            database = Database(database_path)
            database.initialize()
            details = {
                "status": "SUCCESS", "batch_count": 1,
                "batches": [{"batch": 1}], "total": 2, "completed": 2,
                "pending": 0, "expired": 0, "unknown": 0,
            }
            database.begin_run("run-1", "COLLECTION", details)
            database.finish_run("run-1", "SUCCESS", details)
            run_dir = raw_dir / "run-1"
            run_dir.mkdir(parents=True)
            (run_dir / "manifest.json").write_text(json.dumps(details), encoding="utf-8")

            environment = dict(os.environ)
            environment.update({
                "RULES_RECERTIFY_CONFIG": str(config),
                "RULES_RECERTIFY_ENV_FILE": str(env_file),
                "RULES_RECERTIFY_LOCK": str(lock),
            })
            result = subprocess.run(
                ["bash", "scripts/check-collection.sh"], env=environment,
                check=False, capture_output=True, text=True,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertIn("OK run=run-1", result.stdout)
        self.assertIn("completed=2/2", result.stdout)

    def test_unlocked_running_run_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database_path = root / "state.sqlite"
            config = root / "config.json"
            env_file = root / ".env"
            config.write_text(json.dumps({
                "pce": "pce", "state_db": str(database_path),
                "raw_dir": str(root / "raw"),
            }), encoding="utf-8")
            env_file.write_text("", encoding="utf-8")
            env_file.chmod(0o600)
            database = Database(database_path)
            database.initialize()
            database.begin_run("run-interrupted", "COLLECTION", {})

            environment = dict(os.environ)
            environment.update({
                "RULES_RECERTIFY_CONFIG": str(config),
                "RULES_RECERTIFY_ENV_FILE": str(env_file),
                "RULES_RECERTIFY_LOCK": str(root / "collect.lock"),
            })
            result = subprocess.run(
                ["bash", "scripts/check-collection.sh"], env=environment,
                check=False, capture_output=True, text=True,
            )

        self.assertEqual(result.returncode, 2)
        self.assertEqual(len(result.stdout.splitlines()), 1)
        self.assertIn("CRITICAL run=run-interrupted", result.stdout)
        self.assertIn("interrupted_collection", result.stdout)
