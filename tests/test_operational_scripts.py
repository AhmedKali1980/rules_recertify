import fcntl
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

from rules_recertify.history.database import Database, RUN_TYPE_BACKFILL, RUN_TYPE_TRAFFIC


FAKE='''#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$RULES_RECERTIFY_TEST_LOG"
'''


class OperationalScriptsTest(unittest.TestCase):
    def _setup(self, root):
        config=root/"config.json"; env_file=root/".env"; cli=root/"fake-cli"; log=root/"calls.log"
        config.write_text(json.dumps({"pce":"p","state_db":str(root/"state.sqlite"),"raw_dir":str(root/"raw")}))
        env_file.write_text(""); env_file.chmod(0o600)
        cli.write_text(FAKE); cli.chmod(cli.stat().st_mode|stat.S_IEXEC)
        environment=dict(os.environ)
        environment.update({
            "RULES_RECERTIFY_CONFIG":str(config),"RULES_RECERTIFY_ENV_FILE":str(env_file),
            "RULES_RECERTIFY_LOCK":str(root/"shared.lock"),"RULES_RECERTIFY_CLI":str(cli),
            "RULES_RECERTIFY_TEST_LOG":str(log),"RULES_RECERTIFY_TRAFFIC_END":"2026-09-20",
            "RULES_RECERTIFY_NOW":"2026-09-19T03:00:00+00:00","RULES_RECERTIFY_WEEKDAY":"6",
        })
        return Database(root/"state.sqlite"),environment,log

    def test_daily_policy_uses_dedicated_command(self):
        with tempfile.TemporaryDirectory() as directory:
            _,environment,log=self._setup(Path(directory))
            result=subprocess.run(["bash","scripts/daily-policy-collect.sh"],env=environment,check=False)
            self.assertEqual(result.returncode,0)
            self.assertIn("collect-policy",log.read_text())

    def test_shared_lock_prevents_collector_collision(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); _,environment,log=self._setup(root)
            with (root/"shared.lock").open("w") as handle:
                fcntl.flock(handle,fcntl.LOCK_EX|fcntl.LOCK_NB)
                result=subprocess.run(["bash","scripts/daily-policy-collect.sh"],env=environment,
                                      capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,75)
            self.assertIn("Another Rules Recertify collection",result.stderr)
            self.assertFalse(log.exists())

    def test_sunday_retry_is_noop_after_successful_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); database,environment,log=self._setup(root); database.initialize()
            database.begin_traffic_window("weekly",RUN_TYPE_TRAFFIC,"run","2026-09-13","2026-09-20")
            database.finish_traffic_window("weekly",RUN_TYPE_TRAFFIC,"run","2026-09-13","2026-09-20",True)
            result=subprocess.run(["bash","scripts/weekly-traffic-collect.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("already complete",result.stdout)
            self.assertFalse(log.exists())

    def test_weekly_wrapper_requests_available_server_local_date_when_due(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); database,environment,log=self._setup(root); database.initialize()
            result=subprocess.run(["bash","scripts/weekly-traffic-collect.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("collect-traffic --traffic-end 2026-09-20",log.read_text())

    def test_backfill_daily_cron_is_gated_to_one_attempt_per_two_days(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); database,environment,log=self._setup(root); database.initialize()
            database.initialize_backfill("traffic-92-days","2026-06-20","2026-09-20")
            database.begin_run("recent",RUN_TYPE_BACKFILL,{})
            with database.connect() as connection:
                connection.execute("UPDATE runs SET started_at=? WHERE run_id='recent'",("2026-09-18T03:00:00+00:00",))
            result=subprocess.run(["bash","scripts/backfill-traffic.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn("less than two days",result.stdout)
            self.assertFalse(log.exists())

    def test_reference_cron_has_daily_weekly_retry_and_backfill_entries(self):
        cron=Path("config/rules-recertify.cron").read_text()
        self.assertIn("10 0 * * *",cron)
        self.assertIn("0 1 * * 0",cron)
        self.assertIn("0 2 * * 0",cron)
        self.assertIn("0 3 * * 1-6",cron)
