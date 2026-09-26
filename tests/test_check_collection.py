import json
import os
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from rules_recertify.history.database import Database, RUN_TYPE_POLICY, RUN_TYPE_TRAFFIC


class CheckCollectionTest(unittest.TestCase):
    def _environment(self, root):
        database_path=root/"state.sqlite"; raw=root/"raw"; snapshot=raw/"snapshot"
        config=root/"config.json"; env_file=root/".env"
        config.write_text(json.dumps({"pce":"pce","state_db":str(database_path),"raw_dir":str(raw)}))
        env_file.write_text(""); env_file.chmod(0o600)
        database=Database(database_path); database.initialize()
        database.begin_run("policy-1",RUN_TYPE_POLICY,{})
        snapshot.mkdir(parents=True); (snapshot/"manifest.json").write_text("{}")
        database.complete_policy_snapshot(
            "policy-1","policy-1",[{"rule_href":"/r/1","ruleset_href":"/rs/1"}],
            snapshot_path=str(snapshot),manifest_path=str(snapshot/"manifest.json"),run_details={},
        )
        database.begin_run("traffic-1",RUN_TYPE_TRAFFIC,{})
        database.begin_traffic_window("weekly",RUN_TYPE_TRAFFIC,"traffic-1","2026-09-13","2026-09-20")
        database.finish_traffic_window(
            "weekly",RUN_TYPE_TRAFFIC,"traffic-1","2026-09-13","2026-09-20",True,
            run_details={},run_status="SUCCESS",
        )
        archive=raw/"archives"/"traffic-1.tar.gz"; archive.parent.mkdir(); archive.write_bytes(b"archive")
        database.record_archive("traffic-1","TRAFFIC",str(archive),"abc",7,"2028-01-01")
        database.initialize_backfill("traffic-92-days","2026-06-20","2026-09-20")
        environment=dict(os.environ)
        environment.update({
            "RULES_RECERTIFY_CONFIG":str(config),"RULES_RECERTIFY_ENV_FILE":str(env_file),
            "RULES_RECERTIFY_LOCK":str(root/"collect.lock"),
            "RULES_RECERTIFY_NOW":"2026-09-20T01:30:00+00:00",
        })
        return database,environment,archive

    def test_healthy_production_state_is_reported_on_one_line(self):
        with tempfile.TemporaryDirectory() as directory:
            _,environment,_=self._environment(Path(directory))
            result=subprocess.run(["bash","scripts/check-collection.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertEqual(len(result.stdout.splitlines()),1)
        self.assertIn("OK policy=SUCCESS:policy-1 traffic=SUCCESS:traffic-1",result.stdout)
        self.assertIn("weekly_cursor=2026-09-20",result.stdout)
        self.assertIn("backfill=PENDING:2026-06-20/2026-09-20",result.stdout)
        self.assertIn("archive=VERIFIED",result.stdout)
        self.assertIn("disk_used=",result.stdout)

    def test_unlocked_running_run_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            database,environment,_=self._environment(Path(directory))
            database.begin_run("interrupted",RUN_TYPE_POLICY,{})
            result=subprocess.run(["bash","scripts/check-collection.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,2)
        self.assertIn("interrupted_runs=1",result.stdout)

    def test_success_with_exceptions_is_healthy(self):
        with tempfile.TemporaryDirectory() as directory:
            database,environment,_=self._environment(Path(directory))
            with database.connect() as connection:
                connection.execute(
                    "UPDATE runs SET status='SUCCESS_WITH_EXCEPTIONS' "
                    "WHERE run_id='traffic-1'"
                )
            result=subprocess.run(["bash","scripts/check-collection.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)
        self.assertIn("traffic=SUCCESS_WITH_EXCEPTIONS:traffic-1",result.stdout)

    def test_missing_expected_sunday_archive_is_critical(self):
        with tempfile.TemporaryDirectory() as directory:
            _,environment,archive=self._environment(Path(directory)); archive.unlink()
            result=subprocess.run(["bash","scripts/check-collection.sh"],env=environment,
                                  capture_output=True,text=True,check=False)
        self.assertEqual(result.returncode,2)
        self.assertIn("archive=MISSING:traffic-1",result.stdout)
