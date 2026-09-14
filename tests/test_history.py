import json, tempfile, unittest
from datetime import date
from pathlib import Path
from rules_recertify.history.database import Database, ensure_sqlite_compatible
from rules_recertify.history.metrics import summarize_usage

class HistoryTest(unittest.TestCase):
    def test_rule_history_tracks_first_import_and_content_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            base={"rule_href":"/r/1","ruleset_href":"/rs/1","services":"443 TCP"}
            db.upsert_rules([base], "2026-01-01T00:00:00+00:00")
            db.upsert_rules([base], "2026-02-01T00:00:00+00:00")
            db.upsert_rules([{**base,"services":"22 TCP"}], "2026-03-01T00:00:00+00:00")
            with db.connect() as connection:
                rows=connection.execute(
                    "SELECT snapshot_at,changed FROM rule_history ORDER BY snapshot_at"
                ).fetchall()
            self.assertEqual([tuple(row) for row in rows], [
                ("2026-01-01T00:00:00+00:00",1),
                ("2026-02-01T00:00:00+00:00",0),
                ("2026-03-01T00:00:00+00:00",1),
            ])
    def test_progress_update_does_not_finish_run(self):
        with tempfile.TemporaryDirectory() as directory:
            db = Database(Path(directory) / "db.sqlite")
            db.initialize()
            db.begin_run("progress", "COLLECTION", {"current_stage": "STARTING"})
            db.update_run_details("progress", {"current_stage": "POLLING", "current_batch": 2})
            with db.connect() as connection:
                row = connection.execute(
                    "SELECT status, finished_at, details_json FROM runs WHERE run_id='progress'"
                ).fetchone()
            self.assertEqual(row["status"], "RUNNING")
            self.assertIsNone(row["finished_at"])
            self.assertEqual(json.loads(row["details_json"])["current_batch"], 2)

    def test_production_sqlite_version_is_supported(self):
        ensure_sqlite_compatible((3, 26, 0))
        with self.assertRaises(RuntimeError):
            ensure_sqlite_compatible((3, 23, 0))
    def test_completed_result_is_not_replaced_by_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize(); db.begin_run("r","T",{})
            db.upsert_rules([{"rule_href":"/r/1","ruleset_href":"/rs/1"}],"now")
            base={"rule_href":"/r/1","query_body":json.dumps({"start_date":"2026-08-20T00:00:00Z","end_date":"2026-08-21T00:00:00Z"}),"flows_by_port":"443 TCP (2)"}
            db.upsert_usage("r",[{**base,"async_query_status":"completed","flows":"2"}])
            db.upsert_usage("r",[{**base,"async_query_status":"pending","flows":""}])
            with db.connect() as c: row=c.execute("select status,flows from usage_windows").fetchone()
            self.assertEqual(tuple(row),("completed",2))
    def test_hit_metrics(self):
        rows=[{"status":"completed","flows":2,"window_start":"2026-08-20T00:00:00Z","window_end":"2026-08-21T00:00:00Z"}]
        result=summarize_usage(rows,date(2026,8,22),2)
        self.assertEqual(result["hit_status"],"HAS_HIT"); self.assertEqual(result["days_since_last_hit"],1)
    def test_overlapping_windows_are_not_double_counted(self):
        rows=[
            {"status":"completed","flows":0,"window_start":"2026-08-19T00:00:00Z","window_end":"2026-08-21T00:00:00Z"},
            {"status":"completed","flows":0,"window_start":"2026-08-20T00:00:00Z","window_end":"2026-08-22T00:00:00Z"},
        ]
        result=summarize_usage(rows,date(2026,8,22),4)
        self.assertEqual(result["coverage_days"],3)
        self.assertEqual(result["hit_status"],"UNKNOWN_INCOMPLETE_COVERAGE")
