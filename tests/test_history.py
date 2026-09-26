import json, tempfile, unittest
from datetime import date
from pathlib import Path
from rules_recertify.history.database import (
    Database, RUN_TYPE_BACKFILL, RUN_TYPE_POLICY, RUN_TYPE_TRAFFIC,
    SCHEMA_VERSION, ensure_sqlite_compatible,
)
from rules_recertify.history.metrics import summarize_usage

class HistoryTest(unittest.TestCase):
    def test_new_database_uses_latest_explicit_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            db.initialize()
            with db.connect() as connection:
                versions=[row[0] for row in connection.execute("SELECT version FROM schema_version")]
                columns={row[1] for row in connection.execute("PRAGMA table_info(rules)")}
                tables={row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )}
            self.assertEqual(versions, [SCHEMA_VERSION])
            self.assertTrue({"is_present", "last_seen_snapshot_id"} <= columns)
            self.assertTrue({"policy_snapshots", "traffic_cursors", "traffic_windows",
                             "backfill_states", "run_archives"} <= tables)

    def test_schema_version_one_is_migrated_without_losing_rules(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"db.sqlite"
            import sqlite3
            with sqlite3.connect(str(path)) as connection:
                connection.executescript("""
                CREATE TABLE schema_version(version INTEGER PRIMARY KEY);
                INSERT INTO schema_version VALUES(1);
                CREATE TABLE rules(
                 rule_href TEXT PRIMARY KEY, ruleset_href TEXT NOT NULL, ruleset_name TEXT,
                 ruleset_scope TEXT, ruleset_enabled INTEGER, rule_type TEXT, rule_description TEXT,
                 rule_enabled INTEGER, unscoped_consumers INTEGER, source_text TEXT,
                 destination_text TEXT, services TEXT, raw_json TEXT NOT NULL, snapshot_at TEXT NOT NULL
                );
                INSERT INTO rules VALUES('/r/1','/rs/1','','',1,'allow','',1,0,'','','443 TCP','{}','old');
                """)
            db=Database(path); db.initialize()
            with db.connect() as connection:
                rule=connection.execute(
                    "SELECT rule_href,is_present,last_seen_snapshot_id FROM rules"
                ).fetchone()
                versions=[row[0] for row in connection.execute("SELECT version FROM schema_version")]
            self.assertEqual(tuple(rule), ("/r/1", 1, None))
            self.assertEqual(versions, [SCHEMA_VERSION])

    def test_complete_policy_snapshot_marks_absent_rules_atomically(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            old={"rule_href":"/r/old","ruleset_href":"/rs/1"}
            kept={"rule_href":"/r/kept","ruleset_href":"/rs/1"}
            db.complete_policy_snapshot("snapshot-1", "run-1", [old, kept], "2026-01-01")
            db.complete_policy_snapshot("snapshot-2", "run-2", [kept], "2026-01-02")
            db.upsert_rules([{**old, "services": "22 TCP"}], "2026-01-03")
            with db.connect() as connection:
                states={row[0]:(row[1],row[2]) for row in connection.execute(
                    "SELECT rule_href,is_present,last_seen_snapshot_id FROM rules"
                )}
            self.assertEqual(states["/r/old"], (0, "snapshot-1"))
            self.assertEqual(states["/r/kept"], (1, "snapshot-2"))
            self.assertEqual(db.current_policy_snapshot()["snapshot_id"], "snapshot-2")

    def test_failed_policy_snapshot_does_not_change_current_state(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            first={"rule_href":"/r/1","ruleset_href":"/rs/1","services":"443 TCP"}
            db.complete_policy_snapshot("snapshot-1", "run-1", [first], "2026-01-01")
            with self.assertRaises(Exception):
                db.complete_policy_snapshot(
                    "snapshot-1", "run-2",
                    [{**first,"services":"22 TCP"}], "2026-01-02",
                )
            with db.connect() as connection:
                row=connection.execute(
                    "SELECT services,snapshot_at,is_present FROM rules WHERE rule_href='/r/1'"
                ).fetchone()
            self.assertEqual(tuple(row), ("443 TCP", "2026-01-01", 1))

    def test_traffic_cursor_advances_only_after_success(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            db.begin_traffic_window("weekly", RUN_TYPE_TRAFFIC, "run-1", "2026-01-01", "2026-01-08")
            db.finish_traffic_window("weekly", RUN_TYPE_TRAFFIC, "run-1", "2026-01-01", "2026-01-08", False, "PCE error")
            failed=db.traffic_cursor("weekly")
            self.assertIsNone(failed["last_successful_end"])
            self.assertEqual(failed["last_status"], "FAILED")
            self.assertEqual(failed["in_progress_start"], "2026-01-01")
            with self.assertRaisesRegex(ValueError, "replayed unchanged"):
                db.begin_traffic_window("weekly", RUN_TYPE_TRAFFIC, "wrong", "2026-01-01", "2026-01-09")
            db.begin_traffic_window("weekly", RUN_TYPE_TRAFFIC, "run-2", "2026-01-01", "2026-01-08")
            db.finish_traffic_window("weekly", RUN_TYPE_TRAFFIC, "run-2", "2026-01-01", "2026-01-08", True)
            success=db.traffic_cursor("weekly")
            self.assertEqual(success["last_successful_end"], "2026-01-08")
            self.assertEqual(success["last_status"], "SUCCESS")
            with self.assertRaisesRegex(ValueError, "must start at cursor"):
                db.begin_traffic_window("weekly", RUN_TYPE_TRAFFIC, "gap", "2026-01-09", "2026-01-16")

    def test_certification_coverage_counts_unique_successful_days(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            with db.connect() as connection:
                connection.executemany(
                    "INSERT INTO traffic_windows VALUES(?,?,?,?,?,?,?,?)",
                    [
                        (RUN_TYPE_BACKFILL,"2026-01-01","2026-01-08","one","SUCCESS","","now","now"),
                        (RUN_TYPE_BACKFILL,"2026-01-08","2026-01-15","two","SUCCESS","","now","now"),
                        (RUN_TYPE_TRAFFIC,"2026-01-08","2026-01-15","duplicate","SUCCESS","","now","now"),
                        (RUN_TYPE_TRAFFIC,"2026-01-15","2026-01-22","failed","FAILED","","now","now"),
                    ],
                )
            self.assertEqual(db.certification_coverage(), {
                "certifiable_days": 14,
                "successful_window_count": 2,
            })

    def test_backfill_state_retries_and_completes_without_skipping(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            db.initialize_backfill("initial", "2026-01-01", "2026-01-10")
            first=db.begin_backfill_window("initial", "run-1")
            self.assertEqual(first["window_start"], "2026-01-01")
            db.update_backfill_window("initial", "run-1", "2026-01-08", False)
            retry=db.begin_backfill_window("initial", "run-2")
            self.assertEqual(retry["window_start"], "2026-01-01")
            db.update_backfill_window("initial", "run-2", "2026-01-08", True)
            final=db.begin_backfill_window("initial", "run-3")
            self.assertEqual(final["window_start"], "2026-01-08")
            db.update_backfill_window("initial", "run-3", "2026-01-10", True)
            state=db.backfill_state("initial")
            self.assertEqual(state["status"], "COMPLETED")
            self.assertEqual(state["next_window_start"], "2026-01-10")
            with self.assertRaisesRegex(ValueError, "already complete"):
                db.begin_backfill_window("initial", "run-4")

    def test_92_day_backfill_has_thirteen_full_windows_and_one_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            db.initialize_backfill("history", "2026-06-20", "2026-09-20")
            windows=[]
            for index in range(14):
                lease=db.begin_backfill_window("history", f"run-{index}")
                windows.append((lease["window_start"],lease["window_end"]))
                db.update_backfill_window("history", f"run-{index}", lease["window_end"], True)
            state=db.backfill_state("history")
            self.assertEqual(state["status"],"COMPLETED")
            self.assertEqual(state["next_window_start"],"2026-09-20")
            self.assertEqual(
                [(date.fromisoformat(end)-date.fromisoformat(start)).days for start,end in windows],
                [7]*13+[1],
            )
            self.assertTrue(all(windows[index][1] == windows[index+1][0] for index in range(13)))
            with self.assertRaisesRegex(ValueError,"cannot be reinitialized"):
                db.initialize_backfill("history", "2026-06-20", "2026-09-20")

    def test_run_types_and_archive_metadata_are_available(self):
        self.assertEqual(
            (RUN_TYPE_POLICY, RUN_TYPE_TRAFFIC, RUN_TYPE_BACKFILL),
            ("POLICY_COLLECTION", "TRAFFIC_COLLECTION", "TRAFFIC_BACKFILL"),
        )
        with tempfile.TemporaryDirectory() as directory:
            db=Database(Path(directory)/"db.sqlite"); db.initialize()
            db.record_archive("run-1", "TRAFFIC", "/raw/run-1.tar.gz", "abc", 42, "2027-07-01")
            with db.connect() as connection:
                row=connection.execute("SELECT archive_kind,status,size_bytes FROM run_archives").fetchone()
            self.assertEqual(tuple(row), ("TRAFFIC", "VERIFIED", 42))

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
