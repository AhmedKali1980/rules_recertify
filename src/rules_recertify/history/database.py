"""SQLite persistence with idempotent usage-window ingestion."""
from __future__ import annotations

import json
import hashlib
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

SCHEMA_VERSION = 2
RUN_TYPE_POLICY = "POLICY_COLLECTION"
RUN_TYPE_TRAFFIC = "TRAFFIC_COLLECTION"
RUN_TYPE_BACKFILL = "TRAFFIC_BACKFILL"

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version(version) VALUES (2);
CREATE TABLE IF NOT EXISTS runs(
 run_id TEXT PRIMARY KEY, run_type TEXT NOT NULL, status TEXT NOT NULL,
 started_at TEXT NOT NULL, finished_at TEXT, details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS artifacts(
 run_id TEXT NOT NULL REFERENCES runs(run_id), kind TEXT NOT NULL, path TEXT NOT NULL,
 sha256 TEXT NOT NULL, row_count INTEGER, PRIMARY KEY(run_id, kind, path)
);
CREATE TABLE IF NOT EXISTS rules(
 rule_href TEXT PRIMARY KEY, ruleset_href TEXT NOT NULL, ruleset_name TEXT,
 ruleset_scope TEXT, ruleset_enabled INTEGER, rule_type TEXT, rule_description TEXT,
 rule_enabled INTEGER, unscoped_consumers INTEGER, source_text TEXT,
 destination_text TEXT, services TEXT, raw_json TEXT NOT NULL, snapshot_at TEXT NOT NULL,
 is_present INTEGER NOT NULL DEFAULT 1, last_seen_snapshot_id TEXT
);
CREATE TABLE IF NOT EXISTS rule_history(
 rule_href TEXT NOT NULL, snapshot_at TEXT NOT NULL, content_hash TEXT NOT NULL,
 changed INTEGER NOT NULL, PRIMARY KEY(rule_href, snapshot_at)
);
CREATE TABLE IF NOT EXISTS usage_windows(
 rule_href TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
 status TEXT NOT NULL, flows INTEGER, async_query_href TEXT,
 port_breakdown_complete INTEGER NOT NULL DEFAULT 1,
 port_details_omitted_count INTEGER NOT NULL DEFAULT 0,
 run_id TEXT NOT NULL REFERENCES runs(run_id), raw_json TEXT NOT NULL,
 PRIMARY KEY(rule_href, window_start, window_end)
);
CREATE TABLE IF NOT EXISTS usage_ports(
 rule_href TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
 protocol TEXT NOT NULL, port INTEGER NOT NULL DEFAULT -1, flows INTEGER NOT NULL,
 PRIMARY KEY(rule_href, window_start, window_end, protocol, port),
 FOREIGN KEY(rule_href, window_start, window_end)
   REFERENCES usage_windows(rule_href, window_start, window_end) ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS workloads(
 href TEXT PRIMARY KEY, hostname TEXT, short_hostname TEXT, name TEXT,
 app TEXT, env TEXT, loc TEXT, role TEXT, managed INTEGER, addresses_json TEXT NOT NULL,
 raw_json TEXT NOT NULL, snapshot_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ip_lists(
 name TEXT NOT NULL, member TEXT NOT NULL, snapshot_at TEXT NOT NULL,
 PRIMARY KEY(name, member)
);
CREATE TABLE IF NOT EXISTS data_quality(
 run_id TEXT NOT NULL REFERENCES runs(run_id), category TEXT NOT NULL,
 object_id TEXT NOT NULL DEFAULT '', message TEXT NOT NULL,
 PRIMARY KEY(run_id, category, object_id, message)
);
CREATE TABLE IF NOT EXISTS policy_snapshots(
 snapshot_id TEXT PRIMARY KEY, run_id TEXT, status TEXT NOT NULL,
 created_at TEXT NOT NULL, completed_at TEXT, rule_count INTEGER NOT NULL DEFAULT 0,
 snapshot_path TEXT, manifest_path TEXT, archive_path TEXT, archive_sha256 TEXT
);
CREATE TABLE IF NOT EXISTS traffic_cursors(
 cursor_name TEXT PRIMARY KEY, last_successful_end TEXT,
 in_progress_start TEXT, in_progress_end TEXT, last_status TEXT NOT NULL,
 last_run_id TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS traffic_windows(
 window_type TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
 run_id TEXT NOT NULL, status TEXT NOT NULL, error TEXT,
 started_at TEXT NOT NULL, finished_at TEXT,
 PRIMARY KEY(window_type,window_start,window_end,run_id)
);
CREATE TABLE IF NOT EXISTS backfill_states(
 backfill_id TEXT PRIMARY KEY, backfill_start TEXT NOT NULL,
 backfill_target_end TEXT NOT NULL, next_window_start TEXT NOT NULL,
 last_successful_window_end TEXT, status TEXT NOT NULL, last_run_id TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_archives(
 run_id TEXT PRIMARY KEY, archive_kind TEXT NOT NULL, archive_path TEXT NOT NULL,
 sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, status TEXT NOT NULL,
 retained_until TEXT, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rules_scope ON rules(ruleset_scope);
CREATE INDEX IF NOT EXISTS idx_rules_present ON rules(is_present);
CREATE INDEX IF NOT EXISTS idx_usage_end ON usage_windows(window_end);
CREATE INDEX IF NOT EXISTS idx_workloads_labels ON workloads(app, env);
"""

MIGRATION_1_TO_2 = """
BEGIN IMMEDIATE;
ALTER TABLE rules ADD COLUMN is_present INTEGER NOT NULL DEFAULT 1;
ALTER TABLE rules ADD COLUMN last_seen_snapshot_id TEXT;
CREATE TABLE policy_snapshots(
 snapshot_id TEXT PRIMARY KEY, run_id TEXT, status TEXT NOT NULL,
 created_at TEXT NOT NULL, completed_at TEXT, rule_count INTEGER NOT NULL DEFAULT 0,
 snapshot_path TEXT, manifest_path TEXT, archive_path TEXT, archive_sha256 TEXT
);
CREATE TABLE traffic_cursors(
 cursor_name TEXT PRIMARY KEY, last_successful_end TEXT,
 in_progress_start TEXT, in_progress_end TEXT, last_status TEXT NOT NULL,
 last_run_id TEXT, updated_at TEXT NOT NULL
);
CREATE TABLE traffic_windows(
 window_type TEXT NOT NULL, window_start TEXT NOT NULL, window_end TEXT NOT NULL,
 run_id TEXT NOT NULL, status TEXT NOT NULL, error TEXT,
 started_at TEXT NOT NULL, finished_at TEXT,
 PRIMARY KEY(window_type,window_start,window_end,run_id)
);
CREATE TABLE backfill_states(
 backfill_id TEXT PRIMARY KEY, backfill_start TEXT NOT NULL,
 backfill_target_end TEXT NOT NULL, next_window_start TEXT NOT NULL,
 last_successful_window_end TEXT, status TEXT NOT NULL, last_run_id TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE run_archives(
 run_id TEXT PRIMARY KEY, archive_kind TEXT NOT NULL, archive_path TEXT NOT NULL,
 sha256 TEXT NOT NULL, size_bytes INTEGER NOT NULL, status TEXT NOT NULL,
 retained_until TEXT, created_at TEXT NOT NULL
);
CREATE INDEX idx_rules_present ON rules(is_present);
DELETE FROM schema_version;
INSERT INTO schema_version(version) VALUES (2);
COMMIT;
"""

MINIMUM_SQLITE_VERSION = (3, 24, 0)


def ensure_sqlite_compatible(version_info: Sequence[int] = sqlite3.sqlite_version_info) -> None:
    """Reject SQLite releases that do not support the UPSERT syntax used here."""
    normalized = tuple(int(part) for part in version_info[:3])
    if normalized < MINIMUM_SQLITE_VERSION:
        found = ".".join(str(part) for part in normalized)
        required = ".".join(str(part) for part in MINIMUM_SQLITE_VERSION)
        raise RuntimeError(f"SQLite {found} is unsupported; version {required} or newer is required")


class Database:
    def __init__(self, path: Path):
        self.path = path

    def connect(self) -> sqlite3.Connection:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path))
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def initialize(self) -> None:
        ensure_sqlite_compatible()
        with self.connect() as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_version'"
            ).fetchone()
            if not exists:
                db.executescript(SCHEMA)
                return
            row = db.execute("SELECT MAX(version) FROM schema_version").fetchone()
            version = int(row[0] or 0)
            if version > SCHEMA_VERSION:
                raise RuntimeError(
                    f"Database schema {version} is newer than supported schema {SCHEMA_VERSION}"
                )
            if version == 1:
                db.executescript(MIGRATION_1_TO_2)
                version = 2
            if version != SCHEMA_VERSION:
                raise RuntimeError(f"Unsupported database schema version: {version}")

    def begin_run(self, run_id: str, run_type: str, details: Mapping[str, object]) -> None:
        with self.connect() as db:
            db.execute("INSERT INTO runs(run_id,run_type,status,started_at,details_json) VALUES(?,?,?,?,?)",
                       (run_id, run_type, "RUNNING", _now(), json.dumps(details, sort_keys=True)))

    def finish_run(self, run_id: str, status: str, details: Mapping[str, object]) -> None:
        with self.connect() as db:
            db.execute("UPDATE runs SET status=?,finished_at=?,details_json=? WHERE run_id=?",
                       (status, _now(), json.dumps(details, sort_keys=True), run_id))

    def update_run_details(self, run_id: str, details: Mapping[str, object]) -> None:
        """Publish progress without marking an active run as finished."""
        with self.connect() as db:
            db.execute(
                "UPDATE runs SET details_json=? WHERE run_id=? AND status='RUNNING'",
                (json.dumps(details, sort_keys=True), run_id),
            )

    def add_quality(self, run_id: str, category: str, object_id: str, message: str) -> None:
        with self.connect() as db:
            db.execute("INSERT OR IGNORE INTO data_quality VALUES(?,?,?,?)", (run_id, category, object_id, message))

    def add_artifact(self, run_id: str, kind: str, path: str, sha256: str, row_count: Optional[int] = None) -> None:
        with self.connect() as db:
            db.execute("INSERT OR REPLACE INTO artifacts VALUES(?,?,?,?,?)",
                       (run_id, kind, path, sha256, row_count))

    def upsert_rules(self, rows: Iterable[Mapping[str, object]], snapshot_at: str) -> int:
        with self.connect() as db:
            return self._upsert_rules(db, rows, snapshot_at, None)

    def _upsert_rules(self, db: sqlite3.Connection, rows: Iterable[Mapping[str, object]],
                      snapshot_at: str, snapshot_id: Optional[str]) -> int:
        count = 0
        sql = """INSERT INTO rules(
        rule_href,ruleset_href,ruleset_name,ruleset_scope,ruleset_enabled,rule_type,
        rule_description,rule_enabled,unscoped_consumers,source_text,destination_text,
        services,raw_json,snapshot_at,is_present,last_seen_snapshot_id
        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(rule_href) DO UPDATE SET ruleset_href=excluded.ruleset_href,
        ruleset_name=excluded.ruleset_name,ruleset_scope=excluded.ruleset_scope,
        ruleset_enabled=excluded.ruleset_enabled,rule_type=excluded.rule_type,
        rule_description=excluded.rule_description,rule_enabled=excluded.rule_enabled,
        unscoped_consumers=excluded.unscoped_consumers,source_text=excluded.source_text,
        destination_text=excluded.destination_text,services=excluded.services,
        raw_json=excluded.raw_json,snapshot_at=excluded.snapshot_at,
        is_present=CASE WHEN excluded.last_seen_snapshot_id IS NULL
          THEN rules.is_present ELSE 1 END,
        last_seen_snapshot_id=COALESCE(excluded.last_seen_snapshot_id,rules.last_seen_snapshot_id)"""
        for row in rows:
            raw_json = json.dumps(dict(row), sort_keys=True)
            existing = db.execute("SELECT raw_json FROM rules WHERE rule_href=?", (row["rule_href"],)).fetchone()
            changed = existing is None or existing[0] != raw_json
            db.execute(
                "INSERT OR REPLACE INTO rule_history VALUES(?,?,?,?)",
                (row["rule_href"], snapshot_at, hashlib.sha256(raw_json.encode("utf-8")).hexdigest(), int(changed)),
            )
            db.execute(sql, (
                row["rule_href"], row["ruleset_href"], row.get("ruleset_name", ""),
                row.get("ruleset_scope", ""), _bool_int(row.get("ruleset_enabled")),
                row.get("rule_type", ""), row.get("rule_description", ""),
                _bool_int(row.get("rule_enabled")), _bool_int(row.get("unscoped_consumers")),
                _side_text(row, "src"), _side_text(row, "dst"), row.get("services", ""),
                raw_json, snapshot_at, 1, snapshot_id,
            )); count += 1
        return count

    def complete_policy_snapshot(self, snapshot_id: str, run_id: str,
                                 rows: Iterable[Mapping[str, object]],
                                 snapshot_at: Optional[str] = None,
                                 snapshot_path: str = "", manifest_path: str = "",
                                 run_details: Optional[Mapping[str, object]] = None) -> int:
        """Atomically publish a complete inventory and mark missing rules absent."""
        timestamp = snapshot_at or _now()
        materialized = list(rows)
        if not snapshot_id.strip():
            raise ValueError("snapshot_id must not be empty")
        with self.connect() as db:
            count = self._upsert_rules(db, materialized, timestamp, snapshot_id)
            db.execute(
                "UPDATE rules SET is_present=0 WHERE COALESCE(last_seen_snapshot_id,'')<>?",
                (snapshot_id,),
            )
            db.execute(
                """INSERT INTO policy_snapshots(
                snapshot_id,run_id,status,created_at,completed_at,rule_count,
                snapshot_path,manifest_path,archive_path,archive_sha256
                ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (snapshot_id, run_id, "COMPLETE", timestamp, timestamp, count,
                 snapshot_path, manifest_path, "", ""),
            )
            if run_details is not None:
                changed = db.execute(
                    "UPDATE runs SET status='SUCCESS',finished_at=?,details_json=? WHERE run_id=? AND status='RUNNING'",
                    (timestamp, json.dumps(dict(run_details), sort_keys=True), run_id),
                ).rowcount
                if changed != 1:
                    raise ValueError("policy collection run is not running or does not exist")
        return count

    def current_policy_snapshot(self) -> Optional[Mapping[str, object]]:
        with self.connect() as db:
            row = db.execute(
                """SELECT * FROM policy_snapshots WHERE status='COMPLETE'
                ORDER BY completed_at DESC LIMIT 1"""
            ).fetchone()
            return dict(row) if row else None

    def traffic_cursor(self, cursor_name: str) -> Optional[Mapping[str, object]]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM traffic_cursors WHERE cursor_name=?", (cursor_name,),
            ).fetchone()
            return dict(row) if row else None

    def begin_traffic_window(self, cursor_name: str, window_type: str, run_id: str,
                             window_start: str, window_end: str) -> None:
        """Record an in-progress window without advancing its durable cursor."""
        if window_end <= window_start:
            raise ValueError("traffic window end must be after start")
        now = _now()
        with self.connect() as db:
            current = db.execute(
                "SELECT * FROM traffic_cursors WHERE cursor_name=?", (cursor_name,),
            ).fetchone()
            if current:
                if current["last_status"] == "RUNNING":
                    raise ValueError("traffic cursor already has a running window")
                expected_start = current["last_successful_end"]
                if current["last_status"] == "FAILED" and current["in_progress_start"]:
                    expected_start = current["in_progress_start"]
                    if current["in_progress_end"] != window_end:
                        raise ValueError("failed traffic window must be replayed unchanged")
                if expected_start and expected_start != window_start:
                    raise ValueError(
                        f"traffic window must start at cursor {expected_start}, got {window_start}"
                    )
            db.execute(
                """INSERT INTO traffic_cursors VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(cursor_name) DO UPDATE SET
                in_progress_start=excluded.in_progress_start,
                in_progress_end=excluded.in_progress_end,last_status='RUNNING',
                last_run_id=excluded.last_run_id,updated_at=excluded.updated_at""",
                (cursor_name, None, window_start, window_end, "RUNNING", run_id, now),
            )
            db.execute(
                "INSERT INTO traffic_windows VALUES(?,?,?,?,?,?,?,?)",
                (window_type, window_start, window_end, run_id, "RUNNING", "", now, None),
            )

    def finish_traffic_window(self, cursor_name: str, window_type: str, run_id: str,
                              window_start: str, window_end: str, success: bool,
                              error: str = "",
                              run_details: Optional[Mapping[str, object]] = None,
                              run_status: Optional[str] = None) -> None:
        """Finish a window and advance the cursor only on success."""
        now = _now(); status = "SUCCESS" if success else "FAILED"
        with self.connect() as db:
            changed = db.execute(
                """UPDATE traffic_windows SET status=?,error=?,finished_at=?
                WHERE window_type=? AND window_start=? AND window_end=? AND run_id=?
                AND status='RUNNING'""",
                (status, error, now, window_type, window_start, window_end, run_id),
            ).rowcount
            if changed != 1:
                raise ValueError("traffic window is not running or does not exist")
            if success:
                cursor_changed = db.execute(
                    """UPDATE traffic_cursors SET last_successful_end=?,in_progress_start=NULL,
                    in_progress_end=NULL,last_status='SUCCESS',last_run_id=?,updated_at=?
                    WHERE cursor_name=? AND in_progress_start=? AND in_progress_end=?""",
                    (window_end, run_id, now, cursor_name, window_start, window_end),
                ).rowcount
            else:
                cursor_changed = db.execute(
                    """UPDATE traffic_cursors SET last_status='FAILED',last_run_id=?,updated_at=? WHERE cursor_name=?
                    AND in_progress_start=? AND in_progress_end=?""",
                    (run_id, now, cursor_name, window_start, window_end),
                ).rowcount
            if cursor_changed != 1:
                raise ValueError("traffic cursor does not match the running window")
            if run_details is not None:
                changed = db.execute(
                    "UPDATE runs SET status=?,finished_at=?,details_json=? WHERE run_id=? AND status='RUNNING'",
                    (run_status or status, now, json.dumps(dict(run_details), sort_keys=True), run_id),
                ).rowcount
                if changed != 1:
                    raise ValueError("traffic collection run is not running or does not exist")

    def initialize_backfill(self, backfill_id: str, start: str, target_end: str) -> None:
        if target_end <= start:
            raise ValueError("backfill target_end must be after start")
        now = _now()
        with self.connect() as db:
            try:
                db.execute(
                    "INSERT INTO backfill_states VALUES(?,?,?,?,?,?,?,?,?)",
                    (backfill_id, start, target_end, start, None, "PENDING", None, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError(f"backfill already exists and cannot be reinitialized: {backfill_id}") from exc

    def backfill_state(self, backfill_id: str) -> Optional[Mapping[str, object]]:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM backfill_states WHERE backfill_id=?", (backfill_id,),
            ).fetchone()
            return dict(row) if row else None

    def update_backfill_window(self, backfill_id: str, run_id: str,
                               window_end: str, success: bool,
                               run_details: Optional[Mapping[str, object]] = None,
                               run_status: Optional[str] = None,
                               error: str = "") -> None:
        """Advance backfill only after a successful window."""
        now = _now()
        with self.connect() as db:
            state = db.execute(
                """SELECT next_window_start,backfill_target_end,status,last_run_id
                FROM backfill_states WHERE backfill_id=?""",
                (backfill_id,),
            ).fetchone()
            if state is None:
                raise ValueError(f"unknown backfill: {backfill_id}")
            if state[2] != "RUNNING" or state[3] != run_id:
                raise ValueError("backfill window is not running for this run")
            if success:
                if window_end <= state[0] or window_end > state[1]:
                    raise ValueError("invalid successful backfill window end")
                status = "COMPLETED" if window_end >= state[1] else "PENDING"
                db.execute(
                    """UPDATE backfill_states SET next_window_start=?,
                    last_successful_window_end=?,status=?,last_run_id=?,updated_at=?
                    WHERE backfill_id=?""",
                    (window_end, window_end, status, run_id, now, backfill_id),
                )
            else:
                db.execute(
                    "UPDATE backfill_states SET status='FAILED',last_run_id=?,updated_at=? WHERE backfill_id=?",
                    (run_id, now, backfill_id),
                )
            window_status = "SUCCESS" if success else "FAILED"
            window_changed = db.execute(
                """UPDATE traffic_windows SET status=?,error=?,finished_at=?
                WHERE window_type=? AND run_id=? AND status='RUNNING'""",
                (window_status, error, now, RUN_TYPE_BACKFILL, run_id),
            ).rowcount
            if window_changed != 1:
                raise ValueError("backfill traffic window is not running or does not exist")
            if run_details is not None:
                changed = db.execute(
                    "UPDATE runs SET status=?,finished_at=?,details_json=? WHERE run_id=? AND status='RUNNING'",
                    (run_status or window_status, now,
                     json.dumps(dict(run_details), sort_keys=True), run_id),
                ).rowcount
                if changed != 1:
                    raise ValueError("backfill run is not running or does not exist")

    def begin_backfill_window(self, backfill_id: str, run_id: str,
                              window_days: int = 7) -> Mapping[str, str]:
        """Mark a pending/failed backfill as running without moving its cursor."""
        now = _now()
        with self.connect() as db:
            state = db.execute(
                """SELECT next_window_start,backfill_target_end,status
                FROM backfill_states WHERE backfill_id=?""", (backfill_id,),
            ).fetchone()
            if state is None:
                raise ValueError(f"unknown backfill: {backfill_id}")
            if state[2] == "COMPLETED":
                raise ValueError(f"backfill is already complete: {backfill_id}")
            if state[2] == "RUNNING":
                raise ValueError(f"backfill already has a running window: {backfill_id}")
            db.execute(
                "UPDATE backfill_states SET status='RUNNING',last_run_id=?,updated_at=? WHERE backfill_id=?",
                (run_id, now, backfill_id),
            )
            start = date.fromisoformat(str(state[0]))
            target = date.fromisoformat(str(state[1]))
            end = min(start + timedelta(days=window_days), target)
            db.execute(
                "INSERT INTO traffic_windows VALUES(?,?,?,?,?,?,?,?)",
                (RUN_TYPE_BACKFILL, start.isoformat(), end.isoformat(), run_id,
                 "RUNNING", "", now, None),
            )
            return {
                "window_start": start.isoformat(), "window_end": end.isoformat(),
                "target_end": target.isoformat(),
            }

    def record_archive(self, run_id: str, archive_kind: str, archive_path: str,
                       sha256: str, size_bytes: int, retained_until: Optional[str],
                       status: str = "VERIFIED") -> None:
        with self.connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO run_archives VALUES(?,?,?,?,?,?,?,?)",
                (run_id, archive_kind, archive_path, sha256, size_bytes, status,
                 retained_until, _now()),
            )

    def upsert_usage(self, run_id: str, rows: Iterable[Mapping[str, object]]) -> int:
        from rules_recertify.workloader.csvio import parse_flows_by_port, query_window
        count = 0
        with self.connect() as db:
            for row in rows:
                start, end = query_window(str(row.get("query_body", "")))
                status = str(row.get("async_query_status", "")).lower() or "unknown"
                raw_flows = str(row.get("flows", "")).strip()
                flows = int(raw_flows) if raw_flows else None
                ports, complete, omitted = parse_flows_by_port(str(row.get("flows_by_port", "")))
                key = (str(row["rule_href"]), start, end)
                existing = db.execute("SELECT status FROM usage_windows WHERE rule_href=? AND window_start=? AND window_end=?", key).fetchone()
                if existing and existing[0] == "completed" and status != "completed":
                    continue
                db.execute("""INSERT INTO usage_windows VALUES(?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(rule_href,window_start,window_end) DO UPDATE SET
                    status=excluded.status,flows=excluded.flows,async_query_href=excluded.async_query_href,
                    port_breakdown_complete=excluded.port_breakdown_complete,
                    port_details_omitted_count=excluded.port_details_omitted_count,
                    run_id=excluded.run_id,raw_json=excluded.raw_json""",
                    (*key, status, flows, row.get("async_query_href", ""), int(complete), omitted, run_id,
                     json.dumps(dict(row), sort_keys=True)))
                db.execute("DELETE FROM usage_ports WHERE rule_href=? AND window_start=? AND window_end=?", key)
                for port in ports:
                    db.execute("INSERT INTO usage_ports VALUES(?,?,?,?,?,?)", (*key, port["protocol"], port["port"] if port["port"] is not None else -1, port["flows"]))
                count += 1
        return count

    def prune(self, retention_days: int, as_of: Optional[date] = None) -> int:
        cutoff = (as_of or datetime.now(timezone.utc).date()) - timedelta(days=retention_days)
        with self.connect() as db:
            cursor = db.execute("DELETE FROM usage_windows WHERE window_end < ?", (cutoff.isoformat(),))
            return cursor.rowcount


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _bool_int(value: object) -> Optional[int]:
    if value is None or str(value).strip() == "": return None
    return int(str(value).strip().lower() in {"true", "1", "yes"})


def _side_text(row: Mapping[str, object], prefix: str) -> str:
    fields = ("all_workloads", "labels", "labels_exclusions", "iplists", "workloads")
    return "\n".join(f"{name}={row.get(prefix + '_' + name)}" for name in fields if row.get(prefix + "_" + name))
