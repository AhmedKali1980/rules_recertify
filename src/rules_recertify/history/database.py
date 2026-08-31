"""SQLite persistence with idempotent usage-window ingestion."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Sequence

SCHEMA = """
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS schema_version(version INTEGER PRIMARY KEY);
INSERT OR IGNORE INTO schema_version(version) VALUES (1);
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
 destination_text TEXT, services TEXT, raw_json TEXT NOT NULL, snapshot_at TEXT NOT NULL
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
CREATE INDEX IF NOT EXISTS idx_rules_scope ON rules(ruleset_scope);
CREATE INDEX IF NOT EXISTS idx_usage_end ON usage_windows(window_end);
CREATE INDEX IF NOT EXISTS idx_workloads_labels ON workloads(app, env);
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
            db.executescript(SCHEMA)

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
        count = 0
        sql = """INSERT INTO rules VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(rule_href) DO UPDATE SET ruleset_href=excluded.ruleset_href,
        ruleset_name=excluded.ruleset_name,ruleset_scope=excluded.ruleset_scope,
        ruleset_enabled=excluded.ruleset_enabled,rule_type=excluded.rule_type,
        rule_description=excluded.rule_description,rule_enabled=excluded.rule_enabled,
        unscoped_consumers=excluded.unscoped_consumers,source_text=excluded.source_text,
        destination_text=excluded.destination_text,services=excluded.services,
        raw_json=excluded.raw_json,snapshot_at=excluded.snapshot_at"""
        with self.connect() as db:
            for row in rows:
                db.execute(sql, (
                    row["rule_href"], row["ruleset_href"], row.get("ruleset_name", ""),
                    row.get("ruleset_scope", ""), _bool_int(row.get("ruleset_enabled")),
                    row.get("rule_type", ""), row.get("rule_description", ""),
                    _bool_int(row.get("rule_enabled")), _bool_int(row.get("unscoped_consumers")),
                    _side_text(row, "src"), _side_text(row, "dst"), row.get("services", ""),
                    json.dumps(dict(row), sort_keys=True), snapshot_at,
                )); count += 1
        return count

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
