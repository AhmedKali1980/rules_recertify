#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${RULES_RECERTIFY_CONFIG:-${ROOT}/config/local.json}"
ENV_FILE="${RULES_RECERTIFY_ENV_FILE:-${ROOT}/.env}"
LOCK="${RULES_RECERTIFY_LOCK:-${ROOT}/var/state/collect.lock}"
NOW="${RULES_RECERTIFY_NOW:-$(date --iso-8601=seconds)}"
SNAPSHOT_MAX_HOURS="${RULES_RECERTIFY_SNAPSHOT_MAX_HOURS:-26}"
TRAFFIC_MAX_HOURS="${RULES_RECERTIFY_TRAFFIC_MAX_HOURS:-192}"

cd "$ROOT"
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
mkdir -p "$(dirname "$LOCK")"
exec 9>"$LOCK"
if flock -n 9; then LOCK_STATE="FREE"; else LOCK_STATE="HELD"; fi

python3 - "$CONFIG" "$ENV_FILE" "$LOCK_STATE" "$NOW" "$SNAPSHOT_MAX_HOURS" "$TRAFFIC_MAX_HOURS" <<'PY'
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from rules_recertify.config import load_settings
from rules_recertify.history.database import Database, RUN_TYPE_BACKFILL, RUN_TYPE_POLICY, RUN_TYPE_TRAFFIC


def age_hours(value, now):
    if not value:
        return None
    parsed = datetime.fromisoformat(str(value))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return max(0.0, (now.astimezone(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() / 3600)


def latest(connection, run_type):
    return connection.execute(
        "SELECT run_id,status,started_at,finished_at FROM runs WHERE run_type=? "
        "ORDER BY started_at DESC LIMIT 1", (run_type,),
    ).fetchone()


try:
    settings = load_settings(Path(sys.argv[1]), Path(sys.argv[2]))
    database = Database(Path(settings.state_db)); database.initialize()
    lock_state = sys.argv[3]
    now = datetime.fromisoformat(sys.argv[4])
    if now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)
    snapshot_limit = float(sys.argv[5]); traffic_limit = float(sys.argv[6])
    with database.connect() as connection:
        policy = latest(connection, RUN_TYPE_POLICY)
        traffic = latest(connection, RUN_TYPE_TRAFFIC)
        running = connection.execute(
            "SELECT COUNT(*) FROM runs WHERE status='RUNNING'"
        ).fetchone()[0]
        snapshot = connection.execute(
            "SELECT snapshot_id,completed_at,snapshot_path FROM policy_snapshots "
            "WHERE status='COMPLETE' ORDER BY completed_at DESC LIMIT 1"
        ).fetchone()
        cursor = connection.execute(
            "SELECT last_successful_end,last_status FROM traffic_cursors WHERE cursor_name='weekly'"
        ).fetchone()
        backfill = connection.execute(
            "SELECT status,next_window_start,backfill_target_end FROM backfill_states "
            "WHERE backfill_id='traffic-92-days'"
        ).fetchone()
        sunday = connection.execute(
            "SELECT window_end,run_id FROM traffic_windows WHERE window_type=? AND status='SUCCESS' "
            "ORDER BY window_end DESC LIMIT 1", (RUN_TYPE_TRAFFIC,),
        ).fetchone()
        archive = None
        if sunday and datetime.fromisoformat(str(sunday[0])).weekday() == 6:
            archive = connection.execute(
                "SELECT archive_path,status FROM run_archives WHERE run_id=?", (sunday[1],),
            ).fetchone()
except Exception as exc:
    print(f"UNKNOWN check_failed={type(exc).__name__}:{exc}".replace("\n", " "))
    raise SystemExit(3)

critical = []
warning = []
if lock_state == "HELD":
    warning.append(f"lock=HELD running={running}")
elif running:
    critical.append(f"interrupted_runs={running}")

if policy is None:
    critical.append("policy=NOT_FOUND")
elif str(policy[1]).upper() != "SUCCESS" and not (
    str(policy[1]).upper() == "RUNNING" and lock_state == "HELD"
):
    critical.append(f"policy={policy[1]}:{policy[0]}")
if traffic is None:
    warning.append("traffic=NOT_FOUND")
elif str(traffic[1]).upper() not in {"SUCCESS", "SUCCESS_WITH_EXCEPTIONS"} and not (
    str(traffic[1]).upper() == "RUNNING" and lock_state == "HELD"
):
    critical.append(f"traffic={traffic[1]}:{traffic[0]}")

snapshot_age = age_hours(snapshot[1], now) if snapshot else None
snapshot_path = Path(str(snapshot[2])) if snapshot else Path(settings.raw_dir) / "snapshot"
if snapshot is None or not (snapshot_path / "manifest.json").is_file():
    critical.append("snapshot=MISSING")
elif snapshot_age is not None and snapshot_age > snapshot_limit:
    critical.append(f"snapshot_age={snapshot_age:.1f}h")

cursor_end = str(cursor[0]) if cursor and cursor[0] else "NONE"
if cursor and str(cursor[1]).upper() == "FAILED":
    critical.append(f"weekly_cursor={cursor_end}:FAILED")
if cursor and cursor[0]:
    cursor_age = age_hours(f"{cursor[0]}T00:00:00+00:00", now)
    if cursor_age is not None and cursor_age > traffic_limit:
        critical.append(f"traffic_age={cursor_age:.1f}h")

archive_state = "N/A"
if sunday and datetime.fromisoformat(str(sunday[0])).weekday() == 6:
    if archive is None or str(archive[1]).upper() != "VERIFIED" or not Path(str(archive[0])).is_file():
        critical.append(f"archive=MISSING:{sunday[1]}")
        archive_state = "MISSING"
    else:
        archive_state = "VERIFIED"

backfill_text = "NOT_INITIALIZED"
if backfill:
    backfill_text = f"{backfill[0]}:{backfill[1]}/{backfill[2]}"
    if str(backfill[0]).upper() == "FAILED":
        warning.append("backfill=FAILED_RETRY_PENDING")

raw_path = Path(settings.raw_dir)
raw_path.mkdir(parents=True, exist_ok=True)
disk = shutil.disk_usage(raw_path)
disk_pct = 100.0 * (disk.total - disk.free) / disk.total if disk.total else 0.0
policy_text = "NONE" if policy is None else f"{policy[1]}:{policy[0]}"
traffic_text = "NONE" if traffic is None else f"{traffic[1]}:{traffic[0]}"
snapshot_text = "NONE" if snapshot_age is None else f"{snapshot_age:.1f}h"
message = (
    f"policy={policy_text} traffic={traffic_text} snapshot_age={snapshot_text} "
    f"weekly_cursor={cursor_end} backfill={backfill_text} archive={archive_state} "
    f"lock={lock_state} disk_used={disk_pct:.1f}% disk_free={disk.free}"
)
if critical:
    print(f"CRITICAL {';'.join(critical)} {message}")
    raise SystemExit(2)
if warning:
    print(f"WARNING {';'.join(warning)} {message}")
    raise SystemExit(1)
print(f"OK {message}")
PY
