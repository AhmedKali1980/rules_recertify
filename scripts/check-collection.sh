#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${RULES_RECERTIFY_CONFIG:-${ROOT}/config/local.json}"
ENV_FILE="${RULES_RECERTIFY_ENV_FILE:-${ROOT}/.env}"
LOCK="${RULES_RECERTIFY_LOCK:-${ROOT}/var/state/collect.lock}"

cd "$ROOT"
export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"

mkdir -p "$(dirname "$LOCK")"
exec 9>"$LOCK"
if flock -n 9; then
  LOCK_STATE="FREE"
else
  LOCK_STATE="HELD"
fi

python3 - "$CONFIG" "$ENV_FILE" "$LOCK_STATE" <<'PY'
import json
import sys
from datetime import datetime
from pathlib import Path

from rules_recertify.config import load_settings
from rules_recertify.history.database import Database


def stop(code, message):
    print(message.replace("\n", " "))
    raise SystemExit(code)


try:
    settings = load_settings(Path(sys.argv[1]), Path(sys.argv[2]))
    database = Database(Path(settings.state_db))
    with database.connect() as connection:
        run = connection.execute(
            """
            SELECT run_id, status, started_at, finished_at, details_json
            FROM runs
            WHERE run_type = 'COLLECTION'
            ORDER BY started_at DESC
            LIMIT 1
            """
        ).fetchone()
except Exception as exc:
    stop(3, f"UNKNOWN check_failed={type(exc).__name__}:{exc}")

if run is None:
    stop(3, "UNKNOWN collection=NOT_FOUND")

run_id = run["run_id"]
status = run["status"].upper()
lock_state = sys.argv[3]

try:
    details = json.loads(run["details_json"] or "{}")
except json.JSONDecodeError:
    stop(2, f"CRITICAL run={run_id} invalid_database_details")

if lock_state == "HELD":
    stop(
        1,
        f"RUNNING run={run_id} db_status={status} lock={lock_state} "
        f"batch={details.get('current_batch', '?')}/{details.get('batch_count', '?')} "
        f"stage={details.get('current_stage', '?')}",
    )

if status == "RUNNING":
    stop(2, f"CRITICAL run={run_id} db_status=RUNNING lock=FREE interrupted_collection")

manifest_path = Path(settings.raw_dir) / run_id / "manifest.json"
if not manifest_path.is_file():
    stop(2, f"CRITICAL run={run_id} status={status} manifest=MISSING")

try:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError) as exc:
    stop(2, f"CRITICAL run={run_id} manifest_invalid={type(exc).__name__}")

manifest_status = str(manifest.get("status", "UNKNOWN")).upper()
batch_values = manifest.get("batches", [])
batches = len(batch_values)


def count(name):
    value = manifest.get(name)
    if value is not None:
        return int(value or 0)
    return sum(int(batch.get(name, 0) or 0) for batch in batch_values)


total = count("total")
completed = count("completed")
pending = count("pending")
expired = count("expired")
unknown = count("unknown")
scope_skipped = int(manifest.get("excluded_scope_ruleset_count", 0) or 0)
oversized_skipped = int(manifest.get("skipped_oversized_ruleset_count", 0) or 0)
expected_batches = int(manifest.get("batch_count", batches) or batches)

duration = "?"
if run["finished_at"]:
    try:
        start = datetime.fromisoformat(run["started_at"])
        finish = datetime.fromisoformat(run["finished_at"])
        duration = str(finish - start).split(".", 1)[0]
    except ValueError:
        pass

common = (
    f"run={run_id} status={status}/{manifest_status} "
    f"batches={batches}/{expected_batches} completed={completed}/{total} "
    f"pending={pending} expired={expired} unknown={unknown} "
    f"scope_skipped={scope_skipped} oversized_skipped={oversized_skipped} "
    f"duration={duration}"
)

failed_at = ""
if manifest.get("current_batch") or manifest.get("current_stage"):
    failed_at = (
        f" failed_at={manifest.get('current_batch', '?')}/"
        f"{manifest.get('current_stage', '?')}"
    )

if (
    status == "SUCCESS"
    and manifest_status == "SUCCESS"
    and total > 0
    and completed == total
    and not pending
    and not expired
    and not unknown
    and batches == expected_batches
):
    stop(0, f"OK {common}")

if status == "WARNING" or manifest_status == "WARNING":
    stop(1, f"WARNING {common}")

error = " ".join(str(manifest.get("error", "unspecified")).split())
if len(error) > 180:
    error = error[:177] + "..."
stop(2, f"CRITICAL {common}{failed_at} error={error}")
PY
