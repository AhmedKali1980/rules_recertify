#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/collection_common.sh"
rr_prepare
rr_lock
rr_ensure_snapshot

NOW="${RULES_RECERTIFY_NOW:-$(date --iso-8601=seconds)}"
if [[ "${RULES_RECERTIFY_WEEKDAY:-$(date +%u)}" -eq 7 ]]; then
  printf '%s\n' 'Backfill is not run on Sunday.'
  exit 0
fi

set +e
python3 - "$CONFIG" "$ENV_FILE" "$NOW" <<'PY'
import sys
from datetime import datetime, timedelta
from pathlib import Path
from rules_recertify.config import load_settings
from rules_recertify.history.database import Database

settings = load_settings(Path(sys.argv[1]), Path(sys.argv[2]))
database = Database(Path(settings.state_db)); database.initialize()
state = database.backfill_state("traffic-92-days")
if state is None:
    print("Backfill traffic-92-days is not initialized.", file=sys.stderr)
    raise SystemExit(3)
if state["status"] == "COMPLETED":
    raise SystemExit(10)
now = datetime.fromisoformat(sys.argv[3])
with database.connect() as connection:
    row = connection.execute(
        "SELECT started_at FROM runs WHERE run_type='TRAFFIC_BACKFILL' "
        "ORDER BY started_at DESC LIMIT 1"
    ).fetchone()
if row:
    previous = datetime.fromisoformat(str(row[0]))
    if previous.tzinfo is None and now.tzinfo is not None:
        previous = previous.replace(tzinfo=now.tzinfo)
    if now - previous < timedelta(hours=47):
        raise SystemExit(11)
PY
due=$?
set -e
case "$due" in
  0) ;;
  10) printf '%s\n' 'Backfill is complete; nothing to run.'; exit 0 ;;
  11) printf '%s\n' 'Backfill was attempted less than two days ago; nothing to run.'; exit 0 ;;
  *) exit "$due" ;;
esac

rr_cli backfill-traffic --backfill-id traffic-92-days
