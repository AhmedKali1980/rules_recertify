#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/collection_common.sh"
rr_prepare
rr_lock

AVAILABLE_END="${RULES_RECERTIFY_TRAFFIC_END:-$(date +%F)}"
set +e
python3 - "$CONFIG" "$ENV_FILE" "$AVAILABLE_END" <<'PY'
import sys
from pathlib import Path
from rules_recertify.config import load_settings
from rules_recertify.history.database import Database

settings = load_settings(Path(sys.argv[1]), Path(sys.argv[2]))
database = Database(Path(settings.state_db)); database.initialize()
cursor = database.traffic_cursor("weekly")
if cursor and cursor.get("last_successful_end") and str(cursor["last_successful_end"]) >= sys.argv[3]:
    raise SystemExit(10)
PY
due=$?
set -e
if [[ $due -eq 10 ]]; then
  printf 'Weekly traffic window ending %s is already complete; retry is a no-op.\n' "$AVAILABLE_END"
  exit 0
elif [[ $due -ne 0 ]]; then
  exit "$due"
fi

rr_cli collect-traffic --traffic-end "$AVAILABLE_END"
