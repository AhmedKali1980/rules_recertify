#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${RULES_RECERTIFY_CONFIG:-${ROOT}/config/local.json}"
VENV="${RULES_RECERTIFY_VENV:-${ROOT}/.venv}"
LOCK="${RULES_RECERTIFY_LOCK:-${ROOT}/var/state/collect.lock}"
mkdir -p "$(dirname "$LOCK")"
exec 9>"$LOCK"
if ! flock -n 9; then
  printf '%s\n' 'Another Rules Recertify collection is running.' >&2
  exit 75
fi
if [[ -x "${VENV}/bin/python" ]]; then
  export PATH="${VENV}/bin:${PATH}"
fi
END="$(date -u +%F)"
START="$(date -u -d 'yesterday' +%F)"
exec "${ROOT}/scripts/rules-recertify" --config "$CONFIG" collect \
  --traffic-start "$START" --traffic-end "$END"
