#!/usr/bin/env bash
# Shared production-launcher plumbing. This file is sourced by the three wrappers.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${RULES_RECERTIFY_CONFIG:-${ROOT}/config/local.json}"
ENV_FILE="${RULES_RECERTIFY_ENV_FILE:-${ROOT}/.env}"
VENV="${RULES_RECERTIFY_VENV:-${ROOT}/.venv}"
LOCK="${RULES_RECERTIFY_LOCK:-${ROOT}/var/state/collect.lock}"
CLI="${RULES_RECERTIFY_CLI:-${ROOT}/scripts/rules-recertify}"

rr_prepare() {
  cd "$ROOT"
  export PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}"
  if [[ -x "${VENV}/bin/python" ]]; then
    export PATH="${VENV}/bin:${PATH}"
  fi
  mkdir -p "$(dirname "$LOCK")"
}

rr_lock() {
  exec 9>"$LOCK"
  if ! flock -n 9; then
    printf '%s\n' 'Another Rules Recertify collection is running.' >&2
    exit 75
  fi
}

rr_cli() {
  "$CLI" --config "$CONFIG" --env-file "$ENV_FILE" "$@"
}

rr_ensure_snapshot() {
  local raw_dir manifest
  raw_dir="$(python3 - "$CONFIG" "$ENV_FILE" <<'PY'
import sys
from pathlib import Path
from rules_recertify.config import load_settings
print(load_settings(Path(sys.argv[1]), Path(sys.argv[2])).raw_dir)
PY
)"
  manifest="${raw_dir}/snapshot/manifest.json"
  if [[ ! -s "$manifest" ]]; then
    printf 'Policy snapshot missing; creating it before traffic collection: %s\n' "$manifest"
    rr_cli collect-policy
  fi
  if [[ ! -s "$manifest" ]]; then
    printf 'Policy snapshot was not created: %s\n' "$manifest" >&2
    return 1
  fi
}
