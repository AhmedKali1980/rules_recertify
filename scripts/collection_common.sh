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
