#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Load simple dotenv assignments without evaluation; existing exported values win.
load_project_env() {
  local file="${RULES_RECERTIFY_ENV_FILE:-${ROOT}/.env}" line key value
  [[ -f "$file" ]] || return 0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line#export }"
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" == *=* ]] || { printf 'Invalid dotenv assignment: %s\n' "$line" >&2; return 64; }
    key="${line%%=*}"; key="${key//[[:space:]]/}"; value="${line#*=}"
    [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || { printf 'Invalid dotenv key: %s\n' "$key" >&2; return 64; }
    value="${value#\"}"; value="${value%\"}"; value="${value#\'}"; value="${value%\'}"
    [[ -v "$key" ]] || printf -v "$key" '%s' "$value"
    export "$key"
  done < "$file"
}

load_project_env
: "${EXECUTABLE:?EXECUTABLE must point to Workloader}"
: "${CFG:?CFG must point to the Workloader configuration file}"

resolve_pce_profile() {
  local explicit="$1" fqdn="$2" required="$3" host resolved=""
  local -a candidates=()
  if [[ -n "$explicit" ]]; then printf '%s\n' "$explicit"; return; fi
  host="${fqdn%%.*}"
  if [[ -n "$host" && -r "$CFG" ]]; then
    resolved="$(awk -v needle="$host" '
      /^[[:alnum:]_.-]+:[[:space:]]*$/ { key=$0; sub(/:.*/, "", key) }
      index(tolower($0), tolower(needle)) { if (key != "") { print key; exit } }
    ' "$CFG")"
    if [[ -n "$resolved" ]]; then printf '%s\n' "$resolved"; return; fi
  fi
  if [[ -r "$CFG" && "$required" == 0 ]]; then
    # The L1 profile is Workloader's configured default.  This is the source of
    # truth used by the production pce.yaml and avoids duplicating it in .env.
    resolved="$(awk '
      /^[[:space:]]*default_pce_name:[[:space:]]*/ {
        value=$0; sub(/^[^:]*:[[:space:]]*/, "", value)
        sub(/[[:space:]]+#.*/, "", value); gsub(/^[[:space:]"'\''"]+|[[:space:]"'\''"]+$/, "", value)
        print value; exit
      }
    ' "$CFG")"
    if [[ -n "$resolved" ]]; then printf '%s\n' "$resolved"; return; fi
  fi
  if [[ -r "$CFG" && "$required" == 1 ]]; then
    # Profile keys are top-level YAML mappings.  Accept the established
    # pce-l3-sm / pce_l3sm naming convention, but never guess from credentials.
    mapfile -t candidates < <(awk '
      /^[[:alnum:]_.-]+:[[:space:]]*$/ {
        key=$0; sub(/:.*/, "", key); normalized=tolower(key)
        gsub(/[^[:alnum:]]/, "", normalized)
        if (normalized ~ /l3sm$/) { print key }
      }
    ' "$CFG")
    if (( ${#candidates[@]} == 1 )); then printf '%s\n' "${candidates[0]}"; return; fi
    if (( ${#candidates[@]} > 1 )); then
      printf 'Several L3SM profiles found in %s; use an explicit override\n' "$CFG" >&2
      return 64
    fi
  fi
  if [[ "$required" == 1 ]]; then
    printf 'Unable to resolve the required L3SM PCE profile\n' >&2; return 64
  fi
}

run_workloader_with_retry() {
  local pce="$1"; shift
  local -a args=("$@") command=("$EXECUTABLE" --config-file "$CFG")
  [[ -n "$pce" ]] && command+=(--pce "$pce")
  command+=("${args[@]}")
  local output_file="" index
  for ((index=0; index<${#args[@]}; index++)); do
    [[ "${args[index]}" == --output-file && $((index+1)) -lt ${#args[@]} ]] && output_file="${args[index+1]}"
  done
  local attempt=1 delay="${BASE_SLEEP:-3}" rc=0 max_attempts="${MAX_ATTEMPTS:-5}"
  while (( attempt <= max_attempts )); do
    printf '[workloader] attempt %d/%d started\n' "$attempt" "$max_attempts" >&2
    rm -f -- "$output_file"
    if command -v timeout >/dev/null 2>&1 && (( ${TIMEOUT_SEC:-2700} > 0 )); then
      timeout "${TIMEOUT_SEC:-2700}" "${command[@]}" || rc=$?
    else
      "${command[@]}" || rc=$?
    fi
    if (( rc == 0 )) && { [[ "${VERIFY_OUTPUT_FILE:-1}" == 0 || -z "$output_file" || -s "$output_file" ]]; }; then
      printf '[workloader] attempt %d succeeded\n' "$attempt" >&2
      sleep "${POST_SUCCESS_PAUSE_SEC:-60}"; return 0
    fi
    (( rc == 0 )) && rc=66
    printf '[workloader] attempt %d failed (status %d)\n' "$attempt" "$rc" >&2
    (( attempt++ )); (( attempt > max_attempts )) && break
    local jitter=0 jitter_pct="${JITTER:-20}"
    (( jitter_pct > 0 && delay > 0 )) && jitter=$(( RANDOM % (delay * jitter_pct / 100 + 1) ))
    printf '[workloader] retrying in %d seconds\n' "$((delay+jitter))" >&2
    sleep "$((delay+jitter))"
    delay=$((delay * ${BACKOFF:-2})); (( delay > ${MAX_SLEEP:-60} )) && delay="${MAX_SLEEP:-60}"
    rc=0
  done
  sleep "${POST_FAILURE_PAUSE_SEC:-60}"
  printf '[workloader] failed after %d attempts\n' "$max_attempts" >&2
  return "$rc"
}
