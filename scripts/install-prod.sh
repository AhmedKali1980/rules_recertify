#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${RULES_RECERTIFY_HOME:-/DATA/mco/illumio-mco/rules_recertify}"
OWNER="${RULES_RECERTIFY_OWNER:-$(id -un)}"
GROUP="${RULES_RECERTIFY_GROUP:-$(id -gn)}"
SHARED_GROUP="${RULES_RECERTIFY_SHARED_GROUP:-}"
PYTHON_BIN="${RULES_RECERTIFY_PYTHON:-python3}"
RELEASE_ID_FILE="$SOURCE/config/release-id"

if [[ "$TARGET" != /DATA/mco/illumio-mco/rules_recertify && "${RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME:-0}" != 1 ]]; then
  printf 'Refusing non-standard target: %s\n' "$TARGET" >&2
  printf '%s\n' 'A non-standard path additionally requires RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME=1.' >&2
  exit 64
fi

if [[ -L "$TARGET/var/.shared-group" ]]; then
  printf '%s\n' 'Refusing a symlink for var/.shared-group.' >&2
  exit 64
fi
if [[ -z "$SHARED_GROUP" && -f "$TARGET/var/.shared-group" ]]; then
  IFS= read -r SHARED_GROUP < "$TARGET/var/.shared-group" || true
fi
if [[ -n "$SHARED_GROUP" ]]; then
  if ! getent group "$SHARED_GROUP" >/dev/null; then
    printf 'Unknown shared runtime group: %s\n' "$SHARED_GROUP" >&2
    exit 64
  fi
  GROUP="$SHARED_GROUP"
fi

if [[ ! -s "$RELEASE_ID_FILE" ]]; then
  printf 'Missing release identity: %s\n' "$RELEASE_ID_FILE" >&2
  exit 65
fi
printf 'Validating release: %s\n' "$(<"$RELEASE_ID_FILE")"

# Refuse to overlay a syntactically invalid release onto the preserved
# production configuration and state. This catches indentation and merge
# damage before any target file is replaced.
"$PYTHON_BIN" -m compileall -q "$SOURCE/src"
for script in "$SOURCE"/scripts/*.sh "$SOURCE/scripts/rules-recertify"; do
  bash -n "$script"
done

install -d -m 0750 "$TARGET"

# Overlay version-controlled application files while preserving local secrets,
# configuration, virtualenv, and runtime state during upgrades.
tar \
  --exclude='.git' \
  --exclude='.env' \
  --exclude='.venv' \
  --exclude='config/local.json' \
  --exclude='var' \
  --exclude='*.sqlite' \
  --exclude='*.sqlite-*' \
  -C "$SOURCE" -cf - . | tar -C "$TARGET" -xf -

# Migration from the first packaging layout: pip 20.2 on the offline RHEL 8 host
# treats pyproject.toml as a PEP 517 trigger and tries to download setuptools>=61.
# Remove it after the overlay as archives can contain an untracked copy.
rm -f "$TARGET/pyproject.toml"

install -d -m 0750 \
  "$TARGET/var/state" \
  "$TARGET/var/raw" \
  "$TARGET/var/raw/archives" \
  "$TARGET/var/output" \
  "$TARGET/var/logs"

# Archive-based transfers may discard executable bits even though Git tracks
# them. Reapply the operational script permissions on every installation.
chmod 0755 "$TARGET/scripts/install-prod.sh" \
  "$TARGET/scripts/rules-recertify" \
  "$TARGET/scripts/daily-collect.sh" \
  "$TARGET/scripts/collection_common.sh" \
  "$TARGET/scripts/daily-policy-collect.sh" \
  "$TARGET/scripts/weekly-traffic-collect.sh" \
  "$TARGET/scripts/backfill-traffic.sh" \
  "$TARGET/scripts/check-collection.sh" \
  "$TARGET/scripts/import-pce-reference.sh" \
  "$TARGET/scripts/workloader_common.sh" \
  "$TARGET/scripts/workloader-wkld-export.sh" \
  "$TARGET/scripts/workloader-wkld-l3sm-managed-export.sh" \
  "$TARGET/scripts/workloader-ipl-export.sh" \
  "$TARGET/scripts/workloader-svc-export.sh" \
  "$TARGET/scripts/workloader-labelgroup-export.sh"

if [[ ! -e "$TARGET/config/local.json" ]]; then
  install -m 0640 "$TARGET/config/production.example.json" "$TARGET/config/local.json"
fi
if [[ ! -e "$TARGET/.env" ]]; then
  # Private by default; shared installations grant group read access.
  ENV_MODE=0600
  if [[ -n "$SHARED_GROUP" ]]; then ENV_MODE=0640; fi
  install -m "$ENV_MODE" "$TARGET/.env.example" "$TARGET/.env"
fi

if grep -q '^STATE_DB=var/state/rules_recertify\.sqlite$' "$TARGET/.env"; then
  printf '%s\n' 'WARNING: .env overrides the absolute production state_db with a relative path.' >&2
  printf '%s\n' 'Remove STATE_DB from .env or set its absolute /DATA path before collection.' >&2
fi

if [[ $(id -u) -eq 0 ]]; then
  chown -R "$OWNER:$GROUP" "$TARGET"
else
  printf 'Not running as root; ownership remains %s:%s.\n' "$(id -un)" "$(id -gn)"
fi

if [[ -n "$SHARED_GROUP" ]]; then
  # Repair only missing group rights; already-shared files may belong to
  # another operator, so do not chmod/chgrp them unnecessarily.
  share_read_access() {
    local directory="$1"
    [[ -d "$directory" ]] || return 0
    find "$directory" ! -type l ! -group "$GROUP" -exec chgrp "$GROUP" {} +
    find "$directory" -type d ! -perm -0050 -exec chmod g+rx {} +
    find "$directory" -type f ! -perm -0040 -exec chmod g+r {} +
    find "$directory" -type f -perm /0111 ! -perm -0010 -exec chmod g+x {} +
  }
  find "$TARGET" -maxdepth 0 ! -group "$GROUP" -exec chgrp "$GROUP" {} +
  for directory in "$TARGET/src" "$TARGET/scripts" "$TARGET/config" "$TARGET/.venv" "$TARGET/var"; do
    share_read_access "$directory"
  done
  find "$TARGET/.env" ! -group "$GROUP" -exec chgrp "$GROUP" {} +
  find "$TARGET/.env" ! -perm -0040 -exec chmod g+r {} +
  install -d -m 2750 "$TARGET/var"
  for directory in "$TARGET/var/state" "$TARGET/var/output" "$TARGET/var/logs"; do
    find "$directory" -type d ! -perm -2070 -exec chmod g+rwx,g+s {} +
    find "$directory" -type f ! -perm -0060 -exec chmod g+rw {} +
  done
  # New collection runs can be created by the group; published snapshots
  # and existing raw references retain their read-only group policy.
  install -d -m 2770 "$TARGET/var/raw" "$TARGET/var/raw/archives"
  printf '%s\n' "$GROUP" > "$TARGET/var/.shared-group"
  chmod 0640 "$TARGET/var/.shared-group"
  if [[ $(id -u) -eq 0 ]]; then
    chown "$OWNER:$GROUP" "$TARGET/var/.shared-group"
  fi
  printf 'Shared runtime access enabled for group %s\n' "$GROUP"
fi

printf 'Rules Recertify installed in %s\n' "$TARGET"
printf 'Preserved local files: %s and %s\n' "$TARGET/.env" "$TARGET/config/local.json"
printf '%s\n' 'Next: review configuration, create the virtualenv, then run validate-config and init-db.'
