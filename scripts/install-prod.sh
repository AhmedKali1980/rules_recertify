#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${RULES_RECERTIFY_HOME:-/DATA/mco/illumio-mco/rules_recertify}"
OWNER="${RULES_RECERTIFY_OWNER:-}"
GROUP="${RULES_RECERTIFY_GROUP:-$(id -gn)}"
SHARED_GROUP="${RULES_RECERTIFY_SHARED_GROUP:-}"
PYTHON_BIN="${RULES_RECERTIFY_PYTHON:-python3}"
RELEASE_ID_FILE="$SOURCE/config/release-id"

if [[ "$TARGET" != /DATA/mco/illumio-mco/rules_recertify && "${RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME:-0}" != 1 ]]; then
  printf 'Refusing non-standard target: %s\n' "$TARGET" >&2
  printf '%s\n' 'A non-standard path additionally requires RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME=1.' >&2
  exit 64
fi

for marker in "$TARGET/var/.shared-group" "$TARGET/var/.shared-owner"; do
  if [[ -L "$marker" ]]; then
    printf 'Refusing a symlink for %s.\n' "$marker" >&2
    exit 64
  fi
done
if [[ -z "$SHARED_GROUP" && -f "$TARGET/var/.shared-group" ]]; then
  IFS= read -r SHARED_GROUP < "$TARGET/var/.shared-group" || true
fi
if [[ -n "$SHARED_GROUP" ]]; then
  if ! getent group "$SHARED_GROUP" >/dev/null; then
    printf 'Unknown shared runtime group: %s\n' "$SHARED_GROUP" >&2
    exit 64
  fi
  GROUP="$SHARED_GROUP"
  if [[ -z "$OWNER" && -f "$TARGET/var/.shared-owner" ]]; then
    IFS= read -r OWNER < "$TARGET/var/.shared-owner" || true
  fi
  for utility in getfacl setfacl; do
    if ! command -v "$utility" >/dev/null; then
      printf 'Shared access requires %s (Linux acl package).\n' "$utility" >&2
      exit 64
    fi
  done
fi
OWNER="${OWNER:-$(id -un)}"
if [[ -n "$SHARED_GROUP" ]] && ! getent passwd "$OWNER" >/dev/null; then
  printf 'Unknown installation owner: %s\n' "$OWNER" >&2
  exit 64
fi
if [[ -n "$SHARED_GROUP" && $(id -u) -ne 0 && $(id -u "$OWNER") -ne $(id -u) ]]; then
  printf 'Run the installer as root to assign installation ownership to %s.\n' "$OWNER" >&2
  exit 64
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
  --exclude='config/headers.conf' \
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
if [[ ! -e "$TARGET/config/headers.conf" ]]; then
  install -m 0640 "$SOURCE/config/headers.conf" "$TARGET/config/headers.conf"
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
  # ACL masks appear as group mode bits in ls/stat. Also grant the named
  # group entry so an existing read-only owning-group ACL cannot hide behind
  # a writable mask. Keep unrelated entries and their current mask limits.
  share_read_access() {
    local directory="$1"
    [[ -d "$directory" ]] || return 0
    find "$directory" ! -type l ! -group "$GROUP" -exec chgrp "$GROUP" {} +
    find "$directory" -type d ! -perm -0050 -exec chmod g+rx {} +
    find "$directory" -type f ! -perm -0040 -exec chmod g+r {} +
    find "$directory" -type f -perm /0111 ! -perm -0010 -exec chmod g+x {} +
    find "$directory" \( -type d -o -type f \) -exec setfacl -n -m "g:$GROUP:rX" -- {} +
  }
  find "$TARGET" -maxdepth 0 ! -group "$GROUP" -exec chgrp "$GROUP" {} +
  setfacl -n -m "g:$GROUP:rx" -- "$TARGET"
  for directory in "$TARGET/src" "$TARGET/scripts" "$TARGET/config" "$TARGET/.venv" "$TARGET/workloader" "$TARGET/var"; do
    share_read_access "$directory"
  done
  find "$TARGET" -maxdepth 1 -type f ! -group "$GROUP" -exec chgrp "$GROUP" {} +
  find "$TARGET" -maxdepth 1 -type f ! -perm -0040 -exec chmod g+r {} +
  find "$TARGET" -maxdepth 1 -type f -exec setfacl -n -m "g:$GROUP:r" -- {} +
  if [[ $(stat -c '%a' "$TARGET/.env") =~ [2367][0-7]$ ]]; then
    setfacl -n -m "g:$GROUP:rw" -- "$TARGET/.env"
  fi
  install -d -m 2750 "$TARGET/var"
  for directory in "$TARGET/var/state" "$TARGET/var/output" "$TARGET/var/logs"; do
    find "$directory" -type d ! -perm -2070 -exec chmod g+rwx,g+s {} +
    find "$directory" -type f ! -perm -0060 -exec chmod g+rw {} +
    find "$directory" \( -type d -o -type f \) -exec setfacl -n -m "g:$GROUP:rwX" -- {} +
    find "$directory" -type d -exec setfacl -m \
      "d:u::rwx,d:g::rwx,d:g:$GROUP:rwx,d:m::rwx,d:o::---" -- {} +
  done
  # New collection runs can be created by the group; published snapshots
  # and existing raw references retain their read-only group policy.
  install -d -m 2770 "$TARGET/var/raw" "$TARGET/var/raw/archives"
  setfacl -n -m "g:$GROUP:rwx" -- "$TARGET/var/raw" "$TARGET/var/raw/archives"
  setfacl -m "d:u::rwx,d:g::rwx,d:g:$GROUP:rwx,d:m::rwx,d:o::---" \
    -- "$TARGET/var/raw" "$TARGET/var/raw/archives"
  printf '%s\n' "$GROUP" > "$TARGET/var/.shared-group"
  printf '%s\n' "$OWNER" > "$TARGET/var/.shared-owner"
  chmod 0640 "$TARGET/var/.shared-group" "$TARGET/var/.shared-owner"
  if [[ $(id -u) -eq 0 ]]; then
    chown "$OWNER:$GROUP" "$TARGET/var/.shared-group" "$TARGET/var/.shared-owner"
  fi
  printf 'Shared runtime access enabled for group %s; installation owner %s\n' "$GROUP" "$OWNER"
fi

printf 'Rules Recertify installed in %s\n' "$TARGET"
printf 'Preserved local files: %s and %s\n' "$TARGET/.env" "$TARGET/config/local.json"
printf '%s\n' 'Next: review configuration, create the virtualenv, then run validate-config and init-db.'
