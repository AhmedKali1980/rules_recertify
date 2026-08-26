#!/usr/bin/env bash
set -Eeuo pipefail

SOURCE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="${RULES_RECERTIFY_HOME:-/DATA/mco/illumio-mco/rules_recertify}"
OWNER="${RULES_RECERTIFY_OWNER:-$(id -un)}"
GROUP="${RULES_RECERTIFY_GROUP:-$(id -gn)}"

if [[ "$TARGET" != /DATA/mco/illumio-mco/rules_recertify && "${RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME:-0}" != 1 ]]; then
  printf 'Refusing non-standard target: %s\n' "$TARGET" >&2
  printf '%s\n' 'A non-standard path additionally requires RULES_RECERTIFY_ALLOW_NONSTANDARD_HOME=1.' >&2
  exit 64
fi

install -d -m 0750 "$TARGET"

# Migration from the first packaging layout: pip 20.2 on the offline RHEL 8 host
# treats pyproject.toml as a PEP 517 trigger and tries to download setuptools>=61.
# Production uses the checked-in legacy setup.py with its installed setuptools.
rm -f "$TARGET/pyproject.toml"

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

install -d -m 0750 \
  "$TARGET/var/state" \
  "$TARGET/var/raw" \
  "$TARGET/var/output" \
  "$TARGET/var/logs"

if [[ ! -e "$TARGET/config/local.json" ]]; then
  install -m 0640 "$TARGET/config/production.example.json" "$TARGET/config/local.json"
fi
if [[ ! -e "$TARGET/.env" ]]; then
  install -m 0600 "$TARGET/.env.example" "$TARGET/.env"
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

printf 'Rules Recertify installed in %s\n' "$TARGET"
printf 'Preserved local files: %s and %s\n' "$TARGET/.env" "$TARGET/config/local.json"
printf '%s\n' 'Next: review configuration, create the virtualenv, then run validate-config and init-db.'
