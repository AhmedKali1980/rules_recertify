#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/workloader_common.sh"
[[ $# == 1 ]] || { echo "Usage: $0 OUTPUT" >&2; exit 64; }
PCE="$(resolve_pce_profile "${PCE_L1_NAME:-}" "${PCE_L1_FQDN:-}" 0)"
run_workloader_with_retry "$PCE" ipl-export --output-file "$1"
