#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/workloader_common.sh"
[[ $# == 1 ]] || { echo "Usage: $0 OUTPUT" >&2; exit 64; }
PCE="$(resolve_pce_profile "${PCE_L3SM_NAME:-}" "${PCE_L3SM_FQDN:-}" 1)"
run_workloader_with_retry "$PCE" wkld-export -m --headers href,hostname,name,external_data_set,created_at,interfaces,public_ip,ip_with_default_gw,app,env,loc,role,managed,enforcement,external_data_reference,OS,os_id --output-file "$1"
