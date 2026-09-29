#!/usr/bin/env bash
set -Eeuo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/collection_common.sh"
rr_prepare
rr_lock
rr_cli collect-policy
