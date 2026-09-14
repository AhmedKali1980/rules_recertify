#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ $# == 1 ]] || { echo "Usage: $0 RAW_DIR" >&2; exit 64; }
RAW="$1"; mkdir -p "$RAW"
"${ROOT}/scripts/workloader-wkld-export.sh" "$RAW/export_wkld.csv"
"${ROOT}/scripts/workloader-wkld-l3sm-managed-export.sh" "$RAW/export_wkld.l3sm.m.csv"
PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" python3 - "$RAW" <<'PY'
import logging, sys
from pathlib import Path
from rules_recertify.workloader.reference_exports import merge_workloads
logging.basicConfig(level=logging.INFO)
count = merge_workloads(Path(sys.argv[1])/'export_wkld.csv', Path(sys.argv[1])/'export_wkld.l3sm.m.csv')
print(f'Merged {count} L3SM workload rows')
PY
"${ROOT}/scripts/workloader-ipl-export.sh" "$RAW/export_iplists.csv"
PYTHONPATH="${ROOT}/src${PYTHONPATH:+:${PYTHONPATH}}" python3 - "$RAW" <<'PY'
import sys
from pathlib import Path
from rules_recertify.workloader.reference_exports import derive_exports
derive_exports(Path(sys.argv[1]))
PY
