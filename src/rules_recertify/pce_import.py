"""Run the reference export pipeline for a collection directory."""
from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Optional

from .workloader.reference_exports import derive_exports, merge_workloads

LOG = logging.getLogger(__name__)
REQUIRED_EXPORTS = ("export_wkld.csv", "export_iplists.csv", "export_wkld.derived.csv", "export_iplists.derived.csv")


def import_pce_exports(raw_dir: Path, stub_dir: Optional[Path] = None,
                       environment: Optional[Mapping[str, str]] = None) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    stub = stub_dir or (Path(os.environ["PCE_STUB_DIR"]) if os.getenv("PCE_STUB_DIR") else None)
    if stub:
        for name in ("export_wkld.csv", "export_iplists.csv"):
            source = stub / name
            if not source.is_file() or source.stat().st_size == 0:
                raise RuntimeError(f"Required stub is missing or empty: {source}")
            shutil.copy2(source, raw_dir / name)
        optional = stub / "export_wkld.l3sm.m.csv"
        if optional.is_file() and optional.stat().st_size:
            shutil.copy2(optional, raw_dir / optional.name)
            count = merge_workloads(raw_dir / "export_wkld.csv", raw_dir / optional.name)
            LOG.info("Merged %s L3SM workload rows", count)
        derive_exports(raw_dir)
    else:
        script = Path(__file__).resolve().parents[2] / "scripts" / "import-pce-reference.sh"
        completed = subprocess.run([str(script), str(raw_dir)], text=True, capture_output=True,
                                   env=dict(environment or os.environ), check=False)
        if completed.stdout: LOG.info("PCE import stdout:\n%s", completed.stdout.rstrip())
        if completed.stderr: LOG.info("PCE import stderr:\n%s", completed.stderr.rstrip())
        if completed.returncode:
            raise RuntimeError(f"PCE reference import failed with status {completed.returncode}")
    missing = [name for name in REQUIRED_EXPORTS if not (raw_dir / name).is_file() or not (raw_dir / name).stat().st_size]
    if missing:
        raise RuntimeError("PCE import did not produce required files: " + ", ".join(missing))
