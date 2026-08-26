from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional, Sequence

LOG = logging.getLogger(__name__)


class WorkloaderError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    elapsed_seconds: float


class WorkloaderRunner:
    def __init__(self, binary: Path, pce: str, log_file: Path):
        self.binary, self.pce, self.log_file = binary, pce, log_file

    def run(self, args: Sequence[str], timeout: Optional[int] = None) -> CommandResult:
        command = [str(self.binary), "--pce", self.pce, "--log-file", str(self.log_file), *map(str, args)]
        LOG.info("Executing Workloader command: %s", " ".join(command))
        started = time.monotonic()
        try:
            completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkloaderError(f"Could not execute Workloader: {exc}") from exc
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr, time.monotonic() - started)
        if result.returncode:
            raise WorkloaderError(f"Workloader exited {result.returncode}: {result.stderr or result.stdout}")
        return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()
