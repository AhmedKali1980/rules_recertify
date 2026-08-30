from __future__ import annotations

import hashlib
import json
import logging
import signal
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
    def __init__(self, binary: Path, pce: str, log_file: Path, config_file: Optional[Path] = None):
        self.binary, self.pce, self.log_file, self.config_file = binary, pce, log_file, config_file

    def run(self, args: Sequence[str], timeout: Optional[int] = None) -> CommandResult:
        command = [str(self.binary)]
        if self.config_file:
            command.extend(["--config-file", str(self.config_file)])
        command.extend(["--pce", self.pce, "--log-file", str(self.log_file), *map(str, args)])
        LOG.info("Executing Workloader command: %s", " ".join(command))
        started = time.monotonic()
        try:
            completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkloaderError(f"Could not execute Workloader: {exc}") from exc
        result = CommandResult(command, completed.returncode, completed.stdout, completed.stderr, time.monotonic() - started)
        if result.returncode:
            output = result.stderr or result.stdout
            reason = _returncode_reason(result.returncode)
            raise WorkloaderError(
                f"Workloader {reason} after {result.elapsed_seconds:.1f}s: "
                f"{_bounded_output(output)}"
            )
        return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _returncode_reason(returncode: int) -> str:
    if returncode >= 0:
        return f"exited with status {returncode}"
    signal_number = -returncode
    try:
        signal_name = signal.Signals(signal_number).name
    except ValueError:
        signal_name = "UNKNOWN"
    hint = ""
    if signal_number == signal.SIGKILL:
        hint = " (forced SIGKILL; check the kernel OOM log and external process limits)"
    return f"was terminated by signal {signal_number} ({signal_name}){hint}"


def _bounded_output(value: str, limit: int = 12000) -> str:
    """Keep failures readable without copying unbounded Workloader output."""
    if len(value) <= limit:
        return value
    half = limit // 2
    omitted = len(value) - (half * 2)
    return f"{value[:half]}\n... [{omitted} characters omitted] ...\n{value[-half:]}"
