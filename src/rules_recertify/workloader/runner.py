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
        process_output = self.log_file.with_name("workloader-output.log")
        process_output.parent.mkdir(parents=True, exist_ok=True)
        try:
            with process_output.open("a+b") as output:
                output.write((f"\n=== {' '.join(command)} ===\n").encode("utf-8"))
                output.flush()
                output_start = output.tell()
                completed = subprocess.run(
                    command,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    timeout=timeout,
                    check=False,
                )
                output.flush()
                output_end = output.tell()
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkloaderError(f"Could not execute Workloader: {exc}") from exc
        result = CommandResult(command, completed.returncode, "", "", time.monotonic() - started)
        if result.returncode:
            output_text = _bounded_file_output(process_output, output_start, output_end)
            reason = _returncode_reason(result.returncode)
            hint = _failure_hint(output_text)
            raise WorkloaderError(
                f"Workloader {reason} after {result.elapsed_seconds:.1f}s{hint}: "
                f"{output_text} (full output: {process_output})"
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


def _failure_hint(output: str) -> str:
    normalized = output.lower()
    if "status code: 429" in normalized or "received a 429" in normalized:
        return " (PCE/API rate limit HTTP 429; wait before submitting more queries)"
    return ""


def _bounded_file_output(path: Path, start: int, end: int, limit: int = 12000) -> str:
    """Read only bounded head/tail excerpts from one command's disk output."""
    size = max(0, end - start)
    with path.open("rb") as handle:
        handle.seek(start)
        if size <= limit:
            value = handle.read(size)
        else:
            half = limit // 2
            head = handle.read(half)
            handle.seek(end - half)
            tail = handle.read(half)
            marker = f"\n... [{size - (half * 2)} bytes omitted] ...\n".encode("ascii")
            value = head + marker + tail
    return value.decode("utf-8", errors="replace")
