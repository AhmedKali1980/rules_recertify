from __future__ import annotations

import hashlib
import json
import logging
import re
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
    def __init__(
        self,
        binary: Path,
        pce: str,
        log_file: Path,
        config_file: Optional[Path] = None,
        rate_limit_retry_delay_minutes: int = 10,
        rate_limit_max_retries: int = 12,
    ):
        self.binary, self.pce, self.log_file, self.config_file = binary, pce, log_file, config_file
        self.rate_limit_retry_delay_minutes = rate_limit_retry_delay_minutes
        self.rate_limit_max_retries = rate_limit_max_retries

    def run(self, args: Sequence[str], timeout: Optional[int] = None) -> CommandResult:
        command = [str(self.binary)]
        if self.config_file:
            command.extend(["--config-file", str(self.config_file)])
        command.extend(["--pce", self.pce, "--log-file", str(self.log_file), *map(str, args)])
        LOG.info("Executing Workloader command: %s", " ".join(command))
        process_output = self.log_file.with_name("workloader-output.log")
        process_output.parent.mkdir(parents=True, exist_ok=True)
        transient_retries = 0
        while True:
            started = time.monotonic()
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
            if not result.returncode:
                return result
            output_text = _bounded_file_output(process_output, output_start, output_end)
            reason = _returncode_reason(result.returncode)
            hint = _failure_hint(output_text)
            error = WorkloaderError(
                f"Workloader {reason} after {result.elapsed_seconds:.1f}s{hint}: "
                f"{output_text} (full output: {process_output})"
            )
            http_status = retryable_http_status(error)
            if http_status is None or transient_retries >= self.rate_limit_max_retries:
                raise error
            transient_retries += 1
            delay_seconds = self.rate_limit_retry_delay_minutes * 60
            LOG.warning(
                "Workloader transient HTTP %s; retrying the same command in %s minutes "
                "(%s/%s)",
                http_status,
                self.rate_limit_retry_delay_minutes,
                transient_retries,
                self.rate_limit_max_retries,
            )
            time.sleep(delay_seconds)


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
    status = _http_status(output)
    if status == 429:
        return " (PCE/API rate limit HTTP 429; wait before submitting more queries)"
    if status in {500, 502, 503, 504}:
        return f" (transient PCE/API HTTP {status}; the command can be retried)"
    return ""


def is_rate_limit_error(exc: WorkloaderError) -> bool:
    return _http_status(str(exc)) == 429


def retryable_http_status(exc: WorkloaderError) -> Optional[int]:
    status = _http_status(str(exc))
    return status if status in {429, 500, 502, 503, 504} else None


def _http_status(output: str) -> Optional[int]:
    patterns = (
        r"(?:response\s+)?status code:\s*(\d{3})",
        r"http status code of\s+(\d{3})",
        r"received (?:an?\s+)?(?:http\s+)?(\d{3})",
    )
    matches = [
        (match.start(), int(match.group(1)))
        for pattern in patterns
        for match in re.finditer(pattern, output, re.IGNORECASE)
    ]
    return max(matches)[1] if matches else None


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
