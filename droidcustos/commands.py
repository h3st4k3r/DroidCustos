"""Subprocess execution with auditable command logging.

Author: h3st4k3r
"""

from __future__ import annotations

import os
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping


@dataclass
class CommandResult:
    command: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        """Handle ok operations."""
        return self.returncode == 0


def command_string(command: Iterable[str]) -> str:
    """Handle command string operations."""
    return " ".join(shlex.quote(str(part)) for part in command)


def _timestamp() -> str:
    """Handle timestamp operations."""
    return datetime.now(timezone.utc).isoformat()


def append_command_log(log_file: Path | None, command: list[str], phase: str = "START", returncode: int | None = None) -> None:
    """Handle append command log operations."""
    if log_file is None:
        return
    log_file.parent.mkdir(parents=True, exist_ok=True)
    suffix = "" if returncode is None else f" returncode={returncode}"
    with log_file.open("a", encoding="utf-8") as handle:
        handle.write(f"[{_timestamp()}] {phase}{suffix} $ {command_string(command)}\n")


def _merged_env(env: Mapping[str, str] | None) -> dict[str, str]:
    """Handle merged env operations."""
    merged = os.environ.copy()
    if env:
        merged.update(env)
    return merged


def run_capture(
    command: list[str],
    *,
    timeout: int | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    command_log: Path | None = None,
) -> CommandResult:
    """Handle run capture operations."""
    append_command_log(command_log, command)
    try:
        process = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            env=_merged_env(env),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        append_command_log(command_log, command, "END", process.returncode)
        return CommandResult(command, process.returncode, process.stdout, process.stderr)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        stderr = exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        append_command_log(command_log, command, "END", 124)
        return CommandResult(command, 124, stdout, f"{stderr}\nCommand timed out")
    except OSError as exc:
        append_command_log(command_log, command, "END", 127)
        return CommandResult(command, 127, "", str(exc))


def run_to_files(
    command: list[str],
    stdout_path: Path,
    stderr_path: Path,
    *,
    timeout: int | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    command_log: Path | None = None,
) -> CommandResult:
    """Handle run to files operations."""
    append_command_log(command_log, command)
    stdout_path.parent.mkdir(parents=True, exist_ok=True)
    stderr_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with stdout_path.open("wb") as stdout_handle, stderr_path.open("wb") as stderr_handle:
            process = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                env=_merged_env(env),
                stdout=stdout_handle,
                stderr=stderr_handle,
                timeout=timeout,
                check=False,
            )
        append_command_log(command_log, command, "END", process.returncode)
        return CommandResult(command, process.returncode)
    except subprocess.TimeoutExpired:
        with stderr_path.open("ab") as stderr_handle:
            stderr_handle.write(b"\nCommand timed out\n")
        append_command_log(command_log, command, "END", 124)
        return CommandResult(command, 124)
    except OSError as exc:
        with stderr_path.open("ab") as stderr_handle:
            stderr_handle.write(f"\n{exc}\n".encode())
        append_command_log(command_log, command, "END", 127)
        return CommandResult(command, 127)


def run_binary_to_file(
    command: list[str],
    output_path: Path,
    stderr_path: Path,
    *,
    timeout: int | None = None,
    command_log: Path | None = None,
) -> CommandResult:
    """Handle run binary to file operations."""
    return run_to_files(
        command,
        output_path,
        stderr_path,
        timeout=timeout,
        command_log=command_log,
    )


def run_stream(
    command: list[str],
    log_path: Path,
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    command_log: Path | None = None,
) -> CommandResult:
    """Run a command while mirroring combined output to the terminal and a log file."""
    append_command_log(command_log, command)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with log_path.open("w", encoding="utf-8", errors="replace") as log_handle:
            process = subprocess.Popen(
                command,
                cwd=str(cwd) if cwd else None,
                env=_merged_env(env),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
            )
            assert process.stdout is not None
            for line in process.stdout:
                print(line, end="")
                log_handle.write(line)
                log_handle.flush()
            returncode = process.wait()
        append_command_log(command_log, command, "END", returncode)
        return CommandResult(command, returncode)
    except OSError as exc:
        log_path.write_text(f"{exc}\n", encoding="utf-8")
        append_command_log(command_log, command, "END", 127)
        return CommandResult(command, 127, "", str(exc))
