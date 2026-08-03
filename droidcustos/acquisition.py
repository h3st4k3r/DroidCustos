"""Android forensic acquisition orchestration.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from .capabilities import DeviceCapabilities
from .case import CasePaths
from .commands import run_stream, run_to_files


VOLATILE_COMMANDS: tuple[tuple[str, list[str], int], ...] = (
    ("processes.txt", ["shell", "ps", "-A", "-o", "USER,PID,PPID,NAME,ARGS"], 60),
    ("ip-address.txt", ["shell", "ip", "address", "show"], 60),
    ("ip-route.txt", ["shell", "ip", "route", "show", "table", "all"], 60),
    ("sockets.txt", ["shell", "sh", "-c", "ss -H -a -n -p 2>/dev/null || netstat -an 2>/dev/null || true"], 90),
    ("logcat-all.txt", ["logcat", "-b", "all", "-d", "-v", "threadtime"], 180),
    ("uptime.txt", ["shell", "uptime"], 30),
    ("date.txt", ["shell", "date", "+%Y-%m-%dT%H:%M:%S%z"], 30),
)


STATIC_COMMANDS: tuple[tuple[str, list[str], int], ...] = (
    ("getprop.txt", ["shell", "getprop"], 60),
    ("services.txt", ["shell", "service", "list"], 60),
    ("settings-global.txt", ["shell", "settings", "list", "global"], 60),
    ("packages-all.txt", ["shell", "pm", "list", "packages", "-f", "-i", "-U", "-u", "--show-versioncode"], 180),
    ("packages-third-party.txt", ["shell", "pm", "list", "packages", "-3", "-f", "-i", "-U", "--show-versioncode"], 180),
    ("packages-disabled.txt", ["shell", "pm", "list", "packages", "-d"], 60),
    ("features.txt", ["shell", "pm", "list", "features"], 60),
    ("permissions.txt", ["shell", "pm", "list", "permissions", "-g", "-f"], 180),
    ("proc-mounts.txt", ["shell", "cat", "/proc/mounts"], 60),
    ("selinux.txt", ["shell", "getenforce"], 30),
    ("verified-boot.txt", ["shell", "sh", "-c", "getprop | grep -Ei 'verifiedboot|vbmeta|flash.locked|bootloader' || true"], 30),
    ("storage-df.txt", ["shell", "df", "-a"], 60),
    ("storage-mount.txt", ["shell", "mount"], 60),
)


DEFAULT_DUMPSYS_SERVICES: tuple[str, ...] = (
    "activity",
    "package",
    "procstats",
    "meminfo",
    "netstats",
    "connectivity",
    "batterystats",
    "usagestats",
    "appops",
    "device_policy",
    "jobscheduler",
    "alarm",
    "notification",
    "accessibility",
    "account",
    "role",
    "wifi",
    "bluetooth_manager",
    "usb",
    "mount",
    "dropbox",
    "trust",
)


def run_androidqf(
    androidqf: Path,
    serial: str,
    case: CasePaths,
    *,
    backup: str,
    download: str,
    remove_trusted: str,
    intrusion_logs: str,
    hash_files: str,
) -> dict[str, object]:
    """Run a non-interactive AndroidQF acquisition."""
    command = [
        str(androidqf),
        "-serial",
        serial,
        "-backup",
        backup,
        "-download",
        download,
        "-remove-trusted",
        remove_trusted,
        "-intrusion-logs",
        intrusion_logs,
        "-hash-files",
        hash_files,
        "-non-interactive",
        "-output",
        str(case.androidqf_evidence),
    ]
    started = datetime.now(timezone.utc).isoformat()
    result = run_stream(command, case.logs / "androidqf.log", cwd=case.androidqf_evidence, command_log=case.command_log)
    archives = sorted(str(path) for path in case.androidqf_evidence.glob("*.zip"))
    encrypted = sorted(str(path) for path in case.androidqf_evidence.glob("*.age"))
    status = {
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "returncode": result.returncode,
        "archives": archives,
        "encrypted_archives": encrypted,
        "complete": result.ok and bool(archives),
    }
    case.write_json("00_metadata/androidqf-status.json", status)
    return status


def _run_collection_set(
    adb: str,
    serial: str,
    commands: tuple[tuple[str, list[str], int], ...],
    destination: Path,
    error_dir: Path,
    command_log: Path,
) -> list[dict[str, object]]:
    """Run one deterministic set of ADB collection commands."""
    results: list[dict[str, object]] = []
    for filename, arguments, timeout in commands:
        result = run_to_files(
            [adb, "-s", serial, *arguments],
            destination / filename,
            error_dir / f"{filename}.stderr",
            timeout=timeout,
            command_log=command_log,
        )
        status = "COLLECTED" if result.ok else "TIMED_OUT" if result.returncode == 124 else "FAILED"
        results.append({"name": filename, "returncode": result.returncode, "status": status})
    return results


def collect_volatile_state(adb: str, serial: str, case: CasePaths) -> dict[str, object]:
    """Collect volatile process, network and log state first."""
    destination = case.adb_evidence / "volatile"
    errors = destination / "errors"
    destination.mkdir(parents=True, exist_ok=True)
    errors.mkdir(parents=True, exist_ok=True)
    results = _run_collection_set(adb, serial, VOLATILE_COMMANDS, destination, errors, case.command_log)
    summary = {
        "phase": "volatile",
        "commands": results,
        "successful": sum(1 for item in results if item["status"] == "COLLECTED"),
        "failed": sum(1 for item in results if item["status"] != "COLLECTED"),
    }
    case.write_json("00_metadata/volatile-status.json", summary)
    return summary


def collect_adb_extras(
    adb: str,
    serial: str,
    case: CasePaths,
    capabilities: DeviceCapabilities,
    user_ids: list[int],
) -> dict[str, object]:
    """Collect capability-aware static ADB diagnostics and bug reports."""
    destination = case.adb_evidence / "static"
    errors = destination / "errors"
    destination.mkdir(parents=True, exist_ok=True)
    errors.mkdir(parents=True, exist_ok=True)
    results = _run_collection_set(adb, serial, STATIC_COMMANDS, destination, errors, case.command_log)

    users_dir = destination / "users"
    for user_id in user_ids:
        for category in ("secure", "system"):
            filename = f"settings-{category}-user-{user_id}.txt"
            result = run_to_files(
                [adb, "-s", serial, "shell", "settings", "--user", str(user_id), "list", category],
                users_dir / filename,
                errors / f"{filename}.stderr",
                timeout=90,
                command_log=case.command_log,
            )
            status = "COLLECTED" if result.ok else "FAILED"
            results.append({"name": f"users/{filename}", "returncode": result.returncode, "status": status})

    dumpsys_dir = destination / "dumpsys"
    dumpsys_dir.mkdir(parents=True, exist_ok=True)
    available = set(capabilities.dumpsys_services)
    services = [service for service in DEFAULT_DUMPSYS_SERVICES if service in available]
    for service in services:
        filename = f"{service}.txt"
        result = run_to_files(
            [adb, "-s", serial, "shell", "dumpsys", service],
            dumpsys_dir / filename,
            errors / f"dumpsys-{service}.stderr",
            timeout=600 if service in {"dropbox", "package"} else 300,
            command_log=case.command_log,
        )
        status = "COLLECTED" if result.ok else "TIMED_OUT" if result.returncode == 124 else "FAILED"
        results.append({"name": f"dumpsys/{filename}", "returncode": result.returncode, "status": status})

    bugreport_dir = case.adb_evidence / "bugreport"
    bugreport_dir.mkdir(parents=True, exist_ok=True)
    bugreport = run_to_files(
        [adb, "-s", serial, "bugreport", str(bugreport_dir)],
        case.logs / "adb-bugreport.stdout.log",
        case.logs / "adb-bugreport.stderr.log",
        timeout=1800,
        command_log=case.command_log,
    )
    bugreport_status = "COLLECTED" if bugreport.ok else "TIMED_OUT" if bugreport.returncode == 124 else "FAILED"
    results.append({"name": "bugreport", "returncode": bugreport.returncode, "status": bugreport_status})

    summary = {
        "phase": "static",
        "commands": results,
        "successful": sum(1 for item in results if item["status"] == "COLLECTED"),
        "failed": sum(1 for item in results if item["status"] != "COLLECTED"),
        "available_dumpsys_services": len(available),
        "selected_dumpsys_services": services,
    }
    case.write_json("00_metadata/adb-extra-status.json", summary)
    return summary


def _safe_extract(archive: Path, destination: Path) -> None:
    """Extract an AndroidQF ZIP without path traversal."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as package:
        base = destination.resolve()
        for member in package.infolist():
            target = (destination / member.filename).resolve()
            if base not in target.parents and target != base:
                raise RuntimeError(f"Unsafe ZIP member in {archive}: {member.filename}")
        package.extractall(destination)


def prepare_working_copy(case: CasePaths) -> list[Path]:
    """Extract AndroidQF archives into a disposable working tree."""
    if case.androidqf_working.exists():
        shutil.rmtree(case.androidqf_working)
    case.androidqf_working.mkdir(parents=True)
    extracted: list[Path] = []
    archives = sorted(case.androidqf_evidence.glob("*.zip"))
    if len(archives) == 1:
        _safe_extract(archives[0], case.androidqf_working)
        extracted.append(case.androidqf_working)
    else:
        for index, archive in enumerate(archives, start=1):
            destination = case.androidqf_working / f"acquisition_{index}"
            _safe_extract(archive, destination)
            extracted.append(destination)
    return extracted
