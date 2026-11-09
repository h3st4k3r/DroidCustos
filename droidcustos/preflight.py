"""Pre-acquisition readiness checks with auditable forensic output."""

from __future__ import annotations

import re
import shutil
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .commands import run_capture


MIN_FREE_BYTES = 512 * 1024 * 1024
RECOMMENDED_FREE_BYTES = 2 * 1024 * 1024 * 1024
LOW_BATTERY_PERCENT = 15
WARN_BATTERY_PERCENT = 25


@dataclass(frozen=True)
class PreflightCheck:
    """Represent one auditable pre-acquisition readiness check."""

    name: str
    status: str
    detail: str
    observed: dict[str, Any]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe check record."""
        return asdict(self)


def parse_battery_snapshot(output: str) -> dict[str, object]:
    """Parse the stable fields exposed by Android dumpsys battery."""
    level_match = re.search(r"(?im)^\s*level:\s*(\d+)\s*$", output)
    status_match = re.search(r"(?im)^\s*(?:battery )?status:\s*(.+?)\s*$", output)
    charging_fields = {
        name: value.lower() == "true"
        for name, value in re.findall(r"(?im)^\s*(ac powered|usb powered|wireless powered):\s*(true|false)\s*$", output)
    }
    return {
        "level_percent": int(level_match.group(1)) if level_match else None,
        "status": status_match.group(1).strip() if status_match else "",
        "charging": any(charging_fields.values()),
        "power_sources": charging_fields,
    }


def battery_check(snapshot: dict[str, object]) -> PreflightCheck:
    """Classify battery readiness without discarding the observed state."""
    level = snapshot.get("level_percent")
    charging = bool(snapshot.get("charging"))
    if not isinstance(level, int):
        return PreflightCheck("battery", "WARNING", "Battery level was not available from the device", snapshot)
    if level < LOW_BATTERY_PERCENT and not charging:
        return PreflightCheck("battery", "BLOCKED", "Battery is too low for a reliable acquisition unless charging", snapshot)
    if level < WARN_BATTERY_PERCENT and not charging:
        return PreflightCheck("battery", "WARNING", "Battery is low; connect stable power before acquisition", snapshot)
    return PreflightCheck("battery", "PASS", "Battery level and charging state are acceptable", snapshot)


def disk_check(name: str, path: Path) -> PreflightCheck:
    """Classify available storage while retaining exact filesystem values."""
    target = path if path.exists() else path.parent
    try:
        usage = shutil.disk_usage(target)
    except OSError as exc:
        return PreflightCheck(name, "BLOCKED", f"Unable to inspect free space: {exc}", {"path": str(path)})
    observed = {"path": str(path), "free_bytes": usage.free, "total_bytes": usage.total, "used_bytes": usage.used}
    if usage.free < MIN_FREE_BYTES:
        return PreflightCheck(name, "BLOCKED", "Less than 512 MiB is available on the target filesystem", observed)
    if usage.free < RECOMMENDED_FREE_BYTES:
        return PreflightCheck(name, "WARNING", "Less than 2 GiB is available on the target filesystem", observed)
    return PreflightCheck(name, "PASS", "Available storage is suitable for the selected acquisition profile", observed)


def estimate_duration(profile: object) -> dict[str, int]:
    """Estimate acquisition duration from explicit profile scope, not hidden work."""
    minimum = 8
    maximum = 20
    if getattr(profile, "backup", "none") != "none":
        minimum += 5
        maximum += 20
    if getattr(profile, "download", "none") != "none":
        minimum += 5
        maximum += 30
    if getattr(profile, "name", "standard") == "deep":
        minimum += 10
        maximum += 40
    if getattr(profile, "copy_user_files", False):
        minimum += 10
        maximum += 60
    return {"minimum_minutes": minimum, "maximum_minutes": maximum}


def run_preflight(
    adb: str,
    serial: str,
    case_root: Path,
    cache_root: Path,
    androidqf: Path,
    profile: object,
    command_log: Path | None = None,
) -> dict[str, object]:
    """Run and return readiness checks before any lengthy acquisition step."""
    state_result = run_capture([adb, "-s", serial, "get-state"], timeout=20, command_log=command_log)
    battery_result = run_capture([adb, "-s", serial, "shell", "dumpsys", "battery"], timeout=30, command_log=command_log)
    battery = parse_battery_snapshot(battery_result.stdout)
    battery_observed = {
        **battery,
        "returncode": battery_result.returncode,
        "stdout": battery_result.stdout,
        "stderr": battery_result.stderr,
    }
    checks = [
        PreflightCheck(
            "adb_transport",
            "PASS" if state_result.ok and state_result.stdout.strip() == "device" else "BLOCKED",
            "ADB reports an authorized device transport" if state_result.ok and state_result.stdout.strip() == "device" else "ADB transport is not ready",
            {"returncode": state_result.returncode, "stdout": state_result.stdout.strip(), "stderr": state_result.stderr.strip()},
        ),
        battery_check(battery_observed),
        disk_check("case_storage", case_root),
        disk_check("cache_storage", cache_root),
        PreflightCheck(
            "androidqf",
            "PASS" if androidqf.is_file() else "BLOCKED",
            "AndroidQF executable is available" if androidqf.is_file() else "AndroidQF executable is missing",
            {"path": str(androidqf), "exists": androidqf.is_file()},
        ),
    ]
    records = [item.to_dict() for item in checks]
    blocked = [item for item in records if item["status"] == "BLOCKED"]
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "serial": serial,
        "case_root": str(case_root),
        "cache_root": str(cache_root),
        "ready": not blocked,
        "status": "BLOCKED" if blocked else "READY",
        "blocking_checks": [item["name"] for item in blocked],
        "duration_estimate": estimate_duration(profile),
        "checks": records,
    }
