"""Host and Android clock synchronization from acquisition evidence."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path

from .commands import run_capture
from .datetime_utils import parse_iso8601


def _parse_device_time(value: str) -> datetime | None:
    """Parse common ISO Android date output."""
    text = str(value or "").strip()
    if not text:
        return None
    parsed = parse_iso8601(text)
    if parsed is None:
        return None
    return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)


def measure_time_sync(adb: str, serial: str, command_log: Path | None = None) -> dict[str, object]:
    """Measure clock offset and uncertainty with a bounded ADB round trip."""
    host_before = datetime.now(timezone.utc)
    monotonic_before = time.monotonic()
    result = run_capture(
        [adb, "-s", serial, "shell", "date", "-u", "+%Y-%m-%dT%H:%M:%S.%NZ"],
        timeout=30,
        command_log=command_log,
    )
    monotonic_after = time.monotonic()
    host_after = datetime.now(timezone.utc)
    device_time = _parse_device_time(result.stdout)
    rtt_ms = round((monotonic_after - monotonic_before) * 1000, 3)
    midpoint = host_before + (host_after - host_before) / 2
    offset_ms = round((device_time - midpoint).total_seconds() * 1000, 3) if device_time else None
    return {
        "format": "droidcustos-time-sync-v1",
        "host_before_utc": host_before.isoformat(),
        "host_after_utc": host_after.isoformat(),
        "device_time_utc": device_time.isoformat() if device_time else None,
        "rtt_ms": rtt_ms,
        "offset_ms": offset_ms,
        "uncertainty_ms": round(rtt_ms / 2, 3),
        "available": bool(result.ok and device_time),
        "error": None if result.ok and device_time else (result.stderr.strip() or "device-time-unavailable"),
    }
