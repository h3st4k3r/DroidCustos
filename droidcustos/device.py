"""Android device discovery and metadata collection.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path

from .commands import run_capture
from .time_sync import measure_time_sync


@dataclass(frozen=True)
class AndroidDevice:
    serial: str
    state: str
    details: dict[str, str]


def list_devices(adb: str = "adb", command_log: Path | None = None) -> list[AndroidDevice]:
    """Handle list devices operations."""
    result = run_capture([adb, "devices", "-l"], timeout=20, command_log=command_log)
    devices: list[AndroidDevice] = []
    for line in result.stdout.splitlines()[1:]:
        line = line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 2:
            continue
        details: dict[str, str] = {}
        for item in fields[2:]:
            if ":" in item:
                key, value = item.split(":", 1)
                details[key] = value
        devices.append(AndroidDevice(fields[0], fields[1], details))
    return devices


def select_device(
    requested_serial: str | None,
    wait_seconds: int,
    *,
    adb: str = "adb",
    command_log: Path | None = None,
) -> AndroidDevice:
    """Handle select device operations."""
    started = time.monotonic()
    while True:
        devices = list_devices(adb, command_log)
        if requested_serial:
            matches = [device for device in devices if device.serial == requested_serial]
            if matches:
                device = matches[0]
                if device.state != "device":
                    raise RuntimeError(f"Device {requested_serial} is {device.state}, not authorized and ready")
                return device
        else:
            ready = [device for device in devices if device.state == "device"]
            unauthorized = [device for device in devices if device.state == "unauthorized"]
            if len(ready) == 1:
                return ready[0]
            if len(ready) > 1:
                serials = ", ".join(device.serial for device in ready)
                raise RuntimeError(f"Multiple devices detected ({serials}); use --serial")
            if unauthorized:
                raise RuntimeError("Android device detected but unauthorized; unlock it and approve the USB debugging key")

        if wait_seconds == 0:
            time.sleep(2)
            continue
        if time.monotonic() - started >= wait_seconds:
            raise RuntimeError("No authorized Android device detected before timeout")
        time.sleep(2)


def adb_shell(adb: str, serial: str, *arguments: str, command_log: Path | None = None) -> str:
    """Handle adb shell operations."""
    result = run_capture([adb, "-s", serial, "shell", *arguments], timeout=30, command_log=command_log)
    if not result.ok:
        return ""
    return result.stdout.strip()


def collect_device_metadata(adb: str, serial: str, output: Path, command_log: Path | None = None) -> dict[str, object]:
    """Handle collect device metadata operations."""
    properties = {
        "manufacturer": "ro.product.manufacturer",
        "model": "ro.product.model",
        "device": "ro.product.device",
        "product": "ro.product.name",
        "android_version": "ro.build.version.release",
        "sdk": "ro.build.version.sdk",
        "build_fingerprint": "ro.build.fingerprint",
        "build_id": "ro.build.id",
        "security_patch": "ro.build.version.security_patch",
        "verified_boot_state": "ro.boot.verifiedbootstate",
        "flash_locked": "ro.boot.flash.locked",
        "vbmeta_device_state": "ro.boot.vbmeta.device_state",
        "bootloader": "ro.bootloader",
        "timezone": "persist.sys.timezone",
    }
    data: dict[str, object] = {"serial": serial}
    for name, prop in properties.items():
        data[name] = adb_shell(adb, serial, "getprop", prop, command_log=command_log)

    data["device_time"] = adb_shell(adb, serial, "date", command_log=command_log)
    data["time_sync"] = measure_time_sync(adb, serial, command_log)
    data["uptime"] = adb_shell(adb, serial, "uptime", command_log=command_log)
    data["adb_enabled"] = adb_shell(adb, serial, "settings", "get", "global", "adb_enabled", command_log=command_log)
    data["enabled_accessibility_services"] = adb_shell(
        adb,
        serial,
        "settings",
        "get",
        "secure",
        "enabled_accessibility_services",
        command_log=command_log,
    )
    data["default_input_method"] = adb_shell(
        adb, serial, "settings", "get", "secure", "default_input_method", command_log=command_log
    )
    data["su_path"] = adb_shell(adb, serial, "sh", "-c", "command -v su 2>/dev/null || true", command_log=command_log)

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data
