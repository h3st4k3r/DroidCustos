"""Capability-aware OEM collector plugins.

Author: h3st4k3r
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from .capabilities import DeviceCapabilities
from .commands import run_to_files


@dataclass(frozen=True)
class PluginCollector:
    plugin_id: str
    collector_id: str
    description: str
    manufacturers: tuple[str, ...]
    sdk_min: int
    sdk_max: int
    privilege: str
    timeout: int
    command: tuple[str, ...]
    output: str
    sensitivity: str
    required_commands: tuple[str, ...]
    required_dumpsys: tuple[str, ...]


@dataclass(frozen=True)
class CollectorResult:
    collector_id: str
    plugin_id: str
    status: str
    output: str
    returncode: int | None
    reason: str
    sensitivity: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe collector result."""
        return asdict(self)


def _plugin_directory() -> Path:
    """Return the packaged plugin-data directory."""
    return Path(str(files("droidcustos").joinpath("plugin_data")))


def load_plugins(directory: Path | None = None) -> list[PluginCollector]:
    """Load declarative collectors from packaged YAML files."""
    root = directory or _plugin_directory()
    collectors: list[PluginCollector] = []
    for path in sorted(root.glob("*.yml")):
        payload = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        plugin_id = str(payload.get("id", path.stem))
        defaults = payload.get("defaults", {})
        for item in payload.get("collectors", []):
            collectors.append(
                PluginCollector(
                    plugin_id=plugin_id,
                    collector_id=str(item["id"]),
                    description=str(item.get("description", "")),
                    manufacturers=tuple(str(value).lower() for value in item.get("manufacturers", payload.get("manufacturers", ["*"]))),
                    sdk_min=int(item.get("sdk_min", defaults.get("sdk_min", 1))),
                    sdk_max=int(item.get("sdk_max", defaults.get("sdk_max", 999))),
                    privilege=str(item.get("privilege", defaults.get("privilege", "shell"))),
                    timeout=int(item.get("timeout", defaults.get("timeout", 120))),
                    command=tuple(str(value) for value in item.get("command", [])),
                    output=str(item.get("output", f"{item['id']}.txt")),
                    sensitivity=str(item.get("sensitivity", defaults.get("sensitivity", "system"))),
                    required_commands=tuple(str(value) for value in item.get("required_commands", [])),
                    required_dumpsys=tuple(str(value) for value in item.get("required_dumpsys", [])),
                )
            )
    return collectors


def _supports(collector: PluginCollector, capabilities: DeviceCapabilities) -> tuple[bool, str]:
    """Evaluate whether a collector can run on the connected device."""
    family = capabilities.rom_family.lower()
    manufacturer = capabilities.manufacturer.lower()
    if "*" not in collector.manufacturers and family not in collector.manufacturers and manufacturer not in collector.manufacturers:
        return False, "MANUFACTURER_MISMATCH"
    if not collector.sdk_min <= capabilities.sdk <= collector.sdk_max:
        return False, "SDK_OUT_OF_RANGE"
    if collector.privilege == "root" and not capabilities.root_authorized:
        return False, "AUTHORIZED_ROOT_UNAVAILABLE"
    for command in collector.required_commands:
        if not capabilities.commands.get(command, False):
            return False, f"COMMAND_UNAVAILABLE:{command}"
    available_services = set(capabilities.dumpsys_services)
    for service in collector.required_dumpsys:
        if service not in available_services:
            return False, f"DUMPSYS_UNAVAILABLE:{service}"
    if not collector.command:
        return False, "EMPTY_COMMAND"
    return True, ""


def _render_command(collector: PluginCollector, adb: str, serial: str, user_id: int) -> list[str]:
    """Render a trusted local plugin command."""
    values = {"adb": adb, "serial": serial, "user": str(user_id)}
    return [part.format(**values) for part in collector.command]


def execute_plugins(
    adb: str,
    serial: str,
    capabilities: DeviceCapabilities,
    user_ids: list[int],
    destination: Path,
    command_log: Path,
    directory: Path | None = None,
) -> list[CollectorResult]:
    """Execute all supported core and OEM collectors."""
    results: list[CollectorResult] = []
    collectors = load_plugins(directory)
    for collector in collectors:
        supported, reason = _supports(collector, capabilities)
        targets = user_ids if "{user}" in " ".join(collector.command) or "{user}" in collector.output else [user_ids[0] if user_ids else 0]
        if not supported:
            results.append(
                CollectorResult(
                    collector.collector_id,
                    collector.plugin_id,
                    "NOT_SUPPORTED",
                    "",
                    None,
                    reason,
                    collector.sensitivity,
                )
            )
            continue
        for user_id in targets:
            output_name = collector.output.format(user=user_id)
            output_path = destination / collector.plugin_id / output_name
            stderr_path = destination / collector.plugin_id / "errors" / f"{output_name}.stderr"
            command = _render_command(collector, adb, serial, user_id)
            result = run_to_files(
                command,
                output_path,
                stderr_path,
                timeout=collector.timeout,
                command_log=command_log,
            )
            status = "COLLECTED" if result.ok and output_path.exists() else "FAILED"
            error_text = stderr_path.read_text(encoding="utf-8", errors="replace")[:500] if stderr_path.exists() else ""
            lowered = error_text.lower()
            if "permission denial" in lowered or "permission denied" in lowered or "securityexception" in lowered:
                status = "PERMISSION_DENIED"
            if result.returncode == 124:
                status = "TIMED_OUT"
            results.append(
                CollectorResult(
                    collector.collector_id,
                    collector.plugin_id,
                    status,
                    str(output_path),
                    result.returncode,
                    error_text.strip(),
                    collector.sensitivity,
                )
            )
    destination.mkdir(parents=True, exist_ok=True)
    (destination / "collector-results.json").write_text(
        json.dumps([result.to_dict() for result in results], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return results


def coverage_summary(results: list[CollectorResult]) -> dict[str, Any]:
    """Calculate collection coverage from plugin outcomes."""
    relevant = [result for result in results if result.status != "NOT_SUPPORTED"]
    collected = [result for result in relevant if result.status == "COLLECTED"]
    permission_denied = [result for result in relevant if result.status == "PERMISSION_DENIED"]
    failed = [result for result in relevant if result.status in {"FAILED", "TIMED_OUT"}]
    score = round((len(collected) / len(relevant)) * 100, 2) if relevant else 100.0
    return {
        "applicable_collectors": len(relevant),
        "collected_collectors": len(collected),
        "permission_denied_collectors": len(permission_denied),
        "failed_collectors": len(failed),
        "not_supported_collectors": len(results) - len(relevant),
        "coverage_score": score,
    }
