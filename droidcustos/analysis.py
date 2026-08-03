"""MVT execution and result parsing.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterator

from .case import CasePaths
from .commands import run_to_files


@dataclass(frozen=True)
class MvtSummary:
    command_success: bool
    detected_records: int
    detected_files: list[str]
    critical_lines: list[str]
    warning_lines: list[str]
    bugreport_successes: int
    bugreport_failures: int
    alert_records: int = 0
    heuristic_records: int = 0
    unique_alert_records: int = 0
    confirmed_ioc_matches: int = 0
    alerts_by_level: dict[str, int] = field(default_factory=dict)
    alerts_by_module: dict[str, int] = field(default_factory=dict)
    alerts: list[dict[str, object]] = field(default_factory=list)
    matched_indicators: list[dict[str, object]] = field(default_factory=list)
    alert_files: list[str] = field(default_factory=list)
    androidqf_successes: int = 0
    androidqf_failures: int = 0


def _ioc_arguments(ioc_files: list[Path]) -> list[str]:
    """Build repeated MVT IOC arguments."""
    arguments: list[str] = []
    for path in ioc_files:
        arguments.extend(["--iocs", str(path)])
    return arguments


def _acquisition_roots(working: Path) -> list[Path]:
    """Locate extracted AndroidQF acquisition roots."""
    roots = sorted({path.parent for path in working.rglob("acquisition.json")})
    if roots:
        return roots
    if working.exists() and any(working.rglob("*")):
        return [working]
    return []


def _iter_record_dicts(payload: object) -> Iterator[dict[str, object]]:
    """Yield alert-like dictionaries from nested MVT JSON payloads."""
    if isinstance(payload, list):
        for item in payload:
            yield from _iter_record_dicts(item)
        return
    if not isinstance(payload, dict):
        return
    alert_keys = {"matched_indicator", "message", "level", "module"}
    if alert_keys & set(payload):
        yield payload
        return
    for value in payload.values():
        yield from _iter_record_dicts(value)


def _load_alert_records(paths: list[Path]) -> list[dict[str, object]]:
    """Load all alert records from canonical MVT result files."""
    records: list[dict[str, object]] = []
    for path in paths:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for record in _iter_record_dicts(payload):
            normalized = dict(record)
            normalized["source_file"] = str(path)
            records.append(normalized)
    return records


def _normalize_indicator(value: object) -> dict[str, object] | None:
    """Normalize a non-empty matched-indicator value."""
    if isinstance(value, dict) and value:
        return {str(key): item for key, item in value.items()}
    if isinstance(value, str) and value.strip():
        return {"value": value.strip()}
    return None


def _alert_level(record: dict[str, object]) -> str:
    """Return a normalized MVT alert level."""
    raw = str(record.get("level") or record.get("severity") or "informational").strip().upper()
    aliases = {"WARN": "WARNING", "INFO": "INFORMATIONAL"}
    return aliases.get(raw, raw or "INFORMATIONAL")


def _alert_module(record: dict[str, object]) -> str:
    """Return a normalized MVT module name."""
    return str(record.get("module") or record.get("source") or "unknown").strip() or "unknown"


def _alert_message(record: dict[str, object]) -> str:
    """Return a concise human-readable MVT alert message."""
    message = str(record.get("message") or record.get("event") or record.get("value") or "").strip()
    return message or "MVT generated an alert without a message"


def _deduplication_message(message: str) -> str:
    """Normalize duplicate protobuf and text tombstone messages."""
    return re.sub(r"(tombstone_\d+)\.pb\b", r"\1", message, flags=re.IGNORECASE)


def _summarize_alerts(records: list[dict[str, object]]) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Deduplicate MVT alerts and extract confirmed matched indicators."""
    grouped: dict[tuple[str, str, str, str], dict[str, object]] = {}
    indicators: dict[str, dict[str, object]] = {}
    for record in records:
        level = _alert_level(record)
        module = _alert_module(record)
        message = _alert_message(record)
        indicator = _normalize_indicator(record.get("matched_indicator"))
        indicator_key = json.dumps(indicator, sort_keys=True, default=str) if indicator else ""
        key = (level, module, _deduplication_message(message), indicator_key)
        source_file = str(record.get("source_file", ""))
        if key not in grouped:
            grouped[key] = {
                "level": level,
                "classification": "CONFIRMED_IOC" if indicator else "HEURISTIC",
                "module": module,
                "message": _deduplication_message(message),
                "matched_indicator": indicator,
                "occurrences": 0,
                "source_files": [],
            }
        grouped[key]["occurrences"] = int(grouped[key]["occurrences"]) + 1
        sources = grouped[key]["source_files"]
        if isinstance(sources, list) and source_file and source_file not in sources:
            sources.append(source_file)
        if indicator:
            indicators[indicator_key] = indicator
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "WARNING": 3, "LOW": 4, "INFORMATIONAL": 5}
    alerts = sorted(
        grouped.values(),
        key=lambda row: (
            0 if row["classification"] == "CONFIRMED_IOC" else 1,
            severity_order.get(str(row["level"]), 9),
            str(row["module"]),
            str(row["message"]),
        ),
    )
    return alerts, list(indicators.values())


def _mvt_log_lines(paths: list[Path], level: str) -> list[str]:
    """Extract actual structured MVT log-level entries."""
    pattern = re.compile(rf"\b{re.escape(level)}\s+\[[^]]+\]", re.IGNORECASE)
    lines: list[str] = []
    for path in paths:
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        lines.extend(line.strip() for line in content.splitlines() if pattern.search(line))
    return lines[:200]


def run_mvt(case: CasePaths, ioc_files: list[Path]) -> MvtSummary:
    """Run MVT against AndroidQF and bug-report acquisitions."""
    if case.mvt_analysis.exists():
        shutil.rmtree(case.mvt_analysis)
    case.mvt_analysis.mkdir(parents=True, exist_ok=True)
    androidqf_results: list[bool] = []

    for index, acquisition_root in enumerate(_acquisition_roots(case.androidqf_working), start=1):
        output = case.mvt_analysis / f"androidqf_{index}"
        output.mkdir(parents=True, exist_ok=True)
        command = [
            "mvt-android",
            "check-androidqf",
            "--output",
            str(output),
            *_ioc_arguments(ioc_files),
            str(acquisition_root),
        ]
        result = run_to_files(
            command,
            case.logs / f"mvt-androidqf-{index}.stdout.log",
            case.logs / f"mvt-androidqf-{index}.stderr.log",
            timeout=3600,
            command_log=case.command_log,
        )
        androidqf_results.append(result.ok)

    bugreport_results: list[bool] = []
    bugreports = sorted(case.adb_evidence.rglob("*.zip"))
    for index, bugreport in enumerate(bugreports, start=1):
        output = case.mvt_analysis / f"bugreport_{index}"
        output.mkdir(parents=True, exist_ok=True)
        check = run_to_files(
            [
                "mvt-android",
                "check-bugreport",
                "--output",
                str(output),
                *_ioc_arguments(ioc_files),
                str(bugreport),
            ],
            case.logs / f"mvt-bugreport-{index}.stdout.log",
            case.logs / f"mvt-bugreport-{index}.stderr.log",
            timeout=1800,
            command_log=case.command_log,
        )
        bugreport_results.append(check.ok)

    detected_paths = sorted(case.mvt_analysis.rglob("*_detected.json"))
    canonical_alert_paths = sorted(case.mvt_analysis.rglob("alerts.json"))
    alert_paths = canonical_alert_paths or detected_paths
    raw_alerts = _load_alert_records(alert_paths)
    alerts, matched_indicators = _summarize_alerts(raw_alerts)
    confirmed = sum(int(row.get("occurrences", 1)) for row in alerts if row.get("classification") == "CONFIRMED_IOC")
    heuristic = sum(int(row.get("occurrences", 1)) for row in alerts if row.get("classification") == "HEURISTIC")

    levels: dict[str, int] = {}
    modules: dict[str, int] = {}
    for alert in alerts:
        occurrences = int(alert.get("occurrences", 1))
        level = str(alert.get("level", "INFORMATIONAL"))
        module = str(alert.get("module", "unknown"))
        levels[level] = levels.get(level, 0) + occurrences
        modules[module] = modules.get(module, 0) + occurrences

    log_paths = [path for path in case.logs.glob("mvt-*.*.log") if path.is_file()]
    run_results = androidqf_results + bugreport_results
    summary = MvtSummary(
        command_success=bool(run_results) and all(run_results),
        detected_records=confirmed,
        detected_files=[str(path) for path in detected_paths if path.is_file()],
        critical_lines=_mvt_log_lines(log_paths, "CRITICAL"),
        warning_lines=_mvt_log_lines(log_paths, "WARNING"),
        bugreport_successes=sum(1 for result in bugreport_results if result),
        bugreport_failures=sum(1 for result in bugreport_results if not result),
        alert_records=len(raw_alerts),
        heuristic_records=heuristic,
        unique_alert_records=len(alerts),
        confirmed_ioc_matches=confirmed,
        alerts_by_level=dict(sorted(levels.items())),
        alerts_by_module=dict(sorted(modules.items())),
        alerts=alerts[:500],
        matched_indicators=matched_indicators[:500],
        alert_files=[str(path) for path in alert_paths],
        androidqf_successes=sum(1 for result in androidqf_results if result),
        androidqf_failures=sum(1 for result in androidqf_results if not result),
    )
    case.write_json("03_analysis/mvt-summary.json", asdict(summary))
    return summary
