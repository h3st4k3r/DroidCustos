"""Forensic acquisition coverage calculation.

Author: h3st4k3r
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .capabilities import AcquisitionPlan
from .plugins import CollectorResult, coverage_summary


@dataclass
class CoverageReport:
    target_collectors: int
    collected_collectors: int
    partial_collectors: int
    failed_collectors: int
    skipped_collectors: int
    permission_denied_collectors: int
    coverage_score: float
    statuses: list[dict[str, object]] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe coverage report."""
        return asdict(self)


def calculate_coverage(
    plan: AcquisitionPlan,
    plugin_results: list[CollectorResult],
    androidqf: dict[str, object],
    volatile: dict[str, object] | None,
    adb_extra: dict[str, object] | None,
    extended: dict[str, object] | None,
    package_inventory: dict[str, object] | None,
    aleapp: dict[str, object] | None,
) -> CoverageReport:
    """Calculate coverage across planned and capability-aware collectors."""
    statuses: list[dict[str, object]] = []

    def add(name: str, status: str, detail: object = None) -> None:
        """Append one normalized coverage status."""
        statuses.append({"collector": name, "status": status, "detail": detail})

    add("androidqf", "COLLECTED" if androidqf.get("complete") else "PARTIAL", androidqf.get("returncode"))
    if volatile is not None:
        add("volatile-state", "COLLECTED" if int(volatile.get("failed", 0)) == 0 else "PARTIAL", volatile)
    if adb_extra is not None:
        add("adb-diagnostics", "COLLECTED" if int(adb_extra.get("failed", 0)) == 0 else "PARTIAL", adb_extra)
    if package_inventory is not None:
        add("package-inventory", "COLLECTED" if int(package_inventory.get("package_count", 0)) > 0 else "FAILED")
    if extended is not None:
        for item in extended.get("statuses", []):
            add(f"extended:{item.get('category')}:{item.get('target')}", str(item.get("status", "FAILED")), item.get("returncode"))
    if aleapp is not None:
        if aleapp.get("requested") == "no":
            add("aleapp", "NOT_REQUESTED")
        elif aleapp.get("executed") and int(aleapp.get("returncode", 1)) == 0:
            add("aleapp", "COLLECTED")
        elif aleapp.get("available"):
            add("aleapp", "FAILED", aleapp.get("error"))
        else:
            add("aleapp", "NOT_SUPPORTED", aleapp.get("error"))

    for result in plugin_results:
        add(f"plugin:{result.plugin_id}:{result.collector_id}", result.status, result.reason)
    for item in plan.skipped_collectors:
        add(str(item["collector"]), "NOT_SUPPORTED", item["reason"])

    relevant = [item for item in statuses if item["status"] not in {"NOT_REQUESTED", "NOT_SUPPORTED"}]
    collected = sum(1 for item in relevant if item["status"] == "COLLECTED")
    partial = sum(1 for item in relevant if item["status"] == "PARTIAL")
    failed = sum(1 for item in relevant if item["status"] in {"FAILED", "TIMED_OUT"})
    denied = sum(1 for item in relevant if item["status"] == "PERMISSION_DENIED")
    skipped = sum(1 for item in statuses if item["status"] == "NOT_SUPPORTED")
    weighted = collected + partial * 0.5
    score = round(weighted / len(relevant) * 100, 2) if relevant else 0.0
    return CoverageReport(
        target_collectors=len(relevant),
        collected_collectors=collected,
        partial_collectors=partial,
        failed_collectors=failed,
        skipped_collectors=skipped,
        permission_denied_collectors=denied,
        coverage_score=score,
        statuses=statuses,
    )


def write_coverage(report: CoverageReport, destination: Path) -> Path:
    """Write the acquisition coverage report."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination
