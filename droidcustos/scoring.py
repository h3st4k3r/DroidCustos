"""Evidence-based verdict calculation.

Author: h3st4k3r
"""

from __future__ import annotations

from dataclasses import dataclass

from .analysis import MvtSummary
from .coverage import CoverageReport
from .heuristics import Finding


@dataclass(frozen=True)
class Verdict:
    code: str
    message: str
    level: str
    score: int
    exit_code: int
    reasons: list[str]


def calculate_verdict(
    mvt: MvtSummary,
    findings: list[Finding],
    *,
    acquisition_complete: bool,
    ioc_count: int,
    integrity_verified: bool = True,
    coverage: CoverageReport | None = None,
    timeline_ioc_matches: int = 0,
    extended_ioc_matches: int = 0,
) -> Verdict:
    """Calculate a conservative forensic conclusion from confirmed evidence."""
    reasons: list[str] = []
    heuristic_score = min(sum(item.score for item in findings if item.category != "ioc"), 100)
    confirmed_ioc_findings = [item for item in findings if item.category == "ioc"]
    review_findings = [item for item in findings if item.category != "ioc" and item.severity in {"critical", "high"}]
    coverage_score = coverage.coverage_score if coverage else 100.0
    mvt_confirmed = max(mvt.confirmed_ioc_matches, mvt.detected_records)
    confirmed_sources = mvt_confirmed + len(confirmed_ioc_findings) + timeline_ioc_matches + extended_ioc_matches

    if confirmed_sources > 0:
        if mvt_confirmed:
            reasons.append(f"MVT alerts with a non-null matched indicator: {mvt_confirmed}")
        if confirmed_ioc_findings:
            reasons.append(f"DroidCustos package, certificate or hash IOC matches: {len(confirmed_ioc_findings)}")
            reasons.extend(item.title for item in confirmed_ioc_findings[:10])
        if timeline_ioc_matches:
            reasons.append(f"Timeline events with active IOC matches: {timeline_ioc_matches}")
        if extended_ioc_matches:
            reasons.append(f"Extended artifact IOC matches: {extended_ioc_matches}")
        if not integrity_verified:
            reasons.append("Evidence integrity verification failed; IOC evidence requires independent validation")
        if not acquisition_complete:
            reasons.append("The acquisition was incomplete, but confirmed IOC evidence was present in acquired artifacts")
        return Verdict("KNOWN_IOC_MATCHES", "KNOWN IOC MATCHES DETECTED", "detected", 100, 20, reasons)

    incomplete = (
        not integrity_verified
        or not acquisition_complete
        or not mvt.command_success
        or ioc_count == 0
        or coverage_score < 60.0
        or bool(coverage and coverage.missing_critical_sources)
    )
    if incomplete:
        if not integrity_verified:
            reasons.append("Evidence manifest verification failed or was unavailable")
        if not acquisition_complete:
            reasons.append("AndroidQF did not produce a complete plaintext acquisition")
        if not mvt.command_success:
            reasons.append("No complete successful MVT analysis run was available")
        if ioc_count == 0:
            reasons.append("No STIX2 indicator files were available")
        if coverage_score < 60.0:
            reasons.append(f"Acquisition coverage was below the minimum threshold: {coverage_score:.2f}%")
        if coverage and coverage.missing_critical_sources:
            reasons.append("Critical evidence sources missing: " + ", ".join(coverage.missing_critical_sources))
        if review_findings:
            reasons.extend(f"{item.severity.upper()}: {item.title}" for item in review_findings[:15])
            return Verdict(
                "INCONCLUSIVE_WITH_FINDINGS",
                "INCONCLUSIVE — FINDINGS REQUIRE REVIEW",
                "suspicious",
                max(heuristic_score, 50),
                30,
                reasons,
            )
        return Verdict("INCONCLUSIVE", "INCONCLUSIVE OR INCOMPLETE ACQUISITION", "inconclusive", heuristic_score, 30, reasons)

    high_mvt_alerts = int(mvt.alerts_by_level.get("CRITICAL", 0)) + int(mvt.alerts_by_level.get("HIGH", 0))
    if heuristic_score >= 30 or review_findings or high_mvt_alerts:
        reasons.extend(f"{item.severity.upper()}: {item.title}" for item in review_findings[:15])
        if high_mvt_alerts:
            reasons.append(f"MVT high or critical heuristic alerts without a confirmed IOC: {high_mvt_alerts}")
        reasons.append(f"Acquisition coverage: {coverage_score:.2f}%")
        return Verdict("SUSPICIOUS", "SUSPICIOUS ARTIFACTS REQUIRE REVIEW", "suspicious", heuristic_score, 10, reasons)

    reasons.append("No confirmed published IOC matches were found in the acquired artifacts")
    reasons.append(f"Acquisition coverage: {coverage_score:.2f}%")
    if findings:
        reasons.append(f"Low or medium-confidence heuristic findings: {len(findings)}")
    if mvt.heuristic_records:
        reasons.append(f"MVT heuristic alerts without matched indicators: {mvt.heuristic_records}")
    return Verdict("NO_KNOWN_INDICATORS", "NO KNOWN INDICATORS DETECTED", "clear", heuristic_score, 0, reasons)
