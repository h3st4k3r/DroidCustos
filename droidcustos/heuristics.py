"""Conservative Android heuristic checks.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from pathlib import Path

from .hashing import sha256_file
from .ioc_matcher import IOCExpression, load_stix_expressions, match_expressions


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    title: str
    evidence: str
    score: int


ROOT_PACKAGE_TOKENS = (
    "magisk",
    "kernelsu",
    "apatch",
    "supersu",
    "kingroot",
    "xposed",
    "lsposed",
    "riru",
    "frida",
)


HIGH_RISK_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.BIND_VPN_SERVICE",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
}


def _read(path: Path) -> str:
    """Read a text artifact without interrupting analysis."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def analyze_device_metadata(metadata: dict[str, object]) -> list[Finding]:
    """Evaluate boot integrity, patch age and sensitive settings."""
    findings: list[Finding] = []
    verified = str(metadata.get("verified_boot_state", "")).lower()
    flash_locked = str(metadata.get("flash_locked", "")).lower()
    vbmeta = str(metadata.get("vbmeta_device_state", "")).lower()
    if verified and verified != "green":
        findings.append(Finding("high", "boot-integrity", "Verified Boot is not green", verified, 55))
    if flash_locked and flash_locked not in {"1", "locked"}:
        findings.append(Finding("high", "boot-integrity", "Bootloader does not report locked state", flash_locked, 55))
    if vbmeta and vbmeta not in {"locked"}:
        findings.append(Finding("high", "boot-integrity", "VBMeta device state is not locked", vbmeta, 55))
    patch = str(metadata.get("security_patch", ""))
    try:
        patch_date = date.fromisoformat(patch)
        age = (datetime.now(timezone.utc).date() - patch_date).days
        if age > 180:
            findings.append(Finding("high", "patch-level", "Security patch is more than 180 days old", f"{patch} ({age} days)", 35))
        elif age > 90:
            findings.append(Finding("medium", "patch-level", "Security patch is more than 90 days old", f"{patch} ({age} days)", 20))
    except ValueError:
        if patch:
            findings.append(Finding("low", "patch-level", "Unable to parse security patch date", patch, 5))
    services = str(metadata.get("enabled_accessibility_services", ""))
    if services and services.lower() not in {"null", "none"}:
        findings.append(Finding("medium", "accessibility", "Accessibility services are enabled", services, 15))
    su_path = str(metadata.get("su_path", ""))
    if su_path:
        findings.append(Finding("high", "root", "su executable is available to the shell", su_path, 60))
    return findings


def _ioc_expressions(ioc_files: list[Path]) -> list[IOCExpression]:
    """Load complete active-capable STIX expressions for heuristic scopes."""
    return load_stix_expressions(ioc_files)


def _ioc_findings(matches: list[dict[str, object]], evidence: str) -> list[Finding]:
    """Convert complete STIX expression matches into confirmed findings."""
    findings: list[Finding] = []
    for match in matches:
        findings.append(
            Finding(
                "critical",
                "ioc",
                "Complete STIX expression matches published IOC evidence",
                f"{evidence}: {match.get('pattern', '')}",
                100,
            )
        )
    return findings


def analyze_packages(packages_file: Path, ioc_files: list[Path]) -> list[Finding]:
    """Check package identifiers from the basic ADB inventory."""
    findings: list[Finding] = []
    content = _read(packages_file)
    packages = set(re.findall(r"package:(?:\S+=)?(?P<package>[A-Za-z0-9_.]+)", content))
    for package in sorted(packages):
        lowered = package.lower()
        if any(token in lowered for token in ROOT_PACKAGE_TOKENS):
            findings.append(Finding("high", "package", "Root or instrumentation package detected", package, 50))
    expressions = _ioc_expressions(ioc_files)
    for package in sorted(packages):
        findings.extend(_ioc_findings(match_expressions({"package": [package]}, expressions), package))
    return findings


def analyze_package_inventory(inventory_path: Path, ioc_files: list[Path]) -> list[Finding]:
    """Evaluate normalized package metadata and signing certificates."""
    if not inventory_path.is_file():
        return []
    payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    expressions = _ioc_expressions(ioc_files)
    findings: list[Finding] = []
    for record in payload.get("records", []):
        package = str(record.get("package", ""))
        installer = str(record.get("installer", ""))
        permissions = set(str(value) for value in record.get("requested_permissions", []))
        certificates = {str(value).lower() for value in record.get("signing_certificates_sha256", [])}
        local_apks = record.get("local_apks", [])
        evidence = {
            "package": [package],
            "certificate-sha256": certificates,
            "sha256": [str(item.get("sha256", "")) for item in local_apks],
        }
        findings.extend(_ioc_findings(match_expressions(evidence, expressions), package))
        risky = permissions & HIGH_RISK_PERMISSIONS
        if len(risky) >= 5 and installer in {"", "null", "com.android.shell"}:
            findings.append(
                Finding(
                    "medium",
                    "package-permissions",
                    "Sideloaded package requests multiple high-risk capabilities",
                    f"{package}: {', '.join(sorted(risky))}",
                    25,
                )
            )
    return findings


def analyze_apk_hashes(working: Path, ioc_files: list[Path], output: Path) -> list[Finding]:
    """Hash acquired APKs and match active SHA-256 indicators."""
    findings: list[Finding] = []
    expressions = _ioc_expressions(ioc_files)
    rows: list[dict[str, str]] = []
    for apk in sorted(working.rglob("*.apk")):
        digest = sha256_file(apk)
        rows.append({"path": str(apk), "sha256": digest})
        findings.extend(_ioc_findings(match_expressions({"sha256": [digest]}, expressions), f"{digest} {apk}"))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return findings


def run_heuristics(
    metadata_file: Path,
    packages_file: Path,
    package_inventory: Path,
    working: Path,
    ioc_files: list[Path],
    output_dir: Path,
) -> list[Finding]:
    """Run all built-in conservative Android heuristics."""
    metadata = json.loads(metadata_file.read_text(encoding="utf-8")) if metadata_file.is_file() else {}
    findings = analyze_device_metadata(metadata)
    findings.extend(analyze_packages(packages_file, ioc_files))
    findings.extend(analyze_package_inventory(package_inventory, ioc_files))
    findings.extend(analyze_apk_hashes(working, ioc_files, output_dir / "apk-hashes.json"))
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "findings.json").write_text(
        json.dumps([asdict(item) for item in findings], indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return findings
