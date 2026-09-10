"""Evidence-only Android security posture analysis."""

from __future__ import annotations

from datetime import date, datetime, timezone
from typing import Mapping


ROOT_TOKENS = ("magisk", "kernelsu", "apatch", "xposed", "lsposed", "frida", "riru")


def _text(value: object) -> str:
    """Normalize one evidence value to text."""
    return str(value or "").strip()


def _truthy(value: object) -> bool:
    """Interpret common Android and JSON boolean representations."""
    return _text(value).lower() in {"1", "true", "yes", "on", "enabled", "running"}


def _package_evidence(package_inventory: Mapping[str, object] | None) -> tuple[set[str], set[str], set[str], set[str]]:
    """Collect package names, permissions, installers and capabilities from inventory evidence."""
    packages: set[str] = set()
    permissions: set[str] = set()
    installers: set[str] = set()
    capabilities: set[str] = set()
    records = package_inventory.get("records", []) if isinstance(package_inventory, Mapping) else []
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, Mapping):
            continue
        packages.add(_text(record.get("package")).lower())
        permissions.update(_text(item) for item in record.get("requested_permissions", []) if _text(item))
        installer = _text(record.get("installer")).lower()
        if installer:
            installers.add(installer)
        for apk in record.get("local_apks", []) if isinstance(record.get("local_apks"), list) else []:
            if isinstance(apk, Mapping):
                capabilities.update(_text(item).lower() for item in apk.get("special_capabilities", []) if _text(item))
    return packages, permissions, installers, capabilities


def _finding(severity: str, signal: str, detail: str, score: int) -> dict[str, object]:
    """Build a normalized posture finding."""
    return {"severity": severity, "signal": signal, "detail": detail, "score": score}


def analyze_security_state(
    metadata: Mapping[str, object],
    capabilities: Mapping[str, object] | None = None,
    package_inventory: Mapping[str, object] | None = None,
    auxiliary: Mapping[str, object] | None = None,
    *,
    now: date | None = None,
) -> dict[str, object]:
    """Analyze previously acquired Android evidence without querying the device."""
    capabilities = capabilities or {}
    auxiliary = auxiliary or {}
    packages, permissions, installers, package_capabilities = _package_evidence(package_inventory)
    findings: list[dict[str, object]] = []
    signals: dict[str, object] = {}
    verified = _text(metadata.get("verified_boot_state")).lower()
    flash_locked = _text(metadata.get("flash_locked")).lower()
    vbmeta = _text(metadata.get("vbmeta_device_state")).lower()
    signals["verified_boot"] = verified or "unknown"
    signals["bootloader_locked"] = flash_locked in {"1", "locked"} if flash_locked else None
    signals["vbmeta_locked"] = vbmeta == "locked" if vbmeta else None
    if verified and verified != "green":
        findings.append(_finding("high", "verified-boot", f"verified boot state is {verified}", 40))
    if flash_locked and flash_locked not in {"1", "locked"}:
        findings.append(_finding("high", "bootloader", f"flash lock state is {flash_locked}", 35))
    if vbmeta and vbmeta != "locked":
        findings.append(_finding("high", "vbmeta", f"VBMeta device state is {vbmeta}", 35))

    selinux = _text(metadata.get("selinux") or auxiliary.get("selinux")).lower()
    signals["selinux"] = selinux or "unknown"
    if selinux in {"permissive", "disabled"}:
        findings.append(_finding("high", "selinux", f"SELinux mode is {selinux}", 30))
    patch = _text(metadata.get("security_patch"))
    if patch:
        try:
            age = ((now or datetime.now(timezone.utc).date()) - date.fromisoformat(patch)).days
            signals["security_patch_age_days"] = age
            if age > 180:
                findings.append(_finding("high", "security-patch", f"patch is {age} days old", 25))
            elif age > 90:
                findings.append(_finding("medium", "security-patch", f"patch is {age} days old", 15))
        except ValueError:
            findings.append(_finding("low", "security-patch", f"unparseable patch value: {patch}", 5))

    adb_enabled = _truthy(metadata.get("adb_enabled"))
    signals["adb_enabled"] = adb_enabled
    if adb_enabled:
        findings.append(_finding("low", "adb", "ADB is enabled in acquired settings", 5))
    root_path = _text(metadata.get("su_path"))
    root_authorized = _truthy(capabilities.get("root_authorized"))
    root_packages = sorted(package for package in packages if any(token in package for token in ROOT_TOKENS))
    signals["root"] = bool(root_path or root_authorized or root_packages)
    signals["root_packages"] = root_packages
    if root_path or root_authorized:
        findings.append(_finding("high", "root", "root evidence is present or authorized", 35))
    if root_packages:
        findings.append(_finding("medium", "root-tools", ", ".join(root_packages), 20))

    accessibility = _text(metadata.get("enabled_accessibility_services") or auxiliary.get("accessibility_services"))
    overlay = "android.permission.SYSTEM_ALERT_WINDOW" in permissions
    install_packages = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions
    sideloaded = bool(installers & {"", "com.android.shell", "adb"}) or _truthy(auxiliary.get("sideloaded"))
    signals.update({"accessibility": bool(accessibility and accessibility.lower() not in {"none", "null"}), "overlay": overlay, "install_packages": install_packages, "sideloaded": sideloaded})
    if signals["accessibility"]:
        findings.append(_finding("medium", "accessibility", accessibility, 10))
    if signals["accessibility"] and overlay and (install_packages or sideloaded):
        findings.append(_finding("high", "composite-accessibility-overlay-sideload", "accessibility + overlay + package installation evidence", 35))
    if signals["accessibility"] and install_packages:
        findings.append(_finding("high", "composite-accessibility-install", "accessibility + REQUEST_INSTALL_PACKAGES", 30))

    for key, label, score in (
        ("device_owner", "device-owner", 15),
        ("profile_owner", "profile-owner", 10),
        ("device_admins", "device-admin", 15),
        ("notification_listeners", "notification-listener", 15),
        ("vpn", "vpn", 10),
    ):
        value = auxiliary.get(key)
        if value not in (None, "", [], {}, False, "none", "null"):
            signals[label] = value
            findings.append(_finding("medium", label, _text(value), score))
    signals["package_capabilities"] = sorted(package_capabilities)
    if package_capabilities:
        findings.append(_finding("medium", "apk-special-capabilities", ", ".join(sorted(package_capabilities)), 15))
    for key in ("proxy", "private_dns", "default_input_method", "role_holders"):
        value = auxiliary.get(key) or metadata.get(key)
        if value not in (None, "", [], {}, False, "none", "null"):
            signals[key] = value
    risk_score = min(sum(int(item["score"]) for item in findings), 100)
    return {
        "format": "droidcustos-security-state-v1",
        "evidence_only": True,
        "signals": signals,
        "findings": findings,
        "risk_score": risk_score,
        "limitations": [
            "The result describes acquired evidence only.",
            "Absence of a signal does not prove that the device is clean.",
        ],
    }
