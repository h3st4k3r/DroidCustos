"""Static APK inspection without executing or extracting application code."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import zipfile
from pathlib import Path
from xml.etree import ElementTree

from .archive_safety import UnsafeArchiveError
from .commands import run_capture


ANDROID_NS = "http://schemas.android.com/apk/res/android"
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_APK_MEMBERS = 10000
MAX_APK_MEMBER_BYTES = 512 * 1024 * 1024
MAX_APK_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_APK_COMPRESSION_RATIO = 2000
MAX_TEXT_SCAN_BYTES = 8 * 1024 * 1024
MAX_TEXT_ENTRY_BYTES = 2 * 1024 * 1024
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
HASH_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")


def _sha256_bytes(value: bytes) -> str:
    """Hash an in-memory APK entry."""
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    """Hash an APK file in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _entry_hashes(package: zipfile.ZipFile, names: list[str]) -> list[dict[str, object]]:
    """Hash selected APK entries without writing them to disk."""
    rows: list[dict[str, object]] = []
    for name in names:
        info = package.getinfo(name)
        if info.file_size > 512 * 1024 * 1024:
            rows.append({"path": name, "size": info.file_size, "sha256": None, "error": "entry-too-large"})
            continue
        with package.open(info, "r") as handle:
            digest = hashlib.sha256()
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        rows.append({"path": name, "size": info.file_size, "sha256": digest.hexdigest()})
    return rows


def _validate_apk_entries(infos: list[zipfile.ZipInfo]) -> None:
    """Reject APK ZIP metadata that could cause unbounded analysis."""
    if len(infos) > MAX_APK_MEMBERS:
        raise UnsafeArchiveError("APK contains too many ZIP members")
    total = 0
    for info in infos:
        size = 0 if info.is_dir() else info.file_size
        if size < 0 or size > MAX_APK_MEMBER_BYTES:
            raise UnsafeArchiveError(f"APK member exceeds the analysis limit: {info.filename}")
        total += size
        if total > MAX_APK_TOTAL_BYTES:
            raise UnsafeArchiveError("APK exceeds the total analysis size limit")
        if not info.is_dir() and info.compress_size and size / info.compress_size > MAX_APK_COMPRESSION_RATIO:
            raise UnsafeArchiveError(f"APK member compression ratio is too high: {info.filename}")


def _manifest_attribute(element: ElementTree.Element, name: str) -> str:
    """Read an Android manifest attribute with or without its namespace."""
    return str(element.attrib.get(f"{{{ANDROID_NS}}}{name}") or element.attrib.get(name) or "")


def _parse_manifest_xml(raw: bytes) -> dict[str, object]:
    """Parse a plaintext Android manifest when an APK contains one."""
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError:
        return {}
    if root.tag.rsplit("}", 1)[-1] != "manifest":
        return {}
    components: dict[str, list[dict[str, object]]] = {"activities": [], "services": [], "receivers": [], "providers": []}
    permissions: list[str] = []
    for child in root:
        name = child.tag.rsplit("}", 1)[-1]
        if name in {"uses-permission", "uses-permission-sdk-23"}:
            permission = _manifest_attribute(child, "name")
            if permission:
                permissions.append(permission)
    application = next((child for child in root if child.tag.rsplit("}", 1)[-1] == "application"), None)
    if application is None:
        return {"package": root.attrib.get("package", ""), "permissions": sorted(set(permissions)), "components": components}
    component_actions: set[str] = set()
    for child in application:
        component_type = child.tag.rsplit("}", 1)[-1]
        key = {"activity": "activities", "activity-alias": "activities", "service": "services", "receiver": "receivers", "provider": "providers"}.get(component_type)
        if not key:
            continue
        actions: list[str] = []
        for intent_filter in child:
            if intent_filter.tag.rsplit("}", 1)[-1] != "intent-filter":
                continue
            for action in intent_filter:
                if action.tag.rsplit("}", 1)[-1] == "action":
                    value = _manifest_attribute(action, "name")
                    if value:
                        actions.append(value)
                        component_actions.add(value)
        exported = _manifest_attribute(child, "exported")
        components[key].append({
            "name": _manifest_attribute(child, "name"),
            "exported": exported.lower() if exported else None,
            "permission": _manifest_attribute(child, "permission"),
            "actions": sorted(set(actions)),
        })
    flags: list[str] = []
    if "android.accessibilityservice.AccessibilityService" in component_actions:
        flags.append("accessibility-service")
    if "android.app.action.DEVICE_ADMIN_ENABLED" in component_actions:
        flags.append("device-admin")
    if "android.net.VpnService" in component_actions:
        flags.append("vpn-service")
    if "android.service.notification.NotificationListenerService" in component_actions:
        flags.append("notification-listener")
    if "android.intent.action.BOOT_COMPLETED" in component_actions:
        flags.append("boot-completed")
    return {
        "package": root.attrib.get("package", ""),
        "permissions": sorted(set(permissions)),
        "debuggable": _manifest_attribute(application, "debuggable").lower() == "true",
        "allow_backup": _manifest_attribute(application, "allowBackup").lower() == "true",
        "uses_cleartext_traffic": _manifest_attribute(application, "usesCleartextTraffic").lower() == "true",
        "network_security_config": _manifest_attribute(application, "networkSecurityConfig"),
        "components": components,
        "special_capabilities": flags,
    }


def _parse_aapt_output(text: str) -> dict[str, object]:
    """Parse portable metadata from aapt or aapt2 badging output."""
    result: dict[str, object] = {"permissions": [], "aapt": text[:10000]}
    package_match = re.search(r"package: name='([^']+)'(?: versionCode='([^']*)')?(?: versionName='([^']*)')?", text)
    if package_match:
        result.update({"package": package_match.group(1), "version_code": package_match.group(2) or "", "version_name": package_match.group(3) or ""})
    result["permissions"] = sorted(set(re.findall(r"uses-permission: name='([^']+)'", text)))
    result["launchable_activities"] = sorted(set(re.findall(r"launchable-activity: name='([^']+)'", text)))
    return result


def _signing_metadata(apk: Path) -> dict[str, object]:
    """Inspect APK signing schemes when apksigner is available."""
    apksigner = shutil.which("apksigner")
    if not apksigner:
        return {"available": False, "v1": None, "v2": None, "v3": None, "v4": None, "certificates_sha256": [], "history_sha256": []}
    result = run_capture([apksigner, "verify", "--verbose", "--print-certs", str(apk)], timeout=120)
    text = f"{result.stdout}\n{result.stderr}"
    schemes: dict[str, str | None] = {}
    for number in range(1, 5):
        match = re.search(rf"Verified using v{number} scheme \([^)]*\):\s*(true|false)", text, re.IGNORECASE)
        schemes[f"v{number}"] = match.group(1).lower() == "true" if match else None
    certificates = sorted(set(re.findall(r"certificate SHA-256 digest:\s*([A-Fa-f0-9]+)", text, re.IGNORECASE)))
    return {"available": result.ok, **schemes, "certificates_sha256": [value.lower() for value in certificates], "history_sha256": [value.lower() for value in certificates], "raw": text[:10000]}


def _extract_observables(text: str) -> dict[str, list[str]]:
    """Extract passive network and hash observables from APK text."""
    urls = sorted({value.rstrip(".,);]") for value in URL_RE.findall(text)})
    domains = sorted({value.lower().rstrip(".") for value in DOMAIN_RE.findall(text)})
    ips = sorted(set(IP_RE.findall(text)))
    hashes = sorted({value.lower() for value in HASH_RE.findall(text)})
    return {"urls": urls, "domains": domains, "ipv4": ips, "sha256": hashes}


def analyze_apk(apk: Path, output: Path | None = None) -> dict[str, object]:
    """Analyze APK metadata, signing, DEX, native libraries and passive observables."""
    if not apk.is_file():
        raise FileNotFoundError(apk)
    with zipfile.ZipFile(apk) as package:
        infos = package.infolist()
        _validate_apk_entries(infos)
        names = sorted(info.filename for info in infos if not info.is_dir())
        manifest = {}
        if "AndroidManifest.xml" in names:
            info = package.getinfo("AndroidManifest.xml")
            if info.file_size <= MAX_MANIFEST_BYTES:
                manifest = _parse_manifest_xml(package.read(info))
        dex_names = [name for name in names if re.fullmatch(r"classes(?:\d+)?\.dex", Path(name).name)]
        native_names = [name for name in names if name.startswith("lib/") and name.endswith(".so")]
        signing_entries = [name for name in names if name.upper().startswith("META-INF/") and name.upper().endswith((".RSA", ".DSA", ".EC", ".SF", "MANIFEST.MF"))]
        text_entries = [name for name in names if name.endswith((".xml", ".json", ".txt", ".properties"))]
        text = ""
        text_budget = MAX_TEXT_SCAN_BYTES
        for name in text_entries[:200]:
            if text_budget <= 0:
                break
            info = package.getinfo(name)
            if info.file_size <= MAX_TEXT_ENTRY_BYTES:
                raw = package.read(info)[:text_budget]
                text += raw.decode("utf-8", errors="ignore") + "\n"
                text_budget -= len(raw)
        result: dict[str, object] = {
            "format": "droidcustos-apk-analysis-v1",
            "analysis_status": "OK",
            "path": str(apk),
            "size": apk.stat().st_size,
            "sha256": _sha256_file(apk),
            "package": manifest.get("package", ""),
            "manifest": manifest,
            "dex": _entry_hashes(package, dex_names),
            "native_libraries": _entry_hashes(package, native_names),
            "abis": sorted({Path(name).parts[1] for name in native_names if len(Path(name).parts) > 2}),
            "signing_entries": signing_entries,
            "observables": _extract_observables(text),
            "signing": _signing_metadata(apk),
        }
    aapt = shutil.which("aapt2") or shutil.which("aapt")
    if aapt:
        result["aapt"] = _parse_aapt_output(run_capture([aapt, "dump", "badging", str(apk)], timeout=120).stdout)
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def analyze_apk_tree(root: Path, output: Path | None = None) -> list[dict[str, object]]:
    """Analyze every APK below a working evidence root."""
    results: list[dict[str, object]] = []
    for path in sorted(root.rglob("*.apk")):
        try:
            results.append(analyze_apk(path))
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            results.append(
                {
                    "format": "droidcustos-apk-analysis-v1",
                    "analysis_status": "ERROR",
                    "path": str(path),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return results
