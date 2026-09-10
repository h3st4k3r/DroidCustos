"""Android package inventory, certificate extraction and baseline comparison.

Author: h3st4k3r
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Iterable

from .commands import run_capture, run_to_files


@dataclass
class PackageRecord:
    package: str
    user_id: int
    uid: str = ""
    installer: str = ""
    source_path: str = ""
    version_code: str = ""
    version_name: str = ""
    first_install_time: str = ""
    last_update_time: str = ""
    target_sdk: str = ""
    requested_permissions: list[str] = field(default_factory=list)
    granted_permissions: list[str] = field(default_factory=list)
    apk_paths: list[str] = field(default_factory=list)
    local_apks: list[dict[str, object]] = field(default_factory=list)
    signing_certificates_sha256: list[str] = field(default_factory=list)
    signing_history_sha256: list[str] = field(default_factory=list)
    exported_components: dict[str, list[str]] = field(default_factory=dict)
    native_libraries: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe package record."""
        return asdict(self)


_PACKAGE_LINE_RE = re.compile(r"^package:(?P<body>\S+)(?P<rest>\s.*)?$")


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate SHA-256 for one APK file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def parse_package_list(text: str, user_id: int) -> list[PackageRecord]:
    """Parse package-manager inventory output."""
    records: list[PackageRecord] = []
    for line in text.splitlines():
        line = line.strip()
        match = _PACKAGE_LINE_RE.match(line)
        if not match:
            continue
        body = match.group("body")
        if "=" not in body:
            continue
        source_path, package = body.rsplit("=", 1)
        if not source_path or not package:
            continue
        rest = match.group("rest") or ""
        uid_match = re.search(r"\buid:(\d+)", rest)
        installer_match = re.search(r"\binstaller=([^\s]+)", rest)
        version_match = re.search(r"\bversionCode:(\d+)", rest)
        records.append(
            PackageRecord(
                package=package,
                user_id=user_id,
                uid=uid_match.group(1) if uid_match else "",
                installer=installer_match.group(1) if installer_match else "",
                source_path=source_path,
                version_code=version_match.group(1) if version_match else "",
            )
        )
    return records


def _parse_dumpsys(record: PackageRecord, text: str) -> None:
    """Enrich one package record from dumpsys output."""
    patterns = {
        "version_name": r"\bversionName=([^\s]+)",
        "version_code": r"\bversionCode=(\d+)",
        "first_install_time": r"\bfirstInstallTime=(.+)",
        "last_update_time": r"\blastUpdateTime=(.+)",
        "target_sdk": r"\btargetSdk=(\d+)",
    }
    for attribute, pattern in patterns.items():
        match = re.search(pattern, text)
        if match:
            setattr(record, attribute, match.group(1).strip())

    sections = {
        "requested_permissions": "requested permissions:",
        "granted_permissions": "install permissions:",
    }
    lowered_lines = text.splitlines()
    for attribute, marker in sections.items():
        collecting = False
        values: list[str] = []
        for line in lowered_lines:
            stripped = line.strip()
            if stripped.lower() == marker:
                collecting = True
                continue
            if collecting and stripped and not line.startswith(" "):
                break
            if collecting and stripped:
                value = stripped.split(":", 1)[0].strip()
                if ".permission." in value or value.startswith("android.permission"):
                    values.append(value)
        setattr(record, attribute, sorted(set(values)))

    flags_match = re.search(r"\bpkgFlags=\[([^]]*)\]", text)
    if flags_match:
        record.flags = sorted({value.strip() for value in flags_match.group(1).split() if value.strip()})

    native_match = re.findall(r"\bnativeLibraryDir=([^\s]+)", text)
    record.native_libraries = sorted(set(native_match))

    certificate_matches = re.findall(r"(?:SHA-256|sha256)[^A-Fa-f0-9]*([A-Fa-f0-9:]{64,95})", text)
    record.signing_certificates_sha256 = sorted({value.replace(":", "").lower() for value in certificate_matches})


def _parse_apksigner(text: str) -> tuple[list[str], list[str]]:
    """Parse certificate digests from apksigner output."""
    current = re.findall(r"Signer #\d+ certificate SHA-256 digest: ([A-Fa-f0-9]+)", text)
    lineage = re.findall(r"Signer #\d+ certificate SHA-256 lineage: ([A-Fa-f0-9]+)", text)
    return sorted({value.lower() for value in current}), sorted({value.lower() for value in [*current, *lineage]})


def _parse_aapt_package(text: str) -> str | None:
    """Parse the package identifier from aapt output."""
    match = re.search(r"package: name='([^']+)'", text)
    return match.group(1) if match else None


def _index_local_apks(roots: Iterable[Path]) -> dict[str, list[dict[str, object]]]:
    """Index acquired APKs by package identifier when tooling permits."""
    by_package: dict[str, list[dict[str, object]]] = {}
    aapt = shutil.which("aapt2") or shutil.which("aapt")
    apksigner = shutil.which("apksigner")
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*.apk"):
            item: dict[str, object] = {
                "path": str(path),
                "size": path.stat().st_size,
                "sha256": sha256_file(path),
                "certificate_sha256": [],
            }
            package = None
            if aapt:
                result = run_capture([aapt, "dump", "badging", str(path)], timeout=60)
                if result.ok:
                    package = _parse_aapt_package(result.stdout)
            if apksigner:
                result = run_capture([apksigner, "verify", "--print-certs", str(path)], timeout=60)
                if result.ok:
                    current, history = _parse_apksigner(result.stdout)
                    item["certificate_sha256"] = current
                    item["certificate_history_sha256"] = history
            key = package or path.parent.name
            by_package.setdefault(key, []).append(item)
    return by_package


def collect_package_inventory(
    adb: str,
    serial: str,
    user_ids: list[int],
    evidence_dir: Path,
    analysis_dir: Path,
    command_log: Path,
    apk_roots: Iterable[Path],
    detailed: bool,
) -> dict[str, object]:
    """Collect and normalize installed package metadata."""
    evidence_dir.mkdir(parents=True, exist_ok=True)
    analysis_dir.mkdir(parents=True, exist_ok=True)
    records: list[PackageRecord] = []
    local_apks = _index_local_apks(apk_roots)

    for user_id in user_ids:
        result = run_capture(
            [
                adb,
                "-s",
                serial,
                "shell",
                "pm",
                "list",
                "packages",
                "-f",
                "-i",
                "-U",
                "-u",
                "--show-versioncode",
                "--user",
                str(user_id),
            ],
            timeout=300,
            command_log=command_log,
        )
        raw_path = evidence_dir / f"packages-user-{user_id}.txt"
        raw_path.write_text(result.stdout, encoding="utf-8")
        user_records = parse_package_list(result.stdout, user_id)
        for record in user_records:
            path_result = run_capture(
                [adb, "-s", serial, "shell", "pm", "path", "--user", str(user_id), record.package],
                timeout=60,
                command_log=command_log,
            )
            record.apk_paths = [line.partition(":")[2].strip() for line in path_result.stdout.splitlines() if line.startswith("package:")]
            system_path = record.source_path.startswith(("/system/", "/product/", "/vendor/", "/apex/", "/system_ext/"))
            if detailed or not system_path:
                package_dir = evidence_dir / "dumpsys" / f"user-{user_id}"
                package_dir.mkdir(parents=True, exist_ok=True)
                stdout_path = package_dir / f"{record.package}.txt"
                stderr_path = package_dir / f"{record.package}.stderr"
                dump_result = run_to_files(
                    [adb, "-s", serial, "shell", "dumpsys", "package", record.package],
                    stdout_path,
                    stderr_path,
                    timeout=180,
                    command_log=command_log,
                )
                if dump_result.ok:
                    _parse_dumpsys(record, stdout_path.read_text(encoding="utf-8", errors="replace"))
            record.local_apks = local_apks.get(record.package, [])
            for item in record.local_apks:
                record.signing_certificates_sha256.extend(str(value) for value in item.get("certificate_sha256", []))
                record.signing_history_sha256.extend(str(value) for value in item.get("certificate_history_sha256", []))
            record.signing_certificates_sha256 = sorted(set(record.signing_certificates_sha256))
            record.signing_history_sha256 = sorted(set(record.signing_history_sha256))
        records.extend(user_records)

    records.sort(key=lambda item: (item.package, item.user_id))
    payload = {
        "serial": serial,
        "users": user_ids,
        "package_count": len(records),
        "unique_package_count": len({record.package for record in records}),
        "records": [record.to_dict() for record in records],
    }
    output = analysis_dir / "package-inventory.json"
    output.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def load_inventory(path_or_case: Path) -> dict[str, object]:
    """Load a package inventory from a file or case directory."""
    path = path_or_case
    if path.is_dir():
        path = path / "03_analysis" / "packages" / "package-inventory.json"
    if not path.is_file():
        raise RuntimeError(f"Package inventory not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def create_baseline(case: Path, destination: Path) -> Path:
    """Create a portable package and device baseline."""
    inventory = load_inventory(case)
    device_path = case / "00_metadata" / "device.json"
    capabilities_path = case / "00_metadata" / "capabilities.json"
    baseline = {
        "format": "droidcustos-baseline-v1",
        "author": "h3st4k3r",
        "device": json.loads(device_path.read_text(encoding="utf-8")) if device_path.is_file() else {},
        "capabilities": json.loads(capabilities_path.read_text(encoding="utf-8")) if capabilities_path.is_file() else {},
        "inventory": inventory,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination


def _package_map(payload: dict[str, object]) -> dict[tuple[str, int], dict[str, object]]:
    """Index package records for deterministic comparison."""
    inventory = payload.get("inventory", payload)
    records = inventory.get("records", []) if isinstance(inventory, dict) else []
    return {(str(record.get("package")), int(record.get("user_id", 0))): record for record in records}


def compare_inventories(base: dict[str, object], current: dict[str, object]) -> dict[str, object]:
    """Compare package and security state between two acquisitions."""
    before = _package_map(base)
    after = _package_map(current)
    added = [after[key] for key in sorted(after.keys() - before.keys())]
    removed = [before[key] for key in sorted(before.keys() - after.keys())]
    changed: list[dict[str, object]] = []
    fields = (
        "version_code",
        "version_name",
        "installer",
        "signing_certificates_sha256",
        "requested_permissions",
        "granted_permissions",
        "local_apks",
    )
    for key in sorted(before.keys() & after.keys()):
        differences = {
            field: {"before": before[key].get(field), "after": after[key].get(field)}
            for field in fields
            if before[key].get(field) != after[key].get(field)
        }
        if differences:
            changed.append({"package": key[0], "user_id": key[1], "changes": differences})
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "summary": {"added": len(added), "removed": len(removed), "changed": len(changed)},
    }


def write_inventory_diff(base_path: Path, current_path: Path, output: Path) -> Path:
    """Write a package baseline comparison report."""
    base = json.loads(base_path.read_text(encoding="utf-8")) if base_path.is_file() else load_inventory(base_path)
    current = json.loads(current_path.read_text(encoding="utf-8")) if current_path.is_file() else load_inventory(current_path)
    result = compare_inventories(base, current)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return output


def enrich_inventory_with_local_apks(inventory_path: Path, apk_roots: Iterable[Path]) -> dict[str, object]:
    """Enrich a sealed package inventory from working-copy APK files."""
    payload = json.loads(inventory_path.read_text(encoding="utf-8"))
    local_apks = _index_local_apks(apk_roots)
    for record in payload.get("records", []):
        package = str(record.get("package", ""))
        items = local_apks.get(package, [])
        record["local_apks"] = items
        certificates = set(str(value) for value in record.get("signing_certificates_sha256", []))
        history = set(str(value) for value in record.get("signing_history_sha256", []))
        for item in items:
            certificates.update(str(value) for value in item.get("certificate_sha256", []))
            history.update(str(value) for value in item.get("certificate_history_sha256", []))
        record["signing_certificates_sha256"] = sorted(certificates)
        record["signing_history_sha256"] = sorted(history)
    inventory_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload
