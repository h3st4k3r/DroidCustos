"""Optional privacy-sensitive Android artifact acquisition.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import re
import shlex
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .capabilities import AcquisitionPlan, DeviceCapabilities
from .case import CasePaths
from .commands import run_binary_to_file, run_capture, run_stream, run_to_files
from .profiles import AcquisitionProfile


BROWSER_PACKAGES: tuple[str, ...] = (
    "com.android.chrome",
    "org.chromium.chrome",
    "org.mozilla.firefox",
    "org.mozilla.fenix",
    "com.brave.browser",
    "com.microsoft.emmx",
    "com.opera.browser",
    "com.opera.mini.native",
    "com.duckduckgo.mobile.android",
    "com.vivaldi.browser",
    "com.kiwibrowser.browser",
    "com.sec.android.app.sbrowser",
    "com.huawei.browser",
    "com.heytap.browser",
    "com.mi.globalbrowser",
)


CHAT_PACKAGES: tuple[str, ...] = (
    "com.google.android.apps.messaging",
    "com.android.mms",
    "com.samsung.android.messaging",
    "com.whatsapp",
    "com.whatsapp.w4b",
    "org.telegram.messenger",
    "org.thoughtcrime.securesms",
    "com.facebook.orca",
    "com.discord",
    "com.skype.raider",
    "com.viber.voip",
    "jp.naver.line.android",
    "com.snapchat.android",
    "com.tencent.mm",
)


NETWORK_COMMANDS: tuple[tuple[str, list[str], int], ...] = (
    ("ip-rule.txt", ["shell", "ip", "rule", "show"], 60),
    ("ip-neighbour.txt", ["shell", "ip", "neigh", "show"], 60),
    ("ip-route-all.txt", ["shell", "ip", "route", "show", "table", "all"], 60),
    ("ss-all.txt", ["shell", "sh", "-c", "ss -H -a -n -p 2>/dev/null || netstat -an 2>/dev/null || true"], 120),
    ("proc-net-tcp.txt", ["shell", "cat", "/proc/net/tcp"], 60),
    ("proc-net-tcp6.txt", ["shell", "cat", "/proc/net/tcp6"], 60),
    ("proc-net-udp.txt", ["shell", "cat", "/proc/net/udp"], 60),
    ("proc-net-udp6.txt", ["shell", "cat", "/proc/net/udp6"], 60),
    ("proc-net-unix.txt", ["shell", "cat", "/proc/net/unix"], 60),
    ("dumpsys-dnsresolver.txt", ["shell", "dumpsys", "dnsresolver"], 180),
    ("dumpsys-connectivity.txt", ["shell", "dumpsys", "connectivity"], 180),
    ("dumpsys-netstats.txt", ["shell", "dumpsys", "netstats"], 300),
    ("dumpsys-wifi.txt", ["shell", "dumpsys", "wifi"], 180),
    ("iptables.txt", ["shell", "sh", "-c", "iptables-save 2>/dev/null || true"], 120),
    ("ip6tables.txt", ["shell", "sh", "-c", "ip6tables-save 2>/dev/null || true"], 120),
)


CONTENT_QUERIES: tuple[tuple[str, str], ...] = (
    ("sms.txt", "content://sms"),
    ("mms.txt", "content://mms"),
    ("mms-sms-conversations.txt", "content://mms-sms/conversations"),
    ("call-log.txt", "content://call_log/calls"),
    ("legacy-chrome-history.txt", "content://com.android.chrome.browser/history"),
    ("legacy-browser-history.txt", "content://browser/bookmarks"),
)


USER_FILE_EXTENSIONS: dict[str, tuple[str, ...]] = {
    "images": ("jpg", "jpeg", "png", "gif", "webp", "heic", "heif", "bmp", "tif", "tiff", "dng", "raw", "avif"),
    "documents": (
        "pdf",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "ppt",
        "pptx",
        "odt",
        "ods",
        "odp",
        "rtf",
        "txt",
        "csv",
        "json",
        "xml",
        "yaml",
        "yml",
        "md",
        "epub",
        "mobi",
        "pages",
        "numbers",
        "key",
        "zip",
        "7z",
        "rar",
        "tar",
        "gz",
    ),
}


SHARED_SUBPATHS: tuple[str, ...] = (
    "Download",
    "Documents",
    "DCIM",
    "Pictures",
    "Movies",
    "Android/media/com.whatsapp/WhatsApp",
    "Android/media/com.whatsapp.w4b/WhatsApp Business",
    "Android/media/org.telegram.messenger",
    "Telegram",
    "WhatsApp",
)


PRIVATE_TEMPLATES: tuple[str, ...] = (
    "/data/user/{user}/com.android.chrome/app_chrome/Default/History",
    "/data/user/{user}/com.android.chrome/app_chrome/Default/History-wal",
    "/data/user/{user}/com.android.chrome/app_chrome/Default/History-shm",
    "/data/user/{user}/com.brave.browser/app_chrome/Default/History",
    "/data/user/{user}/com.microsoft.emmx/app_chrome/Default/History",
    "/data/user/{user}/com.vivaldi.browser/app_chrome/Default/History",
    "/data/user/{user}/org.mozilla.firefox/files/mozilla",
    "/data/user/{user}/org.mozilla.fenix/files/mozilla",
    "/data/user/{user}/com.whatsapp/databases/msgstore.db",
    "/data/user/{user}/com.whatsapp/databases/msgstore.db-wal",
    "/data/user/{user}/com.whatsapp/databases/wa.db",
    "/data/user/{user}/com.whatsapp.w4b/databases/msgstore.db",
    "/data/user/{user}/org.telegram.messenger/files/cache4.db",
    "/data/user/{user}/org.thoughtcrime.securesms/databases/signal.db",
    "/data/user/{user}/com.android.providers.telephony/databases/mmssms.db",
    "/data/user_de/{user}/com.android.providers.telephony/databases/mmssms.db",
)


@dataclass
class ExtendedAcquisitionSummary:
    enabled: bool
    started_at: str
    finished_at: str = ""
    selected_users: list[int] = field(default_factory=list)
    storage_roots: list[str] = field(default_factory=list)
    network_commands: int = 0
    package_artifacts: int = 0
    content_queries: int = 0
    user_hash_jobs: int = 0
    user_inventory_jobs: int = 0
    copied_paths: list[str] = field(default_factory=list)
    failed_copy_paths: list[str] = field(default_factory=list)
    root_available: bool = False
    private_paths_found: list[str] = field(default_factory=list)
    private_archive: str | None = None
    statuses: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)



def _installed_packages(adb: str, serial: str, user_id: int, command_log: Path) -> set[str]:
    """List packages visible for one Android user."""
    result = run_capture(
        [adb, "-s", serial, "shell", "pm", "list", "packages", "-u", "--user", str(user_id)],
        timeout=180,
        command_log=command_log,
    )
    return {
        line.partition(":")[2].strip()
        for line in result.stdout.splitlines()
        if line.startswith("package:") and line.partition(":")[2].strip()
    }


def _collect_package_set(
    adb: str,
    serial: str,
    user_id: int,
    packages: set[str],
    requested: tuple[str, ...],
    destination: Path,
    command_log: Path,
) -> int:
    """Collect metadata for selected browser or messaging packages."""
    destination.mkdir(parents=True, exist_ok=True)
    collected = 0
    for package in sorted(packages.intersection(requested)):
        package_dir = destination / f"user-{user_id}" / package
        package_dir.mkdir(parents=True, exist_ok=True)
        commands = (
            ("package.txt", ["shell", "dumpsys", "package", package]),
            ("paths.txt", ["shell", "pm", "path", "--user", str(user_id), package]),
            ("appops.txt", ["shell", "appops", "get", "--user", str(user_id), package]),
        )
        for filename, arguments in commands:
            result = run_to_files(
                [adb, "-s", serial, *arguments],
                package_dir / filename,
                package_dir / f"{filename}.stderr",
                timeout=300,
                command_log=command_log,
            )
            collected += int(result.ok)
    return collected


def _extension_expression() -> str:
    """Build a portable find expression for supported user files."""
    extensions = sorted({extension for values in USER_FILE_EXTENSIONS.values() for extension in values})
    return " -o ".join(f"-iname '*.{extension}'" for extension in extensions)


def _hash_script(root: str) -> str:
    """Build a bounded device-side SHA-256 command."""
    expression = _extension_expression()
    quoted_root = shlex.quote(root)
    return (
        f"test -d {quoted_root} || exit 3; "
        "if command -v sha256sum >/dev/null 2>&1; then "
        f"find {quoted_root} -type f \\( {expression} \\) -exec sha256sum {{}} \\; ; "
        "elif toybox sha256sum /dev/null >/dev/null 2>&1; then "
        f"find {quoted_root} -type f \\( {expression} \\) -exec toybox sha256sum {{}} \\; ; "
        "else exit 127; fi"
    )


def _inventory_script(root: str) -> str:
    """Build a portable user-file metadata command."""
    expression = _extension_expression()
    quoted_root = shlex.quote(root)
    return (
        f"test -d {quoted_root} || exit 3; "
        f"if stat -c '%s' {quoted_root} >/dev/null 2>&1; then "
        f"find {quoted_root} -type f \\( {expression} \\) -exec stat -c '%s\\t%Y\\t%n' {{}} \\; ; "
        f"else find {quoted_root} -type f \\( {expression} \\) -print; fi"
    )


def _existing_private_paths(adb: str, serial: str, user_ids: list[int], command_log: Path) -> list[str]:
    """Find selected private artifacts through authorized root access."""
    found: list[str] = []
    for user_id in user_ids:
        for template in PRIVATE_TEMPLATES:
            path = template.format(user=user_id)
            result = run_capture(
                [adb, "-s", serial, "shell", "su", "-c", f"test -e {shlex.quote(path)}"],
                timeout=20,
                command_log=command_log,
            )
            if result.ok:
                found.append(path)
    return found


def _record_status(summary: ExtendedAcquisitionSummary, category: str, target: str, returncode: int) -> None:
    """Record a normalized optional collector outcome."""
    status = "COLLECTED" if returncode == 0 else "NOT_PRESENT" if returncode == 3 else "TIMED_OUT" if returncode == 124 else "PERMISSION_DENIED" if returncode in {1, 13} else "FAILED"
    summary.statuses.append({"category": category, "target": target, "status": status, "returncode": returncode})


def collect_extended_artifacts(
    adb: str,
    serial: str,
    case: CasePaths,
    profile: AcquisitionProfile,
    capabilities: DeviceCapabilities,
    plan: AcquisitionPlan,
) -> ExtendedAcquisitionSummary:
    """Collect optional extended artifacts across users and storage roots."""
    started = datetime.now(timezone.utc).isoformat()
    summary = ExtendedAcquisitionSummary(
        enabled=True,
        started_at=started,
        selected_users=list(plan.selected_users),
        storage_roots=list(plan.storage_roots),
        root_available=capabilities.root_authorized,
    )
    root = case.extended_evidence
    root.mkdir(parents=True, exist_ok=True)
    errors = root / "errors"
    errors.mkdir(parents=True, exist_ok=True)
    packages_by_user = {
        user_id: _installed_packages(adb, serial, user_id, case.command_log)
        for user_id in plan.selected_users
    }

    if profile.collect_connections:
        network = root / "network"
        network.mkdir(parents=True, exist_ok=True)
        for filename, arguments, timeout in NETWORK_COMMANDS:
            result = run_to_files(
                [adb, "-s", serial, *arguments],
                network / filename,
                errors / f"network-{filename}.stderr",
                timeout=timeout,
                command_log=case.command_log,
            )
            summary.network_commands += int(result.ok)
            _record_status(summary, "network", filename, result.returncode)

    for user_id in plan.selected_users:
        packages = packages_by_user[user_id]
        if profile.collect_web:
            summary.package_artifacts += _collect_package_set(
                adb,
                serial,
                user_id,
                packages,
                BROWSER_PACKAGES,
                root / "web" / "packages",
                case.command_log,
            )
        if profile.collect_chats:
            chat_root = root / "chats"
            summary.package_artifacts += _collect_package_set(
                adb,
                serial,
                user_id,
                packages,
                CHAT_PACKAGES,
                chat_root / "packages",
                case.command_log,
            )
            notification = run_to_files(
                [adb, "-s", serial, "shell", "dumpsys", "notification", "--noredact"],
                chat_root / f"notification-history-user-{user_id}.txt",
                errors / f"notification-history-user-{user_id}.stderr",
                timeout=300,
                command_log=case.command_log,
            )
            _record_status(summary, "chat", f"notification-user-{user_id}", notification.returncode)
            query_dir = chat_root / "content-queries" / f"user-{user_id}"
            query_dir.mkdir(parents=True, exist_ok=True)
            for filename, uri in CONTENT_QUERIES:
                result = run_to_files(
                    [adb, "-s", serial, "shell", "content", "query", "--user", str(user_id), "--uri", uri],
                    query_dir / filename,
                    errors / f"content-user-{user_id}-{filename}.stderr",
                    timeout=300,
                    command_log=case.command_log,
                )
                summary.content_queries += int(result.ok)
                _record_status(summary, "content", f"user-{user_id}:{uri}", result.returncode)

    if profile.hash_user_files:
        file_root = root / "user-files"
        file_root.mkdir(parents=True, exist_ok=True)
        combined_hashes = file_root / "user-files.sha256"
        combined_inventory = file_root / "user-files.tsv"
        with combined_hashes.open("w", encoding="utf-8") as hash_output, combined_inventory.open("w", encoding="utf-8") as inventory_output:
            for index, storage_root in enumerate(plan.storage_roots, start=1):
                slug = re.sub(r"[^A-Za-z0-9._-]+", "_", storage_root.strip("/")) or f"root-{index}"
                hash_path = file_root / "parts" / f"{slug}.sha256"
                inventory_path = file_root / "parts" / f"{slug}.tsv"
                hash_result = run_to_files(
                    [adb, "-s", serial, "shell", "sh", "-c", _hash_script(storage_root)],
                    hash_path,
                    errors / f"user-files-{slug}.sha256.stderr",
                    timeout=28800,
                    command_log=case.command_log,
                )
                inventory_result = run_to_files(
                    [adb, "-s", serial, "shell", "sh", "-c", _inventory_script(storage_root)],
                    inventory_path,
                    errors / f"user-files-{slug}.tsv.stderr",
                    timeout=14400,
                    command_log=case.command_log,
                )
                _record_status(summary, "hash", storage_root, hash_result.returncode)
                _record_status(summary, "inventory", storage_root, inventory_result.returncode)
                if hash_result.ok:
                    summary.user_hash_jobs += 1
                    hash_output.write(hash_path.read_text(encoding="utf-8", errors="replace"))
                if inventory_result.ok:
                    summary.user_inventory_jobs += 1
                    inventory_output.write(inventory_path.read_text(encoding="utf-8", errors="replace"))

    if profile.copy_user_files:
        copy_root = root / "user-files" / "copied"
        copy_root.mkdir(parents=True, exist_ok=True)
        candidates: list[str] = []
        for storage_root in plan.storage_roots:
            for subpath in SHARED_SUBPATHS:
                candidates.append(f"{storage_root.rstrip('/')}/{subpath}")
        for source in sorted(set(candidates)):
            exists = run_capture(
                [adb, "-s", serial, "shell", "test", "-e", source],
                timeout=20,
                command_log=case.command_log,
            )
            if not exists.ok:
                continue
            slug = re.sub(r"[^A-Za-z0-9._-]+", "_", source.strip("/"))
            destination = copy_root / slug
            result = run_stream(
                [adb, "-s", serial, "pull", source, str(destination)],
                case.logs / f"adb-pull-{slug}.log",
                command_log=case.command_log,
            )
            if result.ok:
                summary.copied_paths.append(source)
            else:
                summary.failed_copy_paths.append(source)
            _record_status(summary, "copy", source, result.returncode)

    if profile.root_mode != "never":
        if profile.root_mode == "require" and not capabilities.root_authorized:
            raise RuntimeError("Root mode was required, but an authorized root shell was unavailable")
        if capabilities.root_authorized:
            found = _existing_private_paths(adb, serial, plan.selected_users, case.command_log)
            summary.private_paths_found = found
            if found:
                private_root = root / "private"
                private_root.mkdir(parents=True, exist_ok=True)
                archive = private_root / "selected-private-artifacts.tar"
                quoted = " ".join(shlex.quote(path) for path in found)
                result = run_binary_to_file(
                    [adb, "-s", serial, "exec-out", "su", "-c", f"tar -cpf - {quoted} 2>/dev/null"],
                    archive,
                    errors / "private-artifacts.stderr",
                    timeout=14400,
                    command_log=case.command_log,
                )
                if result.ok and archive.is_file() and archive.stat().st_size > 0:
                    summary.private_archive = str(archive)
                else:
                    archive.unlink(missing_ok=True)
                    summary.errors.append("Private artifact TAR acquisition failed")
                _record_status(summary, "private", "selected-private-artifacts", result.returncode)

    summary.finished_at = datetime.now(timezone.utc).isoformat()
    case.write_json("00_metadata/extended-acquisition-status.json", asdict(summary))
    (root / "status.json").write_text(json.dumps(asdict(summary), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
