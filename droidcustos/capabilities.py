"""Android capability discovery and acquisition planning.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .commands import CommandResult, run_capture


@dataclass(frozen=True)
class AndroidUser:
    user_id: int
    name: str
    flags: str
    running: bool
    profile_group_id: int | None = None
    user_type: str = "unknown"
    parent_id: int | None = None
    unlocked: bool | None = None
    quiet_mode: bool = False
    managed: bool = False
    private: bool = False
    clone: bool = False
    guest: bool = False


@dataclass(frozen=True)
class StorageVolume:
    volume_id: str
    state: str
    fs_uuid: str | None
    path: str | None
    kind: str


@dataclass(frozen=True)
class ProbeResult:
    name: str
    status: str
    returncode: int | None
    detail: str = ""


@dataclass
class DeviceCapabilities:
    serial: str
    sdk: int
    android_version: str
    manufacturer: str
    model: str
    build_fingerprint: str
    rom_family: str
    users: list[AndroidUser] = field(default_factory=list)
    storage_volumes: list[StorageVolume] = field(default_factory=list)
    storage_roots: list[str] = field(default_factory=list)
    commands: dict[str, bool] = field(default_factory=dict)
    dumpsys_services: list[str] = field(default_factory=list)
    cmd_services: list[str] = field(default_factory=list)
    probes: dict[str, ProbeResult] = field(default_factory=dict)
    root_binary_present: bool = False
    root_authorized: bool = False
    intrusion_logging: str = "unknown"
    bugreport_available: bool = False
    package_visibility: str = "shell"

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe capability snapshot."""
        return asdict(self)


@dataclass(frozen=True)
class AcquisitionPlan:
    selected_users: list[int]
    storage_roots: list[str]
    collectors: list[str]
    skipped_collectors: list[dict[str, str]]
    coverage_target: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe acquisition plan."""
        return asdict(self)


_USER_RE = re.compile(
    r"UserInfo\{(?P<id>\d+):(?P<name>[^:}]*):(?P<flags>[^}]*)\}(?:\s+running)?",
    re.IGNORECASE,
)


def _adb_shell(adb: str, serial: str, arguments: list[str], command_log: Path | None, timeout: int = 30) -> CommandResult:
    """Run a bounded ADB shell probe."""
    return run_capture([adb, "-s", serial, "shell", *arguments], timeout=timeout, command_log=command_log)


def parse_users(text: str) -> list[AndroidUser]:
    """Parse Android user and profile output."""
    return parse_user_sources(text)


def parse_user_sources(*sources: str) -> list[AndroidUser]:
    """Merge user records from pm, cmd user and dumpsys user evidence."""
    users: list[AndroidUser] = []
    merged: dict[int, AndroidUser] = {}
    for text in sources:
        for line in text.splitlines():
            match = _USER_RE.search(line)
            if not match:
                continue
            user_id = int(match.group("id"))
            name = match.group("name").strip() or f"user-{user_id}"
            flags = match.group("flags").strip()
            lowered = line.lower()
            profile_group = re.search(r"(?:profilegroupid|profile_group_id)[=:](\d+)", lowered)
            parent = re.search(r"(?:parentid|parent_id)[=:](\d+)", lowered)
            managed = "managed" in lowered or "profile" in lowered
            private = "private" in lowered
            clone = "clone" in lowered
            guest = "guest" in lowered
            if private:
                user_type = "private-space"
            elif clone:
                user_type = "clone-profile"
            elif guest:
                user_type = "guest"
            elif managed:
                user_type = "work-profile"
            else:
                user_type = "primary" if user_id == 0 else "secondary"
            current = AndroidUser(
                user_id=user_id,
                name=name,
                flags=flags,
                running="running" in lowered,
                profile_group_id=int(profile_group.group(1)) if profile_group else None,
                user_type=user_type,
                parent_id=int(parent.group(1)) if parent else None,
                unlocked=True if "unlocked" in lowered else None,
                quiet_mode="quiet_mode" in lowered or "quiet mode" in lowered,
                managed=managed,
                private=private,
                clone=clone,
                guest=guest,
            )
            previous = merged.get(user_id)
            if previous is None:
                merged[user_id] = current
            else:
                merged[user_id] = AndroidUser(
                    user_id=user_id,
                    name=previous.name if previous.name != f"user-{user_id}" else current.name,
                    flags=" ".join(sorted(set(filter(None, (previous.flags, current.flags))))),
                    running=previous.running or current.running,
                    profile_group_id=previous.profile_group_id or current.profile_group_id,
                    user_type=current.user_type if current.user_type != "secondary" else previous.user_type,
                    parent_id=previous.parent_id or current.parent_id,
                    unlocked=previous.unlocked if previous.unlocked is not None else current.unlocked,
                    quiet_mode=previous.quiet_mode or current.quiet_mode,
                    managed=previous.managed or current.managed,
                    private=previous.private or current.private,
                    clone=previous.clone or current.clone,
                    guest=previous.guest or current.guest,
                )
    users.extend(merged.values())
    if not users:
        users.append(AndroidUser(0, "Owner", "", True, user_type="primary"))
    return sorted(users, key=lambda item: item.user_id)


def parse_storage_volumes(text: str) -> list[StorageVolume]:
    """Parse storage-manager volume output."""
    volumes: list[StorageVolume] = []
    for line in text.splitlines():
        fields = line.strip().split()
        if not fields:
            continue
        volume_id = fields[0]
        state = fields[1] if len(fields) > 1 else "unknown"
        fs_uuid = fields[2] if len(fields) > 2 and fields[2] != "null" else None
        kind = "emulated" if volume_id.startswith("emulated") else "public" if volume_id.startswith("public") else "private"
        path = None
        if kind == "emulated":
            path = "/storage/emulated"
        elif fs_uuid:
            path = f"/storage/{fs_uuid}"
        volumes.append(StorageVolume(volume_id, state, fs_uuid, path, kind))
    return volumes


def detect_rom_family(manufacturer: str, fingerprint: str) -> str:
    """Map common Android distributions to stable plugin families."""
    value = f"{manufacturer} {fingerprint}".lower()
    mappings = (
        (("samsung",), "samsung"),
        (("asus", "rog"), "asus"),
        (("xiaomi", "redmi", "poco", "hyperos", "miui"), "xiaomi"),
        (("oneplus", "oxygen"), "oneplus"),
        (("oppo", "coloros"), "oppo"),
        (("realme",), "realme"),
        (("motorola", "moto"), "motorola"),
        (("vivo", "iqoo"), "vivo"),
        (("huawei", "honor", "harmony"), "huawei"),
        (("google", "pixel"), "google"),
    )
    for needles, family in mappings:
        if any(needle in value for needle in needles):
            return family
    return "aosp"


def _probe_command(adb: str, serial: str, command: str, command_log: Path | None) -> bool:
    """Check whether a shell command is available."""
    result = _adb_shell(adb, serial, ["sh", "-c", f"command -v {command} >/dev/null 2>&1"], command_log)
    return result.ok


def _probe_content(adb: str, serial: str, name: str, uri: str, command_log: Path | None) -> ProbeResult:
    """Test content-provider accessibility without retaining private rows."""
    result = _adb_shell(
        adb,
        serial,
        ["sh", "-c", f"content query --uri {uri} --projection _id 2>&1 | head -n 1"],
        command_log,
        timeout=20,
    )
    combined = f"{result.stdout}\n{result.stderr}".strip()
    lowered = combined.lower()
    if result.ok and "permission denial" not in lowered and "securityexception" not in lowered:
        return ProbeResult(name, "AVAILABLE", result.returncode, combined[:300])
    if "permission denial" in lowered or "securityexception" in lowered:
        return ProbeResult(name, "PERMISSION_DENIED", result.returncode, combined[:300])
    if "unknown uri" in lowered or "not found" in lowered:
        return ProbeResult(name, "NOT_PRESENT", result.returncode, combined[:300])
    return ProbeResult(name, "FAILED", result.returncode, combined[:300])


def _discover_storage_roots(users: list[AndroidUser], volumes: list[StorageVolume]) -> list[str]:
    """Build candidate shared-storage roots for all visible users."""
    roots: set[str] = set()
    for user in users:
        roots.add(f"/storage/emulated/{user.user_id}")
        roots.add(f"/data/media/{user.user_id}")
    for volume in volumes:
        if volume.path:
            roots.add(volume.path)
    roots.update({"/sdcard", "/storage/self/primary"})
    return sorted(roots)


def discover_capabilities(
    adb: str,
    serial: str,
    output: Path | None = None,
    command_log: Path | None = None,
    root_mode: str = "never",
) -> DeviceCapabilities:
    """Discover Android features before selecting collectors."""
    props_result = _adb_shell(adb, serial, ["getprop"], command_log, timeout=60)
    props: dict[str, str] = {}
    for line in props_result.stdout.splitlines():
        match = re.match(r"\[(.+?)\]: \[(.*?)\]", line)
        if match:
            props[match.group(1)] = match.group(2)

    users_result = _adb_shell(adb, serial, ["pm", "list", "users"], command_log, timeout=60)
    cmd_users_result = _adb_shell(adb, serial, ["cmd", "user", "list"], command_log, timeout=60)
    dumpsys_users_result = _adb_shell(adb, serial, ["dumpsys", "user"], command_log, timeout=60)
    volumes_result = _adb_shell(adb, serial, ["sm", "list-volumes", "all"], command_log, timeout=60)
    dumpsys_result = _adb_shell(adb, serial, ["dumpsys", "-l"], command_log, timeout=60)
    cmd_result = _adb_shell(adb, serial, ["cmd", "-l"], command_log, timeout=60)

    users = parse_user_sources(users_result.stdout, cmd_users_result.stdout, dumpsys_users_result.stdout)
    volumes = parse_storage_volumes(volumes_result.stdout)
    commands = {
        name: _probe_command(adb, serial, name, command_log)
        for name in ("sh", "toybox", "find", "stat", "sha256sum", "tar", "content", "sqlite3", "ss", "netstat", "ip", "su")
    }
    dumpsys_services = sorted({line.strip() for line in dumpsys_result.stdout.splitlines() if line.strip()})
    cmd_services = sorted({line.strip() for line in cmd_result.stdout.splitlines() if line.strip()})
    probes = {
        "sms": _probe_content(adb, serial, "sms", "content://sms", command_log),
        "mms": _probe_content(adb, serial, "mms", "content://mms", command_log),
        "call_log": _probe_content(adb, serial, "call_log", "content://call_log/calls", command_log),
    }

    root_authorized = False
    if root_mode in {"auto", "require"} and commands.get("su", False):
        root_result = _adb_shell(adb, serial, ["su", "-c", "id"], command_log, timeout=20)
        root_authorized = root_result.ok and "uid=0" in root_result.stdout

    sdk_text = props.get("ro.build.version.sdk", "0")
    try:
        sdk = int(sdk_text)
    except ValueError:
        sdk = 0
    intrusion_logging = "unsupported"
    joined_services = " ".join([*dumpsys_services, *cmd_services]).lower()
    if sdk >= 36:
        intrusion_logging = "available" if "intrusion" in joined_services or "advanced_protection" in joined_services else "possible"

    capabilities = DeviceCapabilities(
        serial=serial,
        sdk=sdk,
        android_version=props.get("ro.build.version.release", ""),
        manufacturer=props.get("ro.product.manufacturer", ""),
        model=props.get("ro.product.model", ""),
        build_fingerprint=props.get("ro.build.fingerprint", ""),
        rom_family=detect_rom_family(props.get("ro.product.manufacturer", ""), props.get("ro.build.fingerprint", "")),
        users=users,
        storage_volumes=volumes,
        storage_roots=_discover_storage_roots(users, volumes),
        commands=commands,
        dumpsys_services=dumpsys_services,
        cmd_services=cmd_services,
        probes=probes,
        root_binary_present=commands.get("su", False),
        root_authorized=root_authorized,
        intrusion_logging=intrusion_logging,
        bugreport_available=True,
    )
    if output:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(capabilities.to_dict(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return capabilities


def select_users(capabilities: DeviceCapabilities, mode: str, explicit: str | None = None) -> list[int]:
    """Resolve the user and profile scope requested by the operator."""
    available = {user.user_id: user for user in capabilities.users}
    if explicit:
        requested = []
        for value in explicit.split(","):
            value = value.strip()
            if value:
                requested.append(int(value))
        missing = [value for value in requested if value not in available]
        if missing:
            raise RuntimeError(f"Requested Android users are unavailable: {', '.join(map(str, missing))}")
        return sorted(set(requested))
    if mode == "primary":
        return [0] if 0 in available else [min(available)]
    if mode == "active":
        active = [user.user_id for user in capabilities.users if user.running]
        return sorted(active or ([0] if 0 in available else [min(available)]))
    return sorted(available)


def build_acquisition_plan(capabilities: DeviceCapabilities, profile: object) -> AcquisitionPlan:
    """Create a capability-aware acquisition plan."""
    mode = str(getattr(profile, "users", "active"))
    explicit = getattr(profile, "user_ids", None)
    users = select_users(capabilities, mode, explicit)
    collectors = ["device-metadata", "volatile-state", "androidqf", "package-inventory", "bugreport"]
    skipped: list[dict[str, str]] = []

    requested = {
        "extended-connections": bool(getattr(profile, "collect_connections", False)),
        "web-artifacts": bool(getattr(profile, "collect_web", False)),
        "chat-artifacts": bool(getattr(profile, "collect_chats", False)),
        "user-file-hashes": bool(getattr(profile, "hash_user_files", False)),
        "user-file-copy": bool(getattr(profile, "copy_user_files", False)),
        "private-artifacts": str(getattr(profile, "root_mode", "never")) != "never",
        "aleapp": str(getattr(profile, "aleapp", "auto")) != "no",
    }
    for collector, enabled in requested.items():
        if not enabled:
            continue
        if collector == "private-artifacts" and not capabilities.root_authorized:
            skipped.append({"collector": collector, "reason": "AUTHORIZED_ROOT_UNAVAILABLE"})
            continue
        if collector == "user-file-hashes" and not (capabilities.commands.get("sha256sum") or capabilities.commands.get("toybox")):
            skipped.append({"collector": collector, "reason": "SHA256_UTILITY_UNAVAILABLE"})
            continue
        collectors.append(collector)

    coverage_target = len(collectors) + len(skipped)
    return AcquisitionPlan(users, capabilities.storage_roots, collectors, skipped, coverage_target)
