"""Acquisition profile resolution.

Author: h3st4k3r
"""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class AcquisitionProfile:
    name: str
    backup: str
    download: str
    remove_trusted: str
    intrusion_logs: str
    androidqf_hash_files: str
    adb_extra: bool
    collect_connections: bool
    collect_web: bool
    collect_chats: bool
    hash_user_files: bool
    copy_user_files: bool
    root_mode: str
    users: str
    user_ids: str | None
    aleapp: str
    collect_oem: bool
    package_inventory: bool
    unified_timeline: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe acquisition profile."""
        return asdict(self)


def resolve_profile(args) -> AcquisitionProfile:
    """Resolve CLI options into one acquisition profile."""
    deep = bool(getattr(args, "deep", False))
    backup = args.backup or ("all" if deep else "sms")
    download = args.download or "all"
    collect_connections = deep or bool(getattr(args, "collect_connections", False))
    collect_web = deep or bool(getattr(args, "collect_web", False))
    collect_chats = deep or bool(getattr(args, "collect_chats", False))
    hash_user_files = deep or bool(getattr(args, "hash_user_files", False))
    copy_user_files = bool(getattr(args, "copy_user_files", False))
    return AcquisitionProfile(
        name="deep" if deep else "standard",
        backup=backup,
        download=download,
        remove_trusted=args.remove_trusted,
        intrusion_logs=args.intrusion_logs,
        androidqf_hash_files=args.androidqf_hash_files,
        adb_extra=not args.no_adb_extra,
        collect_connections=collect_connections,
        collect_web=collect_web,
        collect_chats=collect_chats,
        hash_user_files=hash_user_files,
        copy_user_files=copy_user_files,
        root_mode=args.root_mode,
        users=getattr(args, "users", "active"),
        user_ids=getattr(args, "user", None),
        aleapp=getattr(args, "aleapp", "auto"),
        collect_oem=not bool(getattr(args, "no_oem_plugins", False)),
        package_inventory=not bool(getattr(args, "no_package_inventory", False)),
        unified_timeline=not bool(getattr(args, "no_timeline", False)),
    )
