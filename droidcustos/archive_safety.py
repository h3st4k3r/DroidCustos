"""Bounded extraction helpers for untrusted ZIP and TAR archives."""

from __future__ import annotations

import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath


DEFAULT_MAX_MEMBERS = 10000
DEFAULT_MAX_MEMBER_BYTES = 512 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MAX_COMPRESSION_RATIO = 2000


class UnsafeArchiveError(ValueError):
    """Report an archive member that is unsafe to extract."""


def _destination_root(destination: Path) -> Path:
    """Prepare and validate the extraction destination."""
    if destination.exists() and destination.is_symlink():
        raise UnsafeArchiveError(f"Extraction destination is a symlink: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    return destination.resolve()


def _member_target(root: Path, name: str) -> Path:
    """Resolve a member name while rejecting traversal and absolute paths."""
    raw = str(name or "")
    posix = PurePosixPath(raw)
    windows = PureWindowsPath(raw)
    if not raw or posix.is_absolute() or windows.is_absolute() or windows.drive:
        raise UnsafeArchiveError(f"Unsafe archive member path: {name}")
    if ".." in posix.parts or ".." in windows.parts:
        raise UnsafeArchiveError(f"Unsafe archive member path: {name}")
    target = (root / Path(*posix.parts)).resolve()
    if target != root and root not in target.parents:
        raise UnsafeArchiveError(f"Unsafe archive member path: {name}")
    return target


def _assert_no_symlink_parents(root: Path, target: Path) -> None:
    """Reject pre-existing symlink components below the extraction root."""
    current = target
    parents: list[Path] = []
    while current != root:
        parents.append(current)
        if current.parent == current:
            break
        current = current.parent
    for path in reversed(parents):
        if path.is_symlink():
            raise UnsafeArchiveError(f"Archive target crosses a symlink: {path}")


def _validate_limits(size: int, total: int, members: int, *, max_member_bytes: int, max_total_bytes: int, max_members: int) -> int:
    """Validate archive size and member-count limits."""
    if members > max_members:
        raise UnsafeArchiveError("Archive contains too many members")
    if size < 0 or size > max_member_bytes:
        raise UnsafeArchiveError("Archive member exceeds the configured size limit")
    updated_total = total + size
    if updated_total > max_total_bytes:
        raise UnsafeArchiveError("Archive exceeds the configured uncompressed size limit")
    return updated_total


def _zip_member_is_regular(info: zipfile.ZipInfo) -> bool:
    """Return whether a ZIP member has a regular-file or directory mode."""
    mode = (info.external_attr >> 16) & 0xFFFF
    if not mode:
        return True
    file_type = stat.S_IFMT(mode)
    return file_type in {0, stat.S_IFREG, stat.S_IFDIR}


def safe_extract_zip(
    archive: Path,
    destination: Path,
    *,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
    max_compression_ratio: int = DEFAULT_MAX_COMPRESSION_RATIO,
) -> list[Path]:
    """Extract a ZIP after validating paths, types and decompression bounds."""
    root = _destination_root(destination)
    extracted: list[Path] = []
    total = 0
    with zipfile.ZipFile(archive) as package:
        infos = package.infolist()
        for index, info in enumerate(infos, start=1):
            target = _member_target(root, info.filename)
            total = _validate_limits(
                0 if info.is_dir() else info.file_size,
                total,
                index,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes,
                max_members=max_members,
            )
            if not _zip_member_is_regular(info):
                raise UnsafeArchiveError(f"ZIP member is not a regular file: {info.filename}")
            if not info.is_dir() and info.compress_size and info.file_size / info.compress_size > max_compression_ratio:
                raise UnsafeArchiveError(f"ZIP member compression ratio is too high: {info.filename}")
        for info in infos:
            target = _member_target(root, info.filename)
            _assert_no_symlink_parents(root, target)
            if info.is_dir() or info.filename.endswith(("/", "\\")):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with package.open(info, "r") as source, target.open("wb") as output:
                copied = 0
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > max_member_bytes:
                        raise UnsafeArchiveError(f"ZIP member expanded beyond its declared limit: {info.filename}")
                    output.write(chunk)
            extracted.append(target)
    return extracted


def _tar_member_is_supported(member: tarfile.TarInfo) -> bool:
    """Return whether a TAR member is a safe regular file or directory."""
    return member.isdir() or member.isreg()


def safe_extract_tar(
    archive: Path,
    destination: Path,
    *,
    max_members: int = DEFAULT_MAX_MEMBERS,
    max_member_bytes: int = DEFAULT_MAX_MEMBER_BYTES,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> list[Path]:
    """Extract a TAR after rejecting links, devices, FIFOs and bombs."""
    root = _destination_root(destination)
    extracted: list[Path] = []
    total = 0
    with tarfile.open(archive, "r:*") as package:
        members = package.getmembers()
        for index, member in enumerate(members, start=1):
            _member_target(root, member.name)
            total = _validate_limits(
                0 if member.isdir() else member.size,
                total,
                index,
                max_member_bytes=max_member_bytes,
                max_total_bytes=max_total_bytes,
                max_members=max_members,
            )
            if not _tar_member_is_supported(member):
                raise UnsafeArchiveError(f"TAR member type is not supported: {member.name}")
        for member in members:
            target = _member_target(root, member.name)
            _assert_no_symlink_parents(root, target)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = package.extractfile(member)
            if source is None:
                raise UnsafeArchiveError(f"Unable to read TAR member: {member.name}")
            with source, target.open("wb") as output:
                copied = 0
                while chunk := source.read(1024 * 1024):
                    copied += len(chunk)
                    if copied > max_member_bytes:
                        raise UnsafeArchiveError(f"TAR member expanded beyond its declared limit: {member.name}")
                    output.write(chunk)
            extracted.append(target)
    return extracted
