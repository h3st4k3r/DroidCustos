"""Evidence hashing, sealing and verification helpers.

Author: h3st4k3r
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Handle sha256 file operations."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def iter_files(paths: Iterable[Path]) -> Iterable[Path]:
    """Handle iter files operations."""
    for base in paths:
        if base.is_file() and not base.is_symlink():
            yield base
        elif base.is_dir():
            for path in sorted(base.rglob("*")):
                if path.is_file() and not path.is_symlink():
                    yield path


def create_evidence_manifest(
    paths: Iterable[Path],
    text_manifest: Path,
    json_manifest: Path,
    root: Path,
    *,
    exclude: set[Path] | None = None,
) -> dict[str, object]:
    """Handle create evidence manifest operations."""
    text_manifest.parent.mkdir(parents=True, exist_ok=True)
    excluded = {path.resolve() for path in (exclude or set())}
    entries: list[dict[str, object]] = []

    for path in iter_files(paths):
        resolved = path.resolve()
        if resolved in excluded:
            continue
        try:
            relative = resolved.relative_to(root.resolve())
        except ValueError:
            relative = resolved
        stat_result = path.stat()
        entries.append(
            {
                "path": str(relative),
                "sha256": sha256_file(path),
                "size": stat_result.st_size,
                "mtime_ns": stat_result.st_mtime_ns,
            }
        )

    entries.sort(key=lambda item: str(item["path"]))
    with text_manifest.open("w", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(f"{entry['sha256']}  {entry['path']}\n")

    payload: dict[str, object] = {
        "algorithm": "SHA-256",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "generated_by": "DroidCustos",
        "author": "h3st4k3r",
        "root": str(root.resolve()),
        "file_count": len(entries),
        "entries": entries,
    }
    json_manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return payload


def verify_evidence_manifest(json_manifest: Path, root: Path | None = None) -> dict[str, object]:
    """Handle verify evidence manifest operations."""
    if not json_manifest.is_file():
        return {"verified": False, "missing_manifest": True, "checked": 0, "mismatches": []}

    payload = json.loads(json_manifest.read_text(encoding="utf-8"))
    case_root = root.resolve() if root else Path(str(payload["root"])).resolve()
    mismatches: list[dict[str, object]] = []
    checked = 0

    for entry in payload.get("entries", []):
        checked += 1
        path = case_root / str(entry["path"])
        if not path.is_file():
            mismatches.append({"path": str(entry["path"]), "reason": "missing"})
            continue
        size = path.stat().st_size
        if size != int(entry["size"]):
            mismatches.append(
                {
                    "path": str(entry["path"]),
                    "reason": "size",
                    "expected": int(entry["size"]),
                    "actual": size,
                }
            )
            continue
        digest = sha256_file(path)
        if digest != entry["sha256"]:
            mismatches.append(
                {
                    "path": str(entry["path"]),
                    "reason": "sha256",
                    "expected": entry["sha256"],
                    "actual": digest,
                }
            )

    return {
        "verified": not mismatches,
        "missing_manifest": False,
        "checked": checked,
        "mismatches": mismatches,
    }


def seal_read_only(paths: Iterable[Path]) -> int:
    """Remove write bits from original evidence after hashing."""
    changed = 0
    for base in paths:
        if not base.exists():
            continue
        all_paths = [base, *sorted(base.rglob("*"), reverse=True)] if base.is_dir() else [base]
        for path in all_paths:
            if path.is_symlink():
                continue
            try:
                mode = path.stat().st_mode
                path.chmod(mode & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
                changed += 1
            except OSError:
                continue
    return changed


def restore_owner_write(path: Path) -> None:
    """Utility for controlled maintenance of a sealed local test case."""
    for item in [path, *path.rglob("*")]:
        if item.is_symlink():
            continue
        try:
            item.chmod(item.stat().st_mode | stat.S_IWUSR)
        except OSError:
            pass
