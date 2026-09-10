import io
import tarfile
import zipfile
from pathlib import Path

import pytest

from droidcustos.archive_safety import UnsafeArchiveError, safe_extract_tar, safe_extract_zip


def test_safe_extract_zip_rejects_traversal(tmp_path: Path) -> None:
    """Reject ZIP members that escape the destination."""
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr("../../outside.txt", "no")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(archive, tmp_path / "output")


def test_safe_extract_zip_rejects_symlink(tmp_path: Path) -> None:
    """Reject ZIP symlink entries."""
    archive = tmp_path / "symlink.zip"
    info = zipfile.ZipInfo("link")
    info.external_attr = (0o120777 << 16) | 0xA0000000
    with zipfile.ZipFile(archive, "w") as package:
        package.writestr(info, "/etc/passwd")
    with pytest.raises(UnsafeArchiveError):
        safe_extract_zip(archive, tmp_path / "output")


def test_safe_extract_tar_rejects_hardlink(tmp_path: Path) -> None:
    """Reject TAR hardlinks and other non-regular members."""
    archive = tmp_path / "hardlink.tar"
    with tarfile.open(archive, "w") as package:
        info = tarfile.TarInfo("link")
        info.type = tarfile.LNKTYPE
        info.linkname = "target"
        package.addfile(info)
    with pytest.raises(UnsafeArchiveError):
        safe_extract_tar(archive, tmp_path / "output")


def test_safe_extract_tar_enforces_total_size(tmp_path: Path) -> None:
    """Reject TAR archives over the configured uncompressed limit."""
    archive = tmp_path / "large.tar"
    with tarfile.open(archive, "w") as package:
        payload = b"x" * 16
        info = tarfile.TarInfo("payload")
        info.size = len(payload)
        package.addfile(info, io.BytesIO(payload))
    with pytest.raises(UnsafeArchiveError):
        safe_extract_tar(archive, tmp_path / "output", max_total_bytes=8)


def test_safe_extract_helpers_copy_regular_files(tmp_path: Path) -> None:
    """Extract regular ZIP and TAR files into their destination."""
    zip_path = tmp_path / "sample.zip"
    with zipfile.ZipFile(zip_path, "w") as package:
        package.writestr("nested/evidence.txt", "zip evidence")
    tar_path = tmp_path / "sample.tar"
    with tarfile.open(tar_path, "w") as package:
        payload = b"tar evidence"
        info = tarfile.TarInfo("nested/evidence.txt")
        info.size = len(payload)
        package.addfile(info, io.BytesIO(payload))
    zip_destination = tmp_path / "zip-output"
    tar_destination = tmp_path / "tar-output"
    safe_extract_zip(zip_path, zip_destination)
    safe_extract_tar(tar_path, tar_destination)
    assert (zip_destination / "nested/evidence.txt").read_text() == "zip evidence"
    assert (tar_destination / "nested/evidence.txt").read_bytes() == b"tar evidence"
