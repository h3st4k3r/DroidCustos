"""Encrypted forensic case export and import.

Author: h3st4k3r
"""

from __future__ import annotations

import base64
import json
import os
import struct
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .hashing import sha256_file


MAGIC = b"DROIDCUSTOS-EXPORT-V1\n"


def _derive_key(password: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive a 256-bit export key from an operator password."""
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password)


def _create_tar(case_root: Path, destination: Path) -> None:
    """Create a deterministic compressed case archive."""
    with tarfile.open(destination, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        archive.add(case_root, arcname=case_root.name, recursive=True)


def export_encrypted_case(case_root: Path, destination: Path, password: bytes) -> Path:
    """Export a case as an authenticated AES-256-GCM archive."""
    if not password:
        raise RuntimeError("An export password is required")
    destination.parent.mkdir(parents=True, exist_ok=True)
    salt = os.urandom(16)
    nonce = os.urandom(12)
    iterations = 600000
    key = _derive_key(password, salt, iterations)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as temporary:
        tar_path = Path(temporary.name)
    try:
        _create_tar(case_root, tar_path)
        header = {
            "format": "droidcustos-encrypted-export-v1",
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
            "author": "h3st4k3r",
            "case_name": case_root.name,
            "cipher": "AES-256-GCM",
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": iterations,
            "salt": base64.b64encode(salt).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "plaintext_sha256": sha256_file(tar_path),
            "plaintext_size": tar_path.stat().st_size,
        }
        header_bytes = json.dumps(header, sort_keys=True).encode("utf-8")
        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(header_bytes)
        with destination.open("wb") as output, tar_path.open("rb") as source:
            output.write(MAGIC)
            output.write(struct.pack(">I", len(header_bytes)))
            output.write(header_bytes)
            while chunk := source.read(1024 * 1024):
                output.write(encryptor.update(chunk))
            output.write(encryptor.finalize())
            output.write(encryptor.tag)
    finally:
        tar_path.unlink(missing_ok=True)
    return destination


def _safe_extract(archive: tarfile.TarFile, destination: Path) -> None:
    """Extract a case archive without path traversal."""
    root = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if root not in target.parents and target != root:
            raise RuntimeError(f"Unsafe archive member: {member.name}")
    archive.extractall(destination, filter="data")


def import_encrypted_case(source: Path, destination: Path, password: bytes) -> Path:
    """Decrypt, authenticate and extract a DroidCustos case export."""
    with source.open("rb") as handle:
        if handle.read(len(MAGIC)) != MAGIC:
            raise RuntimeError("Unsupported DroidCustos export format")
        header_size = struct.unpack(">I", handle.read(4))[0]
        header_bytes = handle.read(header_size)
        header = json.loads(header_bytes)
        ciphertext_with_tag = handle.read()
    if len(ciphertext_with_tag) < 16:
        raise RuntimeError("The encrypted export is truncated")
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    salt = base64.b64decode(header["salt"])
    nonce = base64.b64decode(header["nonce"])
    key = _derive_key(password, salt, int(header["iterations"]))
    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
    decryptor.authenticate_additional_data(header_bytes)
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as temporary:
        tar_path = Path(temporary.name)
    try:
        with tar_path.open("wb") as output:
            for offset in range(0, len(ciphertext), 1024 * 1024):
                output.write(decryptor.update(ciphertext[offset : offset + 1024 * 1024]))
            output.write(decryptor.finalize())
        if sha256_file(tar_path) != header["plaintext_sha256"]:
            raise RuntimeError("Decrypted export hash verification failed")
        with tarfile.open(tar_path, "r:gz") as archive:
            _safe_extract(archive, destination)
    finally:
        tar_path.unlink(missing_ok=True)
    return destination / str(header["case_name"])
