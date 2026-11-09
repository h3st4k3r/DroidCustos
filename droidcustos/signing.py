"""Cryptographic key management and detached case sealing.

Author: h3st4k3r
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from pathlib import Path
from pathlib import PureWindowsPath

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .custody import verify_custody_log
from .hashing import sha256_file


def generate_signing_keypair(private_path: Path, public_path: Path, password: bytes | None = None) -> tuple[Path, Path]:
    """Generate an Ed25519 operator signing keypair."""
    private_key = Ed25519PrivateKey.generate()
    encryption = serialization.NoEncryption() if password is None else serialization.BestAvailableEncryption(password)
    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path.parent.mkdir(parents=True, exist_ok=True)
    public_path.parent.mkdir(parents=True, exist_ok=True)
    private_path.write_bytes(private_bytes)
    public_path.write_bytes(public_bytes)
    private_path.chmod(0o600)
    public_path.chmod(0o644)
    return private_path, public_path


def _hash_if_present(path: Path, case_root: Path) -> dict[str, object] | None:
    """Return integrity metadata for an existing case file."""
    if not path.is_file():
        return None
    return {"path": str(path.relative_to(case_root)), "size": path.stat().st_size, "sha256": sha256_file(path)}


def _case_targets(case_root: Path, excluded: set[Path]) -> list[Path]:
    """Collect every regular case file except the seal artifacts."""
    return [
        path
        for path in sorted(case_root.rglob("*"))
        if path.is_file() and not path.is_symlink() and path.resolve() not in excluded
    ]


def create_case_seal(case_root: Path, private_key_path: Path, signature_path: Path, seal_path: Path, password: bytes | None = None) -> dict[str, object]:
    """Create and sign a complete case seal while excluding only seal artifacts."""
    excluded = {seal_path.resolve(), signature_path.resolve()}
    targets = _case_targets(case_root, excluded)
    custody = verify_custody_log(case_root / "00_metadata" / "custody.jsonl")
    seal = {
        "format": "droidcustos-case-seal-v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "generated_by": "DroidCustos",
        "author": "h3st4k3r",
        "case_root": str(case_root.resolve()),
        "custody_chain": custody,
        "files": [item for item in (_hash_if_present(path, case_root) for path in targets) if item is not None],
    }
    encoded = json.dumps(seal, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    private_key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=password)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise RuntimeError("The private key is not Ed25519")
    signature = private_key.sign(encoded)
    seal_path.parent.mkdir(parents=True, exist_ok=True)
    seal_path.write_bytes(encoded)
    signature_path.write_text(base64.b64encode(signature).decode("ascii") + "\n", encoding="ascii")
    return seal


def verify_case_seal(seal_path: Path, signature_path: Path, public_key_path: Path) -> dict[str, object]:
    """Verify a detached Ed25519 case seal and its referenced files."""
    if not seal_path.is_file() or not signature_path.is_file() or not public_key_path.is_file():
        return {"verified": False, "signature_valid": False, "files_valid": False, "errors": ["Missing seal, signature or public key"]}
    encoded = seal_path.read_bytes()
    signature = base64.b64decode(signature_path.read_text(encoding="ascii").strip())
    public_key = serialization.load_pem_public_key(public_key_path.read_bytes())
    if not isinstance(public_key, Ed25519PublicKey):
        raise RuntimeError("The public key is not Ed25519")
    signature_valid = True
    try:
        public_key.verify(signature, encoded)
    except InvalidSignature:
        signature_valid = False
    payload = json.loads(encoded)
    errors: list[str] = []
    signed_paths: set[str] = set()
    case_root = seal_path.parent.parent
    for item in payload.get("files", []):
        raw_path = str(item.get("path", ""))
        signed_paths.add(raw_path)
        relative = Path(raw_path)
        windows = PureWindowsPath(raw_path)
        if not raw_path or relative.is_absolute() or windows.is_absolute() or windows.drive or ".." in relative.parts or ".." in windows.parts:
            errors.append(f"Unsafe sealed path: {raw_path}")
            continue
        path = case_root / relative
        try:
            path.resolve().relative_to(case_root.resolve())
        except ValueError:
            errors.append(f"Outside case root: {raw_path}")
            continue
        if path.is_symlink() or not path.is_file():
            errors.append(f"Missing sealed file: {path}")
            continue
        actual = sha256_file(path)
        if actual != item["sha256"]:
            errors.append(f"Hash mismatch: {path}")
    if payload.get("format") == "droidcustos-case-seal-v2":
        excluded = {seal_path.resolve(), signature_path.resolve()}
        for path in _case_targets(case_root, excluded):
            relative = str(path.relative_to(case_root))
            if relative not in signed_paths:
                errors.append(f"Unexpected unsigned file: {path}")
    custody = verify_custody_log(case_root / "00_metadata" / "custody.jsonl")
    return {
        "verified": signature_valid and not errors,
        "signature_valid": signature_valid,
        "files_valid": not errors,
        "custody_chain_verified": bool(custody["verified"]),
        "custody_chain_complete": bool(custody["chain_complete"]),
        "custody_chain": custody,
        "errors": errors,
        "file_count": len(payload.get("files", [])),
    }
