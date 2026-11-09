"""Generate a small, dependency-free CycloneDX-style build manifest."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path


def _sha256(path: Path) -> str:
    """Hash a build artifact in bounded chunks."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _component(distribution: importlib.metadata.Distribution) -> dict[str, object]:
    """Convert installed distribution metadata into a component record."""
    name = distribution.metadata.get("Name", distribution.name)
    license_name = distribution.metadata.get("License", "")
    return {
        "type": "library",
        "name": name,
        "version": distribution.version,
        "scope": "runtime" if name.lower() == "droidcustos" else "development",
        "licenses": [{"license": {"name": license_name}}] if license_name else [],
        "purl": f"pkg:pypi/{name.lower().replace('_', '-')}@{distribution.version}",
    }


def generate_sbom(output: Path, wheel_dir: Path) -> None:
    """Write installed-package and wheel-hash metadata for a CI build."""
    components = sorted((_component(item) for item in importlib.metadata.distributions()), key=lambda item: str(item["name"]).lower())
    wheels = []
    for wheel in sorted(wheel_dir.glob("*.whl")):
        wheels.append(
            {
                "type": "file",
                "name": wheel.name,
                "hashes": [{"alg": "SHA-256", "content": _sha256(wheel)}],
                "properties": [{"name": "size-bytes", "value": str(wheel.stat().st_size)}],
            }
        )
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:00000000-0000-4000-8000-000000000000",
        "metadata": {"component": {"type": "application", "name": "droidcustos"}},
        "components": components + wheels,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def main() -> int:
    """Parse command-line arguments and generate the build manifest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wheel-dir", type=Path, required=True)
    args = parser.parse_args()
    generate_sbom(args.output, args.wheel_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
