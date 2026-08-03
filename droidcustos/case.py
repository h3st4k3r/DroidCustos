"""Case directory management.

Author: h3st4k3r
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def safe_component(value: str) -> str:
    """Normalize a value for safe filesystem use."""
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value.strip())
    return value.strip("._-") or "unknown"


@dataclass(frozen=True)
class CasePaths:
    root: Path
    metadata: Path
    evidence: Path
    androidqf_evidence: Path
    adb_evidence: Path
    plugin_evidence: Path
    package_evidence: Path
    extended_evidence: Path
    working: Path
    androidqf_working: Path
    private_working: Path
    analysis: Path
    mvt_analysis: Path
    heuristic_analysis: Path
    extended_analysis: Path
    aleapp_analysis: Path
    package_analysis: Path
    timeline_analysis: Path
    reports: Path
    hashes: Path
    exports: Path
    logs: Path

    @classmethod
    def create(cls, base: Path, serial: str, case_id: str | None = None) -> "CasePaths":
        """Create a new timestamped forensic case."""
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        suffix = safe_component(case_id) if case_id else safe_component(serial)
        root = base.expanduser().resolve() / f"{timestamp}_{suffix}"
        instance = cls._build(root)
        for path in instance.__dict__.values():
            if isinstance(path, Path):
                path.mkdir(parents=True, exist_ok=True)
        return instance

    @classmethod
    def from_existing(cls, root: Path) -> "CasePaths":
        """Open an existing forensic case structure."""
        instance = cls._build(root.expanduser().resolve())
        for path in instance.__dict__.values():
            if isinstance(path, Path):
                path.mkdir(parents=True, exist_ok=True)
        return instance

    @classmethod
    def _build(cls, root: Path) -> "CasePaths":
        """Build deterministic case paths."""
        return cls(
            root=root,
            metadata=root / "00_metadata",
            evidence=root / "01_evidence",
            androidqf_evidence=root / "01_evidence" / "androidqf",
            adb_evidence=root / "01_evidence" / "adb",
            plugin_evidence=root / "01_evidence" / "plugins",
            package_evidence=root / "01_evidence" / "packages",
            extended_evidence=root / "01_evidence" / "extended",
            working=root / "02_working",
            androidqf_working=root / "02_working" / "androidqf",
            private_working=root / "02_working" / "private",
            analysis=root / "03_analysis",
            mvt_analysis=root / "03_analysis" / "mvt",
            heuristic_analysis=root / "03_analysis" / "heuristics",
            extended_analysis=root / "03_analysis" / "extended",
            aleapp_analysis=root / "03_analysis" / "aleapp",
            package_analysis=root / "03_analysis" / "packages",
            timeline_analysis=root / "03_analysis" / "timeline",
            reports=root / "04_reports",
            hashes=root / "05_hashes",
            exports=root / "06_exports",
            logs=root / "logs",
        )

    @property
    def command_log(self) -> Path:
        """Return the auditable command log path."""
        return self.logs / "commands.log"

    @property
    def custody_log(self) -> Path:
        """Return the append-only custody event path."""
        return self.metadata / "custody.jsonl"

    @property
    def evidence_manifest_json(self) -> Path:
        """Return the JSON evidence-manifest path."""
        return self.hashes / "evidence-manifest.json"

    @property
    def evidence_manifest_text(self) -> Path:
        """Return the text evidence-manifest path."""
        return self.hashes / "SHA256SUMS.txt"

    @property
    def case_seal_json(self) -> Path:
        """Return the signed case-seal metadata path."""
        return self.hashes / "case-seal.json"

    @property
    def case_seal_signature(self) -> Path:
        """Return the detached case-seal signature path."""
        return self.hashes / "case-seal.sig"

    def write_json(self, relative: str, data: Any) -> Path:
        """Write deterministic JSON inside the case."""
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")
        return target
