"""Optional ALEAPP execution and result inventory.

Author: h3st4k3r
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .commands import run_stream
from .tools import find_aleapp


@dataclass
class AleappSummary:
    requested: str
    available: bool
    executed: bool
    returncode: int | None = None
    report_files: list[str] = field(default_factory=list)
    timeline_files: list[str] = field(default_factory=list)
    parsed_rows: int = 0
    error: str = ""

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe ALEAPP summary."""
        return asdict(self)


def run_aleapp(
    cache: Path,
    input_path: Path,
    output_path: Path,
    mode: str,
    log_path: Path,
    command_log: Path,
) -> AleappSummary:
    """Run ALEAPP when requested and available."""
    tool = find_aleapp(cache)
    summary = AleappSummary(requested=mode, available=tool is not None, executed=False)
    if mode == "no":
        return summary
    if not tool:
        summary.error = "ALEAPP is not installed"
        return summary
    if not input_path.exists() or not any(input_path.rglob("*")):
        summary.error = "No working acquisition was available for ALEAPP"
        return summary
    python, script = tool
    output_path.mkdir(parents=True, exist_ok=True)
    result = run_stream(
        [str(python), str(script), "-t", "fs", "-i", str(input_path), "-o", str(output_path)],
        log_path,
        command_log=command_log,
    )
    summary.executed = True
    summary.returncode = result.returncode
    summary.report_files = [str(path) for path in sorted(output_path.rglob("*.html"))]
    summary.timeline_files = [str(path) for path in sorted(output_path.rglob("*.tsv"))] + [
        str(path) for path in sorted(output_path.rglob("*.csv"))
    ]
    summary.parsed_rows = count_tabular_rows([Path(path) for path in summary.timeline_files])
    if not result.ok:
        summary.error = "ALEAPP execution failed"
    (output_path / "droidcustos-aleapp-summary.json").write_text(
        json.dumps(summary.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return summary


def count_tabular_rows(paths: list[Path]) -> int:
    """Count rows in ALEAPP CSV and TSV outputs."""
    total = 0
    for path in paths:
        try:
            delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                reader = csv.reader(handle, delimiter=delimiter)
                next(reader, None)
                total += sum(1 for _ in reader)
        except OSError:
            continue
    return total
