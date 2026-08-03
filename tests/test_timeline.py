import json
from pathlib import Path

from droidcustos.timeline import write_unified_timeline


def test_unified_timeline(tmp_path: Path):
    """Create a timeline from custody and analysis records."""
    case = tmp_path / "case"
    metadata = case / "00_metadata"
    metadata.mkdir(parents=True)
    (metadata / "custody.jsonl").write_text(
        json.dumps({"timestamp": "2026-01-01T00:00:00Z", "event": "case_created"}) + "\n",
        encoding="utf-8",
    )
    output = case / "03_analysis" / "timeline"
    result = write_unified_timeline(case, output, tmp_path / "missing.db")
    assert result["event_count"] == 1
    assert (output / "timeline.csv").is_file()
