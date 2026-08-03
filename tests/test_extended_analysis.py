"""DroidCustos extended artifact tests.

Author: h3st4k3r
"""

from droidcustos.extended_analysis import _parse_user_hashes


def test_user_file_hash_summary_and_duplicates(tmp_path) -> None:
    """Confirm user-file counts and duplicate detection."""
    manifest = tmp_path / "user-files.sha256"
    digest = "a" * 64
    manifest.write_text(
        f"{digest}  /sdcard/DCIM/a.jpg\n"
        f"{digest}  /sdcard/Pictures/copy.jpg\n"
        f"{'b' * 64}  /sdcard/Documents/report.pdf\n",
        encoding="utf-8",
    )
    summary, matches = _parse_user_hashes(manifest, {"hashes": set()})
    assert summary["total"] == 3
    assert summary["images"] == 2
    assert summary["documents"] == 1
    assert summary["duplicates"] == 1
    assert matches == []
