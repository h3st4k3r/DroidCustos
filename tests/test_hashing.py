"""DroidCustos evidence manifest tests.

Author: h3st4k3r
"""

from droidcustos.hashing import create_evidence_manifest, verify_evidence_manifest


def test_manifest_verification_detects_modification(tmp_path) -> None:
    """Confirm that evidence changes invalidate the manifest."""
    evidence = tmp_path / "01_evidence"
    evidence.mkdir()
    sample = evidence / "sample.bin"
    sample.write_bytes(b"original")
    hashes = tmp_path / "05_hashes"
    text_manifest = hashes / "SHA256SUMS.txt"
    json_manifest = hashes / "evidence-manifest.json"

    create_evidence_manifest([evidence], text_manifest, json_manifest, tmp_path)
    assert verify_evidence_manifest(json_manifest, tmp_path)["verified"] is True

    sample.write_bytes(b"modified")
    result = verify_evidence_manifest(json_manifest, tmp_path)
    assert result["verified"] is False
    assert result["mismatches"]
