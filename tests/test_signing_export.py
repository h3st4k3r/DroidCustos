from pathlib import Path

from droidcustos.export_case import export_encrypted_case, import_encrypted_case
from droidcustos.custody import append_event
from droidcustos.signing import create_case_seal, generate_signing_keypair, verify_case_seal


def test_signed_case_seal(tmp_path: Path):
    """Create and verify an Ed25519 case seal."""
    case = tmp_path / "case"
    (case / "05_hashes").mkdir(parents=True)
    (case / "04_reports").mkdir(parents=True)
    (case / "05_hashes" / "evidence-manifest.json").write_text("{}\n", encoding="utf-8")
    (case / "04_reports" / "summary.json").write_text("{}\n", encoding="utf-8")
    append_event(case / "00_metadata" / "custody.jsonl", "case_created", actor="tester")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_signing_keypair(private, public)
    create_case_seal(case, private, case / "05_hashes" / "case-seal.sig", case / "05_hashes" / "case-seal.json")
    result = verify_case_seal(case / "05_hashes" / "case-seal.json", case / "05_hashes" / "case-seal.sig", public)
    assert result["verified"] is True
    assert result["custody_chain_complete"] is True
    assert result["file_count"] >= 3


def test_encrypted_export_round_trip(tmp_path: Path):
    """Encrypt, authenticate and import a case archive."""
    case = tmp_path / "case"
    case.mkdir()
    (case / "evidence.txt").write_text("evidence", encoding="utf-8")
    archive = export_encrypted_case(case, tmp_path / "case.dcx", b"strong-password")
    imported = import_encrypted_case(archive, tmp_path / "imported", b"strong-password")
    assert (imported / "evidence.txt").read_text(encoding="utf-8") == "evidence"


def test_case_seal_detects_unsigned_files(tmp_path: Path):
    """Reject files added after a complete case seal was created."""
    case = tmp_path / "case"
    (case / "00_metadata").mkdir(parents=True)
    append_event(case / "00_metadata" / "custody.jsonl", "case_created", actor="tester")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_signing_keypair(private, public)
    seal = case / "05_hashes" / "case-seal.json"
    signature = case / "05_hashes" / "case-seal.sig"
    create_case_seal(case, private, signature, seal)
    (case / "unexpected.txt").write_text("unsealed", encoding="utf-8")
    result = verify_case_seal(seal, signature, public)
    assert result["verified"] is False
    assert any("Unexpected unsigned file" in item for item in result["errors"])
