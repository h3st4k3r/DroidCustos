from pathlib import Path

from droidcustos.export_case import export_encrypted_case, import_encrypted_case
from droidcustos.signing import create_case_seal, generate_signing_keypair, verify_case_seal


def test_signed_case_seal(tmp_path: Path):
    """Create and verify an Ed25519 case seal."""
    case = tmp_path / "case"
    (case / "05_hashes").mkdir(parents=True)
    (case / "04_reports").mkdir(parents=True)
    (case / "05_hashes" / "evidence-manifest.json").write_text("{}\n", encoding="utf-8")
    (case / "04_reports" / "summary.json").write_text("{}\n", encoding="utf-8")
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    generate_signing_keypair(private, public)
    create_case_seal(case, private, case / "05_hashes" / "case-seal.sig", case / "05_hashes" / "case-seal.json")
    result = verify_case_seal(case / "05_hashes" / "case-seal.json", case / "05_hashes" / "case-seal.sig", public)
    assert result["verified"] is True


def test_encrypted_export_round_trip(tmp_path: Path):
    """Encrypt, authenticate and import a case archive."""
    case = tmp_path / "case"
    case.mkdir()
    (case / "evidence.txt").write_text("evidence", encoding="utf-8")
    archive = export_encrypted_case(case, tmp_path / "case.dcx", b"strong-password")
    imported = import_encrypted_case(archive, tmp_path / "imported", b"strong-password")
    assert (imported / "evidence.txt").read_text(encoding="utf-8") == "evidence"
