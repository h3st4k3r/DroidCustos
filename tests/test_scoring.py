"""DroidCustos verdict tests.

Author: h3st4k3r
"""

from droidcustos.analysis import MvtSummary
from droidcustos.heuristics import Finding
from droidcustos.scoring import calculate_verdict


def mvt(detected: int = 0, success: bool = True) -> MvtSummary:
    """Build a minimal MVT summary."""
    return MvtSummary(success, detected, [], [], [], 0, 0)


def test_known_ioc_wins() -> None:
    """Confirm that known IOC matches take precedence."""
    result = calculate_verdict(mvt(), [Finding("critical", "ioc", "Package IOC", "bad.package", 100)], acquisition_complete=True, ioc_count=10)
    assert result.code == "KNOWN_IOC_MATCHES"
    assert result.exit_code == 20


def test_negative_is_not_called_clean() -> None:
    """Confirm that negative findings are not labeled clean."""
    result = calculate_verdict(mvt(), [], acquisition_complete=True, ioc_count=10)
    assert result.code == "NO_KNOWN_INDICATORS"
    assert "CLEAN" not in result.message


def test_incomplete_is_inconclusive() -> None:
    """Confirm that incomplete acquisition is inconclusive."""
    result = calculate_verdict(mvt(), [], acquisition_complete=False, ioc_count=10)
    assert result.code == "INCONCLUSIVE"


def test_heuristics_trigger_review() -> None:
    """Confirm that strong heuristics require review."""
    finding = Finding("high", "boot", "Boot state changed", "orange", 55)
    result = calculate_verdict(mvt(), [finding], acquisition_complete=True, ioc_count=10)
    assert result.code == "SUSPICIOUS"
