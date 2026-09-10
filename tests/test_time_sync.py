from unittest.mock import patch

from droidcustos.commands import CommandResult
from droidcustos.time_sync import measure_time_sync


def test_time_sync_records_offset_and_uncertainty() -> None:
    """Record host bounds, device time, round trip and uncertainty."""
    result = CommandResult(["adb"], 0, "2026-09-10T10:00:00.000000000Z\n", "")
    with patch("droidcustos.time_sync.run_capture", return_value=result), patch(
        "droidcustos.time_sync.time.monotonic", side_effect=[10.0, 10.2]
    ):
        sync = measure_time_sync("adb", "serial")
    assert sync["available"] is True
    assert sync["rtt_ms"] == 200.0
    assert sync["uncertainty_ms"] == 100.0
    assert sync["device_time_utc"].startswith("2026-09-10T10:00:00")
