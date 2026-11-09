from droidcustos.preflight import battery_check, estimate_duration, parse_battery_snapshot


def test_battery_snapshot_preserves_power_state() -> None:
    """Parse Android battery output without reducing it to a boolean."""
    snapshot = parse_battery_snapshot(
        "Battery service state:\n  AC powered: false\n  USB powered: true\n  level: 18\n  status: 2\n"
    )
    assert snapshot["level_percent"] == 18
    assert snapshot["charging"] is True
    assert battery_check(snapshot).status == "PASS"


def test_low_battery_is_blocked_only_when_not_charging() -> None:
    """Block unreliable low-power acquisition while preserving charging context."""
    snapshot = {"level_percent": 10, "charging": False, "power_sources": {}}
    assert battery_check(snapshot).status == "BLOCKED"
    snapshot["charging"] = True
    assert battery_check(snapshot).status == "PASS"


def test_duration_estimate_expands_for_deep_file_copy() -> None:
    """Expose a larger transparent estimate for expensive acquisition scope."""
    profile = type("Profile", (), {"name": "deep", "backup": "all", "download": "all", "copy_user_files": True})()
    estimate = estimate_duration(profile)
    assert estimate["minimum_minutes"] < estimate["maximum_minutes"]
    assert estimate["maximum_minutes"] >= 100
