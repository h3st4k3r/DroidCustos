from droidcustos.security_state import analyze_security_state


def test_security_state_composes_evidence() -> None:
    """Increase risk for accessibility, overlay and installation evidence together."""
    result = analyze_security_state(
        {
            "verified_boot_state": "green",
            "flash_locked": "1",
            "vbmeta_device_state": "locked",
            "security_patch": "2025-01-01",
            "adb_enabled": "1",
            "enabled_accessibility_services": "com.example/.Assist",
        },
        {"root_authorized": False},
        {
            "records": [{
                "package": "com.example.app",
                "installer": "com.android.shell",
                "requested_permissions": [
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.REQUEST_INSTALL_PACKAGES",
                ],
            }]
        },
    )
    signals = result["signals"]
    assert signals["accessibility"] is True
    assert signals["overlay"] is True
    assert signals["install_packages"] is True
    assert any(item["signal"] == "composite-accessibility-overlay-sideload" for item in result["findings"])


def test_security_state_does_not_query_device() -> None:
    """Analyze only supplied mappings and preserve explicit limitations."""
    result = analyze_security_state({"verified_boot_state": "green"}, now=None)
    assert result["evidence_only"] is True
    assert result["limitations"]
    assert result["risk_score"] == 0
