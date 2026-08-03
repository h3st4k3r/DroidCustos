"""DroidCustos MVT parsing and report-table tests.

Author: h3st4k3r
"""

from pathlib import Path

from droidcustos.analysis import MvtSummary, _mvt_log_lines, _summarize_alerts
from droidcustos.apk_inventory import parse_package_list
from droidcustos.heuristics import Finding
from droidcustos.scoring import calculate_verdict


def test_mvt_heuristic_is_not_ioc() -> None:
    """Confirm non-null matched indicators are required for an IOC match."""
    alerts, indicators = _summarize_alerts(
        [
            {
                "level": "MEDIUM",
                "module": "tombstones",
                "message": "Potentially suspicious crash in tombstone_00",
                "matched_indicator": None,
                "source_file": "alerts.json",
            },
            {
                "level": "MEDIUM",
                "module": "tombstones",
                "message": "Potentially suspicious crash in tombstone_00.pb",
                "matched_indicator": None,
                "source_file": "alerts.json",
            },
        ]
    )
    assert len(alerts) == 1
    assert alerts[0]["classification"] == "HEURISTIC"
    assert alerts[0]["occurrences"] == 2
    assert indicators == []


def test_mvt_matched_indicator_is_confirmed() -> None:
    """Confirm a populated MVT matched indicator is retained as IOC evidence."""
    alerts, indicators = _summarize_alerts(
        [
            {
                "level": "CRITICAL",
                "module": "browser",
                "message": "Known domain matched",
                "matched_indicator": {"type": "domain", "value": "example.invalid", "name": "Test IOC"},
                "source_file": "alerts.json",
            }
        ]
    )
    assert alerts[0]["classification"] == "CONFIRMED_IOC"
    assert indicators[0]["value"] == "example.invalid"


def test_zero_critical_summary_is_not_log_error(tmp_path: Path) -> None:
    """Confirm summary prose containing CRITICAL is not parsed as a critical log entry."""
    log = tmp_path / "mvt.log"
    log.write_text("│ MVT produced 0 CRITICAL alerts. │\n12:00:00 CRITICAL [mvt.module] Actual failure\n", encoding="utf-8")
    assert _mvt_log_lines([log], "CRITICAL") == ["12:00:00 CRITICAL [mvt.module] Actual failure"]


def test_package_path_with_equals_is_parsed_from_last_separator() -> None:
    """Confirm APK paths containing base64 padding do not corrupt package names."""
    records = parse_package_list(
        "package:/data/app/~~ABC==/com.example.app-XYZ==/base.apk=com.example.app uid:10123 installer=com.android.vending versionCode:42",
        0,
    )
    assert records[0].package == "com.example.app"
    assert records[0].source_path.endswith("/base.apk")
    assert records[0].installer == "com.android.vending"


def test_critical_non_ioc_finding_never_becomes_known_ioc() -> None:
    """Confirm critical heuristics are review findings rather than IOC matches."""
    summary = MvtSummary(True, 0, [], [], [], 1, 0)
    finding = Finding("critical", "boot-integrity", "Verified Boot is red", "red", 80)
    result = calculate_verdict(summary, [finding], acquisition_complete=True, ioc_count=17)
    assert result.code == "SUSPICIOUS"


def test_incomplete_case_with_only_medium_alerts_remains_inconclusive() -> None:
    """Confirm medium MVT heuristics do not escalate an incomplete case to IOC detection."""
    summary = MvtSummary(
        True,
        0,
        [],
        [],
        [],
        1,
        0,
        alert_records=28,
        heuristic_records=28,
        unique_alert_records=14,
        alerts_by_level={"MEDIUM": 28},
    )
    finding = Finding("medium", "patch-level", "Security patch is old", "94 days", 20)
    result = calculate_verdict(summary, [finding], acquisition_complete=False, ioc_count=17)
    assert result.code == "INCONCLUSIVE"
