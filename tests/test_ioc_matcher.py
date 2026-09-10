import json
from datetime import datetime, timezone
from pathlib import Path

from droidcustos.ioc_matcher import (
    is_active,
    match_stix_files,
    normalize_value,
    parse_stix_expression,
)


def test_and_requires_all_observables_in_one_scope(tmp_path: Path) -> None:
    """Require every atom in an AND expression to be present."""
    path = tmp_path / "and.stix2"
    path.write_text(
        json.dumps({
            "type": "bundle",
            "objects": [{
                "type": "indicator",
                "id": "indicator--and",
                "pattern": "[domain-name:value = 'bad.example' AND ipv4-addr:value = '192.0.2.1']",
            }],
        }),
        encoding="utf-8",
    )
    assert match_stix_files({"domain": ["bad.example"]}, [path]) == []
    matches = match_stix_files({"domain": ["sub.bad.example"], "ipv4": ["192.0.2.1"]}, [path])
    assert len(matches) == 1
    assert len(matches[0]["matched_observables"]) == 2


def test_nested_or_and_expression(tmp_path: Path) -> None:
    """Evaluate nested STIX boolean expressions with normal precedence."""
    path = tmp_path / "nested.stix2"
    path.write_text(
        json.dumps({
            "type": "bundle",
            "objects": [{
                "type": "indicator",
                "id": "indicator--nested",
                "pattern": "[(domain-name:value = 'one.example' OR domain-name:value = 'two.example') AND file:hashes.'SHA-256' = '" + "A" * 64 + "']",
            }],
        }),
        encoding="utf-8",
    )
    matches = match_stix_files({"domain": ["two.example"], "sha256": ["a" * 64]}, [path])
    assert len(matches) == 1


def test_future_and_revoked_indicators_are_ignored(tmp_path: Path) -> None:
    """Ignore indicators that are not active at the matching instant."""
    path = tmp_path / "validity.stix2"
    path.write_text(
        json.dumps({
            "type": "bundle",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--future",
                    "valid_from": "2030-01-01T00:00:00Z",
                    "pattern": "[domain-name:value = 'future.example']",
                },
                {
                    "type": "indicator",
                    "id": "indicator--revoked",
                    "revoked": True,
                    "pattern": "[domain-name:value = 'revoked.example']",
                },
            ],
        }),
        encoding="utf-8",
    )
    now = datetime(2026, 9, 10, tzinfo=timezone.utc)
    assert match_stix_files({"domain": ["future.example", "revoked.example"]}, [path], now=now) == []
    assert not is_active("2030-01-01T00:00:00Z", None, False, now)


def test_unsupported_pattern_is_not_matched(tmp_path: Path) -> None:
    """Skip unsupported STIX operators instead of treating their atoms as IOCs."""
    node, observables, reason = parse_stix_expression("[domain-name:value MATCHES 'bad']")
    assert node is not None
    assert observables == ()
    assert reason


def test_observable_normalization() -> None:
    """Normalize domains, URLs, hashes and IP addresses consistently."""
    assert normalize_value("domain", "Sub.Bad.Example.") == "sub.bad.example"
    assert normalize_value("url", "HTTPS://Bad.Example/path,") == "https://bad.example/path"
    assert normalize_value("sha256", "A" * 64) == "a" * 64
    assert normalize_value("ipv6", "2001:0db8:0:0:0:0:0:1") == "2001:db8::1"
