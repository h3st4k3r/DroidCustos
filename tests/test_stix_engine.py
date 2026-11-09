import json
import sqlite3
from pathlib import Path

from droidcustos.indicators import build_ioc_database, load_ioc_lookup, parse_stix_pattern
from droidcustos.ioc_matcher import match_database


def test_compound_stix_pattern():
    """Extract multiple equality atoms from compound STIX."""
    pattern = "[domain-name:value = 'bad.example' OR ipv4-addr:value = '192.0.2.1']"
    assert parse_stix_pattern(pattern) == [
        ("domain-name", "value", "bad.example"),
        ("ipv4-addr", "value", "192.0.2.1"),
    ]


def test_build_ioc_database(tmp_path: Path):
    """Build and query the normalized IOC database."""
    stix = tmp_path / "source.stix2"
    stix.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--1",
                        "pattern": "[domain-name:value = 'bad.example' AND file:hashes.'SHA-256' = '" + "a" * 64 + "']",
                        "confidence": 90,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    database = build_ioc_database([stix], tmp_path / "ioc.db", {"sources": []})
    lookup = load_ioc_lookup(database)
    assert "bad.example" in lookup["domain"]
    assert "a" * 64 in lookup["sha256"]
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM indicators").fetchone()[0] == 2


def test_database_match_retains_stix_attribution(tmp_path: Path):
    """Preserve entity attribution after STIX normalization into SQLite."""
    stix = tmp_path / "attribution.stix2"
    stix.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "indicator",
                        "id": "indicator--one",
                        "pattern": "[domain-name:value = 'bad.example']",
                    },
                    {"type": "malware", "id": "malware--one", "name": "Test Pegasus"},
                    {
                        "type": "relationship",
                        "id": "relationship--one",
                        "relationship_type": "indicates",
                        "source_ref": "indicator--one",
                        "target_ref": "malware--one",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    database = build_ioc_database([stix], tmp_path / "ioc.db", {"sources": []})
    matches = match_database({"domain": ["bad.example"]}, database)
    assert matches[0]["attribution"][0]["name"] == "Test Pegasus"
    assert matches[0]["attribution"][0]["scope"] == "direct"
