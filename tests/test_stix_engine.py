import json
import sqlite3
from pathlib import Path

from droidcustos.indicators import build_ioc_database, load_ioc_lookup, parse_stix_pattern


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
