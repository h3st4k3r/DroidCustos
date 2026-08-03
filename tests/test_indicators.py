"""DroidCustos STIX parsing tests.

Author: h3st4k3r
"""

import json

from droidcustos.indicators import extract_simple_indicators


def test_extract_simple_indicators(tmp_path) -> None:
    """Confirm extraction of simple STIX indicators."""
    path = tmp_path / "test.stix2"
    path.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {"type": "indicator", "pattern": "[app:id = 'com.example.bad']"},
                    {"type": "indicator", "pattern": "[domain-name:value = 'bad.example']"},
                ],
            }
        ),
        encoding="utf-8",
    )
    values = extract_simple_indicators([path])
    assert "com.example.bad" in values["app:id"]
    assert "bad.example" in values["domain-name:value"]
