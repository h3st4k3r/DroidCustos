"""Compatible ISO 8601 datetime parsing helpers."""

from __future__ import annotations

import re
from datetime import datetime


_FRACTION_RE = re.compile(r"(\.)(\d+)(?=(?:[+-]\d{2}:\d{2})?$)")


def parse_iso8601(value: object) -> datetime | None:
    """Parse ISO 8601 values, including Android nanosecond timestamps.

    ``datetime.fromisoformat`` on Python 3.10 accepts at most six fractional
    digits. Android's ``date +%N`` commonly emits nine, so retain the
    representable microsecond precision and truncate only the excess digits.
    """
    text = str(value or "").strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    text = _FRACTION_RE.sub(lambda match: match.group(1) + match.group(2)[:6], text)
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None
