"""Chain-of-custody event recording.

Author: h3st4k3r
"""

from __future__ import annotations

import getpass
import json
import platform
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    """Handle utc now operations."""
    return datetime.now(timezone.utc).isoformat()


def append_event(log_path: Path, event: str, *, actor: str, details: dict[str, Any] | None = None) -> None:
    """Handle append event operations."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "timestamp_utc": utc_now(),
        "event": event,
        "actor": actor,
        "details": details or {},
    }
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
        handle.flush()


def host_snapshot() -> dict[str, str]:
    """Handle host snapshot operations."""
    return {
        "hostname": socket.gethostname(),
        "operator_account": getpass.getuser(),
        "platform": platform.platform(),
        "python": sys.version.replace("\n", " "),
    }
