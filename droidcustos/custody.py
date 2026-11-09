"""Chain-of-custody event recording.

Author: h3st4k3r
"""

from __future__ import annotations

import getpass
import hashlib
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


def _canonical_event(payload: dict[str, Any]) -> bytes:
    """Serialize one custody event deterministically for hashing."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8")


def _raw_line_hash(raw_line: bytes) -> str:
    """Hash one raw legacy custody line for chain continuity."""
    return hashlib.sha256(raw_line).hexdigest()


def _last_event_hash(log_path: Path) -> str:
    """Return the previous event hash or anchor legacy records safely."""
    if not log_path.is_file():
        return ""
    raw_lines = log_path.read_bytes().splitlines()
    if not raw_lines:
        return ""
    last_line = raw_lines[-1]
    try:
        payload = json.loads(last_line)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Cannot append to a malformed custody log") from exc
    if payload.get("event_hash"):
        return str(payload["event_hash"])
    return _raw_line_hash(last_line)


def append_event(log_path: Path, event: str, *, actor: str, details: dict[str, Any] | None = None) -> None:
    """Append a hash-chained custody event without rewriting prior records."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.is_file():
        integrity = verify_custody_log(log_path)
        if not integrity["verified"]:
            raise RuntimeError("Cannot append to a tampered custody log")
    payload = {
        "timestamp_utc": utc_now(),
        "event": event,
        "actor": actor,
        "details": details or {},
        "previous_event_hash": _last_event_hash(log_path),
    }
    payload["event_hash"] = hashlib.sha256(_canonical_event(payload)).hexdigest()
    with log_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
        handle.flush()


def verify_custody_log(log_path: Path) -> dict[str, object]:
    """Verify hash links in a custody log and report legacy prefixes explicitly."""
    if not log_path.is_file():
        return {
            "verified": False,
            "chain_complete": False,
            "events": 0,
            "legacy_events": 0,
            "errors": ["missing-log"],
            "last_event_hash": "",
        }
    raw_lines = log_path.read_bytes().splitlines()
    expected_previous = ""
    errors: list[str] = []
    legacy_events = 0
    events = 0
    for line_number, raw_line in enumerate(raw_lines, start=1):
        events += 1
        try:
            payload = json.loads(raw_line)
        except json.JSONDecodeError:
            errors.append(f"line-{line_number}:invalid-json")
            expected_previous = _raw_line_hash(raw_line)
            continue
        if not isinstance(payload, dict):
            errors.append(f"line-{line_number}:invalid-event")
            expected_previous = _raw_line_hash(raw_line)
            continue
        event_hash = payload.get("event_hash")
        if not event_hash:
            legacy_events += 1
            expected_previous = _raw_line_hash(raw_line)
            continue
        previous_hash = str(payload.get("previous_event_hash", ""))
        if previous_hash != expected_previous:
            errors.append(f"line-{line_number}:previous-hash-mismatch")
        unsigned = dict(payload)
        unsigned.pop("event_hash", None)
        calculated = hashlib.sha256(_canonical_event(unsigned)).hexdigest()
        if str(event_hash) != calculated:
            errors.append(f"line-{line_number}:event-hash-mismatch")
        expected_previous = str(event_hash)
    return {
        "verified": not errors,
        "chain_complete": not errors and legacy_events == 0,
        "events": events,
        "legacy_events": legacy_events,
        "errors": errors,
        "last_event_hash": expected_previous,
    }


def host_snapshot() -> dict[str, str]:
    """Handle host snapshot operations."""
    return {
        "hostname": socket.gethostname(),
        "operator_account": getpass.getuser(),
        "platform": platform.platform(),
        "python": sys.version.replace("\n", " "),
    }
