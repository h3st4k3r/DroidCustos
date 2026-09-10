"""Unified Android forensic timeline generation.

Author: h3st4k3r
"""

from __future__ import annotations

import csv
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

from .datetime_utils import parse_iso8601
from .ioc_matcher import IOCExpression, load_database_expressions, match_expressions


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HASH_RE = re.compile(r"\b[A-Fa-f0-9]{64}\b")
TIMESTAMP_KEYS = (
    "timestamp",
    "timestamp_utc",
    "datetime",
    "date",
    "time",
    "created_at",
    "created_at_utc",
    "event_time",
    "visit_time",
    "last_visit_time",
    "firstInstallTime",
    "lastUpdateTime",
    "first_install_time",
    "last_update_time",
)


@dataclass(frozen=True)
class TimelineEvent:
    timestamp: str
    source: str
    artifact: str
    event_type: str
    user_id: int | None
    package: str
    process: str
    value: str
    severity: str
    confidence: int
    evidence_file: str
    evidence_sha256: str
    parser: str
    ioc_matches: list[dict[str, object]]
    raw: dict[str, object]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe timeline event."""
        return asdict(self)


def _normalize_timestamp(value: object) -> str:
    """Normalize common timestamp forms to ISO 8601 UTC when possible."""
    if value is None or value == "":
        return ""
    if isinstance(value, (int, float)):
        number = float(value)
        if number > 10**17:
            number /= 10**9
        elif number > 10**14:
            number /= 10**6
        elif number > 10**11:
            number /= 10**3
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return str(value)
    text = str(value).strip()
    formats = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
    )
    parsed = parse_iso8601(text)
    if parsed is not None:
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    for pattern in formats:
        try:
            return datetime.strptime(text, pattern).replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            continue
    return text


def _timestamp_from_record(record: dict[str, object]) -> str:
    """Select the best timestamp from a parsed artifact record."""
    lowered = {str(key).lower(): value for key, value in record.items()}
    for key in TIMESTAMP_KEYS:
        if key.lower() in lowered and lowered[key.lower()] not in (None, ""):
            return _normalize_timestamp(lowered[key.lower()])
    return ""


def _string_value(record: dict[str, object], keys: Iterable[str]) -> str:
    """Return the first populated textual field."""
    lowered = {str(key).lower(): value for key, value in record.items()}
    for key in keys:
        value = lowered.get(key.lower())
        if value not in (None, ""):
            return str(value)
    return ""


def _extract_observables(text: str) -> set[str]:
    """Extract URLs, domains, IP addresses and SHA-256 values."""
    values: set[str] = set()
    for url in URL_RE.findall(text):
        cleaned = url.rstrip(".,);]")
        values.add(cleaned)
        hostname = urlparse(cleaned).hostname
        if hostname:
            values.add(hostname.lower())
    for domain in DOMAIN_RE.findall(text):
        values.add(domain.lower().rstrip("."))
    for candidate in IP_RE.findall(text):
        try:
            values.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    values.update(value.lower() for value in HASH_RE.findall(text))
    return values


def _typed_observables(text: str) -> dict[str, set[str]]:
    """Extract observables grouped by the types understood by the IOC matcher."""
    values: dict[str, set[str]] = {"url": set(), "domain": set(), "ipv4": set(), "ipv6": set(), "sha256": set()}
    for url in URL_RE.findall(text):
        cleaned = url.rstrip(".,);]")
        values["url"].add(cleaned)
        hostname = urlparse(cleaned).hostname
        if hostname:
            values["domain"].add(hostname)
    for domain in DOMAIN_RE.findall(text):
        values["domain"].add(domain)
    for candidate in IP_RE.findall(text):
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        values["ipv4" if address.version == 4 else "ipv6"].add(str(address))
    values["sha256"].update(value.lower() for value in HASH_RE.findall(text))
    return values


def _event_from_record(record: dict[str, object], source: str, artifact: str, evidence_file: str, parser: str, expressions: list[IOCExpression]) -> TimelineEvent:
    """Convert one arbitrary artifact record into a timeline event."""
    text = json.dumps(record, sort_keys=True, default=str)
    matches = match_expressions(_typed_observables(text), expressions)
    severity = "critical" if matches else str(record.get("severity", "informational")).lower()
    confidence = 100 if matches else int(record.get("confidence", 50) or 50)
    user_text = _string_value(record, ("user_id", "user", "userid"))
    try:
        user_id = int(user_text) if user_text else None
    except ValueError:
        user_id = None
    return TimelineEvent(
        timestamp=_timestamp_from_record(record),
        source=source,
        artifact=artifact,
        event_type=_string_value(record, ("event_type", "type", "event", "category")) or artifact,
        user_id=user_id,
        package=_string_value(record, ("package", "package_name", "application", "app")),
        process=_string_value(record, ("process", "process_name", "name")),
        value=_string_value(record, ("url", "domain", "address", "value", "message", "title", "path")),
        severity=severity,
        confidence=confidence,
        evidence_file=evidence_file,
        evidence_sha256=str(record.get("evidence_sha256", "")),
        parser=parser,
        ioc_matches=matches,
        raw=record,
    )


def _read_json_records(path: Path) -> Iterable[dict[str, object]]:
    """Yield records from JSON and JSON Lines artifacts."""
    try:
        if path.suffix.lower() == ".jsonl":
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    value = json.loads(line)
                    if isinstance(value, dict):
                        yield value
            return
        payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return
    if isinstance(payload, list):
        for value in payload:
            if isinstance(value, dict):
                yield value
    elif isinstance(payload, dict):
        records = payload.get("records") or payload.get("events") or payload.get("data")
        if isinstance(records, list):
            for value in records:
                if isinstance(value, dict):
                    yield value
        else:
            yield payload


def _read_tabular(path: Path) -> Iterable[dict[str, object]]:
    """Yield records from CSV and TSV parser outputs."""
    delimiter = "\t" if path.suffix.lower() == ".tsv" else ","
    try:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
            for row in csv.DictReader(handle, delimiter=delimiter):
                yield dict(row)
    except OSError:
        return


def collect_timeline_events(case_root: Path, ioc_database: Path) -> list[TimelineEvent]:
    """Collect normalized events from all available analysis products."""
    expressions = load_database_expressions(ioc_database)
    events: list[TimelineEvent] = []
    sources = [
        (case_root / "00_metadata" / "custody.jsonl", "custody", "custody-event", "droidcustos"),
        (case_root / "03_analysis" / "packages" / "package-inventory.json", "packages", "package-state", "droidcustos"),
    ]
    for path, source, artifact, parser in sources:
        if not path.is_file():
            continue
        for record in _read_json_records(path):
            events.append(_event_from_record(record, source, artifact, str(path), parser, expressions))

    recursive_roots = [
        (case_root / "03_analysis" / "mvt", "mvt", "mvt-record", "mvt"),
        (case_root / "03_analysis" / "extended", "extended", "extended-record", "droidcustos"),
        (case_root / "03_analysis" / "aleapp", "aleapp", "aleapp-record", "aleapp"),
    ]
    for root, source, artifact, parser in recursive_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() in {".json", ".jsonl"}:
                records = _read_json_records(path)
            elif path.suffix.lower() in {".csv", ".tsv"}:
                records = _read_tabular(path)
            else:
                continue
            for record in records:
                events.append(_event_from_record(record, source, artifact, str(path), parser, expressions))
    return events


def write_unified_timeline(case_root: Path, output_dir: Path, ioc_database: Path) -> dict[str, object]:
    """Write sorted JSON Lines, CSV and summary timeline products."""
    output_dir.mkdir(parents=True, exist_ok=True)
    events = collect_timeline_events(case_root, ioc_database)
    events.sort(key=lambda item: (item.timestamp == "", item.timestamp, item.source, item.artifact))
    jsonl_path = output_dir / "timeline.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event.to_dict(), sort_keys=True, default=str) + "\n")
    csv_path = output_dir / "timeline.csv"
    with csv_path.open("w", encoding="utf-8", newline="") as handle:
        fields = ["timestamp", "source", "artifact", "event_type", "user_id", "package", "process", "value", "severity", "confidence", "evidence_file", "parser", "ioc_matches"]
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for event in events:
            row = event.to_dict()
            row["ioc_matches"] = json.dumps(row["ioc_matches"], sort_keys=True)
            writer.writerow({field: row.get(field, "") for field in fields})
    summary = {
        "event_count": len(events),
        "timestamped_events": sum(1 for event in events if event.timestamp),
        "critical_events": sum(1 for event in events if event.severity == "critical"),
        "ioc_matched_events": sum(1 for event in events if event.ioc_matches),
        "sources": sorted({event.source for event in events}),
        "jsonl": str(jsonl_path),
        "csv": str(csv_path),
    }
    (output_dir / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary
