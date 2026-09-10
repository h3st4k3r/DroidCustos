"""Analysis of optional privacy-sensitive Android artifacts.

Author: h3st4k3r
"""

from __future__ import annotations

import ipaddress
import json
import re
import shutil
import sqlite3
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Iterator
from urllib.parse import urlparse

from .archive_safety import UnsafeArchiveError, safe_extract_tar
from .case import CasePaths
from .heuristics import Finding
from .indicators import extract_simple_indicators
from .ioc_matcher import IOCExpression, load_stix_expressions, match_expressions


URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"(?<![A-Za-z0-9_-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}(?![A-Za-z0-9_-])")
IP_RE = re.compile(r"(?<![0-9A-Fa-f:.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
HASH_LINE_RE = re.compile(r"^(?P<hash>[0-9a-fA-F]{64})\s+(?P<path>.+)$")

IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".heif", ".bmp", ".tif", ".tiff", ".dng", ".raw"}
DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".odt", ".ods", ".odp", ".rtf", ".txt",
    ".csv", ".json", ".xml", ".yaml", ".yml", ".md", ".epub", ".mobi", ".pages", ".numbers", ".key",
    ".zip", ".7z", ".rar",
}


@dataclass
class ExtendedAnalysisSummary:
    enabled: bool = False
    private_archive_extracted: bool = False
    browser_databases: int = 0
    browser_records: int = 0
    chat_databases: int = 0
    chat_records: int = 0
    sms_records: int = 0
    connection_artifacts: int = 0
    unique_network_observables: int = 0
    user_file_hashes: int = 0
    image_hashes: int = 0
    document_hashes: int = 0
    duplicate_hash_groups: int = 0
    copied_user_files: int = 0
    ioc_matches: list[dict[str, str]] = field(default_factory=list)
    database_inventory: list[dict[str, object]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _safe_extract_tar(archive: Path, destination: Path) -> None:
    """Handle safe extract tar operations."""
    if destination.exists():
        shutil.rmtree(destination)
    safe_extract_tar(archive, destination)


def _connect_read_only(path: Path) -> sqlite3.Connection:
    """Handle connect read only operations."""
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    connection.row_factory = sqlite3.Row
    return connection


def _table_names(connection: sqlite3.Connection) -> list[str]:
    """Handle table names operations."""
    return [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]


def _columns(connection: sqlite3.Connection, table: str) -> list[str]:
    """Handle columns operations."""
    quoted = table.replace('"', '""')
    return [row[1] for row in connection.execute(f'PRAGMA table_info("{quoted}")')]


def _json_safe(value):
    """Handle json safe operations."""
    if isinstance(value, bytes):
        return value.hex()
    return value


def _write_query_jsonl(connection: sqlite3.Connection, query: str, output: Path) -> tuple[int, set[str]]:
    """Handle write query jsonl operations."""
    output.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    observables: set[str] = set()
    with output.open("w", encoding="utf-8") as handle:
        cursor = connection.execute(query)
        while True:
            rows = cursor.fetchmany(1000)
            if not rows:
                break
            for row in rows:
                payload = {key: _json_safe(row[key]) for key in row.keys()}
                handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
                count += 1
                observables.update(_extract_observables(" ".join(str(value) for value in payload.values() if value is not None)))
    return count, observables


def _chrome_time(value: int | float | None) -> str | None:
    """Handle chrome time operations."""
    if not value:
        return None
    try:
        return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=int(value))).isoformat()
    except (ValueError, OverflowError):
        return None


def _parse_chrome_history(path: Path, output: Path) -> tuple[int, set[str]]:
    """Handle parse chrome history operations."""
    connection = _connect_read_only(path)
    try:
        if "urls" not in _table_names(connection):
            return 0, set()
        columns = set(_columns(connection, "urls"))
        wanted = [name for name in ("id", "url", "title", "visit_count", "typed_count", "last_visit_time") if name in columns]
        query = f"SELECT {', '.join(wanted)} FROM urls ORDER BY last_visit_time DESC" if "last_visit_time" in columns else f"SELECT {', '.join(wanted)} FROM urls"
        output.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        observables: set[str] = set()
        with output.open("w", encoding="utf-8") as handle:
            for row in connection.execute(query):
                payload = {key: _json_safe(row[key]) for key in row.keys()}
                if "last_visit_time" in payload:
                    payload["last_visit_time_utc"] = _chrome_time(payload["last_visit_time"])
                handle.write(json.dumps(payload, ensure_ascii=False, default=str) + "\n")
                count += 1
                observables.update(_extract_observables(str(payload.get("url", ""))))
        return count, observables
    finally:
        connection.close()


def _parse_firefox_history(path: Path, output: Path) -> tuple[int, set[str]]:
    """Handle parse firefox history operations."""
    connection = _connect_read_only(path)
    try:
        tables = set(_table_names(connection))
        if "moz_places" not in tables:
            return 0, set()
        if "moz_historyvisits" in tables:
            query = (
                "SELECT p.id, p.url, p.title, p.visit_count, v.visit_date "
                "FROM moz_places p LEFT JOIN moz_historyvisits v ON v.place_id=p.id "
                "ORDER BY v.visit_date DESC"
            )
        else:
            query = "SELECT id, url, title, visit_count FROM moz_places ORDER BY id DESC"
        return _write_query_jsonl(connection, query, output)
    finally:
        connection.close()


def _parse_sms(path: Path, output: Path) -> tuple[int, set[str]]:
    """Handle parse sms operations."""
    connection = _connect_read_only(path)
    try:
        if "sms" not in _table_names(connection):
            return 0, set()
        columns = set(_columns(connection, "sms"))
        wanted = [name for name in ("_id", "thread_id", "address", "date", "date_sent", "type", "body", "read", "status") if name in columns]
        query = f"SELECT {', '.join(wanted)} FROM sms ORDER BY date" if "date" in columns else f"SELECT {', '.join(wanted)} FROM sms"
        return _write_query_jsonl(connection, query, output)
    finally:
        connection.close()


def _parse_whatsapp(path: Path, output: Path) -> tuple[int, set[str]]:
    """Handle parse whatsapp operations."""
    connection = _connect_read_only(path)
    try:
        tables = set(_table_names(connection))
        if "message" in tables:
            columns = set(_columns(connection, "message"))
            wanted = [
                name for name in ("_id", "chat_row_id", "sender_jid_row_id", "from_me", "timestamp", "text_data", "message_type")
                if name in columns
            ]
            if wanted:
                order = " ORDER BY timestamp" if "timestamp" in columns else ""
                return _write_query_jsonl(connection, f"SELECT {', '.join(wanted)} FROM message{order}", output)
        if "messages" in tables:
            columns = set(_columns(connection, "messages"))
            wanted = [name for name in ("_id", "key_remote_jid", "key_from_me", "timestamp", "data", "media_wa_type") if name in columns]
            if wanted:
                order = " ORDER BY timestamp" if "timestamp" in columns else ""
                return _write_query_jsonl(connection, f"SELECT {', '.join(wanted)} FROM messages{order}", output)
        return 0, set()
    finally:
        connection.close()


def _database_inventory(path: Path) -> dict[str, object]:
    """Handle database inventory operations."""
    try:
        connection = _connect_read_only(path)
        try:
            tables = _table_names(connection)
            return {"path": str(path), "tables": tables, "error": None}
        finally:
            connection.close()
    except sqlite3.Error as exc:
        return {"path": str(path), "tables": [], "error": str(exc)}


def _extract_observables(text: str) -> set[str]:
    """Handle extract observables operations."""
    values: set[str] = set()
    for url in URL_RE.findall(text):
        values.add(url.rstrip(".,);]"))
        hostname = urlparse(url).hostname
        if hostname:
            values.add(hostname.lower())
    for domain in DOMAIN_RE.findall(text):
        values.add(domain.lower())
    for candidate in IP_RE.findall(text):
        try:
            values.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue
    return values


def _ioc_lookup(ioc_files: Iterable[Path]) -> dict[str, set[str]]:
    """Handle ioc lookup operations."""
    raw = extract_simple_indicators(ioc_files)
    return {
        "domains": {value.lower().rstrip(".") for value in raw.get("domain-name:value", set())},
        "ips": set(raw.get("ipv4-addr:value", set())) | set(raw.get("ipv6-addr:value", set())),
        "urls": set(raw.get("url:value", set())),
        "hashes": {value.lower() for value in raw.get("file:hashes.'SHA-256'", set()) | raw.get("file:hashes.SHA-256", set())},
    }


def _match_observables(observables: Iterable[str], lookup: dict[str, set[str]], source: str) -> list[dict[str, str]]:
    """Handle match observables operations."""
    matches: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for observable in observables:
        kind = ""
        matched = ""
        lowered = observable.lower().rstrip(".")
        if observable in lookup["urls"]:
            kind, matched = "url", observable
        elif lowered in lookup["ips"]:
            kind, matched = "ip", lowered
        else:
            hostname = urlparse(observable).hostname if observable.startswith(("http://", "https://")) else lowered
            if hostname:
                for domain in lookup["domains"]:
                    if hostname == domain or hostname.endswith("." + domain):
                        kind, matched = "domain", domain
                        break
        if kind and (kind, observable) not in seen:
            seen.add((kind, observable))
            matches.append({"type": kind, "observable": observable, "matched_ioc": matched, "source": source})
    return matches


def _typed_observables(observables: Iterable[str]) -> dict[str, set[str]]:
    """Group extended artifact values by matcher observable type."""
    typed: dict[str, set[str]] = {"url": set(), "domain": set(), "ipv4": set(), "ipv6": set(), "sha256": set()}
    for value in observables:
        raw = str(value).strip()
        if URL_RE.match(raw):
            typed["url"].add(raw)
            hostname = urlparse(raw).hostname
            if hostname:
                typed["domain"].add(hostname)
            continue
        if re.fullmatch(r"[0-9a-fA-F]{64}", raw):
            typed["sha256"].add(raw)
            continue
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            typed["domain"].add(raw)
        else:
            typed["ipv4" if address.version == 4 else "ipv6"].add(str(address))
    return typed


def _parse_user_hashes(path: Path, lookup: dict[str, set[str]], expressions: list[IOCExpression] | None = None) -> tuple[dict[str, object], list[dict[str, str]]]:
    """Handle parse user hashes operations."""
    by_hash: dict[str, list[str]] = defaultdict(list)
    extension_counts: Counter[str] = Counter()
    images = 0
    documents = 0
    matches: list[dict[str, str]] = []
    if not path.is_file():
        return {"total": 0, "images": 0, "documents": 0, "duplicates": 0, "extensions": {}}, matches

    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = HASH_LINE_RE.match(line.strip())
        if not match:
            continue
        digest = match.group("hash").lower()
        file_path = match.group("path")
        by_hash[digest].append(file_path)
        suffix = Path(file_path).suffix.lower()
        extension_counts[suffix or "<none>"] += 1
        images += int(suffix in IMAGE_EXTENSIONS)
        documents += int(suffix in DOCUMENT_EXTENSIONS)
        if expressions is not None:
            for item in match_expressions({"sha256": [digest]}, expressions):
                matches.append({"type": "sha256", "observable": digest, "matched_ioc": str(item.get("pattern", "")), "source": file_path})
        elif digest in lookup["hashes"]:
            matches.append({"type": "sha256", "observable": digest, "matched_ioc": digest, "source": file_path})

    duplicates = {digest: paths for digest, paths in by_hash.items() if len(paths) > 1}
    return {
        "total": sum(len(paths) for paths in by_hash.values()),
        "images": images,
        "documents": documents,
        "duplicates": len(duplicates),
        "extensions": dict(extension_counts.most_common()),
        "duplicate_groups": duplicates,
    }, matches


def analyze_extended(case: CasePaths, ioc_files: list[Path]) -> tuple[ExtendedAnalysisSummary, list[Finding]]:
    """Handle analyze extended operations."""
    summary = ExtendedAnalysisSummary(enabled=case.extended_evidence.exists() and any(case.extended_evidence.rglob("*")))
    findings: list[Finding] = []
    case.extended_analysis.mkdir(parents=True, exist_ok=True)
    if not summary.enabled:
        case.write_json("03_analysis/extended/summary.json", asdict(summary))
        return summary, findings
    lookup = _ioc_lookup(ioc_files)
    expressions = load_stix_expressions(ioc_files)
    observables_by_source: dict[str, set[str]] = defaultdict(set)

    private_archive = case.extended_evidence / "private" / "selected-private-artifacts.tar"
    if private_archive.is_file():
        try:
            _safe_extract_tar(private_archive, case.private_working)
            summary.private_archive_extracted = True
        except (OSError, UnsafeArchiveError, RuntimeError) as exc:
            summary.errors.append(f"Private archive extraction failed: {exc}")

    search_roots = [case.androidqf_working, case.private_working]
    database_paths: set[Path] = set()
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for path in search_root.rglob("*"):
            if not path.is_file():
                continue
            name = path.name.lower()
            known_names = {"history", "places.sqlite", "mmssms.db", "msgstore.db", "wa.db", "cache4.db", "signal.db"}
            if name in known_names or (search_root == case.private_working and name.endswith(".db")):
                database_paths.add(path)

    for index, path in enumerate(sorted(database_paths), start=1):
        inventory = _database_inventory(path)
        summary.database_inventory.append(inventory)
        lowered = path.name.lower()
        try:
            if lowered == "history":
                count, values = _parse_chrome_history(path, case.extended_analysis / "web" / f"chrome-history-{index}.jsonl")
                if count:
                    summary.browser_databases += 1
                    summary.browser_records += count
                    observables_by_source[str(path)].update(values)
            elif lowered == "places.sqlite":
                count, values = _parse_firefox_history(path, case.extended_analysis / "web" / f"firefox-history-{index}.jsonl")
                if count:
                    summary.browser_databases += 1
                    summary.browser_records += count
                    observables_by_source[str(path)].update(values)
            elif lowered == "mmssms.db":
                count, values = _parse_sms(path, case.extended_analysis / "chats" / f"sms-{index}.jsonl")
                if count:
                    summary.chat_databases += 1
                    summary.sms_records += count
                    summary.chat_records += count
                    observables_by_source[str(path)].update(values)
            elif lowered == "msgstore.db":
                count, values = _parse_whatsapp(path, case.extended_analysis / "chats" / f"whatsapp-{index}.jsonl")
                summary.chat_databases += 1
                summary.chat_records += count
                observables_by_source[str(path)].update(values)
            elif lowered in {"cache4.db", "signal.db"}:
                summary.chat_databases += 1
        except sqlite3.Error as exc:
            summary.errors.append(f"SQLite parse failed for {path}: {exc}")

    raw_text_roots = [case.extended_evidence / "network", case.extended_evidence / "chats" / "content_queries"]
    for raw_root in raw_text_roots:
        if not raw_root.exists():
            continue
        for path in raw_root.rglob("*.txt"):
            try:
                values = _extract_observables(path.read_text(encoding="utf-8", errors="replace"))
            except OSError as exc:
                summary.errors.append(f"Unable to read {path}: {exc}")
                continue
            observables_by_source[str(path)].update(values)
            if "network" in path.parts:
                summary.connection_artifacts += 1

    hash_summary, hash_matches = _parse_user_hashes(
        case.extended_evidence / "user_files" / "user-files.sha256",
        lookup,
        expressions,
    )
    summary.user_file_hashes = int(hash_summary["total"])
    summary.image_hashes = int(hash_summary["images"])
    summary.document_hashes = int(hash_summary["documents"])
    summary.duplicate_hash_groups = int(hash_summary["duplicates"])
    (case.extended_analysis / "user-file-summary.json").write_text(
        json.dumps(hash_summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    copied_root = case.extended_evidence / "user_files" / "copied"
    if copied_root.exists():
        summary.copied_user_files = sum(1 for path in copied_root.rglob("*") if path.is_file())

    for source, values in observables_by_source.items():
        for match in match_expressions(_typed_observables(values), expressions):
            observed = ", ".join(
                f"{item.get('type')}={item.get('value')}"
                for item in match.get("matched_observables", [])
            )
            summary.ioc_matches.append(
                {
                    "type": "stix-expression",
                    "observable": observed,
                    "matched_ioc": str(match.get("pattern", "")),
                    "source": source,
                }
            )
    summary.ioc_matches.extend(hash_matches)
    summary.unique_network_observables = len(set().union(*observables_by_source.values())) if observables_by_source else 0

    deduplicated: dict[tuple[str, str, str], dict[str, str]] = {}
    for match in summary.ioc_matches:
        deduplicated[(match["type"], match["observable"], match["source"])] = match
    summary.ioc_matches = list(deduplicated.values())

    for match in summary.ioc_matches:
        findings.append(
            Finding(
                "critical",
                "extended-ioc",
                f"{match['type'].upper()} matches a published IOC",
                f"{match['observable']} ({match['source']})",
                100,
            )
        )

    (case.extended_analysis / "database-inventory.json").write_text(
        json.dumps(summary.database_inventory, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (case.extended_analysis / "ioc-matches.json").write_text(
        json.dumps(summary.ioc_matches, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    case.write_json("03_analysis/extended/summary.json", asdict(summary))
    return summary, findings
