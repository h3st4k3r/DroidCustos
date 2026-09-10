"""STIX source acquisition, normalization and IOC database management.

Author: h3st4k3r
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import shutil
import sqlite3
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml

from . import __version__
from .commands import run_capture
from .ioc_matcher import is_active, normalize_type


INDEX_REPOSITORY = "https://github.com/mvt-project/mvt-indicators.git"
_ATOM_RE = re.compile(
    r"(?P<object>[A-Za-z0-9_-]+):(?P<field>[A-Za-z0-9_.\-']+(?:\[[^]]+\])?)\s*=\s*(?P<quote>['\"])(?P<value>(?:\\.|(?!\3).)+)(?P=quote)",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class IndicatorRecord:
    stix_id: str
    object_type: str
    field: str
    value: str
    normalized_type: str
    source_name: str
    source_url: str
    confidence: int
    valid_from: str | None
    valid_until: str | None
    revoked: bool
    labels: list[str]
    name: str
    description: str
    pattern: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe normalized indicator."""
        return asdict(self)


def _download(url: str, destination: Path) -> None:
    """Download one public indicator source."""
    request = urllib.request.Request(url, headers={"User-Agent": f"DroidCustos/{__version__} (h3st4k3r)"})
    destination.parent.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(request, timeout=90) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def _safe_name(value: str) -> str:
    """Normalize an indicator source name for local storage."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("._") or "source"


def update_index(repository_dir: Path, command_log: Path | None = None) -> None:
    """Clone or fast-forward the official MVT indicator index."""
    if (repository_dir / ".git").is_dir():
        result = run_capture(["git", "-C", str(repository_dir), "pull", "--ff-only"], timeout=180, command_log=command_log)
    else:
        repository_dir.parent.mkdir(parents=True, exist_ok=True)
        result = run_capture(["git", "clone", "--depth", "1", INDEX_REPOSITORY, str(repository_dir)], timeout=300, command_log=command_log)
    if not result.ok:
        raise RuntimeError(f"Unable to update mvt-indicators: {result.stderr.strip()}")


def repository_commit(repository_dir: Path, command_log: Path | None = None) -> str:
    """Return the exact Git commit used for the indicator index."""
    result = run_capture(["git", "-C", str(repository_dir), "rev-parse", "HEAD"], timeout=30, command_log=command_log)
    return result.stdout.strip() if result.ok else ""


def _custom_entries(custom_sources: Path | None) -> list[dict[str, object]]:
    """Load optional operator-maintained STIX source definitions."""
    if not custom_sources or not custom_sources.is_file():
        return []
    payload = yaml.safe_load(custom_sources.read_text(encoding="utf-8")) or {}
    entries = payload.get("sources", [])
    return [entry for entry in entries if isinstance(entry, dict)]


def download_all_stix(repository_dir: Path, output_dir: Path, custom_sources: Path | None = None) -> dict[str, object]:
    """Download and validate every indexed and custom STIX source."""
    index_file = repository_dir / "indicators.yaml"
    if not index_file.is_file():
        raise RuntimeError(f"Missing indicator index: {index_file}")
    parsed = yaml.safe_load(index_file.read_text(encoding="utf-8")) or {}
    entries = list(parsed.get("indicators", []))
    entries.extend(_custom_entries(custom_sources))
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "author": "h3st4k3r",
        "index_repository": INDEX_REPOSITORY,
        "index_commit": repository_commit(repository_dir),
        "sources": [],
        "errors": [],
    }

    for entry in entries:
        name = str(entry.get("name", "unnamed-source"))
        github = entry.get("github") or {}
        url = entry.get("url")
        if github:
            owner = github.get("owner")
            repo = github.get("repo")
            branch = github.get("branch", "main")
            path = github.get("path")
            if all((owner, repo, branch, path)):
                url = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/{path}"
        if not url:
            manifest["errors"].append({"name": name, "error": "Unsupported or incomplete source"})
            continue
        destination = output_dir / f"{_safe_name(name)}.stix2"
        try:
            _download(str(url), destination)
            raw = destination.read_bytes()
            payload = json.loads(raw)
            if payload.get("type") != "bundle" and "objects" not in payload:
                raise ValueError("The source is not a STIX bundle")
            manifest["sources"].append(
                {
                    "name": name,
                    "providers": entry.get("sources", entry.get("providers", [])),
                    "url": str(url),
                    "path": str(destination),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                    "size": len(raw),
                    "references": entry.get("references", []),
                }
            )
        except Exception as exc:
            destination.unlink(missing_ok=True)
            manifest["errors"].append({"name": name, "url": str(url), "error": str(exc)})

    known_hashes = {str(item["sha256"]) for item in manifest["sources"]}
    for source in repository_dir.rglob("*.stix2"):
        raw = source.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest in known_hashes:
            continue
        destination = output_dir / f"repository_{_safe_name(str(source.relative_to(repository_dir)))}.stix2"
        shutil.copy2(source, destination)
        manifest["sources"].append(
            {
                "name": str(source.relative_to(repository_dir)),
                "providers": ["mvt-project community repository"],
                "url": f"local:{source}",
                "path": str(destination),
                "sha256": digest,
                "size": len(raw),
                "references": [],
            }
        )
        known_hashes.add(digest)

    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    build_ioc_database(stix_files(output_dir), output_dir / "ioc.db", manifest)
    return manifest


def update_mvt_native(command_log: Path | None = None) -> bool:
    """Update MVT's native public indicator store."""
    result = run_capture(["mvt-android", "download-iocs"], timeout=300, command_log=command_log)
    return result.ok


def stix_files(output_dir: Path) -> list[Path]:
    """List valid local STIX source files."""
    return sorted(path for path in output_dir.glob("*.stix2") if path.is_file())


def _normalized_type(object_type: str, field: str) -> str:
    """Map STIX object fields to operational observable types."""
    return normalize_type(object_type, field)


def parse_stix_pattern(pattern: str) -> list[tuple[str, str, str]]:
    """Extract equality observables from compound STIX patterns."""
    atoms: list[tuple[str, str, str]] = []
    for match in _ATOM_RE.finditer(pattern):
        literal = match.group("quote") + match.group("value") + match.group("quote")
        value = str(ast.literal_eval(literal))
        atoms.append((match.group("object"), match.group("field"), value))
    return atoms


def _source_map(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    """Index manifest source metadata by local filename."""
    mapping: dict[str, dict[str, object]] = {}
    for source in manifest.get("sources", []):
        path = Path(str(source.get("path", "")))
        mapping[path.name] = source
    return mapping


def iter_indicator_records(paths: Iterable[Path], manifest: dict[str, object] | None = None) -> Iterable[IndicatorRecord]:
    """Yield normalized indicators with source and validity metadata."""
    sources = _source_map(manifest or {})
    for path in paths:
        try:
            bundle = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        source = sources.get(path.name, {})
        source_name = str(source.get("name", path.name))
        source_url = str(source.get("url", ""))
        for obj in bundle.get("objects", []):
            if obj.get("type") != "indicator":
                continue
            pattern = str(obj.get("pattern", ""))
            for object_type, field, value in parse_stix_pattern(pattern):
                yield IndicatorRecord(
                    stix_id=str(obj.get("id", "")),
                    object_type=object_type,
                    field=field,
                    value=value,
                    normalized_type=_normalized_type(object_type, field),
                    source_name=source_name,
                    source_url=source_url,
                    confidence=int(obj.get("confidence", 50) or 50),
                    valid_from=obj.get("valid_from"),
                    valid_until=obj.get("valid_until"),
                    revoked=bool(obj.get("revoked", False)),
                    labels=[str(item) for item in obj.get("labels", [])],
                    name=str(obj.get("name", "")),
                    description=str(obj.get("description", "")),
                    pattern=pattern,
                )


def build_ioc_database(paths: Iterable[Path], database: Path, manifest: dict[str, object] | None = None) -> Path:
    """Build a normalized SQLite IOC database from STIX bundles."""
    database.parent.mkdir(parents=True, exist_ok=True)
    database.unlink(missing_ok=True)
    connection = sqlite3.connect(database)
    try:
        connection.executescript(
            """
            PRAGMA journal_mode=DELETE;
            CREATE TABLE sources (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                url TEXT NOT NULL,
                sha256 TEXT,
                providers TEXT,
                UNIQUE(name, url)
            );
            CREATE TABLE indicators (
                id INTEGER PRIMARY KEY,
                stix_id TEXT,
                object_type TEXT NOT NULL,
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                normalized_type TEXT NOT NULL,
                source_id INTEGER,
                confidence INTEGER NOT NULL,
                valid_from TEXT,
                valid_until TEXT,
                revoked INTEGER NOT NULL,
                labels TEXT,
                name TEXT,
                description TEXT,
                pattern TEXT,
                UNIQUE(normalized_type, value, stix_id, source_id),
                FOREIGN KEY(source_id) REFERENCES sources(id)
            );
            CREATE TABLE entities (
                stix_id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT,
                description TEXT
            );
            CREATE TABLE relationships (
                stix_id TEXT PRIMARY KEY,
                source_ref TEXT,
                target_ref TEXT,
                relationship_type TEXT,
                description TEXT
            );
            CREATE TABLE update_history (
                generated_at TEXT,
                index_commit TEXT,
                source_count INTEGER,
                indicator_count INTEGER
            );
            CREATE INDEX idx_indicator_lookup ON indicators(normalized_type, value);
            """
        )
        source_ids: dict[tuple[str, str], int] = {}
        for source in (manifest or {}).get("sources", []):
            key = (str(source.get("name", "")), str(source.get("url", "")))
            cursor = connection.execute(
                "INSERT OR IGNORE INTO sources(name, url, sha256, providers) VALUES (?, ?, ?, ?)",
                (key[0], key[1], source.get("sha256"), json.dumps(source.get("providers", []))),
            )
            source_id = cursor.lastrowid or connection.execute("SELECT id FROM sources WHERE name=? AND url=?", key).fetchone()[0]
            source_ids[key] = int(source_id)

        records = list(iter_indicator_records(paths, manifest))
        for record in records:
            source_id = source_ids.get((record.source_name, record.source_url))
            connection.execute(
                """
                INSERT OR IGNORE INTO indicators(
                    stix_id, object_type, field, value, normalized_type, source_id, confidence,
                    valid_from, valid_until, revoked, labels, name, description, pattern
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    record.stix_id,
                    record.object_type,
                    record.field,
                    record.value,
                    record.normalized_type,
                    source_id,
                    record.confidence,
                    record.valid_from,
                    record.valid_until,
                    int(record.revoked),
                    json.dumps(record.labels),
                    record.name,
                    record.description,
                    record.pattern,
                ),
            )

        for path in paths:
            try:
                bundle = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            for obj in bundle.get("objects", []):
                object_type = str(obj.get("type", ""))
                stix_id = str(obj.get("id", ""))
                if object_type in {"malware", "campaign", "threat-actor", "tool", "infrastructure", "identity"}:
                    connection.execute(
                        "INSERT OR REPLACE INTO entities(stix_id, type, name, description) VALUES (?, ?, ?, ?)",
                        (stix_id, object_type, obj.get("name", ""), obj.get("description", "")),
                    )
                if object_type == "relationship":
                    connection.execute(
                        "INSERT OR REPLACE INTO relationships(stix_id, source_ref, target_ref, relationship_type, description) VALUES (?, ?, ?, ?, ?)",
                        (stix_id, obj.get("source_ref"), obj.get("target_ref"), obj.get("relationship_type"), obj.get("description", "")),
                    )
        connection.execute(
            "INSERT INTO update_history VALUES (?, ?, ?, ?)",
            (
                (manifest or {}).get("generated_at", datetime.now(timezone.utc).isoformat()),
                (manifest or {}).get("index_commit", ""),
                len((manifest or {}).get("sources", [])),
                len(records),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    return database


def _is_active(valid_from: str | None, valid_until: str | None, revoked: bool, now: datetime | None = None) -> bool:
    """Evaluate whether an indicator remains operationally active."""
    return is_active(valid_from, valid_until, revoked, now)


def extract_simple_indicators(paths: Iterable[Path]) -> dict[str, set[str]]:
    """Return compatibility sets for existing analyzers."""
    values: dict[str, set[str]] = {}
    for record in iter_indicator_records(paths):
        if not _is_active(record.valid_from, record.valid_until, record.revoked):
            continue
        key = f"{record.object_type}:{record.field}"
        values.setdefault(key, set()).add(record.value)
    return values


def load_ioc_lookup(database: Path) -> dict[str, set[str]]:
    """Load active operational IOC values from SQLite."""
    lookup: dict[str, set[str]] = {}
    if not database.is_file():
        return lookup
    connection = sqlite3.connect(database)
    try:
        rows = connection.execute(
            "SELECT normalized_type, value, valid_from, valid_until, revoked FROM indicators"
        ).fetchall()
        for indicator_type, value, valid_from, valid_until, revoked in rows:
            if _is_active(valid_from, valid_until, bool(revoked)):
                lookup.setdefault(str(indicator_type), set()).add(str(value))
    finally:
        connection.close()
    return lookup
