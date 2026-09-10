"""Shared STIX expression parsing, normalization and matching."""

from __future__ import annotations

import ast
import ipaddress
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Mapping
from urllib.parse import urlsplit, urlunsplit


_ATOM_RE = re.compile(
    r"(?P<object>[A-Za-z0-9_-]+):(?P<field>[A-Za-z0-9_.\-'\[\]]+)\s*=\s*"
    r"(?P<value>'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")",
    re.IGNORECASE,
)
_OPERATOR_RE = re.compile(r"(?:AND|OR)\b", re.IGNORECASE)


@dataclass(frozen=True)
class Observable:
    """Represent one normalized evidence observable."""

    normalized_type: str
    value: str
    object_type: str = ""
    field: str = ""


@dataclass(frozen=True)
class Atom:
    """Represent one equality atom in a STIX expression."""

    observable: Observable


@dataclass(frozen=True)
class Logic:
    """Represent a boolean composition of STIX expression nodes."""

    operator: str
    left: object
    right: object


@dataclass(frozen=True)
class Unsupported:
    """Represent a STIX pattern that the matcher deliberately cannot evaluate."""

    reason: str


@dataclass(frozen=True)
class IOCExpression:
    """Represent one complete STIX indicator expression and its metadata."""

    stix_id: str
    pattern: str
    source_name: str
    source_url: str
    confidence: int
    valid_from: str | None
    valid_until: str | None
    revoked: bool
    labels: tuple[str, ...]
    name: str
    description: str
    node: object
    observables: tuple[Observable, ...]
    unsupported_reason: str | None = None


class PatternSyntaxError(ValueError):
    """Report a STIX pattern that cannot be parsed by the safe subset."""


def normalize_type(object_type: str, field: str) -> str:
    """Map a STIX object path to a stable operational observable type."""
    key = f"{object_type}:{field}".lower().replace("'", "")
    if key.startswith("domain-name:value"):
        return "domain"
    if key.startswith("ipv4-addr:value"):
        return "ipv4"
    if key.startswith("ipv6-addr:value"):
        return "ipv6"
    if key.startswith("url:value"):
        return "url"
    if key.startswith("file:hashes") and "sha-256" in key:
        return "sha256"
    if key.startswith("x509-certificate:hashes") and "sha-256" in key:
        return "certificate-sha256"
    if key.startswith("android-app:package") or key.startswith("software:name"):
        return "package"
    if key.startswith("file:name"):
        return "filename"
    if key.startswith("process:name"):
        return "process"
    return key


def normalize_value(normalized_type: str, value: object) -> str:
    """Normalize an observable value without changing its semantic type."""
    raw = str(value or "").strip()
    if normalized_type in {"domain", "package", "filename", "process"}:
        return raw.lower().rstrip(".") if normalized_type == "domain" else raw.lower()
    if normalized_type in {"sha256", "certificate-sha256"}:
        return raw.lower()
    if normalized_type in {"ipv4", "ipv6"}:
        try:
            return str(ipaddress.ip_address(raw))
        except ValueError:
            return raw.lower()
    if normalized_type == "url":
        cleaned = raw.rstrip(".,;:)]}")
        try:
            parsed = urlsplit(cleaned)
            if parsed.scheme and parsed.netloc:
                hostname = (parsed.hostname or "").lower()
                port = parsed.port
                netloc = hostname if port is None else f"{hostname}:{port}"
                if parsed.username or parsed.password:
                    netloc = parsed.netloc.lower()
                return urlunsplit((parsed.scheme.lower(), netloc, parsed.path, parsed.query, parsed.fragment))
        except ValueError:
            pass
        return cleaned
    return raw


def make_observable(object_type: str, field: str, value: object) -> Observable:
    """Create a normalized observable from a STIX object path."""
    normalized_type = normalize_type(object_type, field)
    return Observable(normalized_type, normalize_value(normalized_type, value), object_type, field)


def _tokenize(pattern: str) -> list[tuple[str, object]]:
    """Tokenize the supported STIX equality and boolean syntax."""
    tokens: list[tuple[str, object]] = []
    position = 0
    while position < len(pattern):
        if pattern[position].isspace() or pattern[position] in "[]":
            position += 1
            continue
        if pattern[position] == "(":
            tokens.append(("LPAREN", pattern[position]))
            position += 1
            continue
        if pattern[position] == ")":
            tokens.append(("RPAREN", pattern[position]))
            position += 1
            continue
        operator = _OPERATOR_RE.match(pattern, position)
        if operator:
            tokens.append((operator.group(0).upper(), operator.group(0).upper()))
            position = operator.end()
            continue
        atom = _ATOM_RE.match(pattern, position)
        if atom:
            try:
                value = ast.literal_eval(atom.group("value"))
            except (SyntaxError, ValueError) as exc:
                raise PatternSyntaxError("Invalid STIX string literal") from exc
            tokens.append(("ATOM", make_observable(atom.group("object"), atom.group("field"), value)))
            position = atom.end()
            continue
        raise PatternSyntaxError(f"Unsupported STIX syntax near: {pattern[position:position + 32]}")
    return tokens


class _PatternParser:
    """Parse boolean STIX tokens with AND precedence over OR."""

    def __init__(self, tokens: list[tuple[str, object]]) -> None:
        """Initialize the parser state."""
        self.tokens = tokens
        self.position = 0

    def _accept(self, token_type: str) -> object | None:
        """Consume one token when it has the requested type."""
        if self.position < len(self.tokens) and self.tokens[self.position][0] == token_type:
            value = self.tokens[self.position][1]
            self.position += 1
            return value
        return None

    def parse(self) -> object:
        """Parse the complete token stream."""
        result = self._parse_or()
        if self.position != len(self.tokens):
            raise PatternSyntaxError("Unexpected token at the end of STIX pattern")
        return result

    def _parse_or(self) -> object:
        """Parse OR expressions."""
        result = self._parse_and()
        while self._accept("OR") is not None:
            result = Logic("OR", result, self._parse_and())
        return result

    def _parse_and(self) -> object:
        """Parse AND expressions."""
        result = self._parse_primary()
        while self._accept("AND") is not None:
            result = Logic("AND", result, self._parse_primary())
        return result

    def _parse_primary(self) -> object:
        """Parse one atom or parenthesized expression."""
        atom = self._accept("ATOM")
        if atom is not None:
            return Atom(atom)
        if self._accept("LPAREN") is not None:
            result = self._parse_or()
            if self._accept("RPAREN") is None:
                raise PatternSyntaxError("Unclosed STIX expression group")
            return result
        raise PatternSyntaxError("Expected a STIX equality atom")


def _tree_observables(node: object) -> list[Observable]:
    """Collect atoms from a parsed STIX expression tree."""
    if isinstance(node, Atom):
        return [node.observable]
    if isinstance(node, Logic):
        return _tree_observables(node.left) + _tree_observables(node.right)
    return []


def parse_stix_expression(pattern: str) -> tuple[object, tuple[Observable, ...], str | None]:
    """Parse a complete STIX pattern and identify unsupported syntax."""
    try:
        node = _PatternParser(_tokenize(str(pattern or ""))).parse()
    except PatternSyntaxError as exc:
        return Unsupported(str(exc)), (), str(exc)
    return node, tuple(_tree_observables(node)), None


def is_active(
    valid_from: str | None,
    valid_until: str | None,
    revoked: bool,
    now: datetime | None = None,
) -> bool:
    """Return whether a STIX indicator is valid at the requested instant."""
    if revoked:
        return False
    current = now or datetime.now(timezone.utc)
    for raw, lower_bound in ((valid_from, True), (valid_until, False)):
        if not raw:
            continue
        try:
            timestamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        except ValueError:
            continue
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if lower_bound and current < timestamp:
            return False
        if not lower_bound and current > timestamp:
            return False
    return True


def _source_metadata(manifest: Mapping[str, object] | None) -> dict[str, dict[str, object]]:
    """Index source metadata by local STIX filename."""
    result: dict[str, dict[str, object]] = {}
    for item in (manifest or {}).get("sources", []):
        if isinstance(item, Mapping):
            result[Path(str(item.get("path", ""))).name] = dict(item)
    return result


def load_stix_expressions(paths: Iterable[Path], manifest: Mapping[str, object] | None = None) -> list[IOCExpression]:
    """Load complete indicator expressions from STIX bundles."""
    from .indicators import iter_indicator_records

    sources = _source_metadata(manifest)
    grouped: dict[tuple[str, str, str, str], IOCExpression] = {}
    for record in iter_indicator_records(paths, manifest):
        key = (record.stix_id, record.pattern, record.source_name, record.source_url)
        if key in grouped:
            continue
        node, observables, unsupported = parse_stix_expression(record.pattern)
        grouped[key] = IOCExpression(
            stix_id=record.stix_id,
            pattern=record.pattern,
            source_name=record.source_name or str(sources.get(record.source_name, {}).get("name", "")),
            source_url=record.source_url,
            confidence=record.confidence,
            valid_from=record.valid_from,
            valid_until=record.valid_until,
            revoked=record.revoked,
            labels=tuple(record.labels),
            name=record.name,
            description=record.description,
            node=node,
            observables=observables,
            unsupported_reason=unsupported,
        )
    return list(grouped.values())


def _available_observables(evidence: Mapping[str, Iterable[object]] | Iterable[Observable]) -> list[Observable]:
    """Normalize evidence supplied by an analyzer."""
    if isinstance(evidence, Mapping):
        values: list[Observable] = []
        for raw_type, raw_values in evidence.items():
            normalized_type = normalize_type(*raw_type.split(":", 1)) if ":" in raw_type else raw_type.lower()
            candidates = [raw_values] if isinstance(raw_values, (str, bytes)) else raw_values
            for value in candidates:
                values.append(Observable(normalized_type, normalize_value(normalized_type, value)))
        return values
    return [item if isinstance(item, Observable) else Observable("unknown", str(item)) for item in evidence]


def _value_matches(expected: Observable, candidate: Observable) -> bool:
    """Compare one expression atom with one normalized evidence value."""
    if expected.normalized_type != candidate.normalized_type:
        return False
    if expected.normalized_type == "domain":
        return candidate.value == expected.value or candidate.value.endswith("." + expected.value)
    return candidate.value == expected.value


def _evaluate(node: object, available: list[Observable]) -> tuple[bool, list[Observable]]:
    """Evaluate a parsed expression and return the evidence used by the match."""
    if isinstance(node, Atom):
        for candidate in available:
            if _value_matches(node.observable, candidate):
                return True, [candidate]
        return False, []
    if isinstance(node, Logic):
        left_ok, left_matches = _evaluate(node.left, available)
        right_ok, right_matches = _evaluate(node.right, available)
        if node.operator == "AND":
            return left_ok and right_ok, left_matches + right_matches if left_ok and right_ok else []
        return (True, left_matches) if left_ok else (True, right_matches) if right_ok else (False, [])
    return False, []


def match_expressions(
    evidence: Mapping[str, Iterable[object]] | Iterable[Observable],
    expressions: Iterable[IOCExpression],
    *,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Return active complete-expression matches for one evidence scope."""
    available = _available_observables(evidence)
    matches: list[dict[str, object]] = []
    for expression in expressions:
        if expression.unsupported_reason or not expression.observables:
            continue
        if not is_active(expression.valid_from, expression.valid_until, expression.revoked, now):
            continue
        matched, used = _evaluate(expression.node, available)
        if not matched:
            continue
        matches.append(
            {
                "stix_id": expression.stix_id,
                "pattern": expression.pattern,
                "name": expression.name,
                "source": expression.source_name,
                "source_url": expression.source_url,
                "confidence": expression.confidence,
                "labels": list(expression.labels),
                "matched_observables": [
                    {"type": item.normalized_type, "value": item.value} for item in used
                ],
            }
        )
    return matches


def match_stix_files(
    evidence: Mapping[str, Iterable[object]] | Iterable[Observable],
    paths: Iterable[Path],
    manifest: Mapping[str, object] | None = None,
    *,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Match evidence against complete expressions loaded from STIX files."""
    return match_expressions(evidence, load_stix_expressions(paths, manifest), now=now)


def load_database_expressions(database: Path) -> list[IOCExpression]:
    """Load complete expressions from the normalized IOC database."""
    if not database.is_file():
        return []
    connection = sqlite3.connect(database)
    connection.row_factory = sqlite3.Row
    expressions: list[IOCExpression] = []
    try:
        rows = connection.execute(
            """
            SELECT stix_id, pattern, confidence, valid_from, valid_until, revoked,
                   labels, name, description, sources.name AS source_name, sources.url AS source_url
            FROM indicators
            LEFT JOIN sources ON sources.id = indicators.source_id
            GROUP BY stix_id, pattern, source_id
            """
        ).fetchall()
        for row in rows:
            node, observables, unsupported = parse_stix_expression(row["pattern"] or "")
            try:
                labels = tuple(json.loads(row["labels"] or "[]"))
            except (TypeError, json.JSONDecodeError):
                labels = ()
            expressions.append(
                IOCExpression(
                    stix_id=str(row["stix_id"] or ""),
                    pattern=str(row["pattern"] or ""),
                    source_name=str(row["source_name"] or ""),
                    source_url=str(row["source_url"] or ""),
                    confidence=int(row["confidence"] or 0),
                    valid_from=row["valid_from"],
                    valid_until=row["valid_until"],
                    revoked=bool(row["revoked"]),
                    labels=labels,
                    name=str(row["name"] or ""),
                    description=str(row["description"] or ""),
                    node=node,
                    observables=observables,
                    unsupported_reason=unsupported,
                )
            )
    finally:
        connection.close()
    return expressions


def match_database(
    evidence: Mapping[str, Iterable[object]] | Iterable[Observable],
    database: Path,
    *,
    now: datetime | None = None,
) -> list[dict[str, object]]:
    """Match evidence against complete expressions stored in SQLite."""
    return match_expressions(evidence, load_database_expressions(database), now=now)
