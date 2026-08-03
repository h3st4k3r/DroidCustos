"""JSON, Markdown, CSV and offline HTML report generation.

Author: h3st4k3r
"""

from __future__ import annotations

import csv
import html
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .aleapp import AleappSummary
from .analysis import MvtSummary
from .console import BANNER
from .coverage import CoverageReport
from .extended_analysis import ExtendedAnalysisSummary
from .heuristics import Finding
from .profiles import AcquisitionProfile
from .scoring import Verdict


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "warning": 3, "low": 4, "informational": 5}
SYSTEM_PREFIXES = ("/system/", "/product/", "/vendor/", "/apex/", "/system_ext/", "/odm/")


def _profile_payload(profile: AcquisitionProfile | dict[str, object]) -> dict[str, object]:
    """Normalize profile data for reports."""
    return profile.to_dict() if isinstance(profile, AcquisitionProfile) else profile


def _compact(value: object, limit: int = 240) -> str:
    """Render a compact value suitable for tabular reports."""
    if value in (None, "", [], {}):
        return ""
    if isinstance(value, (dict, list, tuple, set)):
        text = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    else:
        text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _write_csv(path: Path, headers: list[str], rows: list[list[object]]) -> Path:
    """Write one report table as UTF-8 CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(headers)
        writer.writerows(rows)
    return path


def _markdown_escape(value: object) -> str:
    """Escape one Markdown table cell."""
    return _compact(value, 500).replace("|", "\\|").replace("\n", "<br>")


def _markdown_table(headers: list[str], rows: list[list[object]], maximum: int | None = None) -> list[str]:
    """Render a Markdown table with an optional row limit."""
    visible = rows[:maximum] if maximum is not None else rows
    output = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    if not visible:
        output.append("| " + " | ".join(["None"] + [""] * (len(headers) - 1)) + " |")
    else:
        output.extend("| " + " | ".join(_markdown_escape(value) for value in row) + " |" for row in visible)
    if maximum is not None and len(rows) > maximum:
        output.extend(["", f"_Showing {maximum} of {len(rows)} rows. See the corresponding CSV table for the complete dataset._"])
    return output


def _html_data_table(
    headers: list[str],
    rows: list[list[object]],
    table_id: str,
    *,
    searchable: bool = True,
    collapsed: bool = False,
    title: str = "",
) -> str:
    """Render a searchable offline HTML data table."""
    head = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body_rows: list[str] = []
    for row in rows:
        cells = []
        for index, value in enumerate(row):
            text = _compact(value, 4000)
            class_name = ""
            if index == 0 and text.lower() in SEVERITY_ORDER:
                class_name = f" class='sev-{html.escape(text.lower())}'"
            cells.append(f"<td{class_name}>{html.escape(text)}</td>")
        body_rows.append("<tr>" + "".join(cells) + "</tr>")
    body = "".join(body_rows) or f"<tr><td colspan='{len(headers)}'>No records.</td></tr>"
    search = (
        f"<input class='table-search' type='search' placeholder='Filter table…' "
        f"oninput=\"filterTable('{table_id}', this.value)\">"
        if searchable
        else ""
    )
    table = f"{search}<div class='table-wrap'><table id='{table_id}'><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>"
    if collapsed:
        return f"<details><summary>{html.escape(title)} · {len(rows)} rows</summary>{table}</details>"
    return table


def _finding_classification(finding: Finding) -> str:
    """Classify a finding without conflating heuristics and IOC matches."""
    if finding.category == "ioc":
        return "CONFIRMED IOC"
    if finding.severity in {"critical", "high"}:
        return "HIGH-PRIORITY REVIEW"
    if finding.severity == "medium":
        return "REVIEW"
    return "INFORMATIONAL"


def _finding_rows(findings: list[Finding]) -> list[list[object]]:
    """Build sorted rows for built-in heuristic findings."""
    ordered = sorted(findings, key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.category, item.title, item.evidence))
    return [
        [item.severity.upper(), _finding_classification(item), item.category, item.title, item.evidence, item.score]
        for item in ordered
    ]


def _indicator_value(indicator: object) -> str:
    """Extract a concise value from an IOC object."""
    if isinstance(indicator, dict):
        for key in ("value", "indicator", "observable", "pattern"):
            if indicator.get(key):
                return _compact(indicator.get(key), 500)
        return _compact(indicator, 500)
    return _compact(indicator, 500)


def _ioc_rows(
    mvt: MvtSummary,
    extended: ExtendedAnalysisSummary,
    findings: list[Finding],
) -> list[list[object]]:
    """Build a deduplicated table of confirmed IOC evidence only."""
    rows: dict[tuple[str, str, str], list[object]] = {}
    for indicator in mvt.matched_indicators:
        indicator_type = _compact(indicator.get("type", "unknown")) if isinstance(indicator, dict) else "unknown"
        value = _indicator_value(indicator)
        name = _compact(indicator.get("name", "")) if isinstance(indicator, dict) else ""
        source = _compact(indicator.get("stix2_file_name") or indicator.get("source", "")) if isinstance(indicator, dict) else ""
        rows[("MVT", indicator_type, value)] = ["MVT", indicator_type, value, name, source]
    for match in extended.ioc_matches:
        indicator_type = _compact(match.get("type") or match.get("indicator_type") or "unknown")
        value = _compact(match.get("value") or match.get("indicator") or match.get("observable") or "")
        name = _compact(match.get("name") or match.get("indicator_name") or "")
        source = _compact(match.get("source") or match.get("stix2_file_name") or "")
        rows[("Extended analysis", indicator_type, value)] = ["Extended analysis", indicator_type, value, name, source]
    for finding in findings:
        if finding.category != "ioc":
            continue
        rows[("DroidCustos", finding.title, finding.evidence)] = ["DroidCustos", finding.title, finding.evidence, "", "Normalized STIX database"]
    return sorted(rows.values(), key=lambda row: (str(row[0]), str(row[1]), str(row[2])))


def _mvt_alert_rows(mvt: MvtSummary) -> list[list[object]]:
    """Build human-readable rows from deduplicated MVT alerts."""
    rows: list[list[object]] = []
    for alert in mvt.alerts:
        indicator = _indicator_value(alert.get("matched_indicator"))
        rows.append(
            [
                str(alert.get("level", "INFORMATIONAL")),
                str(alert.get("classification", "HEURISTIC")),
                str(alert.get("module", "unknown")),
                int(alert.get("occurrences", 1)),
                str(alert.get("message", "")),
                indicator,
            ]
        )
    return rows


def _coverage_rows(coverage: CoverageReport) -> list[list[object]]:
    """Build collector-level coverage rows."""
    rows = [
        [item.get("collector", ""), item.get("status", ""), _compact(item.get("detail"), 400)]
        for item in coverage.statuses
    ]
    return sorted(rows, key=lambda row: (str(row[1]), str(row[0])))


def _package_class(record: dict[str, object]) -> str:
    """Classify a package as system or third party."""
    path = str(record.get("source_path", ""))
    flags = {str(value).upper() for value in record.get("flags", [])}
    return "System" if path.startswith(SYSTEM_PREFIXES) or "SYSTEM" in flags else "Third party"


def _package_rows(package_inventory: dict[str, object]) -> list[list[object]]:
    """Build detailed package inventory rows."""
    rows: list[list[object]] = []
    for record in package_inventory.get("records", []):
        permissions = [str(value) for value in record.get("requested_permissions", [])]
        rows.append(
            [
                record.get("package", ""),
                record.get("user_id", ""),
                record.get("uid", ""),
                record.get("version_name") or record.get("version_code", ""),
                record.get("installer", ""),
                _package_class(record),
                len(permissions),
                len(record.get("signing_certificates_sha256", [])),
                record.get("source_path", ""),
            ]
        )
    return sorted(rows, key=lambda row: (str(row[0]), str(row[1])))


def _package_summary_rows(package_inventory: dict[str, object]) -> list[list[object]]:
    """Build concise package inventory statistics."""
    records = list(package_inventory.get("records", []))
    classes = Counter(_package_class(record) for record in records)
    shell_or_unknown = sum(1 for record in records if str(record.get("installer", "")) in {"", "null", "com.android.shell"})
    with_certificates = sum(1 for record in records if record.get("signing_certificates_sha256"))
    with_local_apks = sum(1 for record in records if record.get("local_apks"))
    return [
        ["Package records", package_inventory.get("package_count", len(records))],
        ["Unique package identifiers", package_inventory.get("unique_package_count", len({str(record.get('package', '')) for record in records}))],
        ["Users represented", len({str(record.get("user_id", "")) for record in records})],
        ["System package records", classes.get("System", 0)],
        ["Third-party package records", classes.get("Third party", 0)],
        ["Shell or unknown installer records", shell_or_unknown],
        ["Records with signing certificate data", with_certificates],
        ["Records with locally acquired APKs", with_local_apks],
    ]


def _engine_rows(
    acquisition: dict[str, object],
    mvt: MvtSummary,
    aleapp: AleappSummary,
    findings: list[Finding],
    extended: ExtendedAnalysisSummary,
    timeline: dict[str, object],
    ioc_manifest: dict[str, object],
) -> list[list[object]]:
    """Build an analysis-engine status table."""
    return [
        ["AndroidQF", "Complete" if acquisition.get("complete") else "Incomplete", _compact(acquisition.get("returncode"))],
        ["MVT AndroidQF", f"{mvt.androidqf_successes} successful / {mvt.androidqf_failures} failed", ""],
        ["MVT bugreport", f"{mvt.bugreport_successes} successful / {mvt.bugreport_failures} failed", ""],
        ["MVT confirmed IOC", mvt.confirmed_ioc_matches, "Non-null matched_indicator only"],
        ["MVT heuristic alerts", mvt.heuristic_records, f"{mvt.unique_alert_records} unique grouped alerts"],
        ["DroidCustos heuristics", len(findings), f"{sum(1 for item in findings if item.category == 'ioc')} confirmed IOC findings"],
        ["Extended analysis", "Enabled" if extended.enabled else "Disabled", f"{len(extended.ioc_matches)} IOC matches"],
        ["ALEAPP", "Executed" if aleapp.executed else "Not executed", aleapp.error or f"{aleapp.parsed_rows} parsed rows"],
        ["Unified timeline", timeline.get("event_count", 0), f"{timeline.get('ioc_matched_events', 0)} IOC-matched events"],
        ["IOC intelligence", len(ioc_manifest.get("sources", [])), f"{len(ioc_manifest.get('errors', []))} source errors"],
    ]


def _artifact_rows(
    capabilities: dict[str, object],
    extended: ExtendedAnalysisSummary,
    package_inventory: dict[str, object],
    timeline: dict[str, object],
    integrity: dict[str, object],
) -> list[list[object]]:
    """Build a high-level inventory of acquired and parsed data."""
    return [
        ["Visible Android users/profiles", len(capabilities.get("users", [])), "Capability discovery"],
        ["Storage roots", len(capabilities.get("storage_roots", [])), "Capability discovery"],
        ["Package records", package_inventory.get("package_count", 0), "ADB package manager"],
        ["Unique packages", package_inventory.get("unique_package_count", 0), "Normalized package inventory"],
        ["Browser databases", extended.browser_databases, "Extended analysis"],
        ["Browser records", extended.browser_records, "Extended analysis"],
        ["Chat databases", extended.chat_databases, "Extended analysis"],
        ["Chat records", extended.chat_records, "Extended analysis"],
        ["SMS records", extended.sms_records, "Extended analysis"],
        ["Connection artifacts", extended.connection_artifacts, "Extended analysis"],
        ["Unique network observables", extended.unique_network_observables, "Extended analysis"],
        ["User file hashes", extended.user_file_hashes, "Extended analysis"],
        ["Image hashes", extended.image_hashes, "Extended analysis"],
        ["Document hashes", extended.document_hashes, "Extended analysis"],
        ["Timeline events", timeline.get("event_count", 0), "Unified timeline"],
        ["Evidence files verified", integrity.get("checked", 0), "SHA-256 manifest"],
    ]


def _principal_rows(findings: list[Finding], mvt: MvtSummary) -> list[list[object]]:
    """Build the prioritized analyst review queue."""
    rows = _finding_rows(findings)
    for alert in mvt.alerts:
        level = str(alert.get("level", "INFORMATIONAL")).lower()
        if alert.get("classification") == "CONFIRMED_IOC" or level in {"critical", "high", "medium"}:
            rows.append(
                [
                    level.upper(),
                    "CONFIRMED IOC" if alert.get("classification") == "CONFIRMED_IOC" else "MVT HEURISTIC",
                    f"mvt:{alert.get('module', 'unknown')}",
                    str(alert.get("message", "")),
                    f"Occurrences: {alert.get('occurrences', 1)}",
                    100 if alert.get("classification") == "CONFIRMED_IOC" else 0,
                ]
            )
    return sorted(rows, key=lambda row: (SEVERITY_ORDER.get(str(row[0]).lower(), 9), str(row[1]), str(row[2]), str(row[3])))


def _report_tables(
    tables_dir: Path,
    *,
    acquisition: dict[str, object],
    capabilities: dict[str, object],
    mvt: MvtSummary,
    extended: ExtendedAnalysisSummary,
    findings: list[Finding],
    coverage: CoverageReport,
    package_inventory: dict[str, object],
    aleapp: AleappSummary,
    timeline: dict[str, object],
    integrity: dict[str, object],
    ioc_manifest: dict[str, object],
) -> dict[str, object]:
    """Generate normalized report tables and their CSV files."""
    findings_rows = _finding_rows(findings)
    ioc_rows = _ioc_rows(mvt, extended, findings)
    mvt_rows = _mvt_alert_rows(mvt)
    coverage_rows = _coverage_rows(coverage)
    packages_rows = _package_rows(package_inventory)
    package_summary = _package_summary_rows(package_inventory)
    engine_rows = _engine_rows(acquisition, mvt, aleapp, findings, extended, timeline, ioc_manifest)
    artifact_rows = _artifact_rows(capabilities, extended, package_inventory, timeline, integrity)
    principal_rows = _principal_rows(findings, mvt)
    definitions = {
        "principal_findings": (["Severity", "Classification", "Category/Module", "Finding", "Evidence", "Score"], principal_rows),
        "findings": (["Severity", "Classification", "Category", "Finding", "Evidence", "Score"], findings_rows),
        "confirmed_ioc_matches": (["Engine", "Indicator type", "Value", "Name/Campaign", "IOC source"], ioc_rows),
        "mvt_alerts": (["Level", "Classification", "Module", "Occurrences", "Message", "Matched indicator"], mvt_rows),
        "coverage": (["Collector", "Status", "Detail"], coverage_rows),
        "packages": (["Package", "User", "UID", "Version", "Installer", "Class", "Requested permissions", "Certificates", "Source path"], packages_rows),
        "package_summary": (["Metric", "Value"], package_summary),
        "analysis_engines": (["Engine", "Result", "Detail"], engine_rows),
        "artifact_inventory": (["Artifact category", "Count", "Source"], artifact_rows),
    }
    files: dict[str, str] = {}
    for name, (headers, rows) in definitions.items():
        files[name] = str(_write_csv(tables_dir / f"{name}.csv", headers, rows))
    return {
        "definitions": {name: {"headers": headers, "rows": rows} for name, (headers, rows) in definitions.items()},
        "files": files,
    }


def _write_html(path: Path, payload: dict[str, object]) -> None:
    """Write a self-contained searchable offline HTML dashboard."""
    verdict = payload["verdict"]
    device = payload["device"]
    coverage = payload["coverage"]
    tables = payload["report_tables"]["definitions"]
    ioc_count = len(tables["confirmed_ioc_matches"]["rows"])
    principal_count = len(tables["principal_findings"]["rows"])
    high_priority = sum(
        1
        for row in tables["principal_findings"]["rows"]
        if str(row[0]).lower() in {"critical", "high"}
    )
    cards = [
        ("Verdict", verdict["message"]),
        ("Confirmed IOC", ioc_count),
        ("High-priority", high_priority),
        ("Coverage", f"{coverage.get('coverage_score', 0)}%"),
        ("MVT heuristic alerts", payload["mvt"].get("heuristic_records", 0)),
        ("Packages", payload["package_inventory_summary"].get("unique_package_count", 0)),
    ]
    card_html = "".join(
        f"<div class='card'><span>{html.escape(str(label))}</span><strong>{html.escape(str(value))}</strong></div>"
        for label, value in cards
    )
    reason_html = "".join(f"<li>{html.escape(str(reason))}</li>" for reason in verdict.get("reasons", [])) or "<li>No reasons recorded.</li>"
    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DroidCustos Android Forensic Report</title>
<style>
:root{{--bg:#081018;--panel:#101b27;--panel2:#0d1620;--border:#26384a;--text:#e7eef7;--muted:#91a4b7;--accent:#71d6ff;--danger:#ff7b8b;--warn:#ffd166;--ok:#67e8a5}}
*{{box-sizing:border-box}}body{{font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;margin:0;background:var(--bg);color:var(--text)}}main{{max-width:1500px;margin:auto;padding:28px}}pre{{overflow:auto;color:#55d6be;background:var(--panel2);padding:18px;border:1px solid var(--border)}}h1,h2,h3{{color:var(--accent)}}h2{{margin-top:38px;border-bottom:1px solid var(--border);padding-bottom:8px}}code{{color:var(--warn)}}.verdict{{font-size:1.2rem;padding:18px;border:1px solid var(--border);background:var(--panel);margin:20px 0}}.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:18px 0}}.card{{background:var(--panel);border:1px solid var(--border);padding:15px;min-height:92px;display:flex;flex-direction:column;gap:9px}}.card span{{color:var(--muted);font-size:.82rem;text-transform:uppercase;letter-spacing:.06em}}.card strong{{font-size:1.18rem;overflow-wrap:anywhere}}.table-wrap{{overflow:auto;max-height:650px;border:1px solid var(--border);margin-bottom:18px}}table{{width:100%;border-collapse:collapse;background:var(--panel2);font-size:.88rem}}th,td{{text-align:left;border-bottom:1px solid var(--border);padding:9px;vertical-align:top;white-space:pre-wrap;overflow-wrap:anywhere}}th{{position:sticky;top:0;background:#172536;color:#a8dfff;z-index:1}}tr:hover td{{background:#132232}}.table-search{{width:100%;padding:10px 12px;margin:6px 0;background:#0c1722;border:1px solid var(--border);color:var(--text)}}details{{margin:14px 0;background:var(--panel);border:1px solid var(--border);padding:12px}}summary{{cursor:pointer;color:var(--accent);font-weight:700}}.sev-critical,.sev-high{{color:var(--danger);font-weight:700}}.sev-medium,.sev-warning{{color:var(--warn);font-weight:700}}.sev-low{{color:#a7c7ff}}.sev-informational{{color:var(--muted)}}.note{{padding:14px;border-left:4px solid var(--warn);background:var(--panel)}}footer{{margin-top:32px;color:var(--muted)}}
</style>
<script>
function filterTable(id, query){{const needle=query.toLowerCase();document.querySelectorAll('#'+id+' tbody tr').forEach(row=>{{row.style.display=row.innerText.toLowerCase().includes(needle)?'':'none';}});}}
</script>
</head>
<body><main>
<pre>{html.escape(BANNER)}</pre>
<h1>Android Forensic Report</h1>
<p>Generated by DroidCustos {html.escape(__version__)} · Author: h3st4k3r · {html.escape(str(payload['generated_at']))}</p>
<div class="verdict"><strong>{html.escape(str(verdict['message']))}</strong><br>Score: {html.escape(str(verdict['score']))} · Code: {html.escape(str(verdict['code']))}</div>
<div class="cards">{card_html}</div>
<div class="note"><strong>Interpretation:</strong> {html.escape(str(payload['interpretation_warning']))}</div>
<h2>Principal Findings</h2>
{_html_data_table(tables['principal_findings']['headers'], tables['principal_findings']['rows'], 'principal')}
<h2>Confirmed IOC Evidence</h2>
{_html_data_table(tables['confirmed_ioc_matches']['headers'], tables['confirmed_ioc_matches']['rows'], 'iocs')}
<h2>Analysis Engines</h2>
{_html_data_table(tables['analysis_engines']['headers'], tables['analysis_engines']['rows'], 'engines', searchable=False)}
<h2>Acquisition Coverage</h2>
{_html_data_table(tables['coverage']['headers'], tables['coverage']['rows'], 'coverage')}
<h2>Artifact Inventory</h2>
{_html_data_table(tables['artifact_inventory']['headers'], tables['artifact_inventory']['rows'], 'artifacts', searchable=False)}
<h2>MVT Alerts</h2>
<p>MVT heuristic alerts are not treated as IOC matches unless <code>matched_indicator</code> is non-null.</p>
{_html_data_table(tables['mvt_alerts']['headers'], tables['mvt_alerts']['rows'], 'mvtalerts')}
<h2>DroidCustos Findings</h2>
{_html_data_table(tables['findings']['headers'], tables['findings']['rows'], 'findings')}
<h2>Package Inventory</h2>
{_html_data_table(tables['package_summary']['headers'], tables['package_summary']['rows'], 'pkgsummary', searchable=False)}
{_html_data_table(tables['packages']['headers'], tables['packages']['rows'], 'packages', collapsed=True, title='Complete package inventory')}
<h2>Device</h2>
{_html_data_table(['Field','Value'], [
    ['Serial', device.get('serial', '')],
    ['Manufacturer', device.get('manufacturer', '')],
    ['Model', device.get('model', '')],
    ['Android', device.get('android_version', '')],
    ['Security patch', device.get('security_patch', '')],
    ['Build fingerprint', device.get('build_fingerprint', '')],
], 'device', searchable=False)}
<h2>Verdict Reasons</h2><ul>{reason_html}</ul>
<h2>Collection Limitations</h2><ul>
<li>Logical ADB and AndroidQF acquisition cannot provide physical write blocking.</li>
<li>Application-private and encrypted databases may be unavailable without an authorized backup, export, device-management capability or pre-existing root access.</li>
<li>Absence of a public IOC match does not establish that a device was never targeted or compromised.</li>
</ul>
<footer>Evidence provenance: 00_metadata/custody.jsonl · logs/commands.log · 05_hashes/evidence-manifest.json · Complete tables: 04_reports/tables/</footer>
</main></body></html>"""
    path.write_text(document, encoding="utf-8")


def generate_reports(
    reports_dir: Path,
    *,
    case_root: Path,
    device: dict[str, object],
    capabilities: dict[str, object],
    acquisition: dict[str, object],
    profile: AcquisitionProfile | dict[str, object],
    mvt: MvtSummary,
    extended: ExtendedAnalysisSummary,
    findings: list[Finding],
    verdict: Verdict,
    ioc_manifest: dict[str, object],
    integrity: dict[str, object],
    coverage: CoverageReport,
    package_inventory: dict[str, object],
    aleapp: AleappSummary,
    timeline: dict[str, object],
) -> tuple[Path, Path, Path]:
    """Generate complete machine-readable and analyst-readable reports."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    profile_payload = _profile_payload(profile)
    report_tables = _report_tables(
        reports_dir / "tables",
        acquisition=acquisition,
        capabilities=capabilities,
        mvt=mvt,
        extended=extended,
        findings=findings,
        coverage=coverage,
        package_inventory=package_inventory,
        aleapp=aleapp,
        timeline=timeline,
        integrity=integrity,
        ioc_manifest=ioc_manifest,
    )
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generated_by": f"DroidCustos {__version__}",
        "author": "h3st4k3r",
        "case_root": str(case_root),
        "verdict": asdict(verdict),
        "device": device,
        "capabilities": capabilities,
        "profile": profile_payload,
        "acquisition": acquisition,
        "coverage": coverage.to_dict(),
        "integrity": integrity,
        "mvt": asdict(mvt),
        "aleapp": aleapp.to_dict(),
        "timeline": timeline,
        "package_inventory_summary": {
            "package_count": package_inventory.get("package_count", 0),
            "unique_package_count": package_inventory.get("unique_package_count", 0),
            "users": package_inventory.get("users", []),
        },
        "extended_analysis": asdict(extended),
        "heuristic_findings": [asdict(item) for item in findings],
        "ioc_manifest": ioc_manifest,
        "report_tables": report_tables,
        "interpretation_warning": (
            "Confirmed IOC matches require a non-null matched indicator or an exact active STIX match against a package, "
            "certificate, hash, domain, URL or IP. Heuristic alerts are reported separately. A negative result means only "
            "that no known public indicators were found in the artifacts successfully acquired."
        ),
    }
    json_path = reports_dir / "summary.json"
    json_path.write_text(json.dumps(payload, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")

    tables = report_tables["definitions"]
    lines = [
        "```text",
        BANNER,
        "```",
        "",
        "# DroidCustos Android Forensic Report",
        "",
        f"Generated by **DroidCustos {__version__}**  ",
        "Author: **h3st4k3r**  ",
        f"Case: `{case_root}`",
        "",
        "## Executive Verdict",
        "",
        f"**{verdict.message}**",
        "",
        *_markdown_table(
            ["Metric", "Result"],
            [
                ["Verdict code", verdict.code],
                ["Score", verdict.score],
                ["Confirmed IOC matches", len(tables["confirmed_ioc_matches"]["rows"])],
                ["MVT heuristic alert records", mvt.heuristic_records],
                ["MVT unique grouped alerts", mvt.unique_alert_records],
                ["Coverage", f"{coverage.coverage_score}%"],
                ["Evidence integrity", "Verified" if integrity.get("verified") else "Not verified"],
                ["AndroidQF acquisition", "Complete" if acquisition.get("complete") else "Incomplete"],
            ],
        ),
        "",
        "> Confirmed IOC matches require a non-null MVT `matched_indicator` or an exact active STIX match. MVT heuristic alerts are listed separately and do not by themselves establish compromise.",
        "",
        "## Principal Findings",
        "",
        *_markdown_table(tables["principal_findings"]["headers"], tables["principal_findings"]["rows"], 40),
        "",
        "## Confirmed IOC Evidence",
        "",
        *_markdown_table(tables["confirmed_ioc_matches"]["headers"], tables["confirmed_ioc_matches"]["rows"], 100),
        "",
        "## Analysis Engines",
        "",
        *_markdown_table(tables["analysis_engines"]["headers"], tables["analysis_engines"]["rows"]),
        "",
        "## Acquisition Coverage",
        "",
        *_markdown_table(tables["coverage"]["headers"], tables["coverage"]["rows"], 100),
        "",
        "## Artifact Inventory",
        "",
        *_markdown_table(tables["artifact_inventory"]["headers"], tables["artifact_inventory"]["rows"]),
        "",
        "## MVT Alerts",
        "",
        *_markdown_table(tables["mvt_alerts"]["headers"], tables["mvt_alerts"]["rows"], 60),
        "",
        "## DroidCustos Findings",
        "",
        *_markdown_table(tables["findings"]["headers"], tables["findings"]["rows"], 100),
        "",
        "## Package Inventory Summary",
        "",
        *_markdown_table(tables["package_summary"]["headers"], tables["package_summary"]["rows"]),
        "",
        "The complete package inventory is available in `04_reports/tables/packages.csv` and in the searchable HTML report.",
        "",
        "## Verdict Reasons",
        "",
        *(f"- {reason}" for reason in verdict.reasons),
        "",
        "## Complete CSV Tables",
        "",
        *(f"- `{Path(path).relative_to(case_root)}`" for path in report_tables["files"].values()),
        "",
        "## Collection Limitations",
        "",
        "- Logical ADB and AndroidQF acquisition cannot provide physical write blocking.",
        "- Application-private and encrypted databases may be unavailable without an authorized backup, export, device-management capability or pre-existing root access.",
        "- Absence of a public IOC match does not establish that a device was never targeted or compromised.",
        "- See `00_metadata/custody.jsonl`, `logs/commands.log`, `05_hashes/SHA256SUMS.txt`, and `05_hashes/evidence-manifest.json` for provenance and integrity records.",
        "",
    ]
    markdown_path = reports_dir / "report.md"
    markdown_path.write_text("\n".join(lines), encoding="utf-8")
    html_path = reports_dir / "report.html"
    _write_html(html_path, payload)
    return json_path, markdown_path, html_path
