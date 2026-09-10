"""High-level DroidCustos forensic workflows.

Author: h3st4k3r
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .acquisition import collect_adb_extras, collect_volatile_state, prepare_working_copy, run_androidqf
from .aleapp import AleappSummary, run_aleapp
from .analysis import run_mvt
from .apk_analysis import analyze_apk_tree
from .apk_inventory import collect_package_inventory, enrich_inventory_with_local_apks
from .capabilities import build_acquisition_plan, discover_capabilities
from .case import CasePaths
from .console import error, heading, info, success, verdict as print_verdict, warning
from .coverage import calculate_coverage, write_coverage
from .custody import append_event, host_snapshot
from .device import collect_device_metadata, select_device
from .extended_acquisition import collect_extended_artifacts
from .extended_analysis import analyze_extended
from .hashing import create_evidence_manifest, seal_read_only, verify_evidence_manifest
from .heuristics import Finding, run_heuristics
from .indicators import build_ioc_database, download_all_stix, stix_files, update_index, update_mvt_native
from .plugins import CollectorResult, execute_plugins
from .profiles import AcquisitionProfile, resolve_profile
from .reporting import generate_reports
from .security_state import analyze_security_state
from .scoring import calculate_verdict
from .signing import create_case_seal
from .timeline import write_unified_timeline
from .tools import default_cache_dir, doctor, find_androidqf


def _custom_ioc_path(args) -> Path | None:
    """Resolve an optional operator-maintained IOC source file."""
    value = getattr(args, "ioc_sources", None)
    return Path(value).expanduser().resolve() if value else None


def update_indicators(cache: Path, command_log: Path | None = None, custom_sources: Path | None = None) -> tuple[dict[str, object], list[Path]]:
    """Update public IOC sources and the normalized database."""
    repository = cache / "mvt-indicators"
    output = cache / "stix"
    heading("Updating public IOC sources")
    update_index(repository, command_log)
    manifest = download_all_stix(repository, output, custom_sources)
    native = update_mvt_native(command_log)
    if native:
        success("MVT native IOC store updated")
    else:
        warning("MVT native IOC update failed; downloaded STIX files remain available")
    files = stix_files(output)
    success(f"Available STIX2 files: {len(files)}")
    if manifest.get("errors"):
        warning(f"IOC source errors: {len(manifest['errors'])}")
    return manifest, files


def _cached_indicators(cache: Path) -> tuple[dict[str, object], list[Path]]:
    """Load cached indicators for an offline analysis."""
    output = cache / "stix"
    manifest_path = output / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")) if manifest_path.is_file() else {"sources": [], "errors": []}
    files = stix_files(output)
    database = output / "ioc.db"
    if files and not database.is_file():
        build_ioc_database(files, database, manifest)
    return manifest, files


def _record_tools(case: CasePaths, cache: Path) -> None:
    """Record exact host tool paths, versions and provenance."""
    statuses = doctor(cache)
    case.write_json("00_metadata/tool-versions.json", {name: status.to_dict() for name, status in statuses.items()})


def _load_password_file(path: str | None) -> bytes | None:
    """Read an optional private-key password from a local file."""
    if not path:
        return None
    return Path(path).expanduser().read_bytes().rstrip(b"\r\n")


def _load_plugin_results(case: CasePaths) -> list[CollectorResult]:
    """Load plugin results from an existing case."""
    path = case.plugin_evidence / "collector-results.json"
    if not path.is_file():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    return [CollectorResult(**item) for item in payload]


def _load_json(path: Path, default: object) -> object:
    """Load JSON when available and return a deterministic default."""
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def run_scan(args) -> int:
    """Acquire, preserve, analyze and report one authorized Android device."""
    cache = Path(args.cache).expanduser().resolve() if args.cache else default_cache_dir()
    androidqf = find_androidqf(cache)
    if not androidqf:
        raise RuntimeError("AndroidQF is not installed. Run: droidcustos doctor --fix")
    profile = resolve_profile(args)
    info("Waiting for an authorized Android device")
    device = select_device(args.serial, args.wait, adb=args.adb)
    success(f"Device detected: {device.serial}")
    case = CasePaths.create(Path(args.output), device.serial, args.case_id)
    info(f"Case directory: {case.root}")

    case_metadata = {
        "case_id": args.case_id or case.root.name,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "operator": args.operator,
        "notes": args.notes,
        "device_serial": device.serial,
        "project": "DroidCustos",
        "version": __version__,
        "author": "h3st4k3r",
        "host": host_snapshot(),
        "profile": profile.to_dict(),
        "authorization_note": "The operator invoked acquisition against an explicitly ADB-authorized device.",
    }
    case.write_json("00_metadata/case.json", case_metadata)
    append_event(case.custody_log, "case_created", actor=args.operator, details=case_metadata)
    append_event(case.custody_log, "device_connected", actor=args.operator, details={"serial": device.serial, "state": device.state})

    manifest, iocs = _cached_indicators(cache) if args.no_update else update_indicators(cache, case.command_log, _custom_ioc_path(args))
    case.write_json("00_metadata/ioc-manifest.json", manifest)

    heading("Discovering device capabilities")
    capabilities = discover_capabilities(
        args.adb,
        device.serial,
        case.metadata / "capabilities.json",
        case.command_log,
        profile.root_mode,
    )
    plan = build_acquisition_plan(capabilities, profile)
    case.write_json("00_metadata/acquisition-plan.json", plan.to_dict())
    success(
        f"{capabilities.manufacturer} {capabilities.model} / Android {capabilities.android_version} / "
        f"{capabilities.rom_family} / users {','.join(map(str, plan.selected_users))}"
    )
    if plan.skipped_collectors:
        warning(f"Capability-dependent collectors skipped: {len(plan.skipped_collectors)}")

    heading("Collecting device metadata")
    metadata = collect_device_metadata(args.adb, device.serial, case.metadata / "device.json", case.command_log)
    metadata["droidcustos_version"] = __version__
    metadata["rom_family"] = capabilities.rom_family
    metadata["visible_users"] = [asdict(user) for user in capabilities.users]
    case.write_json("00_metadata/device.json", metadata)

    heading("Collecting volatile state")
    volatile = collect_volatile_state(args.adb, device.serial, case)
    append_event(case.custody_log, "volatile_collection_finished", actor=args.operator, details=volatile)

    heading("Running AndroidQF acquisition")
    if profile.intrusion_logs == "yes":
        info("Keep the phone unlocked; Intrusion Logging acquisition may require confirmation")
    if profile.backup != "none":
        info("Backup acquisition may require confirmation on the phone")
    acquisition = run_androidqf(
        androidqf,
        device.serial,
        case,
        backup=profile.backup,
        download=profile.download,
        remove_trusted=profile.remove_trusted,
        intrusion_logs=profile.intrusion_logs,
        hash_files=profile.androidqf_hash_files,
    )
    append_event(case.custody_log, "androidqf_acquisition_finished", actor=args.operator, details=acquisition)
    if acquisition["complete"]:
        success("AndroidQF acquisition completed")
    else:
        warning("AndroidQF acquisition is incomplete or encrypted")

    adb_summary = None
    if profile.adb_extra:
        heading("Collecting complementary ADB diagnostics")
        adb_summary = collect_adb_extras(args.adb, device.serial, case, capabilities, plan.selected_users)
        append_event(case.custody_log, "adb_collection_finished", actor=args.operator, details=adb_summary)
        success(f"ADB artifacts: {adb_summary['successful']} successful, {adb_summary['failed']} failed")

    plugin_results: list[CollectorResult] = []
    if profile.collect_oem:
        heading("Running capability-aware OEM collectors")
        plugin_results = execute_plugins(
            args.adb,
            device.serial,
            capabilities,
            plan.selected_users,
            case.plugin_evidence,
            case.command_log,
        )
        append_event(
            case.custody_log,
            "plugin_collection_finished",
            actor=args.operator,
            details={"results": [item.to_dict() for item in plugin_results]},
        )
        success(f"OEM and core plugin collectors evaluated: {len(plugin_results)}")

    package_inventory: dict[str, object] = {}
    if profile.package_inventory:
        heading("Collecting package and signing inventory")
        package_inventory = collect_package_inventory(
            args.adb,
            device.serial,
            plan.selected_users,
            case.package_evidence,
            case.package_analysis,
            case.command_log,
            [],
            detailed=profile.name == "deep",
        )
        append_event(
            case.custody_log,
            "package_inventory_finished",
            actor=args.operator,
            details={"package_count": package_inventory.get("package_count", 0)},
        )
        success(f"Package records collected: {package_inventory.get('package_count', 0)}")

    extended_status = None
    if any((profile.collect_connections, profile.collect_web, profile.collect_chats, profile.hash_user_files, profile.copy_user_files, profile.root_mode != "never")):
        heading("Collecting optional extended artifacts")
        warning("This phase can contain highly private data and may require substantial time and storage")
        extended_summary = collect_extended_artifacts(args.adb, device.serial, case, profile, capabilities, plan)
        extended_status = asdict(extended_summary)
        append_event(case.custody_log, "extended_collection_finished", actor=args.operator, details=extended_status)
        success("Extended artifact collection completed")

    _record_tools(case, cache)
    heading("Hashing and sealing original evidence")
    manifest_payload = create_evidence_manifest(
        [case.evidence, case.metadata],
        case.evidence_manifest_text,
        case.evidence_manifest_json,
        case.root,
        exclude={case.custody_log},
    )
    sealed = seal_read_only([case.evidence])
    append_event(
        case.custody_log,
        "evidence_sealed",
        actor=args.operator,
        details={"file_count": manifest_payload["file_count"], "paths_made_read_only": sealed},
    )
    integrity = verify_evidence_manifest(case.evidence_manifest_json, case.root)
    success(f"SHA-256 manifest created and verified for {integrity['checked']} files")

    heading("Preparing working copies")
    extracted = prepare_working_copy(case)
    if extracted:
        success(f"Extracted AndroidQF archives: {len(extracted)}")
    else:
        warning("No plaintext AndroidQF ZIP archive was available for extraction")
    inventory_path = case.package_analysis / "package-inventory.json"
    if inventory_path.is_file():
        package_inventory = enrich_inventory_with_local_apks(inventory_path, [case.androidqf_working])
    apk_analysis = analyze_apk_tree(case.androidqf_working, case.package_analysis / "apk-analysis.json")
    if apk_analysis:
        info(f"Static APK analyses: {len(apk_analysis)}")

    security_state = analyze_security_state(
        metadata,
        capabilities.to_dict(),
        package_inventory,
        auxiliary={"accessibility_services": metadata.get("enabled_accessibility_services")},
    )
    case.write_json("03_analysis/security-state.json", security_state)

    heading("Running MVT analysis")
    mvt = run_mvt(case, iocs)
    if mvt.command_success:
        success("MVT Android analysis completed")
    else:
        warning("MVT analysis failed; inspect the MVT logs")
    if mvt.confirmed_ioc_matches:
        error(f"Confirmed published IOC matches detected by MVT: {mvt.confirmed_ioc_matches}")
    else:
        info("MVT confirmed published IOC matches: 0")
    if mvt.heuristic_records:
        info(f"MVT heuristic alerts without matched indicators: {mvt.heuristic_records} ({mvt.unique_alert_records} grouped)")

    heading("Running ALEAPP analysis")
    aleapp = run_aleapp(
        cache,
        case.androidqf_working,
        case.aleapp_analysis,
        profile.aleapp,
        case.logs / "aleapp.log",
        case.command_log,
    )
    if aleapp.executed and aleapp.returncode == 0:
        success(f"ALEAPP completed with {aleapp.parsed_rows} tabular records")
    elif profile.aleapp == "yes":
        warning(aleapp.error or "ALEAPP did not complete")
    else:
        info(aleapp.error or "ALEAPP was not requested")

    heading("Running DroidCustos heuristics")
    findings = run_heuristics(
        case.metadata / "device.json",
        case.adb_evidence / "static" / "packages-all.txt",
        inventory_path,
        case.androidqf_working,
        iocs,
        case.heuristic_analysis,
    )
    extended, extended_findings = analyze_extended(case, iocs)
    findings.extend(extended_findings)
    findings.extend(
        Finding(
            str(item.get("severity", "medium")),
            "security-state",
            str(item.get("signal", "")),
            str(item.get("detail", "")),
            int(item.get("score", 0)),
        )
        for item in security_state.get("findings", [])
        if str(item.get("signal", "")).startswith("composite-")
    )
    info(f"Heuristic and extended findings: {len(findings)}")
    for finding in findings:
        message = f"{finding.severity.upper()} [{finding.category}] {finding.title}: {finding.evidence}"
        if finding.severity in {"critical", "high"}:
            warning(message)
        else:
            info(message)

    timeline = {"event_count": 0, "ioc_matched_events": 0}
    if profile.unified_timeline:
        heading("Building the unified forensic timeline")
        timeline = write_unified_timeline(case.root, case.timeline_analysis, cache / "stix" / "ioc.db")
        success(f"Timeline events: {timeline.get('event_count', 0)}")

    coverage = calculate_coverage(
        plan,
        plugin_results,
        acquisition,
        volatile,
        adb_summary,
        extended_status,
        package_inventory,
        aleapp.to_dict(),
    )
    write_coverage(coverage, case.analysis / "coverage.json")
    result = calculate_verdict(
        mvt,
        findings,
        acquisition_complete=bool(acquisition.get("complete")),
        ioc_count=len(iocs),
        integrity_verified=bool(integrity.get("verified")),
        coverage=coverage,
        timeline_ioc_matches=int(timeline.get("ioc_matched_events", 0)),
        extended_ioc_matches=len(extended.ioc_matches),
    )
    append_event(case.custody_log, "analysis_finished", actor=args.operator, details={"verdict": asdict(result), "coverage": coverage.to_dict()})
    json_report, markdown_report, html_report = generate_reports(
        case.reports,
        case_root=case.root,
        device=metadata,
        capabilities=capabilities.to_dict(),
        acquisition=acquisition,
        profile=profile,
        mvt=mvt,
        extended=extended,
        findings=findings,
        verdict=result,
        ioc_manifest=manifest,
        integrity=integrity,
        coverage=coverage,
        package_inventory=package_inventory,
        aleapp=aleapp,
        timeline=timeline,
        security_state=security_state,
    )
    append_event(
        case.custody_log,
        "reports_generated",
        actor=args.operator,
        details={"json": str(json_report), "markdown": str(markdown_report), "html": str(html_report)},
    )

    if getattr(args, "signing_key", None):
        append_event(case.custody_log, "case_seal_requested", actor=args.operator, details={"key": str(args.signing_key)})
        create_case_seal(
            case.root,
            Path(args.signing_key).expanduser().resolve(),
            case.case_seal_signature,
            case.case_seal_json,
            _load_password_file(getattr(args, "signing_password_file", None)),
        )
        success(f"Signed case seal: {case.case_seal_signature}")

    print_verdict(result.message, result.level)
    info(f"JSON report: {json_report}")
    info(f"Markdown report: {markdown_report}")
    info(f"HTML report: {html_report}")
    info(f"CSV tables: {case.reports / 'tables'}")
    info(f"Evidence hashes: {case.evidence_manifest_text}")
    info(f"Custody log: {case.custody_log}")
    return result.exit_code


def analyze_existing(args) -> int:
    """Re-analyze an existing case with current tools and indicators."""
    case = CasePaths.from_existing(Path(args.case))
    cache = Path(args.cache).expanduser().resolve() if args.cache else default_cache_dir()
    manifest, iocs = _cached_indicators(cache) if args.no_update else update_indicators(cache, case.command_log, _custom_ioc_path(args))
    integrity = verify_evidence_manifest(case.evidence_manifest_json, case.root)
    if not any(case.androidqf_working.rglob("*")):
        prepare_working_copy(case)

    acquisition = _load_json(case.metadata / "androidqf-status.json", {"complete": False})
    metadata = _load_json(case.metadata / "device.json", {})
    capabilities = _load_json(case.metadata / "capabilities.json", {})
    plan_data = _load_json(case.metadata / "acquisition-plan.json", {"selected_users": [0], "storage_roots": [], "collectors": [], "skipped_collectors": [], "coverage_target": 0})
    case_metadata = _load_json(case.metadata / "case.json", {})
    profile_data = case_metadata.get("profile", {"name": "unknown"}) if isinstance(case_metadata, dict) else {"name": "unknown"}
    profile = AcquisitionProfile(**profile_data) if set(AcquisitionProfile.__dataclass_fields__).issubset(profile_data) else profile_data
    inventory_path = case.package_analysis / "package-inventory.json"
    package_inventory = enrich_inventory_with_local_apks(inventory_path, [case.androidqf_working]) if inventory_path.is_file() else {}
    apk_analysis = analyze_apk_tree(case.androidqf_working, case.package_analysis / "apk-analysis.json")
    security_state = analyze_security_state(metadata, capabilities, package_inventory)
    case.write_json("03_analysis/security-state.json", security_state)

    mvt = run_mvt(case, iocs)
    aleapp_mode = str(profile_data.get("aleapp", "auto")) if isinstance(profile_data, dict) else "auto"
    aleapp = run_aleapp(cache, case.androidqf_working, case.aleapp_analysis, aleapp_mode, case.logs / "aleapp.log", case.command_log)
    findings = run_heuristics(
        case.metadata / "device.json",
        case.adb_evidence / "static" / "packages-all.txt",
        inventory_path,
        case.androidqf_working,
        iocs,
        case.heuristic_analysis,
    )
    extended, extended_findings = analyze_extended(case, iocs)
    findings.extend(extended_findings)
    findings.extend(
        Finding(
            str(item.get("severity", "medium")),
            "security-state",
            str(item.get("signal", "")),
            str(item.get("detail", "")),
            int(item.get("score", 0)),
        )
        for item in security_state.get("findings", [])
        if str(item.get("signal", "")).startswith("composite-")
    )
    timeline = write_unified_timeline(case.root, case.timeline_analysis, cache / "stix" / "ioc.db")

    from .capabilities import AcquisitionPlan

    plan = AcquisitionPlan(**plan_data)
    plugin_results = _load_plugin_results(case)
    volatile = _load_json(case.metadata / "volatile-status.json", None)
    adb_summary = _load_json(case.metadata / "adb-extra-status.json", None)
    extended_status = _load_json(case.metadata / "extended-acquisition-status.json", None)
    coverage = calculate_coverage(
        plan,
        plugin_results,
        acquisition,
        volatile,
        adb_summary,
        extended_status,
        package_inventory,
        aleapp.to_dict(),
    )
    write_coverage(coverage, case.analysis / "coverage.json")
    result = calculate_verdict(
        mvt,
        findings,
        acquisition_complete=bool(acquisition.get("complete")),
        ioc_count=len(iocs),
        integrity_verified=bool(integrity.get("verified")),
        coverage=coverage,
        timeline_ioc_matches=int(timeline.get("ioc_matched_events", 0)),
        extended_ioc_matches=len(extended.ioc_matches),
    )
    json_report, markdown_report, html_report = generate_reports(
        case.reports,
        case_root=case.root,
        device=metadata,
        capabilities=capabilities,
        acquisition=acquisition,
        profile=profile,
        mvt=mvt,
        extended=extended,
        findings=findings,
        verdict=result,
        ioc_manifest=manifest,
        integrity=integrity,
        coverage=coverage,
        package_inventory=package_inventory,
        aleapp=aleapp,
        timeline=timeline,
        security_state=security_state,
    )
    append_event(case.custody_log, "case_reanalyzed", actor="h3st4k3r", details={"verdict": asdict(result)})
    print_verdict(result.message, result.level)
    info(f"JSON report: {json_report}")
    info(f"Markdown report: {markdown_report}")
    info(f"HTML report: {html_report}")
    info(f"CSV tables: {case.reports / 'tables'}")
    return result.exit_code
