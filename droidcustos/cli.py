"""DroidCustos command-line interface.

Author: h3st4k3r
"""

from __future__ import annotations

import argparse
import getpass
import json
import shutil
from pathlib import Path

from . import __version__
from .apk_inventory import create_baseline, write_inventory_diff
from .capabilities import build_acquisition_plan, discover_capabilities
from .console import banner, error, info, success, warning
from .device import list_devices, select_device
from .export_case import export_encrypted_case, import_encrypted_case
from .hashing import verify_evidence_manifest
from .indicators import download_all_stix, stix_files, update_index, update_mvt_native
from .profiles import resolve_profile
from .signing import create_case_seal, generate_signing_keypair, verify_case_seal
from .tools import default_cache_dir, doctor, install_aleapp, install_androidqf, install_mvt
from .workflow import analyze_existing, run_scan


def _add_cache(parser: argparse.ArgumentParser) -> None:
    """Add the shared cache override option."""
    parser.add_argument("--cache", help="Override the DroidCustos cache directory")


def _add_ioc_sources(parser: argparse.ArgumentParser) -> None:
    """Add the optional custom IOC source option."""
    parser.add_argument("--ioc-sources", help="Optional YAML file containing additional public STIX source URLs")


def build_parser() -> argparse.ArgumentParser:
    """Build the complete command-line parser."""
    parser = argparse.ArgumentParser(
        prog="droidcustos",
        description="Universal Android forensic acquisition, evidence preservation, threat hunting and IOC correlation.",
    )
    parser.add_argument("--version", action="version", version=f"DroidCustos {__version__} by h3st4k3r")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor_parser = subparsers.add_parser("doctor", help="Check and optionally install required tools")
    doctor_parser.add_argument("--fix", action="store_true", help="Install MVT and AndroidQF")
    doctor_parser.add_argument("--with-aleapp", action="store_true", help="Install or update ALEAPP in an isolated cache environment")
    _add_cache(doctor_parser)

    devices_parser = subparsers.add_parser("devices", help="List ADB devices")
    devices_parser.add_argument("--adb", default="adb")

    inspect_parser = subparsers.add_parser("inspect", help="Discover Android capabilities without acquiring private content")
    inspect_parser.add_argument("--serial", help="ADB serial; required when multiple devices are attached")
    inspect_parser.add_argument("--wait", type=int, default=120)
    inspect_parser.add_argument("--adb", default="adb")
    inspect_parser.add_argument("--output", help="Optional JSON output path")
    inspect_parser.add_argument("--users", choices=("primary", "active", "all"), default="active")
    inspect_parser.add_argument("--user", help="Explicit comma-separated user IDs")

    update_parser = subparsers.add_parser("update-iocs", help="Update all indexed public STIX2 sources")
    _add_cache(update_parser)
    _add_ioc_sources(update_parser)

    scan = subparsers.add_parser("scan", help="Acquire and analyze an attached Android device")
    scan.add_argument("--serial", help="ADB serial; required when multiple devices are attached")
    scan.add_argument("--wait", type=int, default=120, help="Seconds to wait for a device; 0 waits indefinitely")
    scan.add_argument("--output", default="./droidcustos-cases", help="Base case directory")
    _add_cache(scan)
    _add_ioc_sources(scan)
    scan.add_argument("--adb", default="adb", help="ADB executable")
    scan.add_argument("--operator", default="h3st4k3r", help="Operator recorded in custody metadata")
    scan.add_argument("--case-id", help="Optional external case identifier")
    scan.add_argument("--notes", default="", help="Optional case notes")
    scan.add_argument("--no-update", action="store_true", help="Use cached IOC files without network updates")
    scan.add_argument("--no-adb-extra", action="store_true", help="Skip complementary ADB diagnostics")
    scan.add_argument("--no-oem-plugins", action="store_true", help="Skip capability-aware OEM collectors")
    scan.add_argument("--no-package-inventory", action="store_true", help="Skip the normalized package inventory")
    scan.add_argument("--no-timeline", action="store_true", help="Skip unified timeline generation")
    scan.add_argument("--users", choices=("primary", "active", "all"), default="active", help="Android user and profile scope")
    scan.add_argument("--user", help="Explicit comma-separated Android user IDs")
    scan.add_argument("--aleapp", choices=("auto", "yes", "no"), default="auto", help="ALEAPP execution policy")
    scan.add_argument("--backup", choices=("sms", "all", "none"), default=None)
    scan.add_argument("--download", choices=("all", "non-system", "none"), default=None)
    scan.add_argument("--remove-trusted", choices=("yes", "no"), default="no")
    scan.add_argument("--intrusion-logs", choices=("yes", "no"), default="yes")
    scan.add_argument("--androidqf-hash-files", choices=("yes", "no"), default="no")
    scan.add_argument("--signing-key", help="Optional Ed25519 private key used to sign the final case seal")
    scan.add_argument("--signing-password-file", help="File containing the private-key password")

    privacy = scan.add_argument_group("optional privacy-sensitive acquisition")
    privacy.add_argument("--deep", action="store_true", help="Enable web, chat, connection and user-file hash acquisition")
    privacy.add_argument("--collect-web", action="store_true", help="Collect accessible browser metadata and history artifacts")
    privacy.add_argument("--collect-chats", action="store_true", help="Collect accessible SMS, notification and chat artifacts")
    privacy.add_argument("--collect-connections", action="store_true", help="Collect extended network state and connection artifacts")
    privacy.add_argument("--hash-user-files", action="store_true", help="Hash image and document files in visible shared storage")
    privacy.add_argument("--copy-user-files", action="store_true", help="Copy selected shared user folders")
    privacy.add_argument(
        "--root-mode",
        choices=("never", "auto", "require"),
        default="never",
        help="Use only pre-existing authorized root access; DroidCustos never roots a device",
    )

    analyze = subparsers.add_parser("analyze", help="Re-analyze an existing DroidCustos case")
    analyze.add_argument("case", help="Existing case directory")
    _add_cache(analyze)
    _add_ioc_sources(analyze)
    analyze.add_argument("--no-update", action="store_true")

    verify = subparsers.add_parser("verify", help="Verify evidence integrity and an optional signed case seal")
    verify.add_argument("case", help="Existing case directory")
    verify.add_argument("--public-key", help="Ed25519 public key for signed case-seal verification")

    baseline = subparsers.add_parser("baseline", help="Create a portable package and device baseline")
    baseline.add_argument("case", help="Existing case directory")
    baseline.add_argument("--output", required=True, help="Baseline JSON output")

    diff = subparsers.add_parser("diff", help="Compare two baselines or case package inventories")
    diff.add_argument("base")
    diff.add_argument("current")
    diff.add_argument("--output", required=True)

    keygen = subparsers.add_parser("keygen", help="Generate an Ed25519 case-signing keypair")
    keygen.add_argument("--private", required=True)
    keygen.add_argument("--public", required=True)
    keygen.add_argument("--password-file", help="Optional file containing the private-key password")

    seal = subparsers.add_parser("seal", help="Create a signed final case seal")
    seal.add_argument("case")
    seal.add_argument("--private-key", required=True)
    seal.add_argument("--password-file")

    export = subparsers.add_parser("export", help="Export a case as an authenticated encrypted archive")
    export.add_argument("case")
    export.add_argument("--output", required=True)
    export.add_argument("--password-file")

    import_parser = subparsers.add_parser("import", help="Decrypt and import a DroidCustos case archive")
    import_parser.add_argument("archive")
    import_parser.add_argument("--output", required=True)
    import_parser.add_argument("--password-file")
    return parser


def _cache(args) -> Path:
    """Resolve the active managed cache directory."""
    return Path(args.cache).expanduser().resolve() if getattr(args, "cache", None) else default_cache_dir()


def _password(path: str | None, prompt: str) -> bytes:
    """Read a password from a file or secure interactive prompt."""
    if path:
        return Path(path).expanduser().read_bytes().rstrip(b"\r\n")
    return getpass.getpass(prompt).encode("utf-8")


def command_doctor(args) -> int:
    """Check and optionally install forensic dependencies."""
    cache = _cache(args)
    statuses = doctor(cache)
    for status in statuses.values():
        if status.available:
            success(f"{status.name}: {status.path}{' / ' + status.version if status.version else ''}")
        else:
            warning(f"{status.name}: not found")
    if args.fix:
        if not statuses["mvt-android"].available:
            info("Installing MVT into the current Python environment")
            if not install_mvt():
                error("MVT installation failed")
                return 1
        if not statuses["androidqf"].available:
            info("Downloading the latest compatible AndroidQF release")
            path, version = install_androidqf(cache)
            success(f"AndroidQF {version} installed at {path}")
    if args.with_aleapp:
        info("Installing or updating ALEAPP in the managed cache")
        python, script = install_aleapp(cache)
        success(f"ALEAPP installed at {script} using {python}")
    final = doctor(cache)
    required_missing = [name for name in ("adb", "git", "mvt-android", "androidqf") if not final[name].available]
    if required_missing:
        if "adb" in required_missing:
            warning("Install Android platform-tools using the operating-system package manager")
        return 1
    return 0


def command_devices(args) -> int:
    """List connected ADB devices and their states."""
    devices = list_devices(args.adb)
    if not devices:
        info("No ADB devices detected")
        return 1
    for device in devices:
        print(f"{device.serial}\t{device.state}\t{json.dumps(device.details, sort_keys=True)}")
    return 0


def command_inspect(args) -> int:
    """Discover compatibility without collecting private content."""
    device = select_device(args.serial, args.wait, adb=args.adb)
    capabilities = discover_capabilities(args.adb, device.serial, command_log=None, root_mode="never")
    profile_args = argparse.Namespace(
        deep=False,
        backup=None,
        download=None,
        remove_trusted="no",
        intrusion_logs="yes",
        androidqf_hash_files="no",
        no_adb_extra=False,
        collect_connections=False,
        collect_web=False,
        collect_chats=False,
        hash_user_files=False,
        copy_user_files=False,
        root_mode="never",
        users=args.users,
        user=args.user,
        aleapp="auto",
        no_oem_plugins=False,
        no_package_inventory=False,
        no_timeline=False,
    )
    plan = build_acquisition_plan(capabilities, resolve_profile(profile_args))
    payload = {"capabilities": capabilities.to_dict(), "plan": plan.to_dict()}
    rendered = json.dumps(payload, indent=2, sort_keys=True)
    print(rendered)
    if args.output:
        Path(args.output).expanduser().write_text(rendered + "\n", encoding="utf-8")
    return 0


def command_update(args) -> int:
    """Update every configured public STIX source."""
    cache = _cache(args)
    repository = cache / "mvt-indicators"
    output = cache / "stix"
    custom = Path(args.ioc_sources).expanduser().resolve() if args.ioc_sources else None
    update_index(repository)
    manifest = download_all_stix(repository, output, custom)
    native = bool(shutil.which("mvt-android")) and update_mvt_native()
    success(f"Downloaded STIX2 files: {len(stix_files(output))}")
    if not native:
        warning("MVT native IOC update did not run successfully")
    if manifest.get("errors"):
        warning(f"Source errors recorded: {len(manifest['errors'])}")
    info(f"Manifest: {output / 'manifest.json'}")
    info(f"Normalized database: {output / 'ioc.db'}")
    return 0 if stix_files(output) else 1


def command_verify(args) -> int:
    """Verify evidence hashes and an optional detached signature."""
    root = Path(args.case).expanduser().resolve()
    result = verify_evidence_manifest(root / "05_hashes" / "evidence-manifest.json", root)
    if result["verified"]:
        success(f"Evidence manifest verified: {result['checked']} files")
    else:
        error(f"Evidence verification failed: {len(result.get('mismatches', []))} mismatches")
        for mismatch in result.get("mismatches", [])[:20]:
            print(json.dumps(mismatch, sort_keys=True))
        return 1
    if args.public_key:
        seal = verify_case_seal(
            root / "05_hashes" / "case-seal.json",
            root / "05_hashes" / "case-seal.sig",
            Path(args.public_key).expanduser().resolve(),
        )
        if not seal["verified"]:
            error(json.dumps(seal, sort_keys=True))
            return 1
        success(f"Signed case seal verified: {seal['file_count']} files")
    return 0


def command_baseline(args) -> int:
    """Create a portable baseline from one case."""
    output = create_baseline(Path(args.case).expanduser().resolve(), Path(args.output).expanduser().resolve())
    success(f"Baseline created: {output}")
    return 0


def command_diff(args) -> int:
    """Compare two package inventories or baselines."""
    output = write_inventory_diff(
        Path(args.base).expanduser().resolve(),
        Path(args.current).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
    )
    success(f"Comparison written: {output}")
    return 0


def command_keygen(args) -> int:
    """Generate an operator signing keypair."""
    password = _password(args.password_file, "Private-key password, leave empty for none: ") if args.password_file else None
    private_path, public_path = generate_signing_keypair(
        Path(args.private).expanduser().resolve(),
        Path(args.public).expanduser().resolve(),
        password,
    )
    success(f"Private key: {private_path}")
    success(f"Public key: {public_path}")
    return 0


def command_seal(args) -> int:
    """Create an Ed25519 final case seal."""
    root = Path(args.case).expanduser().resolve()
    password = _password(args.password_file, "Private-key password: ") if args.password_file else None
    create_case_seal(
        root,
        Path(args.private_key).expanduser().resolve(),
        root / "05_hashes" / "case-seal.sig",
        root / "05_hashes" / "case-seal.json",
        password,
    )
    success(f"Case seal created: {root / '05_hashes' / 'case-seal.sig'}")
    return 0


def command_export(args) -> int:
    """Export one case as an authenticated encrypted archive."""
    password = _password(args.password_file, "Export password: ")
    output = export_encrypted_case(
        Path(args.case).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
        password,
    )
    success(f"Encrypted case export: {output}")
    return 0


def command_import(args) -> int:
    """Import one authenticated encrypted case archive."""
    password = _password(args.password_file, "Export password: ")
    output = import_encrypted_case(
        Path(args.archive).expanduser().resolve(),
        Path(args.output).expanduser().resolve(),
        password,
    )
    success(f"Imported case: {output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Dispatch the DroidCustos command-line interface."""
    banner()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        handlers = {
            "doctor": command_doctor,
            "devices": command_devices,
            "inspect": command_inspect,
            "update-iocs": command_update,
            "scan": run_scan,
            "analyze": analyze_existing,
            "verify": command_verify,
            "baseline": command_baseline,
            "diff": command_diff,
            "keygen": command_keygen,
            "seal": command_seal,
            "export": command_export,
            "import": command_import,
        }
        return handlers[args.command](args)
    except KeyboardInterrupt:
        error("Interrupted by user")
        return 130
    except Exception as exc:
        error(str(exc))
        return 1
