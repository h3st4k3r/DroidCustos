```text
 ____  ____   ___ ___ ____      ____ _   _ ____ _____ ___  ____
|  _ \|  _ \ / _ \_ _|  _ \    / ___| | | / ___|_   _/ _ \/ ___|
| | | | |_) | | | | || | | |  | |   | | | \___ \ | || | | \___ \
| |_| |  _ <| |_| | || |_| |  | |___| |_| |___) || || |_| |___) |
|____/|_| \_\\___/___|____/    \____|\___/|____/ |_| \___/|____/
```

# DroidCustos

**Capability-aware Android forensic triage, evidence preservation and IOC correlation.**

[![Status](https://img.shields.io/badge/status-public%20alpha-F59E0B)](./RELEASE_NOTES.md)
[![License](https://img.shields.io/badge/license-GPL--3.0--or--later-001538)](./LICENSE)
[![Language](https://img.shields.io/badge/language-Python%203.10%2B-3776AB?logo=python&logoColor=white)](./pyproject.toml)
[![Security](https://img.shields.io/badge/security-responsible%20disclosure-001538)](./SECURITY.md)
[![Author](https://img.shields.io/badge/author-h3st4k3r-111827?logo=github&logoColor=white)](https://github.com/h3st4k3r)

<img width="1566" height="909" alt="DroidCustos forensic report dashboard" src="https://github.com/user-attachments/assets/37dcfc22-590c-4239-8079-3ad33a489cb8" />

DroidCustos is a command-line toolkit for authorized Android forensic triage. It brings together device discovery, logical acquisition, ADB diagnostics, MVT, optional ALEAPP parsing, STIX threat intelligence, OEM-aware collectors, evidence hashing, timelines and analyst-friendly reports.

It is designed for repeatable examinations where the operator needs to understand exactly what was collected, what failed, what matched and what still requires manual review.

> DroidCustos is not a physical-imaging tool, a screen-lock bypass or a replacement for a validated commercial forensic suite. It performs logical acquisition and triage, and its findings must be reviewed by a qualified analyst.

## At a glance

- **Version:** 0.3.2
- **Status:** Public alpha
- **License:** GPL-3.0-or-later
- **Host systems:** macOS and Linux
- **Target systems:** Designed for Android 8 and later
- **Validated target for this release:** Python 3.12; CI covers Python 3.10–3.13 on Ubuntu and macOS
- **Network use:** Optional; offline analysis is supported with cached tools and IOC data
- **Evidence upload:** None; DroidCustos does not send case data to external services
- **Analysis mode:** Evidence-based and offline-capable; APKs are inspected statically and are never executed

The core workflow uses open-source tools and does not require a paid API or cloud account. MVT,
AndroidQF and ALEAPP are optional managed tools; offline analysis with cached evidence and IOC data
is supported. Network access is used only when the operator explicitly updates tools or public IOC
sources.

Actual coverage depends on the Android version, OEM, device state, available services, user profiles, permissions and whether the device is unlocked.

## Why DroidCustos

Most Android triage workflows require several separate tools and leave the analyst to join the results manually. DroidCustos provides one case structure and one reporting layer around that process.

A normal run can:

- Inspect the device before acquisition.
- Capture volatile system and network state.
- Run AndroidQF.
- Collect complementary ADB diagnostics and a bug report.
- Run MVT against the available evidence.
- Run ALEAPP when installed and suitable input is present.
- Build a normalized multi-user package inventory.
- Correlate packages, certificates, hashes and network observables with STIX indicators.
- Evaluate complete STIX boolean expressions without splitting related observables into independent matches.
- Separate confirmed IOC matches from heuristic alerts.
- Inspect acquired APKs statically, including hashes, DEX/native libraries, signing entries, manifest metadata and suspicious capabilities.
- Record verified-boot, SELinux, patch-level, ADB, root, owner/profile and special-access evidence as a separate security posture.
- Build a unified timeline.
- Measure host/device clock offset, round-trip time and timestamp uncertainty.
- Report acquisition coverage by source, domain and visible Android user.
- Hash and verify the original evidence.
- Generate JSON, Markdown, CSV and searchable offline HTML reports.
- Seal a case with Ed25519.
- Export a case as an authenticated encrypted archive with bounded, safe import extraction.

<img width="842" height="207" alt="DroidCustos command-line output" src="https://github.com/user-attachments/assets/4db2aa4d-8938-4384-9535-14478cbb4c14" />

## Intended use

DroidCustos can support authorized, consent-based examinations carried out by:

- Mobile-forensics and DFIR practitioners.
- Incident-response, SOC and CSIRT teams.
- Journalists and newsrooms responding to suspected mobile surveillance.
- Human-rights organizations and digital-security help desks.
- Corporate security and internal-investigation teams.
- Researchers and educators working with controlled devices or test data.
- Legal teams and expert witnesses preparing a technical triage record.
- Public-sector investigators handling cooperative or victim-support examinations.

Use DroidCustos only on devices and data you are allowed to examine.

MVT and AndroidQF are governed by the MVT License 1.1, which requires explicit consent from the person whose data is extracted or analyzed. Legal authority and third-party license compliance are separate requirements.

See:

- [Third-party tools and licenses](THIRD_PARTY.md)
- [Legal and ethical use](docs/LEGAL-AND-ETHICAL-USE.md)

## What DroidCustos does

- Validates ADB-connected devices.
- Discovers Android version, SDK, build, OEM, users, profiles, storage roots and available services.
- Captures volatile process, route, socket and logging information.
- Runs AndroidQF with explicit acquisition options.
- Collects an Android bug report and complementary ADB artifacts.
- Runs capability-aware core and OEM collectors.
- Builds a normalized package inventory across visible users.
- Acquires APKs when Android allows it.
- Hashes acquired APKs and files.
- Extracts APK signing-certificate data when Android SDK tools are available.
- Performs static APK analysis without executing or unpacking APK content into the host file system.
- Records APK package metadata, permissions, components, exported actions, special capabilities, DEX/native hashes and passive network observables when available.
- Runs MVT against AndroidQF and bug-report evidence.
- Runs ALEAPP when installed and applicable.
- Updates and normalizes public STIX2 indicators.
- Correlates packages, certificates, hashes, domains, URLs and IP addresses using typed, validity-aware STIX expressions.
- Preserves AND/OR indicator semantics and requires AND terms to be observed in the same evidence scope.
- Builds JSON Lines and CSV timelines.
- Produces a separate evidence-only security-state assessment with findings, limitations and a posture score.
- Records acquisition coverage by source, user and analysis domain, including missing critical sources.
- Records host/device time synchronization offset and uncertainty for timestamp interpretation.
- Generates searchable offline HTML reports and complete CSV exports.
- Creates and verifies SHA-256 evidence manifests.
- Creates optional Ed25519 case seals.
- Exports and imports AES-256-GCM encrypted case archives.
- Creates package and device baselines for later comparison.

## Scope and limitations

DroidCustos does not:

- Exploit, root, jailbreak or unlock a device.
- Bypass screen locks, encryption, authentication or application sandboxes.
- Perform a physical acquisition of flash storage.
- Guarantee access to private application databases.
- Guarantee that every profile, Private Space or OEM container is visible.
- Treat every MVT heuristic as a confirmed IOC.
- Prove that a device is compromised simply because an anomaly exists.
- Prove that a device is clean simply because no public IOC was found.
- Provide hardware write blocking.
- Guarantee courtroom admissibility.

ADB authorization, bug-report generation, backup prompts and diagnostic commands can modify limited device state. DroidCustos records its actions but does not claim write-blocked acquisition.

## Quick start

### 1. Install host requirements

#### macOS

```bash
brew install python@3.12 git libusb jq coreutils
brew install --cask android-platform-tools
```

#### Kali Linux, Debian or Ubuntu

```bash
sudo apt update
sudo apt install -y \
  adb \
  git \
  python3 \
  python3-venv \
  python3-pip \
  libusb-1.0-0 \
  sqlite3 \
  openssl
```

### 2. Install DroidCustos

```bash
git clone https://github.com/h3st4k3r/DroidCustos.git
cd DroidCustos
python3 bootstrap.py
```

The bootstrap script creates `.venv`, installs DroidCustos in editable mode and installs MVT in the same environment.

Install or repair the managed tools:

```bash
.venv/bin/droidcustos doctor --fix
```

Optional ALEAPP installation:

```bash
.venv/bin/droidcustos doctor --with-aleapp
```

Check the final environment:

```bash
.venv/bin/droidcustos doctor
```

Run the local regression suite from the same environment:

```bash
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The CI workflow also runs `compileall`, the complete pytest suite, a wheel build and a clean wheel
installation smoke test. It does not connect to an Android device.

### 3. Prepare the Android device

1. Record the visible condition of the device.
2. Avoid rebooting, updating or uninstalling applications unless the response plan requires it.
3. Enable **Developer options**.
4. Enable **USB debugging**.
5. Connect the device with a USB data cable.
6. Select **File transfer** when required by the OEM.
7. Accept the RSA authorization prompt.
8. Keep the device unlocked during acquisition when appropriate.

Validate the connection:

```bash
adb kill-server
adb start-server
adb devices -l
```

The device must appear as `device`, not `unauthorized` or `offline`.

### 4. Inspect before collecting

```bash
cd DroidCustos
source .venv/bin/activate

droidcustos doctor
droidcustos devices
droidcustos inspect --users all
droidcustos update-iocs
```

Review the capability output before collecting private content.

### 5. Run a standard scan

```bash
droidcustos scan \
  --users all \
  --operator "Analyst Name" \
  --case-id CASE-2026-001 \
  --notes "Authorized Android forensic triage" \
  --output ~/DFIR/android-cases
```

A standard scan performs:

```text
Device validation
Capability discovery
Volatile-state capture
AndroidQF acquisition
ADB diagnostics
Android bug report
Core and matching OEM collectors
Package inventory
Static APK analysis
Security-state assessment
Evidence hashing and verification
MVT analysis
Optional ALEAPP analysis
Unified timeline generation
Coverage calculation
Host/device time synchronization measurement
JSON, Markdown, CSV and HTML reporting
```

The following machine-readable artifacts are generated when their source evidence is available:

```text
03_analysis/packages/apk-analysis.json
03_analysis/security-state.json
03_analysis/coverage.json
00_metadata/device.json                # includes time_sync
```

APK analysis is passive: DroidCustos reads ZIP metadata and available manifest/signing-tool output,
calculates hashes and extracts observables, but does not execute APKs. Binary Android manifests are
enriched when `aapt2` is available; the workflow remains usable when optional SDK tools are absent.

## Acquisition profiles

### Balanced AndroidQF acquisition

This profile keeps non-system APKs and attempts intrusion-log collection:

```bash
droidcustos scan \
  --users all \
  --backup none \
  --download non-system \
  --remove-trusted no \
  --intrusion-logs yes \
  --androidqf-hash-files no \
  --operator "Analyst Name" \
  --case-id CASE-2026-001 \
  --output ~/DFIR/android-cases
```

Notes:

- `--backup sms` and `--backup all` can require confirmation on the device and are limited on modern Android releases.
- `--intrusion-logs yes` requires a supported Android version and user interaction on the phone.
- `--androidqf-hash-files yes` can be slow and resource-intensive.
- `--download all` can create a large acquisition.
- `--remove-trusted yes` reduces the output size but removes some downloaded APK evidence.

### Deep scan

```bash
droidcustos scan \
  --deep \
  --users all \
  --operator "Analyst Name" \
  --case-id CASE-2026-001 \
  --output ~/DFIR/android-cases
```

Deep mode attempts to collect additional:

- Socket, route and DNS information.
- Accessible browser artifacts.
- Accessible SMS, notification and chat-related artifacts.
- User-file metadata and hashes from visible shared storage.
- Private databases only when pre-existing authorized root access is already available.

Deep mode does not automatically copy every personal file.

### Granular collection

```bash
droidcustos scan \
  --collect-connections \
  --collect-web \
  --collect-chats \
  --hash-user-files
```

Copy selected visible shared folders:

```bash
droidcustos scan \
  --deep \
  --copy-user-files
```

Use pre-existing authorized root access:

```bash
droidcustos scan \
  --deep \
  --root-mode auto
```

DroidCustos never roots a device or unlocks its bootloader.

## Users and profiles

```bash
# Primary owner only
droidcustos inspect --users primary

# Active users and profiles
droidcustos inspect --users active

# All visible users and profiles
droidcustos inspect --users all

# Explicit user IDs
droidcustos inspect --user 0,10,11
```

Private Space, Secure Folder, work profiles and cloned-app environments can be unavailable when locked or hidden from the shell.

## IOC management

Update public IOC sources and the native MVT store:

```bash
droidcustos update-iocs
```

Use cached indicators in an isolated environment:

```bash
droidcustos scan --no-update
```

Add reviewed STIX sources:

```bash
droidcustos update-iocs \
  --ioc-sources ./config/custom-ioc-sources.yml
```

Example:

```yaml
sources:
  - name: Internal reviewed mobile indicators
    providers:
      - Internal Threat Intelligence
    url: https://example.invalid/mobile-indicators.stix2
```

DroidCustos records source URLs, providers, retrieval metadata, hashes, Git commits where available, STIX validity and source errors.

The native matcher understands typed package, domain, URL, IP, file-hash and certificate-hash
observables, including active validity windows and revoked indicators. Boolean STIX patterns are
kept as expressions: an `AND` expression only matches when all of its terms are present in the
same evidence scope. Unsupported pattern syntax is reported for review instead of being silently
treated as a match.

## Re-analyze an existing case

Use this after updating DroidCustos or its IOC sources:

```bash
droidcustos verify CASE_DIRECTORY
droidcustos update-iocs
droidcustos analyze CASE_DIRECTORY
```

Offline re-analysis:

```bash
droidcustos analyze CASE_DIRECTORY --no-update
```

Re-analysis verifies the original evidence manifest, rebuilds disposable working products and regenerates the reports without intentionally modifying `01_evidence/`.

## Reports

Open the main report:

```bash
open CASE_DIRECTORY/04_reports/report.html       # macOS
xdg-open CASE_DIRECTORY/04_reports/report.html   # Linux
```

Start with:

1. **Verdict and reasons**
2. **Confirmed IOC Evidence**
3. **Principal Findings**
4. **Analysis Engines**
5. **Acquisition Coverage**
6. **Security Posture**
7. **MVT Alerts**
8. **Package Inventory and APK Analysis**
9. **Artifact Inventory**

The security posture is evidence-only and is not a device-compromise verdict. It can include
verified-boot and SELinux state, security-patch age, ADB/root indicators, device/profile ownership,
accessibility and overlay capabilities, sideloading evidence, VPN/proxy/private-DNS state and
special APK capabilities. Missing or unavailable sources are retained as limitations.

Complete machine-readable tables are written to:

```text
CASE_DIRECTORY/04_reports/tables/
```

The HTML dashboard is searchable and remains offline.

## Verdict model

DroidCustos does not label a device as simply “clean”.

Possible verdicts are:

```text
KNOWN IOC MATCHES DETECTED
SUSPICIOUS ARTIFACTS REQUIRE REVIEW
INCONCLUSIVE — FINDINGS REQUIRE REVIEW
NO KNOWN INDICATORS DETECTED
INCONCLUSIVE OR INCOMPLETE ACQUISITION
```

A confirmed IOC requires at least one of the following:

- A non-null MVT `matched_indicator`.
- An exact active STIX match against a package identifier.
- An exact active STIX match against an APK or file hash.
- An exact active STIX match against a signing-certificate hash.
- An exact active STIX match against a domain, URL or IP address.

For compound indicators, all required terms must be observed in the same evidence scope. A match
is also checked against STIX `valid_from`, `valid_until` and `revoked` state. This prevents an
expired, revoked or partially observed expression from being promoted to a confirmed match.

MVT heuristics, unusual permissions, crashes, old security patches and package-state anomalies are reported separately for analyst review.

For a detailed explanation, see [Report interpretation](docs/REPORT-INTERPRETATION.md).

## Evidence integrity

Verify a case:

```bash
droidcustos verify CASE_DIRECTORY
```

Generate an Ed25519 signing keypair:

```bash
droidcustos keygen \
  --private ~/secrets/droidcustos-private.pem \
  --public ~/secrets/droidcustos-public.pem
```

Seal a case:

```bash
droidcustos seal CASE_DIRECTORY \
  --private-key ~/secrets/droidcustos-private.pem
```

Verify the signed seal:

```bash
droidcustos verify CASE_DIRECTORY \
  --public-key ~/secrets/droidcustos-public.pem
```

Keep private signing keys separate from the evidence and the acquisition workstation.

## Encrypted case export

Export a case:

```bash
droidcustos export CASE_DIRECTORY \
  --output CASE_DIRECTORY.dcx
```

Import an archive:

```bash
droidcustos import CASE_DIRECTORY.dcx \
  --output ~/DFIR/imported
```

For controlled automation, use a restricted password file:

```bash
droidcustos export CASE_DIRECTORY \
  --output CASE_DIRECTORY.dcx \
  --password-file ~/secrets/export-password
```

The `.dcx` format uses AES-256-GCM authenticated encryption with PBKDF2-HMAC-SHA256 key derivation.

Store passwords and encrypted archives separately.

## Baselines and change detection

Create a portable baseline:

```bash
droidcustos baseline CASE_DIRECTORY \
  --output ~/DFIR/baselines/device-baseline.json
```

Compare it with a later case:

```bash
droidcustos diff \
  ~/DFIR/baselines/device-baseline.json \
  NEW_CASE_DIRECTORY \
  --output ~/DFIR/comparisons/device-diff.json
```

The comparison can identify:

- Added and removed packages.
- Version changes.
- Installer changes.
- Permission changes.
- Signing-certificate changes.
- APK hash changes when APK data was acquired.

## Case structure

```text
CASE_DIRECTORY/
├── 00_metadata/       Case, device, capability, provenance and custody metadata
├── 01_evidence/       Original acquired evidence
├── 02_working/        Disposable extracted and normalized working copies
├── 03_analysis/       MVT, ALEAPP, APK, package, posture, coverage, heuristic and timeline results
├── 04_reports/        JSON, Markdown, HTML and CSV reports
├── 05_hashes/         Evidence manifest, checksums and optional signed seal
├── 06_exports/        Operator-created exports
└── logs/              Tool output and command logs
```

Original evidence is hashed after acquisition. Working and analysis products can be regenerated from preserved evidence.

Archives received from AndroidQF, ALEAPP or private-artifact workflows are extracted with path,
symlink, file-type, member-count, compression-ratio and total-size checks. Unsafe archives are
rejected before files are written outside the disposable working directory. Case export archives
remain authenticated with AES-256-GCM.

## Integrated and associated tools

| Tool or standard | Role | Installation |
|---|---|---|
| Android Debug Bridge (`adb`) | Device communication, diagnostics, bug reports and controlled acquisition | Installed separately |
| AndroidQF | Logical acquisition of Android forensic artifacts | Managed by `doctor --fix` |
| MVT | Analysis of AndroidQF and bug-report evidence | Installed by `bootstrap.py` or `doctor --fix` |
| MVT Indicators | Public mobile threat-intelligence sources | Updated by `update-iocs` |
| ALEAPP | Optional parsing of Android logs and artifacts | Managed by `doctor --with-aleapp` |
| `apksigner` | APK signing-certificate inspection | Optional Android SDK Build Tools dependency |
| `aapt2` | APK manifest and package metadata enrichment | Optional Android SDK Build Tools dependency |
| STIX 2 | Threat-intelligence representation | Normalized into `ioc.db` |
| SQLite | Local indicator and analysis storage | Provided by Python or the host |
| OpenSSL | Host crypto diagnostics and interoperability | Optional host dependency |

DroidCustos does not bundle AndroidQF, MVT, ALEAPP or Android Platform Tools inside its source release. Managed installation retrieves them from their upstream projects, and each remains governed by its own license.

## Chain of custody

DroidCustos records:

- Case ID, operator and notes.
- UTC timestamps.
- Host and device metadata.
- Commands, timings and return codes.
- Tool paths, versions and local hashes where available.
- IOC sources, providers, commits and hashes.
- Collector status and acquisition coverage.
- SHA-256 hashes for original evidence.
- Evidence-verification results.
- Optional Ed25519 case-seal signatures.

The custody record is stored under:

```text
CASE_DIRECTORY/00_metadata/custody.jsonl
```

See [Chain of custody](docs/CHAIN-OF-CUSTODY.md).

## Validation status

This release includes:

- Automated unit tests.
- Simulated end-to-end workflow tests.
- Report-generation tests.
- Verdict regression tests.
- One documented physical-device run on an ASUS/ROG Android 16 device.

It has not received independent laboratory validation and does not make a claim of evidentiary admissibility in any jurisdiction.

Target environments:

```text
Android 8–16+
macOS Intel
macOS Apple Silicon
Kali Linux
Debian
Ubuntu
```

Support is capability-based. The existence of an OEM plugin does not mean every model and firmware has been physically validated.

See [Compatibility](docs/COMPATIBILITY.md).

## Security and privacy

- Store case directories on encrypted media.
- Restrict file-system permissions.
- Keep signing keys outside case directories.
- Do not upload private acquisitions to public malware scanners or AI services.
- Treat HTML and parsed reports as sensitive.
- Review external tools and IOC sources before using them in restricted environments.
- Use `--no-update` when network access is prohibited.
- Preserve the original evidence before opening artifacts with other tools.

Report vulnerabilities through GitHub Private Vulnerability Reporting. Do not disclose unresolved security issues in a public issue.

See [Security policy](SECURITY.md).

## Troubleshooting

Basic checks:

```bash
droidcustos doctor
adb devices -l
droidcustos inspect --users all
```

Case logs:

```text
CASE_DIRECTORY/logs/androidqf.log
CASE_DIRECTORY/logs/mvt-*.log
CASE_DIRECTORY/logs/aleapp.log
CASE_DIRECTORY/logs/commands.log
```

See [Troubleshooting](docs/TROUBLESHOOTING.md).

## Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python -m pytest
.venv/bin/python -m compileall -q droidcustos tests
```

The development requirements install the package in editable mode together with the test and wheel
build tooling. The test suite covers capability parsing, multi-user discovery, safe archive
extraction, APK analysis, security-state assessment, STIX normalization and boolean matching,
package inventory, timelines, clock synchronization, hashing, signing, encrypted exports, verdict
calculation and report generation.

Every push and pull request runs the suite on Ubuntu and macOS with Python 3.10, 3.11, 3.12 and
3.13. CI also builds a wheel and installs it into a clean virtual environment before running a CLI
smoke test. CI uses no Android device and does not require paid APIs or cloud services.

Contributions must use synthetic or redacted data. Do not submit real case evidence, private indicators, personal identifiers or copyrighted vendor files.

See [Contributing](CONTRIBUTING.md).

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Complete user guide](docs/USER-GUIDE.md)
- [Report interpretation](docs/REPORT-INTERPRETATION.md)
- [Android forensic playbook](docs/ANDROID-PLAYBOOK.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Chain of custody](docs/CHAIN-OF-CUSTODY.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Plugin SDK](docs/PLUGIN-SDK.md)
- [Legal and ethical use](docs/LEGAL-AND-ETHICAL-USE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Third-party tools and licenses](THIRD_PARTY.md)
- [Release notes](RELEASE_NOTES.md)
- [Changelog](CHANGELOG.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md)

## Citation

A machine-readable citation file is available in [CITATION.cff](CITATION.cff).

Please preserve attribution to **h3st4k3r** when redistributing or discussing the project.

## License

DroidCustos source code and original documentation are released under GPL-3.0-or-later.

External tools, IOC sources and dependencies retain their own licenses and terms. See [THIRD_PARTY.md](THIRD_PARTY.md).
