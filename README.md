```text
 ____  ____   ___ ___ ____      ____ _   _ ____ _____ ___  ____
|  _ \|  _ \ / _ \_ _|  _ \    / ___| | | / ___|_   _/ _ \/ ___|
| | | | |_) | | | | || | | |  | |   | | | \___ \ | || | | \___ \
| |_| |  _ <| |_| | || |_| |  | |___| |_| |___) || || |_| |___) |
|____/|_| \_\\___/___|____/    \____|\___/|____/ |_| \___/|____/
```
[![Status](https://img.shields.io/badge/status-public%20alpha-F59E0B)](./RELEASE_NOTES.md)
[![License](https://img.shields.io/badge/license-see%20LICENSE-001538)](./LICENSE)
[![Language](https://img.shields.io/badge/language-Python%203.10%2B-3776AB?logo=python&logoColor=white)](./pyproject.toml)
[![Security](https://img.shields.io/badge/security-responsible%20disclosure-001538)](./SECURITY.md)
[![Author](https://img.shields.io/badge/author-h3st4k3r-111827?logo=github&logoColor=white)](https://github.com/h3st4k3r)

<img width="1566" height="909" alt="output-report-html-sample" src="https://github.com/user-attachments/assets/37dcfc22-590c-4239-8079-3ad33a489cb8" />

# DroidCustos

**Android forensic acquisition, evidence preservation, threat hunting and IOC correlation.**

- **Author:** h3st4k3r
- **Version:** 0.3.2
- **Status:** Public alpha
- **License:** GPL-3.0-or-later
- **Host platforms:** macOS and Linux
- **Target platform:** Android 8 and later, capability-dependent

DroidCustos is a command-line orchestrator for authorized Android forensic triage. It combines capability discovery, AndroidQF acquisition, ADB diagnostics, MVT analysis, optional ALEAPP parsing, OEM-aware collectors, package inventory, STIX threat intelligence, unified timelines, integrity manifests, signed case seals and encrypted case exports.

<img width="842" height="207" alt="output-sample" src="https://github.com/user-attachments/assets/4db2aa4d-8938-4384-9535-14478cbb4c14" />

The project is intended to make repeatable mobile-forensic triage accessible to investigators who need transparent evidence handling and readable reports without hiding the underlying artifacts.

> **Important:** DroidCustos is not a physical-imaging tool, a hardware write blocker, a commercial mobile-forensics replacement or a guarantee of courtroom admissibility. It is a logical acquisition and analysis orchestrator whose results must be interpreted by a qualified analyst.

## Intended users

DroidCustos can support authorized, consent-based work performed by:

- Journalists and newsrooms responding to suspected mobile surveillance.
- Human-rights defenders, civil-society organizations and digital-security help desks.
- Incident responders, SOC and CSIRT teams.
- Corporate security and internal investigations teams.
- Mobile-forensics and DFIR practitioners.
- Researchers and educators working with controlled devices or test datasets.
- Legal teams and expert witnesses preparing a technical triage record.
- Law-enforcement and public-sector investigators in cooperative or victim-support cases where the device owner gives explicit consent and all applicable laws, procedures and third-party licenses are satisfied.

### Consent and third-party license restriction

DroidCustos itself is GPL-3.0-or-later. However, its standard workflow integrates **MVT** and **AndroidQF**, which are distributed under the **MVT License 1.1** and include a consensual-use restriction. Their use requires the explicit consent of the person whose data is extracted or analyzed.

A warrant, organizational ownership or another legal authority does not automatically replace the consent requirement imposed by those third-party licenses. Operators are responsible for verifying both legal authority and license compliance before use. See [THIRD_PARTY.md](THIRD_PARTY.md) and [docs/LEGAL-AND-ETHICAL-USE.md](docs/LEGAL-AND-ETHICAL-USE.md).

## What DroidCustos does

- Detects and validates ADB-connected Android devices.
- Discovers Android version, SDK, ROM, manufacturer, users, profiles, storage roots and available services.
- Captures volatile state before longer acquisition steps.
- Runs AndroidQF with explicit acquisition options.
- Collects complementary ADB diagnostics and an Android bug report.
- Runs core and OEM-aware collectors only when their prerequisites match.
- Builds a normalized multi-user package inventory.
- Acquires and hashes APKs when available.
- Extracts APK signing-certificate hashes when Android SDK tools are available.
- Runs MVT against AndroidQF and bug-report artifacts.
- Runs ALEAPP when installed and suitable input exists.
- Updates and normalizes public STIX2 indicator feeds.
- Correlates packages, certificates, hashes, domains, URLs and IP addresses with active indicators.
- Separates confirmed IOC matches from heuristic alerts.
- Builds a unified JSON Lines and CSV timeline.
- Generates JSON, Markdown, CSV and searchable offline HTML reports.
- Creates SHA-256 evidence manifests and verifies them immediately.
- Creates optional Ed25519 signed case seals.
- Exports and imports authenticated AES-256-GCM encrypted case archives.
- Creates portable device/package baselines and compares later states.

## What DroidCustos does not do

- It does not exploit, root, jailbreak or unlock a device.
- It does not bypass screen locks, encryption, app sandboxes or user authentication.
- It does not perform a physical acquisition of flash storage.
- It does not guarantee access to private application databases.
- It does not automatically prove that a device is compromised or uncompromised.
- It does not treat every MVT heuristic as a confirmed IOC.
- It does not replace analyst review, legal process, laboratory validation or independent verification.
- It does not upload evidence to external services.

## Verdict model

DroidCustos never reports a device as simply “clean”. The possible conclusions are:

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

MVT heuristic detections, suspicious permissions, crashes, old security patches and unusual package states are reported separately for review.

## Integrated and associated tools

| Tool or standard | Role in DroidCustos | Installation behavior |
|---|---|---|
| Android Debug Bridge (`adb`) | Device communication, diagnostics, bug reports and controlled file acquisition | Installed separately through Android Platform Tools or the host package manager |
| AndroidQF | Portable logical acquisition of Android forensic artifacts | Downloaded by `doctor --fix` into the managed cache |
| MVT | AndroidQF and bug-report analysis against mobile threat indicators | Installed into the active Python environment by `bootstrap.py` or `doctor --fix` |
| MVT Indicators | Public STIX2 mobile threat-intelligence index | Updated by `update-iocs` |
| ALEAPP | Optional parsing of Android logs, events and protobuf artifacts | Cloned into an isolated managed environment by `doctor --with-aleapp` |
| `apksigner` | APK signing-certificate inspection | Optional Android SDK Build Tools dependency |
| `aapt2` | APK manifest and package metadata enrichment | Optional Android SDK Build Tools dependency |
| OpenSSL | Host crypto diagnostics and interoperability | Optional host dependency |
| STIX 2 | Threat-intelligence representation and normalization | Parsed into DroidCustos `ioc.db` |
| SQLite | Local normalized IOC and analysis data | Provided by Python or the operating system |

DroidCustos does not bundle MVT, AndroidQF, ALEAPP or Android Platform Tools inside its source release. Managed installation retrieves them from their upstream projects. Each remains governed by its own license and release process.

## Installation overview

### Minimum requirements

- Python 3.10–3.13 recommended. Python 3.12 is the validated deployment target for this release.
- Git.
- Android Platform Tools containing `adb`.
- A USB data cable.
- An Android device with USB debugging enabled and explicitly authorized.
- Encrypted host storage with enough free capacity for the expected acquisition.

Optional:

- Android SDK Build Tools containing `apksigner` and `aapt2`.
- ALEAPP.
- `age` for manually decrypting AndroidQF `.zip.age` acquisitions.
- A dedicated evidence volume and separate signing-key storage.

### macOS

Install Homebrew if it is not already available, then:

```bash
brew install python@3.12 git libusb jq coreutils
brew install --cask android-platform-tools
```

Optional SDK tooling:

```bash
brew install --cask temurin
brew install --cask android-commandlinetools
```

Install Android build tools with `sdkmanager` when certificate and APK metadata enrichment is required.

### Kali Linux, Debian or Ubuntu

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

### Install from a source release

```bash
unzip DroidCustos-0.3.2.zip
cd DroidCustos
python3 bootstrap.py
```

The bootstrap script creates `.venv`, installs DroidCustos in editable mode and installs MVT in that environment.

Then run:

```bash
.venv/bin/droidcustos doctor --fix
.venv/bin/droidcustos doctor --with-aleapp
.venv/bin/droidcustos doctor
```

### Install from the wheel

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install droidcustos-0.3.2-py3-none-any.whl
.venv/bin/droidcustos doctor --fix
```

Detailed platform instructions are in [docs/INSTALLATION.md](docs/INSTALLATION.md).

## Verify a downloaded release

Place the release files and checksum file in the same directory:

```bash
shasum -a 256 -c DroidCustos-0.3.2.SHA256SUMS.txt
```

GNU systems can use:

```bash
sha256sum -c DroidCustos-0.3.2.SHA256SUMS.txt
```

Only continue when every downloaded artifact reports `OK`.

## Prepare the Android device

1. Record the device condition, displayed time, battery level, SIM state and visible notifications.
2. Avoid rebooting, updating, uninstalling applications or resetting the device unless the response plan explicitly requires it.
3. Enable Developer options by tapping **Build number** seven times.
4. Enable **USB debugging**.
5. Connect the device using a USB data cable.
6. Select **File transfer** if required by the manufacturer.
7. Accept the RSA authorization prompt on the device.
8. Keep the device unlocked during acquisition when operationally appropriate.

Validate connectivity:

```bash
adb kill-server
adb start-server
adb devices -l
```

The device must appear with state `device`, not `unauthorized` or `offline`.

## First-run workflow

```bash
cd DroidCustos
source .venv/bin/activate

droidcustos doctor
droidcustos devices
droidcustos inspect --users all
droidcustos update-iocs
```

Review the capability output before collecting private content.

## Standard forensic scan

```bash
droidcustos scan \
  --users all \
  --operator "Analyst Name" \
  --case-id CASE-2026-001 \
  --notes "Authorized mobile forensic triage" \
  --output ~/DFIR/android-cases
```

The standard workflow performs:

```text
Device selection and authorization validation
Capability discovery
Volatile process and network-state capture
AndroidQF acquisition
Complementary ADB diagnostics
Android bug-report acquisition
Core and matching OEM collectors
Package inventory
Evidence hashing and verification
MVT analysis
Optional ALEAPP execution
Unified timeline generation
Coverage calculation
JSON, Markdown, CSV and offline HTML reporting
```

## Recommended AndroidQF options

A balanced acquisition that keeps non-system APKs and attempts intrusion logs:

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

- `--backup sms` and `--backup all` can require confirmation on the device and are severely limited on modern Android versions.
- `--intrusion-logs yes` requires supported Android versions and user interaction on the phone.
- `--androidqf-hash-files yes` can be resource-intensive.
- `--download all` can create a very large acquisition.
- `--remove-trusted yes` reduces size but removes some downloaded APK evidence.

## Deep forensic scan

```bash
droidcustos scan \
  --deep \
  --users all \
  --operator "Analyst Name" \
  --case-id CASE-2026-001 \
  --output ~/DFIR/android-cases
```

Deep mode enables additional attempts to collect:

- Extended sockets, routes, DNS state and network diagnostics.
- Accessible browser metadata and history artifacts.
- Accessible SMS, notifications and chat-related artifacts.
- User-file metadata and hashes across visible shared storage.
- Private databases only when pre-existing authorized root access already exists.

Deep mode does not automatically copy all personal files.

### Granular privacy-sensitive options

```bash
droidcustos scan \
  --collect-connections \
  --collect-web \
  --collect-chats \
  --hash-user-files
```

Copy selected visible shared folders only when required by case scope:

```bash
droidcustos scan \
  --deep \
  --copy-user-files
```

Use existing root access only when it was already present and explicitly authorized:

```bash
droidcustos scan \
  --deep \
  --root-mode auto
```

DroidCustos never roots a device or unlocks its bootloader.

## User and profile selection

```bash
# Primary owner only
droidcustos inspect --users primary

# Active users and profiles
droidcustos inspect --users active

# Every visible user/profile
droidcustos inspect --users all

# Explicit IDs
droidcustos inspect --user 0,10,11
```

Private Space, Secure Folder, work profiles and cloned-app environments may be unavailable when locked or hidden from the shell.

## IOC management

Update public sources and the native MVT store:

```bash
droidcustos update-iocs
```

Use cached indicators in an isolated or offline environment:

```bash
droidcustos scan --no-update
```

Add reviewed authorized STIX sources:

```bash
droidcustos update-iocs \
  --ioc-sources ./config/custom-ioc-sources.yml
```

Example source configuration:

```yaml
sources:
  - name: Internal reviewed mobile indicators
    providers:
      - Internal Threat Intelligence
    url: https://example.invalid/mobile-indicators.stix2
```

DroidCustos records source URL, provider, retrieval metadata, SHA-256, Git commit where applicable, STIX validity and source errors.

## Re-analyze an existing case

After updating DroidCustos or threat intelligence:

```bash
droidcustos verify CASE_DIRECTORY
droidcustos update-iocs
droidcustos analyze CASE_DIRECTORY
```

Offline re-analysis:

```bash
droidcustos analyze CASE_DIRECTORY --no-update
```

Re-analysis verifies the original evidence manifest, rebuilds disposable working products and regenerates reports without intentionally modifying the original evidence directory.

## Read the report

Open:

```bash
open CASE_DIRECTORY/04_reports/report.html       # macOS
xdg-open CASE_DIRECTORY/04_reports/report.html   # Linux desktop
```

Start with:

1. **Verdict and reasons** — overall interpretation and limitations.
2. **Confirmed IOC Evidence** — exact threat-intelligence matches only.
3. **Principal Findings** — prioritized analyst-review items.
4. **Analysis Engines** — which engines ran and whether they succeeded.
5. **Acquisition Coverage** — collected, partial, denied, unsupported and failed sources.
6. **MVT Alerts** — heuristics separated from confirmed indicators.
7. **Package Inventory** — complete multi-user package records.
8. **Artifact Inventory** — what data classes were actually acquired.

Complete machine-readable tables are written under:

```text
04_reports/tables/
```

The report interpretation guide is [docs/REPORT-INTERPRETATION.md](docs/REPORT-INTERPRETATION.md).

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

Sign an existing case:

```bash
droidcustos seal CASE_DIRECTORY \
  --private-key ~/secrets/droidcustos-private.pem
```

Verify the signed seal:

```bash
droidcustos verify CASE_DIRECTORY \
  --public-key ~/secrets/droidcustos-public.pem
```

Keep the private signing key separate from the evidence and acquisition workstation.

## Encrypted case export

Export interactively:

```bash
droidcustos export CASE_DIRECTORY \
  --output CASE_DIRECTORY.dcx
```

Import:

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

The `.dcx` format uses AES-256-GCM authenticated encryption and PBKDF2-HMAC-SHA256 key derivation. Store passwords and archives separately.

## Baselines and change detection

Create a portable baseline:

```bash
droidcustos baseline CASE_DIRECTORY \
  --output ~/DFIR/baselines/device-baseline.json
```

Compare with a later case or baseline:

```bash
droidcustos diff \
  ~/DFIR/baselines/device-baseline.json \
  NEW_CASE_DIRECTORY \
  --output ~/DFIR/comparisons/device-diff.json
```

The comparison detects package additions/removals, versions, installers, permissions, signing-certificate changes and APK hash changes when those fields were acquired.

## Case directory

```text
CASE_DIRECTORY/
├── 00_metadata/       Case, device, capability, provenance and custody metadata
├── 01_evidence/       Original acquired evidence
├── 02_working/        Disposable extracted and normalized working copies
├── 03_analysis/       MVT, ALEAPP, package, heuristic and timeline results
├── 04_reports/        JSON, Markdown, HTML and complete CSV tables
├── 05_hashes/         Evidence manifest, checksums and optional signed seal
├── 06_exports/        Operator-created exports
└── logs/              Command, tool stdout and tool stderr logs
```

Original evidence is hashed after acquisition. Working and analysis products can be regenerated from preserved evidence.

## Operational use cases

### Journalist or civil-society triage

Recommended approach:

```bash
droidcustos inspect --users all
droidcustos scan \
  --users all \
  --download non-system \
  --intrusion-logs yes \
  --operator "Digital Security Team" \
  --case-id CONSENT-001
```

Preserve written consent, minimize copied personal content and encrypt the case immediately.

### Corporate incident response

Use only on organization-managed devices when employee notice, consent, policy and applicable law permit the acquisition. Record the exact scope in `--notes`. Create a baseline for repeatable fleet or executive-device comparisons.

### Law-enforcement or public-sector victim support

DroidCustos can support cooperative examinations where the data owner explicitly consents. Preserve the consent record outside the tool, record the operator and case reference, verify the manifest, create a signed seal and export an encrypted archival copy.

Do not use MVT or AndroidQF in non-consensual examinations merely because another legal basis exists; their license separately requires data-owner consent.

### DFIR laboratory validation

Use controlled devices and known test artifacts to validate each OEM, firmware and Android version. Record the build fingerprint, tool versions, coverage states, output hashes and expected findings.

## Chain of custody

DroidCustos records:

- Case identifier, operator and notes.
- UTC timestamps.
- Host and device metadata.
- Every executed command with timing and return code.
- Tool path, version, release metadata and local SHA-256 where available.
- Indicator sources, commits, providers and hashes.
- Collector states and acquisition coverage.
- SHA-256 for original evidence files.
- Evidence-verification results.
- Optional Ed25519 case-seal signatures.

ADB authorization, bug-report generation, backup prompts and diagnostic commands can modify limited device state. DroidCustos records actions but does not claim write-blocked acquisition.

## Support and validation status

The project targets:

```text
Android 8–16+
macOS Intel
macOS Apple Silicon
Kali Linux
Debian
Ubuntu
```

Support is capability-based. An OEM plugin means that matching collectors exist; it does not mean every model and firmware has been physically validated.

This release has:

- Automated unit and simulated workflow tests.
- One documented physical-device run on an ASUS/ROG Android 16 device.
- No independent laboratory validation.
- No declaration of evidentiary admissibility in any jurisdiction.
- No stable Windows support declaration.

See [docs/COMPATIBILITY.md](docs/COMPATIBILITY.md).

## Troubleshooting

Common diagnostics:

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

Common issues and recovery procedures are documented in [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

## Security and privacy

- Store cases on encrypted media.
- Restrict case-directory permissions.
- Do not place signing private keys in case directories.
- Do not upload private acquisitions to public malware scanners or AI services.
- Treat HTML and parsed reports as sensitive because they can expose applications, accounts, messages, browsing records and identifiers.
- Review external tools and indicator sources before installation in restricted environments.
- Use `--no-update` when network access is prohibited.
- Preserve the original acquisition before opening artifacts with other tools.

Security reporting guidance is in [SECURITY.md](SECURITY.md).

## Development and testing

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -e . pytest
.venv/bin/python -m pytest
.venv/bin/python -m compileall -q droidcustos
```

The test suite covers capability parsing, plugins, STIX normalization, package inventory, timeline generation, hashing, signing, encrypted exports, verdict calculation and report generation.

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Complete user guide](docs/USER-GUIDE.md)
- [Report interpretation](docs/REPORT-INTERPRETATION.md)
- [Legal and ethical use](docs/LEGAL-AND-ETHICAL-USE.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [Android forensic playbook](docs/ANDROID-PLAYBOOK.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Chain of custody](docs/CHAIN-OF-CUSTODY.md)
- [Compatibility](docs/COMPATIBILITY.md)
- [Plugin SDK](docs/PLUGIN-SDK.md)
- [Third-party tools and licenses](THIRD_PARTY.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Citation and attribution

DroidCustos must remain attributed to **h3st4k3r**. A machine-readable citation file is provided in [CITATION.cff](CITATION.cff).

## License

DroidCustos source code and original documentation are released under GPL-3.0-or-later. External tools, indicators and dependencies retain their own licenses and terms. See [THIRD_PARTY.md](THIRD_PARTY.md).
