# Changelog

## 0.3.2 - 2026-08-03

- Prepared a clean public-alpha source release with no case data, caches, virtual environments or build products.
- Added complete installation and operator instructions for macOS and Linux.
- Added explicit audience guidance for journalists, civil society, incident responders, DFIR teams, researchers, legal teams and consent-based public-sector examinations.
- Added legal and ethical use documentation, including the MVT License 1.1 consent restriction that applies to MVT and AndroidQF.
- Added report-interpretation, troubleshooting, security, contribution and third-party license documentation.
- Added machine-readable citation metadata and release notes.
- Clarified public-alpha validation status, evidentiary limitations and the distinction between collector execution coverage and forensic depth.

## 0.3.1 - 2026-08-03

- Corrected verdict logic so MVT heuristic detections are never treated as published IOC matches unless `matched_indicator` is populated.
- Corrected MVT log parsing so summary text such as `0 CRITICAL alerts` is not classified as a critical log entry.
- Corrected MVT success handling when a bug-report analysis succeeds without a complete AndroidQF working copy.
- Added `INCONCLUSIVE_WITH_FINDINGS` for incomplete acquisitions containing high-priority non-IOC findings.
- Added a searchable offline HTML forensic dashboard with executive metrics and analyst review tables.
- Added complete CSV exports for findings, confirmed IOC evidence, MVT alerts, acquisition coverage, package inventory, engine status and artifact inventory.
- Added a prioritized findings table that separates confirmed IOC evidence from heuristics and security-hygiene findings.
- Added package and artifact summary tables.
- Corrected Android package parsing for APK paths containing Base64 padding characters.
- Added regression tests for verdict separation, MVT alert parsing, critical-log parsing and package-name integrity.

## 0.3.0 - 2026-08-03

- Added a universal Android capability-discovery engine.
- Added multi-user, work-profile and private-profile awareness.
- Added dynamic storage-volume and shared-root discovery.
- Added capability-aware acquisition planning and coverage scoring.
- Added volatile-state acquisition before long-running tasks.
- Added declarative core and OEM collector plugins.
- Added Google, Samsung, ASUS, Xiaomi, OnePlus, OPPO, Realme, Motorola, Vivo and Huawei plugin definitions.
- Added normalized package inventory, APK hashing and certificate enrichment.
- Added portable package baselines and comparison reports.
- Added optional ALEAPP installation and analysis.
- Added compound STIX pattern parsing and a normalized SQLite IOC database.
- Added STIX source provenance, validity, confidence, revocation, entity and relationship storage.
- Added a unified JSON Lines and CSV forensic timeline.
- Added offline HTML reports.
- Added Ed25519 operator key generation and signed case seals.
- Added authenticated AES-256-GCM encrypted case export and import.
- Added compatibility, plugin, chain-of-custody and Android playbook documentation.
- Added source-policy tests requiring a brief docstring at the start of every function and prohibiting inline source comments.

## 0.2.0 - 2026-08-02

- Renamed the project to DroidCustos.
- Added optional deep acquisition mode.
- Added extended network, browser, messaging and user-file acquisition.
- Added structured custody logging and evidence verification.

## 0.1.0 - 2026-08-02

Initial development release under the former project name.

Author: h3st4k3r
