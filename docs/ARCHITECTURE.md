# DroidCustos Architecture

Author: h3st4k3r

```text
Authorized Android device
          |
          v
Capability discovery
SDK / ROM / users / profiles / storage / services / permissions
          |
          v
Acquisition plan
          |
          +--> Volatile state
          +--> AndroidQF
          +--> ADB diagnostics and bug report
          +--> Core and OEM plugins
          +--> Package inventory
          +--> Optional deep acquisition
          |
          v
Original evidence manifest
SHA-256 / custody log / command log / tool provenance
          |
          v
Evidence sealing and immediate verification
          |
          v
Working copies
          |
          +--> MVT
          +--> ALEAPP
          +--> APK and certificate analysis
          +--> Extended browser and chat parsers
          +--> IOC correlation
          +--> Unified timeline
          |
          v
Coverage-aware verdict
          |
          +--> JSON report
          +--> Markdown report
          +--> Offline HTML report
          +--> Optional Ed25519 case seal
          +--> Optional AES-256-GCM export
```

## Trust boundaries

DroidCustos treats the Android device, public intelligence feeds and external forensic tools as separate trust boundaries.

The device is accessed only through explicit ADB authorization and optional pre-existing authorized root access. Public intelligence is stored separately from evidence and recorded with source metadata. External tools are invoked through recorded commands, and their paths and available provenance are included in the case.

## Original and working data

`01_evidence` contains acquired originals. `02_working` contains extracted or copied material used during analysis. `03_analysis` contains generated findings and timelines.

The evidence manifest is created before analytical enrichment. Original evidence is made read-only after hashing. Re-analysis verifies the manifest and operates on working products.

## Capability model

The capability model records:

- Android version and SDK.
- Manufacturer, model and ROM family.
- Users and profiles.
- Shared and removable storage candidates.
- Available shell commands.
- Available `dumpsys` and `cmd` services.
- Content-provider probe results.
- Root binary and authorized-root status.
- Intrusion Logging capability estimate.

The acquisition plan uses this information to select compatible collectors and record unsupported ones.

## Plugin model

OEM plugins are declarative YAML files packaged with the project. They do not contain Python code and cannot be downloaded from IOC feeds.

Each plugin command is executed as a fixed argument list after local placeholder expansion for ADB path, serial and user ID.

## Intelligence model

STIX bundles are normalized into SQLite. Original STIX files remain available for MVT. The database stores observable type, value, source, confidence, validity, revocation state, entities and relationships.

## Conclusion model

A direct IOC match takes precedence over acquisition gaps. In the absence of a match, evidence integrity, AndroidQF completion, MVT success, IOC availability and acquisition coverage influence the conclusion.

Coverage below sixty percent results in an inconclusive conclusion.
