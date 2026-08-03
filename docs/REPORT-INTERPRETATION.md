# Report Interpretation Guide

Author: h3st4k3r  
Applies to: DroidCustos 0.3.2

## Executive rule

Read the verdict together with acquisition coverage. A zero-match result has meaning only for the artifacts successfully acquired and analyzed.

## Confirmed IOC Evidence

This table contains only evidence that met the confirmed-indicator rule. Each row should identify:

- Engine.
- Indicator type.
- Matched value.
- Threat or campaign name when available.
- Indicator source.
- Evidence path or record.

A confirmed match is a high-priority lead, not automatic proof that the device is currently compromised. Validate freshness, context, provenance and the possibility of cached or historical content.

## Principal Findings

Principal findings combine:

- Confirmed indicators.
- High-priority integrity anomalies.
- Security-exposure findings.
- Selected MVT heuristics requiring review.

Use severity and classification together. A `MEDIUM MVT HEURISTIC` is not equivalent to a `MEDIUM CONFIRMED IOC`.

## MVT Alerts

MVT alerts are grouped by normalized message and module. Duplicate text and protobuf tombstone forms can be combined into one row with an occurrence count.

Classification:

```text
CONFIRMED_IOC  matched_indicator is non-null
HEURISTIC      no matched indicator; analyst review required
```

## Coverage

Collector execution coverage shows how many planned collectors reached a useful state. It is not the percentage of all possible data on the device.

Interpret states:

```text
COLLECTED          Useful data was acquired
PARTIAL            Some expected data was acquired
EMPTY              Collector ran but returned no records
NOT_PRESENT        Expected feature or path was absent
NOT_SUPPORTED      Device or firmware did not match
PERMISSION_DENIED  Android or OEM controls blocked access
TIMED_OUT          Collection exceeded its limit
FAILED             Execution or parser failure
```

A high execution-coverage score can coexist with limited forensic depth when application-private data is inaccessible.

## Analysis Engines

Review each engine independently:

- **AndroidQF:** Complete, partial, encrypted or failed acquisition.
- **MVT AndroidQF:** Analysis of extracted AndroidQF content.
- **MVT bugreport:** Analysis of Android bug-report archives.
- **ALEAPP:** Optional parsing of supported extraction content.
- **DroidCustos heuristics:** Local evidence-based review rules.
- **Extended analysis:** Browser, messaging, connection and file analysis when enabled and accessible.
- **Unified timeline:** Number of normalized events and IOC-matched events.
- **IOC intelligence:** Source count and retrieval errors.

## Package Inventory

Package records are user-specific. One package can appear once per user or profile.

Important columns:

- Package identifier.
- Android user ID.
- Version code and version name.
- Installer.
- Source path.
- Requested and granted permissions.
- Signing-certificate SHA-256.
- Acquired APK SHA-256.

`null`, shell or unknown installers are common for system packages and are not automatically suspicious.

## Common benign or contextual observations

- System package permissions.
- Chrome or file-manager ability to open APK installation flows.
- Trichrome/WebView package replacement during updates.
- OEM virtualization or trusted-VM process crashes.
- Duplicate records from text and protobuf representations.
- Security patches older than organizational policy.

These can still matter, but they require context rather than automatic escalation.

## Recommended conclusion language

Use:

```text
NO KNOWN INDICATORS DETECTED IN THE ACQUIRED ARTIFACTS
```

Do not use:

```text
The device is clean
The device was never compromised
No spyware is present
```

For incomplete cases:

```text
No known public indicators were identified in the successfully acquired artifacts. The acquisition did not include sufficient private application or other evidence to exclude an indicator-unknown or sophisticated compromise.
```
