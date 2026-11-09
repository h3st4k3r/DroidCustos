# Chain of Custody

Author: h3st4k3r

DroidCustos implements a practical logical-acquisition chain of custody. It does not claim hardware write blocking or physical imaging.

## Records

The case stores:

- Case identifier.
- Operator.
- UTC timestamps.
- Host metadata.
- Device serial and build metadata.
- Acquisition profile.
- Device capabilities and acquisition plan.
- Every executed command and return code.
- Tool paths, versions and known hashes.
- IOC sources, URLs, commits and hashes.
- Collector outcomes.
- Evidence SHA-256 manifests.
- Hash-chained custody events with explicit legacy-chain reporting.
- Integrity-verification results.
- Optional signed case seals.

## Evidence lifecycle

```text
Acquire
Record provenance
Hash originals
Verify hashes
Remove write permissions
Create working copies
Analyze working copies
Generate reports
Hash-chain custody events
Sign the complete case seal
Optionally export with authenticated encryption
```

Every new custody event contains the hash of the previous event and its own SHA-256 event hash.
The verifier reports any broken link and distinguishes older unchained records from a complete
chain. The Ed25519 case seal covers all regular files present in the case except the seal JSON and
detached signature themselves; the evidence manifest remains the authoritative file-level hash
record for original evidence.

Once a final seal exists, in-place re-analysis is refused because it would change derived reports
and invalidate the sealed snapshot. Re-analysis should be performed on a verified working copy and
sealed separately.

## Known state changes

The following actions can modify Android state:

- Enabling Developer options.
- Enabling USB debugging.
- Authorizing an ADB host key.
- Executing diagnostic commands.
- Generating a bug report.
- Requesting a backup.
- Requesting Intrusion Logging export.
- Accessing applications or prompts required by AndroidQF.

These actions must be authorized and are logged, but they prevent the acquisition from being described as physically write-blocked.
