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
Optionally sign the final case seal
Optionally export with authenticated encryption
```

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
