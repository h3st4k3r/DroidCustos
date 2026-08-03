# Security Policy

## Supported version

DroidCustos is currently a public alpha. Security fixes are applied to the newest release line only.

## Reporting a vulnerability

After the public repository is created, report security issues through a private GitHub Security Advisory rather than a public issue. Include:

- Affected version.
- Host platform.
- Reproduction steps.
- Security impact.
- Whether evidence integrity, path traversal, command execution, cryptography, secret handling or third-party downloads are affected.
- A minimal non-sensitive proof of concept.

Do not include real case evidence, device identifiers, private IOC feeds, passwords or signing keys.

## High-priority issue classes

- Modification of original evidence after sealing.
- Incorrect evidence-manifest verification.
- Archive path traversal.
- Command injection through device or case metadata.
- Unsafe handling of signing keys or export passwords.
- Cryptographic misuse.
- Unverified third-party executable replacement.
- HTML report injection from untrusted device strings.
- False confirmed-IOC verdicts.

## Operational security

DroidCustos case directories are sensitive. Store them on encrypted media, restrict permissions and do not synchronize them to uncontrolled cloud services.
