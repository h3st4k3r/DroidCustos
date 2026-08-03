# Complete User Guide

Author: h3st4k3r  
Applies to: DroidCustos 0.3.2

## 1. Prepare and document authorization

Before connecting a device:

- Obtain explicit data-owner consent.
- Confirm that the intended use complies with applicable law and organizational policy.
- Confirm compliance with the licenses of MVT, AndroidQF, ALEAPP and indicator sources.
- Record the case reference, operator, date, device condition and scope outside the tool.
- Decide whether private content, APK copies, shared files or existing root access are in scope.

## 2. Prepare the workstation

```bash
cd DroidCustos
source .venv/bin/activate

droidcustos doctor
```

Create evidence storage:

```bash
mkdir -p ~/DFIR/android-cases
chmod 700 ~/DFIR ~/DFIR/android-cases
```

Synchronize indicators before the examination when network policy allows:

```bash
droidcustos update-iocs
```

## 3. Prepare the device

- Photograph or record the initial physical state when required.
- Record the displayed date and time.
- Avoid installing updates or removing applications.
- Enable Developer options and USB debugging.
- Connect with a data-capable USB cable.
- Accept the RSA host authorization.

```bash
adb devices -l
```

## 4. Inspect before acquisition

```bash
droidcustos inspect --users all
```

Save inspection output:

```bash
droidcustos inspect \
  --users all \
  --output pre-acquisition-capabilities.json
```

Review:

- User and profile IDs.
- Shared-storage roots.
- Android and security patch versions.
- Manufacturer and ROM family.
- Root indicators.
- Available services.
- Planned collectors.
- Expected private-data limitations.

## 5. Choose an acquisition profile

### Minimal standard triage

```bash
droidcustos scan \
  --users all \
  --backup none \
  --download non-system \
  --remove-trusted no \
  --intrusion-logs no \
  --operator "Analyst Name" \
  --case-id CASE-001 \
  --output ~/DFIR/android-cases
```

### Spyware-response triage

```bash
droidcustos scan \
  --users all \
  --backup none \
  --download non-system \
  --remove-trusted no \
  --intrusion-logs yes \
  --operator "Digital Security Team" \
  --case-id CONSENT-001 \
  --output ~/DFIR/android-cases
```

### Deep authorized examination

```bash
droidcustos scan \
  --deep \
  --users all \
  --backup none \
  --download all \
  --remove-trusted no \
  --intrusion-logs yes \
  --operator "Forensic Analyst" \
  --case-id LAB-001 \
  --output /Volumes/EncryptedEvidence/android-cases
```

### Existing authorized root

```bash
droidcustos scan \
  --deep \
  --root-mode auto \
  --users all \
  --operator "Forensic Analyst" \
  --case-id ROOTED-001
```

Use `--root-mode require` only when the examination must fail if pre-existing root cannot be used.

## 6. Monitor the acquisition

Keep the device available for:

- RSA authorization.
- Backup authorization when selected.
- Android Intrusion Logging interaction when selected.
- OEM prompts.

Do not disconnect the device until DroidCustos has produced the final report paths or explicitly reports a failed acquisition.

## 7. Immediate post-acquisition actions

Set the case variable:

```bash
CASE="$HOME/DFIR/android-cases/CASE_DIRECTORY"
```

Verify evidence:

```bash
droidcustos verify "$CASE"
```

Open the report:

```bash
open "$CASE/04_reports/report.html"
```

Review logs if any engine is partial or failed:

```bash
find "$CASE/logs" -type f -maxdepth 1 -print
```

## 8. Interpret results conservatively

### Confirmed IOC

A confirmed IOC is an exact active indicator match or a populated MVT `matched_indicator`. Validate:

- Indicator source and campaign.
- Matched value.
- Evidence path.
- Timestamp.
- Package identity and signing certificate.
- Whether the artifact could be historical, cached or user-supplied.

### MVT heuristic

A heuristic is a lead, not a confirmed compromise. Common examples include:

- Risky permissions.
- Unusual process crashes.
- Package install/uninstall history.
- Anomalous timestamps.
- Root or boot-state observations.

### Incomplete acquisition

An incomplete acquisition can still contain useful evidence, but a negative result cannot exclude compromise. Identify which evidence classes are absent.

## 9. Re-analysis

After new indicators or parser improvements:

```bash
droidcustos verify "$CASE"
droidcustos update-iocs
droidcustos analyze "$CASE"
```

Use cached intelligence:

```bash
droidcustos analyze "$CASE" --no-update
```

Compare the regenerated report with the preserved original report according to organizational procedure.

## 10. Baseline workflow

Create a baseline after a trusted setup or first examination:

```bash
droidcustos baseline "$CASE" \
  --output ~/DFIR/baselines/device.json
```

After a later scan:

```bash
droidcustos diff \
  ~/DFIR/baselines/device.json \
  "$NEW_CASE" \
  --output ~/DFIR/comparisons/device-change.json
```

Review signing-certificate and installer changes before ordinary version changes.

## 11. Seal and archive

Generate keys once in controlled storage:

```bash
droidcustos keygen \
  --private /secure-keys/droidcustos-private.pem \
  --public /secure-keys/droidcustos-public.pem
```

Seal:

```bash
droidcustos seal "$CASE" \
  --private-key /secure-keys/droidcustos-private.pem
```

Verify:

```bash
droidcustos verify "$CASE" \
  --public-key /secure-keys/droidcustos-public.pem
```

Export:

```bash
droidcustos export "$CASE" \
  --output "$CASE.dcx"
```

Store the encrypted export, password, signing private key and public verification material according to separate custody controls.

## 12. Close the examination

- Record the final custodian and storage location outside the tool.
- Preserve the original case directory read-only where possible.
- Preserve tool versions and indicator manifests.
- Revoke ADB authorization and disable USB debugging when appropriate.
- Do not reset or remediate the device until preservation requirements are satisfied.
- Escalate confirmed or high-confidence findings to a qualified mobile-forensics laboratory.
