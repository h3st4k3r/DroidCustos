# Troubleshooting

Author: h3st4k3r  
Applies to: DroidCustos 0.3.2

## `adb devices -l` shows no device

- Confirm USB debugging is enabled.
- Use a USB data cable, not a charge-only cable.
- Select File transfer where required.
- Connect directly without a hub.
- Unlock the device.
- Reconnect and accept the RSA prompt.

```bash
adb kill-server
adb start-server
adb devices -l
```

On macOS, confirm physical USB detection:

```bash
system_profiler SPUSBDataType | grep -i -A15 -E 'Android|ASUS|Samsung|Google|Xiaomi|OnePlus|OPPO|Vivo|Motorola|Huawei'
```

## Device is `unauthorized`

Revoke USB debugging authorizations on the device, disable and re-enable USB debugging, reconnect and accept the new RSA fingerprint.

## Device is `offline`

```bash
adb reconnect
adb kill-server
adb start-server
adb devices -l
```

## Python executable not found

macOS Homebrew Python 3.12:

```bash
brew install python@3.12
"$(brew --prefix python@3.12)/bin/python3.12" --version
```

Run bootstrap explicitly:

```bash
"$(brew --prefix python@3.12)/bin/python3.12" bootstrap.py
```

## `mvt-android` not found

Activate the environment:

```bash
source .venv/bin/activate
which droidcustos
which mvt-android
```

Install or update MVT:

```bash
python -m pip install --upgrade mvt
```

## AndroidQF incomplete or encrypted

Review:

```bash
CASE=/path/to/case
cat "$CASE/00_metadata/androidqf-status.json"
tail -n 200 "$CASE/logs/androidqf.log"
find "$CASE/01_evidence/androidqf" -maxdepth 2 -type f -print
```

A `.zip.age` file requires the corresponding age private key. AndroidQF creates encrypted output when a `key.txt` recipient file is present in its working directory or next to the executable.

An incomplete AndroidQF acquisition does not invalidate independently collected ADB artifacts, but the final verdict should remain inconclusive when important evidence is missing.

## MVT analysis failed

Review:

```bash
find "$CASE/logs" -name 'mvt-*.log' -print
for LOG in "$CASE"/logs/mvt-*.log; do
  echo "===== $LOG ====="
  tail -n 100 "$LOG"
done
```

Confirm:

```bash
mvt-android --version
mvt-android download-iocs
```

## ALEAPP not installed

```bash
droidcustos doctor --with-aleapp
droidcustos doctor
```

## `apksigner` or `aapt2` unavailable

Install Android SDK Build Tools and add the selected build-tools directory to `PATH`. The scan can continue without them, but certificate and APK metadata coverage will be reduced.

## Evidence verification failed

Stop analysis and do not overwrite the case. Record the failure, compare the current evidence tree with `05_hashes/evidence-manifest.json`, restore a verified copy if available and investigate storage or handling changes.

## Report says `INCONCLUSIVE`

Read `Verdict Reasons`, `Analysis Engines`, `Acquisition Coverage` and `Artifact Inventory`. Inconclusive is expected when AndroidQF is incomplete, private data is inaccessible or analysis engines fail.
