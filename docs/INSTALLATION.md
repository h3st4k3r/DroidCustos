# Installation Guide

Author: h3st4k3r  
Applies to: DroidCustos 0.3.2

## 1. Deployment model

DroidCustos uses a project-local Python virtual environment and a managed cache:

```text
DroidCustos/.venv/                  Python environment and MVT
~/.cache/droidcustos/bin/          Managed AndroidQF executable
~/.cache/droidcustos/tools/ALEAPP/ Managed ALEAPP clone and isolated environment
~/.cache/droidcustos/stix/         STIX bundles, manifest and ioc.db
```

Cases should be written to a separate encrypted evidence location.

## 2. Recommended Python

Python 3.12 is the recommended deployment version for this release. Python 3.10 and later are accepted by DroidCustos, but external tool compatibility can differ.

Do not remove another system Python version. Install 3.12 in parallel and invoke it explicitly.

## 3. macOS installation

### 3.1 Identify architecture

```bash
uname -m
sw_vers
```

Typical results:

```text
arm64   Apple Silicon
x86_64  Intel
```

### 3.2 Install dependencies

```bash
brew install python@3.12 git libusb jq coreutils
brew install --cask android-platform-tools
```

Verify:

```bash
"$(brew --prefix python@3.12)/bin/python3.12" --version
adb version
git --version
```

### 3.3 Optional Android SDK Build Tools

```bash
brew install --cask temurin
brew install --cask android-commandlinetools
```

Locate `sdkmanager`:

```bash
SDKMANAGER="$(brew --prefix)/share/android-commandlinetools/cmdline-tools/latest/bin/sdkmanager"
"$SDKMANAGER" --version
```

Install build tools:

```bash
yes | "$SDKMANAGER" --licenses
"$SDKMANAGER" \
  "platform-tools" \
  "build-tools;36.0.0" \
  "platforms;android-36"
```

Add the selected build-tools directory to `PATH` when `apksigner` and `aapt2` are required.

### 3.4 Install DroidCustos

```bash
cd ~/Downloads
unzip DroidCustos-0.3.2.zip
cd DroidCustos
"$(brew --prefix python@3.12)/bin/python3.12" bootstrap.py
```

Install managed tools:

```bash
.venv/bin/droidcustos doctor --fix
.venv/bin/droidcustos doctor --with-aleapp
.venv/bin/droidcustos doctor
```

## 4. Kali, Debian and Ubuntu installation

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
  openssl \
  unzip
```

Install:

```bash
unzip DroidCustos-0.3.2.zip
cd DroidCustos
python3 bootstrap.py
.venv/bin/droidcustos doctor --fix
.venv/bin/droidcustos doctor --with-aleapp
.venv/bin/droidcustos doctor
```

## 5. Wheel installation

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install droidcustos-0.3.2-py3-none-any.whl
.venv/bin/droidcustos doctor --fix
```

The wheel contains DroidCustos only. It does not contain ADB, MVT, AndroidQF or ALEAPP.

## 6. Evidence storage

Create a restricted directory:

```bash
mkdir -p ~/DFIR/android-cases
chmod 700 ~/DFIR ~/DFIR/android-cases
```

Prefer a dedicated encrypted volume. Estimate storage conservatively when downloading APKs or copying shared files.

## 7. Verify installation

```bash
source .venv/bin/activate

droidcustos --version
droidcustos doctor
droidcustos devices
```

Expected version:

```text
DroidCustos 0.3.2 by h3st4k3r
```

## 8. Offline or controlled-network installation

In a connected staging environment:

1. Download the DroidCustos release and verify its checksum.
2. Create the virtual environment.
3. Install all Python wheels into a local wheelhouse.
4. Run `doctor --fix` and `doctor --with-aleapp` only after reviewing upstream provenance.
5. Copy the complete project, virtual environment and managed cache to the controlled workstation according to organizational policy.
6. Run `droidcustos doctor` and record tool versions.
7. Use `--no-update` during acquisition and re-analysis.

Managed cache paths can be overridden:

```bash
droidcustos doctor --cache /controlled/tool-cache
```

## 9. Upgrade from 0.3.1

Preserve the previous source tree and virtual environment:

```bash
cd ~/Downloads
mv DroidCustos DroidCustos-0.3.1-backup
unzip DroidCustos-0.3.2.zip
mv DroidCustos-0.3.1-backup/.venv DroidCustos/.venv
cd DroidCustos
.venv/bin/python -m pip install --no-deps --upgrade --editable .
.venv/bin/droidcustos --version
```

Existing cases remain separate and can be re-analyzed:

```bash
droidcustos verify CASE_DIRECTORY
droidcustos analyze CASE_DIRECTORY --no-update
```

## 10. Removal

Remove the project environment:

```bash
rm -rf DroidCustos/.venv
```

Remove managed external tools and indicators only when no active case depends on their provenance records:

```bash
rm -rf ~/.cache/droidcustos
```

Do not remove case directories, signing keys or encrypted exports unless retention policy explicitly authorizes destruction.
