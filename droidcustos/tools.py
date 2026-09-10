"""External tool discovery and managed dependency installation.

Author: h3st4k3r
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import stat
import tempfile
import urllib.request
import venv
from dataclasses import asdict, dataclass
from pathlib import Path

from . import __version__
from .archive_safety import safe_extract_tar, safe_extract_zip
from .commands import run_capture


ANDROIDQF_API = "https://api.github.com/repos/mvt-project/androidqf/releases/latest"
ALEAPP_REPOSITORY = "https://github.com/abrignoni/ALEAPP.git"


@dataclass(frozen=True)
class ToolStatus:
    name: str
    path: str | None
    version: str | None
    provenance: dict[str, object] | None = None

    @property
    def available(self) -> bool:
        """Return whether the tool is executable or addressable."""
        return self.path is not None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe tool status."""
        return asdict(self)


def executable_status(name: str, version_args: list[str] | None = None) -> ToolStatus:
    """Inspect an executable available on the host path."""
    path = shutil.which(name)
    if not path:
        return ToolStatus(name, None, None)
    args = [path] + (version_args or ["--version"])
    result = run_capture(args, timeout=20)
    version = (result.stdout or result.stderr).strip().splitlines()
    provenance = {"sha256": sha256_file(Path(path))} if Path(path).is_file() else None
    return ToolStatus(name, path, version[0] if version else None, provenance)


def sha256_file(path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Calculate SHA-256 for one managed tool file."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def default_cache_dir() -> Path:
    """Return the user-scoped DroidCustos cache directory."""
    return Path(os.getenv("XDG_CACHE_HOME", Path.home() / ".cache")) / "droidcustos"


def find_androidqf(cache_dir: Path | None = None) -> Path | None:
    """Locate AndroidQF on the host or managed cache."""
    path = shutil.which("androidqf")
    if path:
        return Path(path)
    candidate = (cache_dir or default_cache_dir()) / "bin" / "androidqf"
    return candidate if candidate.is_file() and os.access(candidate, os.X_OK) else None


def find_aleapp(cache_dir: Path | None = None) -> tuple[Path, Path] | None:
    """Locate a managed ALEAPP checkout and interpreter."""
    cache = cache_dir or default_cache_dir()
    root = cache / "tools" / "ALEAPP"
    script = root / "aleapp.py"
    python = root / ".venv" / "bin" / "python"
    if os.name == "nt":
        python = root / ".venv" / "Scripts" / "python.exe"
    if script.is_file() and python.is_file():
        return python, script
    return None


def _github_json(url: str) -> dict[str, object]:
    """Download JSON from the GitHub API with explicit client identity."""
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": f"DroidCustos/{__version__} (h3st4k3r)",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(request, timeout=45) as response:
        return json.load(response)


def _asset_score(name: str) -> int:
    """Rank AndroidQF release assets for the current host."""
    lowered = name.lower()
    if any(token in lowered for token in ("checksum", "sha256", ".sig", "sbom", "source")):
        return -1000
    system = platform.system().lower()
    machine = platform.machine().lower()
    score = 0
    if system == "darwin":
        if any(token in lowered for token in ("darwin", "macos", "mac")):
            score += 60
        if any(token in lowered for token in ("universal", "all")):
            score += 25
    elif system == "linux":
        if "linux" in lowered:
            score += 60
    else:
        return -1000
    architecture_tokens = {
        "x86_64": ("x86_64", "amd64", "x64"),
        "amd64": ("x86_64", "amd64", "x64"),
        "arm64": ("arm64", "aarch64", "universal", "all"),
        "aarch64": ("arm64", "aarch64"),
    }.get(machine, (machine,))
    if any(token in lowered for token in architecture_tokens):
        score += 35
    if "androidqf" in lowered:
        score += 20
    if lowered.endswith((".tar.gz", ".tgz", ".zip")):
        score += 5
    return score


def _download(url: str, destination: Path) -> None:
    """Download a managed dependency to a temporary path."""
    request = urllib.request.Request(url, headers={"User-Agent": f"DroidCustos/{__version__} (h3st4k3r)"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)


def _extract_androidqf(archive: Path, target_dir: Path) -> Path:
    """Safely extract an AndroidQF release archive."""
    extract_dir = target_dir / "extract"
    if extract_dir.exists():
        shutil.rmtree(extract_dir)
    extract_dir.mkdir(parents=True)
    lowered = archive.name.lower()
    if lowered.endswith(".zip"):
        safe_extract_zip(archive, extract_dir)
    elif lowered.endswith((".tar.gz", ".tgz", ".tar")):
        safe_extract_tar(archive, extract_dir)
    else:
        candidate = extract_dir / "androidqf"
        shutil.copy2(archive, candidate)
        return candidate
    candidates = [path for path in extract_dir.rglob("*") if path.is_file() and path.name.lower() in {"androidqf", "androidqf.exe"}]
    if not candidates:
        candidates = [path for path in extract_dir.rglob("*") if path.is_file() and "androidqf" in path.name.lower()]
    if not candidates:
        raise RuntimeError(f"No AndroidQF executable found inside {archive.name}")
    return max(candidates, key=lambda path: path.stat().st_size)


def install_androidqf(cache_dir: Path | None = None) -> tuple[Path, str]:
    """Install the latest compatible AndroidQF release."""
    cache = cache_dir or default_cache_dir()
    bin_dir = cache / "bin"
    download_dir = cache / "downloads"
    bin_dir.mkdir(parents=True, exist_ok=True)
    download_dir.mkdir(parents=True, exist_ok=True)
    release = _github_json(ANDROIDQF_API)
    assets = release.get("assets", []) if isinstance(release, dict) else []
    scored = sorted(((_asset_score(str(asset.get("name", ""))), asset) for asset in assets), key=lambda item: item[0], reverse=True)
    if not scored or scored[0][0] < 50:
        names = ", ".join(str(asset.get("name", "")) for asset in assets)
        raise RuntimeError(f"No compatible AndroidQF release asset found. Available assets: {names}")
    asset = scored[0][1]
    archive = download_dir / str(asset["name"])
    with tempfile.NamedTemporaryFile(dir=download_dir, delete=False) as temporary:
        temporary_path = Path(temporary.name)
    try:
        _download(str(asset["browser_download_url"]), temporary_path)
        digest = asset.get("digest")
        if isinstance(digest, str) and digest.startswith("sha256:"):
            actual = sha256_file(temporary_path)
            if actual != digest.split(":", 1)[1]:
                raise RuntimeError("AndroidQF release SHA-256 verification failed")
        temporary_path.replace(archive)
    finally:
        temporary_path.unlink(missing_ok=True)
    source = _extract_androidqf(archive, download_dir)
    destination = bin_dir / "androidqf"
    shutil.copy2(source, destination)
    destination.chmod(destination.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    provenance = {
        "tag": release.get("tag_name", "unknown"),
        "asset": asset.get("name"),
        "download_url": asset.get("browser_download_url"),
        "sha256": sha256_file(destination),
    }
    (cache / "androidqf-release.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return destination, str(release.get("tag_name", "unknown"))


def install_mvt() -> bool:
    """Install or upgrade MVT in the active Python environment."""
    result = run_capture([os.sys.executable, "-m", "pip", "install", "--upgrade", "mvt"], timeout=900)
    return result.ok


def install_aleapp(cache_dir: Path | None = None) -> tuple[Path, Path]:
    """Install ALEAPP in an isolated managed environment."""
    cache = cache_dir or default_cache_dir()
    root = cache / "tools" / "ALEAPP"
    root.parent.mkdir(parents=True, exist_ok=True)
    if (root / ".git").is_dir():
        update = run_capture(["git", "-C", str(root), "pull", "--ff-only"], timeout=300)
        if not update.ok:
            raise RuntimeError(update.stderr.strip() or "ALEAPP update failed")
    else:
        clone = run_capture(["git", "clone", "--depth", "1", ALEAPP_REPOSITORY, str(root)], timeout=600)
        if not clone.ok:
            raise RuntimeError(clone.stderr.strip() or "ALEAPP clone failed")
    environment = root / ".venv"
    if not environment.exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / "bin" / "python"
    if os.name == "nt":
        python = environment / "Scripts" / "python.exe"
    requirements = root / "requirements.txt"
    if requirements.is_file():
        install = run_capture([str(python), "-m", "pip", "install", "-r", str(requirements)], timeout=1800)
        if not install.ok:
            raise RuntimeError(install.stderr.strip() or "ALEAPP dependency installation failed")
    script = root / "aleapp.py"
    if not script.is_file():
        raise RuntimeError("ALEAPP entry point was not found")
    commit = run_capture(["git", "-C", str(root), "rev-parse", "HEAD"], timeout=30)
    provenance = {"repository": ALEAPP_REPOSITORY, "commit": commit.stdout.strip(), "python": str(python)}
    (cache / "aleapp-release.json").write_text(json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return python, script


def doctor(cache_dir: Path | None = None) -> dict[str, ToolStatus]:
    """Inspect required and optional forensic tooling."""
    cache = cache_dir or default_cache_dir()
    androidqf = find_androidqf(cache)
    aleapp = find_aleapp(cache)
    androidqf_provenance = None
    androidqf_record = cache / "androidqf-release.json"
    if androidqf_record.is_file():
        androidqf_provenance = json.loads(androidqf_record.read_text(encoding="utf-8"))
    aleapp_provenance = None
    aleapp_record = cache / "aleapp-release.json"
    if aleapp_record.is_file():
        aleapp_provenance = json.loads(aleapp_record.read_text(encoding="utf-8"))
    statuses = {
        "adb": executable_status("adb", ["version"]),
        "git": executable_status("git", ["--version"]),
        "mvt-android": executable_status("mvt-android", ["--version"]),
        "androidqf": ToolStatus("androidqf", str(androidqf) if androidqf else None, None, androidqf_provenance),
        "aleapp": ToolStatus("aleapp", str(aleapp[1]) if aleapp else None, None, aleapp_provenance),
        "apksigner": executable_status("apksigner", ["--version"]),
        "aapt2": executable_status("aapt2", ["version"]),
        "openssl": executable_status("openssl", ["version"]),
    }
    return statuses
