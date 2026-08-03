#!/usr/bin/env python3
"""Create a local DroidCustos virtual environment.

Author: h3st4k3r
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path


def run(command: list[str]) -> None:
    """Run one bootstrap command and stop on failure."""
    print("$", " ".join(command))
    subprocess.run(command, check=True)


def main() -> int:
    """Install DroidCustos and MVT into a local environment."""
    root = Path(__file__).resolve().parent
    environment = root / ".venv"
    if not environment.exists():
        venv.EnvBuilder(with_pip=True).create(environment)
    python = environment / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    command = environment / ("Scripts/droidcustos.exe" if sys.platform == "win32" else "bin/droidcustos")
    run([str(python), "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"])
    run([str(python), "-m", "pip", "install", "-e", str(root)])
    run([str(python), "-m", "pip", "install", "--upgrade", "mvt"])
    print()
    print("Installation complete.")
    print(f"Run: {command} doctor --fix")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
