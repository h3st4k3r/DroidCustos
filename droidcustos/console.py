"""Console output helpers.

Author: h3st4k3r
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass


BANNER = r"""
 ____  ____   ___ ___ ____      ____ _   _ ____ _____ ___  ____
|  _ \|  _ \ / _ \_ _|  _ \    / ___| | | / ___|_   _/ _ \/ ___|
| | | | |_) | | | | || | | |  | |   | | | \___ \ | || | | \___ \
| |_| |  _ <| |_| | || |_| |  | |___| |_| |___) || || |_| |___) |
|____/|_| \_\\___/___|____/    \____|\___/|____/ |_| \___/|____/
""".strip("\n")


@dataclass(frozen=True)
class Palette:
    reset: str = "\033[0m"
    bold: str = "\033[1m"
    red: str = "\033[31m"
    green: str = "\033[32m"
    yellow: str = "\033[33m"
    blue: str = "\033[34m"
    cyan: str = "\033[36m"
    gray: str = "\033[90m"


P = Palette()
USE_COLOR = sys.stdout.isatty() and os.getenv("NO_COLOR") is None


def _paint(text: str, color: str) -> str:
    """Apply terminal color when supported."""
    return f"{color}{text}{P.reset}" if USE_COLOR else text


def banner() -> None:
    """Print the project identity banner."""
    print(_paint(BANNER, P.cyan))
    print("Universal Android Forensic Acquisition and Threat Hunting")
    print("Author: h3st4k3r\n")


def info(message: str) -> None:
    """Print an informational console message."""
    print(f"{_paint('[*]', P.blue)} {message}")


def success(message: str) -> None:
    """Print a successful console message."""
    print(f"{_paint('[+]', P.green)} {message}")


def warning(message: str) -> None:
    """Print a warning console message."""
    print(f"{_paint('[!]', P.yellow)} {message}")


def error(message: str) -> None:
    """Print an error console message."""
    print(f"{_paint('[-]', P.red)} {message}", file=sys.stderr)


def heading(message: str) -> None:
    """Print a visible workflow heading."""
    print(f"\n{_paint(message, P.bold)}")


def verdict(message: str, level: str) -> None:
    """Print the final conservative verdict."""
    color = {
        "detected": P.red,
        "suspicious": P.yellow,
        "clear": P.green,
        "inconclusive": P.gray,
    }.get(level, P.bold)
    print("\n" + _paint(f"VERDICT: {message}", color))
