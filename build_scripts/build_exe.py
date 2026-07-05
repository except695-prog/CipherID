"""Build a single-file GUI executable with PyInstaller.

Usage:
    pip install -e ".[dev]"
    python build_scripts/build_exe.py

The resulting binary lands in `dist/CipherID(.exe)`.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "build_scripts" / "cipherid.spec"
DIST = ROOT / "dist"
BUILD = ROOT / "build"


def main() -> int:
    if DIST.exists():
        shutil.rmtree(DIST)
    if BUILD.exists():
        shutil.rmtree(BUILD)
    cmd = [sys.executable, "-m", "PyInstaller", "--clean", str(SPEC)]
    print("Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    sys.exit(main())
