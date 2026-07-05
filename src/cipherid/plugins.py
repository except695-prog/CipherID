"""Plugin system for CipherID.

Allows users to add custom cipher detectors without modifying source code.
Plugins are Python modules that export a list of Cipher instances.

Plugin locations (searched in order):
  1. $CIPHERID_PLUGINS_DIR environment variable
  2. ~/.cipherid/plugins/
  3. ./cipherid_plugins/ (project local)

Each plugin module must define:
  CIPHERS: list[Cipher]  — list of Cipher instances to register
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cipherid.cipher import Cipher

_PLUGIN_DIRS: list[Path] = []


def get_plugin_dirs() -> list[Path]:
    """Return directories to search for plugins."""
    global _PLUGIN_DIRS
    if _PLUGIN_DIRS:
        return _PLUGIN_DIRS

    dirs = []

    # Environment variable
    env_dir = os.environ.get("CIPHERID_PLUGINS_DIR")
    if env_dir:
        dirs.append(Path(env_dir))

    # User plugin directory
    home = Path.home()
    dirs.append(home / ".cipherid" / "plugins")

    # Project-local plugin directory
    dirs.append(Path.cwd() / "cipherid_plugins")

    _PLUGIN_DIRS = [d for d in dirs if d.exists() or d.parent.exists()]
    return _PLUGIN_DIRS


def load_plugins() -> list["Cipher"]:
    """Load all plugins from plugin directories."""
    from cipherid.cipher import Cipher

    ciphers: list[Cipher] = []
    plugin_dirs = get_plugin_dirs()

    for plugin_dir in plugin_dirs:
        if not plugin_dir.exists():
            continue
        for py_file in plugin_dir.glob("*.py"):
            if py_file.name.startswith("_"):
                continue
            try:
                module = _load_module(py_file)
                if hasattr(module, "CIPHERS"):
                    for cipher in module.CIPHERS:
                        if isinstance(cipher, Cipher):
                            ciphers.append(cipher)
            except Exception:
                continue

    return ciphers


def _load_module(path: Path):
    """Load a Python module from file path."""
    module_name = f"cipherid_plugin_{path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module
