"""Configuration system for CipherID.

Users can place a `cipherid.json` in their project root or home directory
to customize thresholds, disable ciphers, and add flag format presets.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CipherConfig:
    # Auto-decode settings
    max_depth: int = 5
    beam_width: int = 3

    # Confidence thresholds
    min_confidence: float = 0.3

    # Disabled ciphers by ID
    disabled_ciphers: list[str] = field(default_factory=list)

    # Custom flag format presets (name -> pattern)
    flag_presets: dict[str, str] = field(default_factory=lambda: {
        "flag": "flag{}",
        "CTF": "CTF{}",
        "DASCTF": "DASCTF{}",
    })


_CONFIG_CACHE: CipherConfig | None = None


def _validate_config(data: dict) -> bool:
    """Validate config data structure. Returns True if valid."""
    if not isinstance(data, dict):
        return False
    if "max_depth" in data:
        v = data["max_depth"]
        if not isinstance(v, int) or v < 1 or v > 20:
            return False
    if "beam_width" in data:
        v = data["beam_width"]
        if not isinstance(v, int) or v < 1 or v > 10:
            return False
    if "min_confidence" in data:
        v = data["min_confidence"]
        if not isinstance(v, (int, float)) or v < 0 or v > 1:
            return False
    if "disabled_ciphers" in data:
        v = data["disabled_ciphers"]
        if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
            return False
    if "flag_presets" in data:
        v = data["flag_presets"]
        if not isinstance(v, dict):
            return False
    return True


def _find_config_file() -> Path | None:
    candidates = [
        Path("cipherid.json"),
        Path.home() / ".cipherid.json",
    ]
    xdg_config = os.environ.get("XDG_CONFIG_HOME")
    if xdg_config:
        candidates.append(Path(xdg_config) / "cipherid" / "config.json")
    for p in candidates:
        if p.is_file():
            return p
    return None


def load_config(force: bool = False) -> CipherConfig:
    global _CONFIG_CACHE
    if _CONFIG_CACHE is not None and not force:
        return _CONFIG_CACHE

    config = CipherConfig()
    path = _find_config_file()
    if path is None:
        _CONFIG_CACHE = config
        return config

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        _CONFIG_CACHE = config
        return config

    # Validate config structure before applying
    if not _validate_config(data):
        _CONFIG_CACHE = config
        return config

    if "max_depth" in data:
        config.max_depth = int(data["max_depth"])
    if "beam_width" in data:
        config.beam_width = int(data["beam_width"])
    if "min_confidence" in data:
        config.min_confidence = float(data["min_confidence"])
    if "disabled_ciphers" in data:
        config.disabled_ciphers = list(data["disabled_ciphers"])
    if "flag_presets" in data:
        config.flag_presets.update(data["flag_presets"])

    _CONFIG_CACHE = config
    return config


def get_default_config_path() -> Path:
    return Path.cwd() / "cipherid.json"


def write_default_config(path: Path | None = None) -> Path:
    path = path or get_default_config_path()
    config = CipherConfig()
    data = {
        "max_depth": config.max_depth,
        "beam_width": config.beam_width,
        "min_confidence": config.min_confidence,
        "disabled_ciphers": config.disabled_ciphers,
        "flag_presets": config.flag_presets,
    }
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
