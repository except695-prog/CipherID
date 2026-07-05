"""All built-in cipher detectors / decoders."""
from __future__ import annotations

from cipherid.cipher import Cipher
from cipherid.ciphers.chinese import CHINESE_CIPHERS
from cipherid.ciphers.classical import CLASSICAL_CIPHERS
from cipherid.ciphers.encodings import ENCODING_CIPHERS
from cipherid.ciphers.esoteric import ESOTERIC_CIPHERS
from cipherid.ciphers.hashes import HASH_CIPHERS
from cipherid.ciphers.modern import MODERN_CIPHERS
from cipherid.ciphers.tokens import TOKEN_CIPHERS

_CIPHER_CACHE: list[Cipher] | None = None
_BUILTIN_COUNT: int = 0


def load_ciphers(include_plugins: bool = True) -> list[Cipher]:
    """Load all ciphers, optionally including plugins.

    Args:
        include_plugins: If True, also load external plugins.
    """
    global _CIPHER_CACHE, _BUILTIN_COUNT

    builtins = [
        *ENCODING_CIPHERS,
        *CLASSICAL_CIPHERS,
        *ESOTERIC_CIPHERS,
        *HASH_CIPHERS,
        *TOKEN_CIPHERS,
        *MODERN_CIPHERS,
        *CHINESE_CIPHERS,
    ]
    _BUILTIN_COUNT = len(builtins)

    if not include_plugins:
        return list(builtins)

    if _CIPHER_CACHE is not None:
        return _CIPHER_CACHE

    try:
        from cipherid.plugins import load_plugins
        plugins = load_plugins()
    except Exception:
        plugins = []

    _CIPHER_CACHE = builtins + plugins
    return _CIPHER_CACHE


def get_builtin_count() -> int:
    """Return the number of built-in ciphers (excludes plugins)."""
    return _BUILTIN_COUNT


__all__ = ["load_ciphers", "get_builtin_count"]
