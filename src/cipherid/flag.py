"""Flag format extraction.

Users can specify a format like 'flag{...}', 'CTF{...}', or a custom regex.
"""
from __future__ import annotations

import re

DEFAULT_FORMATS = [
    "flag{.*?}",
    "FLAG{.*?}",
    "Flag{.*?}",
    "CTF{.*?}",
    "ctf{.*?}",
    "[A-Za-z0-9_]+CTF\\{.*?\\}",
    "[A-Za-z0-9_]+ctf\\{.*?\\}",
    "DASCTF\\{.*?\\}",
    "hkcert\\{.*?\\}",
    "rwctf\\{.*?\\}",
    "n1ctf\\{.*?\\}",
    "0ops\\{.*?\\}",
]


def compile_flag_pattern(user_format: str | None) -> re.Pattern[str]:
    """Compile a flag-format pattern.

    - None or empty: use the default broad union.
    - 'flag{}', 'CTF{}', 'xxx{}': treat as a prefix template; body becomes `.+?`.
    - Anything containing regex metachars: used as a raw regex.
    """
    if not user_format:
        return re.compile("|".join(DEFAULT_FORMATS), re.IGNORECASE)
    user_format = user_format.strip()
    # Simple template like 'flag{}' / 'CTF{}'
    m = re.match(r"^([A-Za-z0-9_]+)\{\s*\}$", user_format)
    if m:
        prefix = m.group(1)
        return re.compile(rf"{re.escape(prefix)}\{{.+?\}}", re.IGNORECASE)
    # Otherwise treat as regex (escape only if no metacharacters)
    try:
        return re.compile(user_format, re.IGNORECASE)
    except re.error:
        return re.compile(re.escape(user_format), re.IGNORECASE)


def find_flag(text: str, pattern: re.Pattern[str]) -> str | None:
    m = pattern.search(text)
    return m.group(0) if m else None
