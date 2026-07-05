"""Shared statistical / structural helpers used across detectors."""
from __future__ import annotations

import math
import re
import string
from collections import Counter

ENGLISH_FREQ = {
    "a": 0.082, "b": 0.015, "c": 0.028, "d": 0.043, "e": 0.127, "f": 0.022,
    "g": 0.020, "h": 0.061, "i": 0.070, "j": 0.002, "k": 0.008, "l": 0.040,
    "m": 0.024, "n": 0.067, "o": 0.075, "p": 0.019, "q": 0.001, "r": 0.060,
    "s": 0.063, "t": 0.091, "u": 0.028, "v": 0.010, "w": 0.024, "x": 0.002,
    "y": 0.020, "z": 0.001,
}


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


def chi_square_english(s: str) -> float:
    """Lower means closer to English letter frequency."""
    letters = [c for c in s.lower() if c.isalpha() and ord(c) < 128]
    if not letters:
        return 1e9
    n = len(letters)
    counts = Counter(letters)
    chi = 0.0
    for ch in string.ascii_lowercase:
        observed = counts.get(ch, 0)
        expected = ENGLISH_FREQ[ch] * n
        chi += (observed - expected) ** 2 / max(expected, 1e-6)
    return chi


def looks_like_english(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c in string.printable)
    if printable / len(s) < 0.9:
        return False
    if not re.search(r"[a-zA-Z]", s):
        return False
    return chi_square_english(s) < 200


def looks_like_chinese(s: str) -> bool:
    cjk = sum(1 for c in s if "一" <= c <= "鿿")
    return cjk > 0 and cjk / max(len(s), 1) > 0.3


def is_printable_text(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\n\r\t")
    return printable / len(s) > 0.85


def charset_of(s: str) -> set[str]:
    return set(s)


def stripped(s: str) -> str:
    """Strip whitespace and common delimiters."""
    return s.strip().strip("\n\r\t ")
