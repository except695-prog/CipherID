"""Cipher base class + result types.

Every detector / decoder is a subclass of :class:`Cipher`. A cipher reports
candidate matches with a confidence score and (optionally) decoded plaintext.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class Candidate:
    """One identification result."""
    cipher_id: str
    name: str             # short human-readable name
    category: str         # encoding / classical / hash / modern / esoteric / chinese / token
    confidence: float     # 0.0 - 1.0
    decoded: str | None = None    # plaintext if decode succeeded
    key: str | None = None        # key/shift used to decode if applicable
    notes: str = ""               # extra info ("looks like base64 of jpeg", "key length 5", ...)
    references: list[str] = field(default_factory=list)


@dataclass
class DecodeResult:
    """Final decode pipeline output (may chain multiple ciphers)."""
    final_plaintext: str
    chain: list[Candidate]
    flag_match: str | None = None  # extracted flag if flag_format matched


class Cipher(ABC):
    """Subclass to add a new cipher / encoding detector."""

    id: str = ""
    name: str = ""
    category: str = "encoding"

    @abstractmethod
    def identify(self, text: str) -> list[Candidate]:
        """Return zero or more candidate matches for the input."""

    def decode(self, text: str, key: str | None = None) -> str | None:
        """Best-effort decode. Return None if not decodable without a key."""
        return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        """Encode plaintext using this cipher. Return None if not supported."""
        return None
