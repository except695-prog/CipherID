"""Hash/digest identifiers and computors."""
from __future__ import annotations

import binascii
import hashlib
import re

from cipherid.cipher import Candidate, Cipher

HASH_RULES = [
    # (length, charset_regex, name, confidence, notes)
    (8,  r"^[a-f0-9]{8}$",  "CRC32 / Adler32",          0.7,  ""),
    (16, r"^[a-f0-9]{16}$", "MD4 (128-bit truncated)",   0.65, ""),
    (32, r"^[a-f0-9]{32}$", "MD5 / MD4 / NTLM / LM",   0.85, "32 hex chars — multiple algorithms"),
    (40, r"^[a-f0-9]{40}$", "SHA-1 / RIPEMD-160",       0.9,  ""),
    (56, r"^[a-f0-9]{56}$", "SHA-224",                  0.9,  ""),
    (64, r"^[a-f0-9]{64}$", "SHA-256 / SHA3-256 / BLAKE2s-256", 0.9, ""),
    (96, r"^[a-f0-9]{96}$", "SHA-384 / SHA3-384",       0.9,  ""),
    (128, r"^[a-f0-9]{128}$", "SHA-512 / SHA3-512 / BLAKE2b-512 / Whirlpool", 0.9, ""),
    (128, r"^[a-f0-9]{128}$", "SM3 (Chinese national hash)", 0.85, "国密 SM3"),
]

PREFIX_HASHES = [
    (r"^\$2[aby]\$\d{2}\$.{53}$", "bcrypt", 0.99),
    (r"^\$argon2(?:id|i|d)\$.+", "Argon2", 0.99),
    (r"^\$scrypt\$.+", "scrypt", 0.99),
    (r"^\$1\$[^$]{1,8}\$.{22}$", "MD5 crypt (Unix)", 0.95),
    (r"^\$5\$[^$]+\$.+$", "SHA-256 crypt (Unix)", 0.95),
    (r"^\$6\$[^$]+\$.+$", "SHA-512 crypt (Unix)", 0.95),
    (r"^[A-F0-9]{32}:[A-F0-9]{32}$", "NTLM:LM combined", 0.9),
    (r"^\$pbkdf2[-_]", "PBKDF2", 0.95),
    (r"^\$sha1\$", "SHA-1 crypt", 0.9),
    (r"^\$ml\$", "Apple iCloud keychain", 0.9),
]

# Specific 32-hex hash discrimination (when possible)
HASH_32_VARIANTS = [
    (r"^[a-f0-9]{32}$", "MD5", 0.85, "128-bit"),
    (r"^[a-f0-9]{32}$", "MD4", 0.7, "128-bit, predecessor of MD5"),
    (r"^[a-f0-9]{32}$", "NTLM", 0.7, "Windows password hash"),
    (r"^[a-f0-9]{32}$", "LM", 0.65, "LAN Manager hash (legacy)"),
]


class HashIdentifier(Cipher):
    id = "hash"
    name = "Hash / digest"
    category = "hash"

    _ALGORITHMS = {
        "md4": "md4", "md5": "md5", "sha1": "sha1",
        "sha224": "sha224", "sha256": "sha256",
        "sha384": "sha384", "sha512": "sha512",
        "sha3_224": "sha3_224", "sha3_256": "sha3_256",
        "sha3_384": "sha3_384", "sha3_512": "sha3_512",
        "blake2b": "blake2b", "blake2s": "blake2s",
        "ripemd160": "ripemd160",
    }

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        out: list[Candidate] = []
        for length, pattern, label, conf, notes in HASH_RULES:
            if len(t) == length and re.fullmatch(pattern, t.lower()):
                out.append(Candidate(self.id, label, self.category, conf,
                                     decoded=None, notes=notes))
        for pattern, label, conf in PREFIX_HASHES:
            if re.fullmatch(pattern, t):
                out.append(Candidate(self.id, label, self.category, conf,
                                     decoded=None, notes="modular crypt format"))
        return out

    def encode(self, text: str, key: str | None = None) -> str | None:
        algo = (key or "md5").lower().strip()
        if algo not in self._ALGORITHMS:
            return None
        factory, _ = self._ALGORITHMS[algo]
        h = factory()
        h.update(text.encode("utf-8"))
        return h.hexdigest()


class TigerHashIdentifier(Cipher):
    """Tiger hash: 192-bit (48 hex chars) or 128/160-bit variants."""
    id = "tiger_hash"
    name = "Tiger hash"
    category = "hash"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) == 48 and re.fullmatch(r"[a-f0-9]{48}", t.lower()):
            return [Candidate(self.id, "Tiger (192-bit)", self.category, 0.8,
                              notes="192-bit hash by Anderson et al.")]
        if len(t) == 40 and re.fullmatch(r"[a-f0-9]{40}", t.lower()):
            return [Candidate(self.id, "Tiger (160-bit)", self.category, 0.6,
                              notes="160-bit Tiger variant")]
        return []


class KeccakIdentifier(Cipher):
    """Keccak/SHA-3 family detection."""
    id = "keccak"
    name = "Keccak / SHA-3"
    category = "hash"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Keccak outputs: 224, 256, 384, 512 bits
        keccak_sizes = {28: "Keccak-224", 32: "Keccak-256", 48: "Keccak-384", 64: "Keccak-512"}
        size_bytes = len(t) // 2
        if size_bytes in keccak_sizes and re.fullmatch(r"[a-f0-9]+", t.lower()):
            label = keccak_sizes[size_bytes]
            return [Candidate(self.id, label, self.category, 0.7,
                              notes="Keccak (pre-standard SHA-3)")]
        return []


class SM3Identifier(Cipher):
    """SM3: Chinese national standard hash (256-bit = 64 hex)."""
    id = "sm3"
    name = "SM3 (国密)"
    category = "hash"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) == 64 and re.fullmatch(r"[a-f0-9]{64}", t.lower()):
            return [Candidate(self.id, "SM3 (Chinese national standard)", self.category, 0.6,
                              notes="256-bit — same output size as SHA-256")]
        return []


class CRC32Identifier(Cipher):
    """CRC32 checksum detection and computation."""
    id = "crc32"
    name = "CRC32"
    category = "hash"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) == 8 and re.fullmatch(r"[0-9a-f]{8}", t.lower()):
            return [Candidate(self.id, "CRC32 / Adler32", self.category, 0.7,
                              notes="32-bit checksum")]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        data = text.encode("utf-8")
        return format(binascii.crc32(data) & 0xFFFFFFFF, "08x")


HASH_CIPHERS = [HashIdentifier(), TigerHashIdentifier(), KeccakIdentifier(), SM3Identifier(), CRC32Identifier()]
