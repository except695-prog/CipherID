"""Modern cryptography indicators and lightweight encryptors."""
from __future__ import annotations

import re

from cipherid.cipher import Candidate, Cipher


class AESCipher(Cipher):
    id = "aes_blob"
    name = "Likely AES / block-cipher ciphertext"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[A-Fa-f0-9]+", t) and len(t) % 32 == 0 and len(t) >= 32:
            candidates = []
            candidates.append(Candidate(self.id, "AES-like block (hex, multiple of 16B)",
                                       self.category, 0.55,
                                       notes="needs a key; try AES-CBC/ECB/GCM with known IV"))
            blocks = [t[i:i+32] for i in range(0, len(t), 32)]
            unique = len(set(blocks))
            if len(blocks) > 2 and unique < len(blocks) * 0.8:
                candidates.append(Candidate(
                    "ecb_detect", "Possible AES-ECB (repeated blocks detected)",
                    self.category, 0.7,
                    notes=f"{len(blocks)} blocks, {unique} unique — ECB leaks patterns"))
            return candidates
        return []


class GCMCipher(Cipher):
    id = "gcm_blob"
    name = "AES-GCM blob (with tag)"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[A-Za-z0-9+/=]+", t) and len(t) > 36 and len(t) % 4 == 0:
            return [Candidate(self.id, "Possible AES-GCM (base64 with tag)",
                              self.category, 0.35,
                              notes="if leading 12 bytes are IV and trailing 16 are tag")]
        return []


class RSACipher(Cipher):
    id = "rsa_block"
    name = "Possible RSA ciphertext / modulus"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[0-9]+", t) and len(t) > 200:
            return [Candidate(self.id, "Large decimal integer (RSA n or c?)",
                              self.category, 0.5,
                              notes="try Wiener / Coppersmith / common factor / small e")]
        if re.fullmatch(r"[A-Fa-f0-9]+", t) and len(t) > 256:
            return [Candidate(self.id, "Large hex integer (RSA candidate)",
                              self.category, 0.45)]
        return []


class DSACipher(Cipher):
    id = "dsa_sig"
    name = "DSA signature (DER/PEM)"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[0-9A-Fa-f]+", t) and 80 <= len(t) <= 84:
            return [Candidate(self.id, "Possible DSA signature", self.category, 0.4,
                              notes="40-41 byte hex — could be DSA (r, s pair)")]
        return []


class XorCipher(Cipher):
    """XOR cipher with repeating key — common in CTF."""
    id = "xor"
    name = "XOR cipher"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Hex-encoded XOR output: even length, all hex chars
        if re.fullmatch(r"[0-9A-Fa-f]+", t) and len(t) >= 4 and len(t) % 2 == 0:
            return [Candidate(self.id, "XOR (hex-encoded, needs key)", self.category, 0.3,
                              notes="try single-byte XOR brute force or known-key XOR")]
        # Raw printable XOR: not much to detect
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            # Try hex input
            data = bytes.fromhex(text.strip())
        except ValueError:
            data = text.encode("utf-8")
        key_bytes = key.encode("utf-8") if not all(c in "0123456789abcdefABCDEF" for c in key.strip()) else bytes.fromhex(key.strip())
        result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        try:
            return result.decode("utf-8")
        except UnicodeDecodeError:
            return result.hex()

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        data = text.encode("utf-8")
        key_bytes = key.encode("utf-8") if not all(c in "0123456789abcdefABCDEF" for c in key.strip()) else bytes.fromhex(key.strip())
        result = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
        return result.hex()


class XorBruteForce(Cipher):
    """Single-byte XOR brute force — tries all 256 keys."""
    id = "xor_brute"
    name = "XOR single-byte brute force"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not re.fullmatch(r"[0-9A-Fa-f]+", t) or len(t) % 2 != 0 or len(t) < 4:
            return []
        try:
            data = bytes.fromhex(t)
        except ValueError:
            return []
        best_score = -1.0
        best_key = 0
        best_plain = ""
        for key_byte in range(256):
            decrypted = bytes(b ^ key_byte for b in data)
            try:
                plain = decrypted.decode("utf-8", errors="strict")
            except (UnicodeDecodeError, ValueError):
                continue
            # Score by printable ratio + English letter frequency
            printable = sum(1 for c in plain if c.isprintable() or c in "\n\r\t")
            score = printable / len(plain)
            if score > best_score:
                best_score = score
                best_key = key_byte
                best_plain = plain
        if best_score > 0.8:
            return [Candidate(self.id, f"XOR single-byte (key=0x{best_key:02x}='{chr(best_key) if best_key.isprintable() else '?'}')",
                              self.category, min(0.5 + best_score * 0.4, 0.9),
                              decoded=best_plain, key=f"0x{best_key:02x}")]
        return []


class RC4Cipher(Cipher):
    """RC4 stream cipher — common in CTF, no external deps."""
    id = "rc4"
    name = "RC4 stream cipher"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[0-9A-Fa-f]+", t) and len(t) >= 8 and len(t) % 2 == 0:
            return [Candidate(self.id, "RC4 (hex, needs key)", self.category, 0.25,
                              notes="common stream cipher — try with known plaintext")]
        return []

    @staticmethod
    def _rc4(key: bytes, data: bytes) -> bytes:
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        i = j = 0
        out = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            out.append(byte ^ S[(S[i] + S[j]) % 256])
        return bytes(out)

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            data = bytes.fromhex(text.strip())
        except ValueError:
            data = text.encode("utf-8")
        key_bytes = key.encode("utf-8")
        result = self._rc4(key_bytes, data)
        try:
            return result.decode("utf-8")
        except UnicodeDecodeError:
            return result.hex()

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        data = text.encode("utf-8")
        key_bytes = key.encode("utf-8")
        result = self._rc4(key_bytes, data)
        return result.hex()


class VigenereAutokeyCipher(Cipher):
    """Vigenère autokey variant — key extends with ciphertext."""
    id = "vigenere_autokey"
    name = "Vigenère autokey (ciphertext)"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        ki = 0
        result = []
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)]) - ord('a')
                plain = chr((ord(c.lower()) - ord('a') - k) % 26 + ord('a'))
                result.append(plain)
                key += c.lower()
                ki += 1
            else:
                result.append(c)
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        ki = 0
        result = []
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)]) - ord('a')
                enc = chr((ord(c.lower()) - ord('a') + k) % 26 + ord('a'))
                result.append(enc)
                key += enc
                ki += 1
            else:
                result.append(c)
        return "".join(result)


class HMACCipher(Cipher):
    """HMAC computation — keyed hash for authentication."""
    id = "hmac"
    name = "HMAC"
    category = "modern"

    _ALGORITHMS = {
        "md5": "md5", "sha1": "sha1", "sha256": "sha256",
        "sha224": "sha224", "sha384": "sha384", "sha512": "sha512",
    }

    def identify(self, text: str) -> list[Candidate]:
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        parts = key.split(":", 1)
        algo = parts[0].lower() if len(parts) > 1 else "sha256"
        secret = parts[1] if len(parts) > 1 else parts[0]
        if algo not in self._ALGORITHMS:
            return None
        import hashlib
        import hmac
        h = hmac.new(secret.encode("utf-8"), text.encode("utf-8"), getattr(hashlib, self._ALGORITHMS[algo]))
        return h.hexdigest()


class XorMultiByteBruteForce(Cipher):
    """XOR multi-byte key brute force — tries keys of length 1-8."""
    id = "xor_multibrute"
    name = "XOR 多字节爆破"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not re.fullmatch(r"[0-9A-Fa-f]+", t) or len(t) % 2 != 0 or len(t) < 16:
            return []
        try:
            data = bytes.fromhex(t)
        except ValueError:
            return []
        best_score = -1.0
        best_key = ""
        best_plain = ""
        for klen in range(2, min(9, len(data) // 2 + 1)):
            for key_candidate in self._generate_keys(data[:klen], klen):
                decrypted = bytes(b ^ key_candidate[i % klen] for i, b in enumerate(data))
                try:
                    plain = decrypted.decode("utf-8", errors="strict")
                except (UnicodeDecodeError, ValueError):
                    continue
                printable = sum(1 for c in plain if c.isprintable() or c in "\n\r\t")
                score = printable / len(plain)
                if score > best_score:
                    best_score = score
                    best_key = key_candidate.hex()
                    best_plain = plain
        if best_score > 0.85:
            return [Candidate(self.id, f"XOR multi-byte (key=0x{best_key})",
                              self.category, min(0.5 + best_score * 0.4, 0.9),
                              decoded=best_plain, key=f"0x{best_key}")]
        return []

    @staticmethod
    def _generate_keys(sample: bytes, klen: int):
        """Generate likely key candidates from the first klen bytes."""
        # Try common patterns
        yield sample
        yield bytes(range(klen))
        yield bytes([0x41] * klen)
        for b in range(256):
            yield bytes([b] * klen)


class VigenerePlaintextAutokeyCipher(Cipher):
    """Vigenère autokey variant — key extends with plaintext."""
    id = "vigenere_plain_autokey"
    name = "维吉尼亚 Autokey (明文)"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        ki = 0
        result = []
        full_key = list(key)
        for c in text:
            if c.isalpha():
                k = ord(full_key[ki]) - ord('a')
                plain = chr((ord(c.lower()) - ord('a') - k) % 26 + ord('a'))
                result.append(plain)
                full_key.append(plain)
                ki += 1
            else:
                result.append(c)
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        ki = 0
        result = []
        full_key = list(key)
        for c in text:
            if c.isalpha():
                k = ord(full_key[ki]) - ord('a')
                enc = chr((ord(c.lower()) - ord('a') + k) % 26 + ord('a'))
                result.append(enc)
                full_key.append(c.lower())
                ki += 1
            else:
                result.append(c)
        return "".join(result)


MODERN_CIPHERS = [
    AESCipher(), GCMCipher(), RSACipher(), DSACipher(),
    XorCipher(), XorBruteForce(), RC4Cipher(),
    VigenereAutokeyCipher(), HMACCipher(),
    XorMultiByteBruteForce(), VigenerePlaintextAutokeyCipher(),
]
