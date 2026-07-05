"""Encoding-class ciphers: base*, hex, url, morse, ascii85, uu, html, etc."""
from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import urllib.parse

from cipherid.cipher import Candidate, Cipher
from cipherid.heuristics import is_printable_text, looks_like_chinese, looks_like_english

# -----------------------------------------------------------
# Base families
# -----------------------------------------------------------

class Base64Cipher(Cipher):
    id = "base64"
    name = "Base64"
    category = "encoding"
    aliases = ["b64"]
    _re = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().replace("\n", "").replace(" ", "")
        if len(t) < 4 or len(t) % 4 != 0 or not self._re.match(t):
            return []
        try:
            decoded = base64.b64decode(t, validate=True)
        except (binascii.Error, ValueError):
            return []
        plain = self._safe_decode(decoded)
        if plain is None:
            return []
        conf = 0.75
        if looks_like_english(plain) or looks_like_chinese(plain):
            conf = 0.95
        return [Candidate(self.id, self.name, self.category, conf, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return self._safe_decode(base64.b64decode(text.strip().replace("\n", "").replace(" ", "")))
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return base64.b64encode(text.encode("utf-8")).decode("ascii")
        except Exception:
            return None

    @staticmethod
    def _safe_decode(data: bytes) -> str | None:
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            try:
                return data.decode("latin-1")
            except Exception:
                return None


class Base64UrlCipher(Cipher):
    id = "base64url"
    name = "Base64 URL-safe"
    category = "encoding"
    _re = re.compile(r"^[A-Za-z0-9_\-]+={0,2}$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or not self._re.match(t):
            return []
        if "-" not in t and "_" not in t:
            return []
        try:
            decoded = base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))
            plain = decoded.decode("utf-8", errors="replace")
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.8, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            t = text.strip()
            return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4)).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")
        except Exception:
            return None


class Base32Cipher(Cipher):
    id = "base32"
    name = "Base32"
    category = "encoding"
    _re = re.compile(r"^[A-Z2-7]+={0,6}$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().upper().replace("\n", "").replace(" ", "")
        if len(t) < 8 or len(t) % 8 != 0 or not self._re.match(t):
            return []
        try:
            decoded = base64.b32decode(t)
            plain = decoded.decode("utf-8", errors="replace")
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.85, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return base64.b32decode(text.strip().upper().replace(" ", "")).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return base64.b32encode(text.encode("utf-8")).decode("ascii")
        except Exception:
            return None


class Base16Cipher(Cipher):
    id = "base16"
    name = "Base16 (Hex)"
    category = "encoding"
    _re = re.compile(r"^[0-9A-Fa-f]+$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().replace(" ", "").replace("0x", "").replace("\n", "")
        if len(t) < 4 or len(t) % 2 != 0 or not self._re.match(t):
            return []
        try:
            decoded = bytes.fromhex(t)
            plain = decoded.decode("utf-8", errors="replace")
        except Exception:
            return []
        conf = 0.7
        if is_printable_text(plain):
            conf = 0.9
        return [Candidate(self.id, self.name, self.category, conf, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return bytes.fromhex(text.strip().replace(" ", "").replace("0x", "")).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return text.encode("utf-8").hex()
        except Exception:
            return None


class Base85Cipher(Cipher):
    id = "base85"
    name = "Base85 (RFC1924)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 5:
            return []
        try:
            decoded = base64.b85decode(t)
            plain = decoded.decode("utf-8", errors="replace")
        except Exception:
            return []
        if not is_printable_text(plain):
            return []
        return [Candidate(self.id, self.name, self.category, 0.7, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return base64.b85decode(text.strip()).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return base64.b85encode(text.encode("utf-8")).decode("ascii")
        except Exception:
            return None


class Ascii85Cipher(Cipher):
    id = "ascii85"
    name = "ASCII85 (Adobe)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if t.startswith("<~") and t.endswith("~>"):
            try:
                decoded = base64.a85decode(t, adobe=True)
                return [Candidate(self.id, self.name, self.category, 0.95,
                                  decoded=decoded.decode("utf-8", "replace"))]
            except Exception:
                return []
        try:
            decoded = base64.a85decode(t)
            plain = decoded.decode("utf-8", errors="replace")
            if is_printable_text(plain):
                return [Candidate(self.id, self.name, self.category, 0.55, decoded=plain)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        t = text.strip()
        try:
            adobe = t.startswith("<~") and t.endswith("~>")
            return base64.a85decode(t, adobe=adobe).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return "<~" + base64.a85encode(text.encode("utf-8")).decode("ascii") + "~>"
        except Exception:
            return None


class Base58Cipher(Cipher):
    id = "base58"
    name = "Base58 (Bitcoin)"
    category = "encoding"
    _alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or any(c not in self._alphabet for c in t):
            return []
        try:
            decoded = self._b58decode(t)
            plain = decoded.decode("utf-8", errors="replace")
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.7, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return self._b58decode(text.strip()).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = int.from_bytes(text.encode("utf-8"), "big")
            result = ""
            while n > 0:
                n, r = divmod(n, 58)
                result = self._alphabet[r] + result
            pad = len(text) - len(text.lstrip("\x00"))
            return self._alphabet[0] * pad + result
        except Exception:
            return None

    @classmethod
    def _b58decode(cls, s: str) -> bytes:
        n = 0
        for c in s:
            n = n * 58 + cls._alphabet.index(c)
        full = n.to_bytes((n.bit_length() + 7) // 8, "big")
        pad = len(s) - len(s.lstrip("1"))
        return b"\x00" * pad + full


class Base91Cipher(Cipher):
    id = "base91"
    name = "Base91"
    category = "encoding"
    _alphabet = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
        '0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'
    )

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or any(c not in self._alphabet for c in t):
            return []
        try:
            decoded = self._b91decode(t)
            plain = decoded.decode("utf-8", errors="replace")
            if is_printable_text(plain):
                return [Candidate(self.id, self.name, self.category, 0.6, decoded=plain)]
        except Exception:
            return []
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return self._b91decode(text.strip()).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            data = text.encode("utf-8")
            result = []
            ebq = 0
            en = 0
            for byte in data:
                ebq |= byte << en
                en += 8
                if en > 13:
                    ev = ebq & 8191
                    if ev > 88:
                        ebq >>= 13
                        en -= 13
                    else:
                        ev = ebq & 16383
                        ebq >>= 14
                        en -= 14
                    result.append(self._alphabet[ev % 91])
                    result.append(self._alphabet[ev // 91])
            if en:
                result.append(self._alphabet[ebq % 91])
            return "".join(result)
        except Exception:
            return None

    @classmethod
    def _b91decode(cls, s: str) -> bytes:
        decode_table = {c: i for i, c in enumerate(cls._alphabet)}
        v = -1
        b = 0
        n = 0
        out = bytearray()
        for ch in s:
            if ch not in decode_table:
                continue
            c = decode_table[ch]
            if v < 0:
                v = c
            else:
                v += c * 91
                b |= v << n
                n += 13 if (v & 8191) > 88 else 14
                while n > 7:
                    out.append(b & 255)
                    b >>= 8
                    n -= 8
                v = -1
        if v >= 0:
            out.append((b | v << n) & 255)
        return bytes(out)


# -----------------------------------------------------------
# Other classical encodings
# -----------------------------------------------------------

class URLEncodingCipher(Cipher):
    id = "urlencode"
    name = "URL / Percent encoding"
    category = "encoding"
    _re = re.compile(r"%[0-9A-Fa-f]{2}")

    def identify(self, text: str) -> list[Candidate]:
        if not self._re.search(text):
            return []
        try:
            decoded = urllib.parse.unquote(text)
        except Exception:
            return []
        if decoded == text:
            return []
        return [Candidate(self.id, self.name, self.category, 0.9, decoded=decoded)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        return urllib.parse.unquote(text)

    def encode(self, text: str, key: str | None = None) -> str | None:
        return urllib.parse.quote(text, safe="")


class HtmlEntityCipher(Cipher):
    id = "html"
    name = "HTML entities"
    category = "encoding"
    _re = re.compile(r"&(?:#\d+|#x[0-9A-Fa-f]+|[A-Za-z]+);")

    def identify(self, text: str) -> list[Candidate]:
        if not self._re.search(text):
            return []
        decoded = html.unescape(text)
        if decoded == text:
            return []
        return [Candidate(self.id, self.name, self.category, 0.9, decoded=decoded)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        return html.unescape(text)

    def encode(self, text: str, key: str | None = None) -> str | None:
        return html.escape(text)


class UnicodeEscapeCipher(Cipher):
    id = "unicode_escape"
    name = "Unicode \\uXXXX escape"
    category = "encoding"
    _re = re.compile(r"\\u[0-9A-Fa-f]{4}")

    def identify(self, text: str) -> list[Candidate]:
        if not self._re.search(text):
            return []
        try:
            decoded = codecs.decode(text, "unicode_escape")
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.85, decoded=decoded)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return codecs.decode(text, "unicode_escape")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return text.encode("unicode_escape").decode("ascii")
        except Exception:
            return None


class QuotedPrintableCipher(Cipher):
    id = "quoted_printable"
    name = "Quoted-printable (MIME)"
    category = "encoding"
    _re = re.compile(r"=[0-9A-F]{2}")

    def identify(self, text: str) -> list[Candidate]:
        if not self._re.search(text):
            return []
        try:
            decoded = codecs.decode(text.encode(), "quopri").decode("utf-8", "replace")
        except Exception:
            return []
        if decoded == text:
            return []
        return [Candidate(self.id, self.name, self.category, 0.75, decoded=decoded)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return codecs.decode(text.encode(), "quopri").decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return codecs.encode(text.encode(), "quopri").decode("utf-8", "replace")
        except Exception:
            return None


class UUEncodeCipher(Cipher):
    id = "uuencode"
    name = "UUencode"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        if "begin " not in text or "end" not in text:
            return []
        try:
            import binascii as _b
            lines = text.splitlines()
            out = bytearray()
            for line in lines[1:]:
                if line == "end" or not line:
                    continue
                try:
                    out.extend(_b.a2b_uu(line + "\n"))
                except Exception:
                    pass
            return [Candidate(self.id, self.name, self.category, 0.8,
                              decoded=out.decode("utf-8", "replace"))]
        except Exception:
            return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            import binascii as _b
            lines = text.splitlines()
            out = bytearray()
            for line in lines:
                if line.strip() in ("begin", "end", ""):
                    continue
                try:
                    out.extend(_b.a2b_uu(line + "\n"))
                except Exception:
                    pass
            return out.decode("utf-8", "replace") if out else None
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            import binascii as _b
            data = text.encode("utf-8")
            lines = ["begin 644 file.txt"]
            for i in range(0, len(data), 45):
                chunk = data[i:i+45]
                lines.append(_b.b2a_uu(chunk).decode("ascii"))
            lines.append("end")
            return "\n".join(lines)
        except Exception:
            return None


class MorseCipher(Cipher):
    id = "morse"
    name = "Morse code"
    category = "encoding"
    _table = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E", "..-.": "F",
        "--.": "G", "....": "H", "..": "I", ".---": "J", "-.-": "K", ".-..": "L",
        "--": "M", "-.": "N", "---": "O", ".--.": "P", "--.-": "Q", ".-.": "R",
        "...": "S", "-": "T", "..-": "U", "...-": "V", ".--": "W", "-..-": "X",
        "-.--": "Y", "--..": "Z",
        "-----": "0", ".----": "1", "..---": "2", "...--": "3", "....-": "4",
        ".....": "5", "-....": "6", "--...": "7", "---..": "8", "----.": "9",
        ".-.-.-": ".", "--..--": ",", "..--..": "?", "-.-.--": "!",
        "-....-": "-", "-..-.": "/", ".--.-.": "@",
    }

    def identify(self, text: str) -> list[Candidate]:
        # normalize common morse delimiters
        t = text.strip()
        if not re.fullmatch(r"[\.\-/ \t\n_|]+", t):
            return []
        if "." not in t and "-" not in t:
            return []
        decoded = self.decode(t)
        if not decoded:
            return []
        return [Candidate(self.id, self.name, self.category, 0.95, decoded=decoded)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        t = text.strip().replace("_", "-")
        for sep in [" / ", "/", " | ", "|", "   "]:
            if sep in t:
                words = t.split(sep)
                break
        else:
            words = [t]
        out_words = []
        for w in words:
            letters = re.split(r"\s+", w.strip())
            chars = []
            for sym in letters:
                if not sym:
                    continue
                if sym not in self._table:
                    return None
                chars.append(self._table[sym])
            out_words.append("".join(chars))
        return " ".join(out_words)

    def encode(self, text: str, key: str | None = None) -> str | None:
        _rev = {v: k for k, v in self._table.items()}
        words = text.upper().split(" ")
        encoded_words = []
        for w in words:
            codes = []
            for c in w:
                if c in _rev:
                    codes.append(_rev[c])
                else:
                    return None
            encoded_words.append(" ".join(codes))
        return " / ".join(encoded_words)


class ReverseCipher(Cipher):
    """Detect a reversed string by trying it both directions."""
    id = "reverse"
    name = "Reverse string"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 6:
            return []
        rev = t[::-1]
        if looks_like_english(rev) and not looks_like_english(t):
            return [Candidate(self.id, self.name, self.category, 0.7, decoded=rev)]
        # flag-looking reversal
        if "}" in t and t.startswith("}") or t.endswith("{galf"):
            return [Candidate(self.id, self.name, self.category, 0.6, decoded=rev)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return text[::-1]

    def encode(self, text: str, key: str | None = None) -> str | None:
        return text[::-1]


class BinaryCipher(Cipher):
    id = "binary"
    name = "Binary (8-bit ASCII)"
    category = "encoding"
    _re = re.compile(r"^[01\s]+$")

    def identify(self, text: str) -> list[Candidate]:
        t = re.sub(r"\s+", "", text)
        if len(t) < 8 or len(t) % 8 != 0 or not re.fullmatch(r"[01]+", t):
            return []
        try:
            out = bytes(int(t[i:i+8], 2) for i in range(0, len(t), 8))
            plain = out.decode("utf-8", errors="replace")
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.9, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        t = re.sub(r"\s+", "", text)
        try:
            return bytes(int(t[i:i+8], 2) for i in range(0, len(t), 8)).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return " ".join(format(b, "08b") for b in text.encode("utf-8"))
        except Exception:
            return None


class OctalCipher(Cipher):
    id = "octal"
    name = "Octal (3-digit per byte)"
    category = "encoding"
    _re = re.compile(r"^[0-7\s]+$")

    def identify(self, text: str) -> list[Candidate]:
        t = re.sub(r"\s+", " ", text.strip())
        parts = t.split()
        if len(parts) < 3 or any(not p.isdigit() or len(p) > 3 for p in parts):
            return []
        try:
            out = bytes(int(p, 8) for p in parts)
            plain = out.decode("utf-8", errors="replace")
            if not is_printable_text(plain):
                return []
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.7, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            parts = text.split()
            return bytes(int(p, 8) for p in parts).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return " ".join(format(b, "03o") for b in text.encode("utf-8"))
        except Exception:
            return None


class DecimalCipher(Cipher):
    id = "decimal"
    name = "Decimal byte stream"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        parts = re.split(r"[\s,]+", text.strip())
        if len(parts) < 3 or any(not p.isdigit() for p in parts):
            return []
        try:
            ints = [int(p) for p in parts]
            if any(i > 255 for i in ints):
                return []
            plain = bytes(ints).decode("utf-8", errors="replace")
            if not is_printable_text(plain):
                return []
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.6, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            parts = re.split(r"[\s,]+", text.strip())
            return bytes(int(p) for p in parts).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return " ".join(str(b) for b in text.encode("utf-8"))
        except Exception:
            return None


class PunycodeCipher(Cipher):
    id = "punycode"
    name = "Punycode (IDNA)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t.startswith("xn--"):
            return []
        try:
            decoded = t.encode().decode("idna")
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.95, decoded=decoded)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return text.strip().encode().decode("idna")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return text.strip().encode("idna").decode("ascii")
        except Exception:
            return None


class A1Z26Cipher(Cipher):
    id = "a1z26"
    name = "A1Z26 (letter ordinals)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        parts = re.split(r"[\s,\-]+", text.strip())
        if len(parts) < 3 or any(not p.isdigit() for p in parts):
            return []
        try:
            ints = [int(p) for p in parts]
            if any(i < 1 or i > 26 for i in ints):
                return []
            plain = "".join(chr(i + 64) for i in ints)
        except Exception:
            return []
        return [Candidate(self.id, self.name, self.category, 0.7, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        parts = re.split(r"[\s,\-]+", text.strip())
        try:
            return "".join(chr(int(p) + 64) for p in parts if p)
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return " ".join(str(ord(c.upper()) - 64) for c in text if c.isalpha())
        except Exception:
            return None


class Base62Cipher(Cipher):
    id = "base62"
    name = "Base62"
    category = "encoding"
    _alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or any(c not in self._alphabet for c in t):
            return []
        try:
            decoded = self._b62decode(t)
            plain = decoded.decode("utf-8", errors="replace")
            if 32 <= min(ord(c) for c in plain) and max(ord(c) for c in plain) < 127:
                return [Candidate(self.id, self.name, self.category, 0.6, decoded=plain)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return self._b62decode(text.strip()).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = int.from_bytes(text.encode("utf-8"), "big")
            if n == 0:
                return self._alphabet[0]
            result = ""
            while n > 0:
                n, r = divmod(n, 62)
                result = self._alphabet[r] + result
            return result
        except Exception:
            return None

    @classmethod
    def _b62decode(cls, s: str) -> bytes:
        n = 0
        for c in s:
            n = n * 62 + cls._alphabet.index(c)
        return n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""


class Base36Cipher(Cipher):
    id = "base36"
    name = "Base36"
    category = "encoding"
    _re = re.compile(r"^[0-9A-Za-z]+$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or not self._re.match(t):
            return []
        try:
            n = int(t, 36)
            decoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
            plain = decoded.decode("utf-8", errors="replace")
            if 32 <= min(ord(c) for c in plain) and max(ord(c) for c in plain) < 127:
                return [Candidate(self.id, self.name, self.category, 0.6, decoded=plain)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = int(text.strip(), 36)
            return n.to_bytes((n.bit_length() + 7) // 8, "big").decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = int.from_bytes(text.encode("utf-8"), "big")
            chars = []
            while n > 0:
                n, r = divmod(n, 36)
                chars.append("0123456789abcdefghijklmnopqrstuvwxyz"[r])
            return "".join(reversed(chars)) or "0"
        except Exception:
            return None


class WhitespaceCipher(Cipher):
    id = "whitespace"
    name = "Whitespace encoding"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # Whitespace encoding uses only spaces, tabs, and newlines
        if not all(c in " \t\n\r" for c in t):
            return []
        if len(t) < 9:
            return []
        decoded = self.decode(t)
        if decoded and len(decoded) > 0:
            return [Candidate(self.id, self.name, self.category, 0.8, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        tokens = re.split(r'([\t \n\r]+)', text)
        binary_str = ""
        for tok in tokens:
            if not tok:
                continue
            if all(c == ' ' for c in tok):
                continue
            binary_str += ''.join('1' if c == '\t' else '0' for c in tok if c in ' \t')
        if not binary_str:
            return None
        while len(binary_str) % 8:
            binary_str += "0"
        try:
            chars = [chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)]
            return "".join(chars)
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            bits = "".join(format(b, "08b") for b in text.encode("utf-8"))
            return "".join("\t" if b == "1" else " " for b in bits)
        except Exception:
            return None


class ROT5Cipher(Cipher):
    id = "rot5"
    name = "ROT5 (digits only)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t or not re.search(r'[0-9]', t):
            return []
        decoded = self.decode(t)
        if decoded and decoded != t:
            return [Candidate(self.id, self.name, self.category, 0.7, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return "".join(
            chr((ord(c) - ord('0') + 5) % 10 + ord('0')) if c.isdigit() else c
            for c in text
        )

    def encode(self, text: str, key: str | None = None) -> str | None:
        return self.decode(text)


class ROT18Cipher(Cipher):
    id = "rot18"
    name = "ROT18 (ROT13 + ROT5)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        decoded = self.decode(t)
        if decoded and decoded != t:
            return [Candidate(self.id, self.name, self.category, 0.7, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        result = []
        for c in text:
            if c.isdigit():
                result.append(chr((ord(c) - ord('0') + 5) % 10 + ord('0')))
            elif 'a' <= c <= 'z':
                result.append(chr((ord(c) - ord('a') + 13) % 26 + ord('a')))
            elif 'A' <= c <= 'Z':
                result.append(chr((ord(c) - ord('A') + 13) % 26 + ord('A')))
            else:
                result.append(c)
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        return self.decode(text)


class ROT52Cipher(Cipher):
    id = "rot52"
    name = "ROT52 (swap case)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t or not re.search(r'[a-zA-Z]', t):
            return []
        decoded = self.decode(t)
        if decoded and decoded != t:
            return [Candidate(self.id, self.name, self.category, 0.6, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return "".join(
            c.lower() if c.isupper() else c.upper() if c.islower() else c
            for c in text
        )

    def encode(self, text: str, key: str | None = None) -> str | None:
        return self.decode(text)


class XXEncodeCipher(Cipher):
    id = "xxencode"
    name = "XXencode"
    category = "encoding"
    _alphabet = "+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    _re = re.compile(r"^[+\-0-9A-Za-z]+$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or not self._re.match(t):
            return []
        if not all(c in self._alphabet for c in t):
            return []
        if len(t) % 4 != 0:
            return []
        try:
            decoded = self._xxdecode(t)
            if decoded:
                return [Candidate(self.id, self.name, self.category, 0.65, decoded=decoded)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return self._xxdecode(text.strip())

    @classmethod
    def _xxdecode(cls, s: str) -> str | None:
        pad = 4 - len(s) % 4
        if pad != 4:
            s += cls._alphabet[0] * pad
        result = bytearray()
        for i in range(0, len(s), 4):
            chunk = s[i:i+4]
            try:
                n = 0
                for c in chunk:
                    n = n * 64 + cls._alphabet.index(c)
                group_bytes = n.to_bytes(3, "big")
                # Strip leading nulls (from short final groups)
                gi = 0
                while gi < len(group_bytes) and group_bytes[gi] == 0:
                    gi += 1
                result.extend(group_bytes[gi:])
            except ValueError:
                return None
        try:
            return result.decode("utf-8", errors="replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            data = text.encode("utf-8")
            result = []
            for i in range(0, len(data), 3):
                chunk = data[i:i+3]
                n = int.from_bytes(chunk, "big")
                group = []
                for _ in range(4):
                    group.append(self._alphabet[n % 64])
                    n //= 64
                result.append("".join(reversed(group)))
            return "".join(result)
        except Exception:
            return None


class Z85Cipher(Cipher):
    id = "z85"
    name = "Z85 (ZeroMQ)"
    category = "encoding"
    _alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.,:;+-=!*%&()/?[]{}@^$#"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 5:
            return []
        if not all(c in self._alphabet for c in t):
            return []
        if len(t) % 5 != 0:
            return []
        try:
            n = 0
            for c in t:
                n = n * 85 + self._alphabet.index(c)
            decoded = n.to_bytes((n.bit_length() + 7) // 8, "big")
            plain = decoded.decode("utf-8", errors="replace")
            if any(c.isprintable() for c in plain):
                return [Candidate(self.id, self.name, self.category, 0.6, decoded=plain)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = 0
            for c in text.strip():
                n = n * 85 + self._alphabet.index(c)
            return n.to_bytes((n.bit_length() + 7) // 8, "big").decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = int.from_bytes(text.encode("utf-8"), "big")
            chars = []
            while n > 0:
                n, r = divmod(n, 85)
                chars.append(self._alphabet[r])
            return "".join(reversed(chars)) or self._alphabet[0]
        except Exception:
            return None


class TapCodeCipher(Cipher):
    id = "tapcode"
    name = "Tap code (Polybius variant)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Tap code uses pairs like "11 12 13" or "1,1 1,2 1,3" or ".... / ...."
        if re.fullmatch(r"[\d\s,./|]+", t):
            parts = re.split(r"[\s,./|]+", t)
            parts = [p for p in parts if p]
            if len(parts) >= 2 and len(parts) % 2 == 0:
                try:
                    pairs = [(int(parts[i]), int(parts[i+1])) for i in range(0, len(parts), 2)]
                    if all(1 <= r <= 5 and 1 <= c <= 5 for r, c in pairs):
                        decoded = self.decode(t)
                        if decoded:
                            return [Candidate(self.id, self.name, self.category, 0.75, decoded=decoded)]
                except (ValueError, IndexError):
                    pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        parts = re.split(r"[\s,./|]+", text.strip())
        parts = [p for p in parts if p]
        if len(parts) % 2 != 0:
            return None
        square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        result = []
        for i in range(0, len(parts), 2):
            r, c = int(parts[i]), int(parts[i+1])
            if r < 1 or r > 5 or c < 1 or c > 5:
                return None
            idx = (r - 1) * 5 + (c - 1)
            if idx < len(square):
                result.append(square[idx])
            else:
                return None
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        result = []
        for c in text.upper():
            if c == "J":
                c = "I"
            if c not in square:
                return None
            idx = square.index(c)
            r, col = idx // 5 + 1, idx % 5 + 1
            result.append(f"{r} {col}")
        return " ".join(result)


class Base32CrockfordCipher(Cipher):
    id = "base32_crockford"
    name = "Base32 (Crockford)"
    category = "encoding"
    _alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    _re = re.compile(r"^[0-9A-HJKMNP-TV-Z]+$", re.IGNORECASE)

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().upper().replace("O", "0").replace("I", "1").replace("L", "1")
        if len(t) < 8 or not self._re.match(t):
            return []
        try:
            decoded = self._decode(t)
            if decoded:
                return [Candidate(self.id, self.name, self.category, 0.7, decoded=decoded)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        t = text.strip().upper().replace("O", "0").replace("I", "1").replace("L", "1")
        return self._decode(t)

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            n = int.from_bytes(text.encode("utf-8"), "big")
            chars = []
            while n > 0:
                n, r = divmod(n, 32)
                chars.append(self._alphabet[r])
            return "".join(reversed(chars)) or self._alphabet[0]
        except Exception:
            return None

    def _decode(self, t: str) -> str | None:
        n = 0
        for c in t:
            n = n * 32 + self._alphabet.index(c)
        length = (len(t) * 5) // 8
        return n.to_bytes(length, "big").decode("utf-8", errors="replace") or None


class Base32HexCipher(Cipher):
    id = "base32hex"
    name = "Base32 (Hex alphabet)"
    category = "encoding"
    _re = re.compile(r"^[A-V0-9]+=*$", re.IGNORECASE)

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().upper()
        if len(t) < 8 or len(t) % 8 != 0:
            return []
        if not self._re.match(t):
            return []
        try:
            import base64
            # Map hex alphabet to standard base32
            hex_alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
            std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            trans = str.maketrans(hex_alpha, std_alpha)
            std = t.rstrip("=").translate(trans)
            padding = "=" * (-len(std) % 8)
            decoded = base64.b32decode(std + padding)
            plain = decoded.decode("utf-8", errors="replace")
            return [Candidate(self.id, self.name, self.category, 0.75, decoded=plain)]
        except Exception:
            return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            import base64
            hex_alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
            std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            trans = str.maketrans(hex_alpha, std_alpha)
            std = text.strip().upper().rstrip("=").translate(trans)
            padding = "=" * (-len(std) % 8)
            return base64.b32decode(std + padding).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            import base64
            hex_alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUV"
            std_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
            trans = str.maketrans(std_alpha, hex_alpha)
            return base64.b32encode(text.encode("utf-8")).decode("ascii").translate(trans)
        except Exception:
            return None


class Ascii85ZeroMQCipher(Cipher):
    id = "ascii85_zmq"
    name = "Ascii85 (ZeroMQ variant)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 5:
            return []
        # ZeroMQ variant uses characters 33-117
        if not all(33 <= ord(c) <= 117 for c in t):
            return []
        if len(t) % 5 != 0:
            return []
        try:
            decoded = self._decode(t)
            if decoded and any(c.isprintable() for c in decoded):
                return [Candidate(self.id, self.name, self.category, 0.6, decoded=decoded)]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return self._decode(text.strip())

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            data = text.encode("utf-8")
            result = []
            for i in range(0, len(data), 4):
                chunk = data[i:i+4]
                padded = chunk + b'\x00' * (4 - len(chunk))
                n = int.from_bytes(padded, "big")
                group = []
                for _ in range(5):
                    group.append(chr(n % 85 + 33))
                    n //= 85
                result.append("".join(reversed(group)))
            return "".join(result)
        except Exception:
            return None

    def _decode(self, t: str) -> str | None:
        result = bytearray()
        for i in range(0, len(t), 5):
            chunk = t[i:i+5]
            n = 0
            for c in chunk:
                n = n * 85 + (ord(c) - 33)
            result.extend(n.to_bytes(4, "big"))
        while result and result[-1] == 0:
            result.pop()
        return bytes(result).decode("utf-8", "replace") or None


class BrailleCipher(Cipher):
    id = "braille"
    name = "Braille encoding"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Unicode braille patterns: U+2800 to U+28FF
        if all(0x2800 <= ord(c) <= 0x28FF for c in t) and len(t) > 0:
            decoded = self.decode(t)
            if decoded:
                return [Candidate(self.id, self.name, self.category, 0.85, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        braille_map = {
            0x2801: 'a', 0x2803: 'b', 0x2809: 'c', 0x2819: 'd',
            0x2811: 'e', 0x280B: 'f', 0x281B: 'g', 0x2813: 'h',
            0x280A: 'i', 0x281A: 'j', 0x2805: 'k', 0x2807: 'l',
            0x280D: 'm', 0x281D: 'n', 0x2815: 'o', 0x280F: 'p',
            0x281F: 'q', 0x2817: 'r', 0x280E: 's', 0x281E: 't',
            0x2825: 'u', 0x2827: 'v', 0x283A: 'w', 0x282D: 'x',
            0x283D: 'y', 0x2835: 'z', 0x2800: ' ',
        }
        result = []
        for c in text:
            if ord(c) == 0x2800:
                result.append(' ')
            elif ord(c) in braille_map:
                result.append(braille_map[ord(c)])
            else:
                return None
        return "".join(result) if result else None

    def encode(self, text: str, key: str | None = None) -> str | None:
        _rev = {
            'a': 0x2801, 'b': 0x2803, 'c': 0x2809, 'd': 0x2819,
            'e': 0x2811, 'f': 0x280B, 'g': 0x281B, 'h': 0x2813,
            'i': 0x280A, 'j': 0x281A, 'k': 0x2805, 'l': 0x2807,
            'm': 0x280D, 'n': 0x281D, 'o': 0x2815, 'p': 0x280F,
            'q': 0x281F, 'r': 0x2817, 's': 0x280E, 't': 0x281E,
            'u': 0x2825, 'v': 0x2827, 'w': 0x283A, 'x': 0x282D,
            'y': 0x283D, 'z': 0x2835, ' ': 0x2800,
        }
        result = []
        for c in text.lower():
            if c in _rev:
                result.append(chr(_rev[c]))
            else:
                return None
        return "".join(result)


class SemaphoreCipher(Cipher):
    id = "semaphore"
    name = "Semaphore flag positions"
    category = "encoding"

    _sem_map = {
        'A': '12', 'B': '13', 'C': '14', 'D': '15', 'E': '16',
        'F': '17', 'G': '18', 'H': '23', 'I': '24', 'J': '25',
        'K': '26', 'L': '27', 'M': '28', 'N': '34', 'O': '35',
        'P': '36', 'Q': '37', 'R': '38', 'S': '45', 'T': '46',
        'U': '47', 'V': '48', 'W': '56', 'X': '57', 'Y': '58',
        'Z': '67', ' ': '68',
    }

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        parts = re.split(r"[\s,\-]+", t)
        if len(parts) < 2:
            return []
        valid_positions = set("12345678ULDR")
        if all(p.upper() in valid_positions or p.isdigit() for p in parts):
            decoded = self.decode(t)
            if decoded:
                return [Candidate(self.id, self.name, self.category, 0.65, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        _rev = {v: k for k, v in self._sem_map.items()}
        parts = re.split(r"[\s,]+", text.strip())
        result = []
        for p in parts:
            p = p.strip("-")
            if p in _rev:
                result.append(_rev[p])
            else:
                return None
        return "".join(result) if result else None

    def encode(self, text: str, key: str | None = None) -> str | None:
        result = []
        for c in text.upper():
            if c in self._sem_map:
                result.append(self._sem_map[c])
            else:
                return None
        return " ".join(result)


class PigpenCipher(Cipher):
    id = "pigpen"
    name = "Pigpen / Masonic cipher"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Pigpen uses symbols like ⌐, ⊥, ⊤, etc or simple geometric shapes
        # For CTF, often represented as Unicode geometric shapes
        symbols = set("⌐⊥⊤⊣⊢⊤⌊⌋⌈⌉△▽◇○□■")
        if all(c in symbols or c.isspace() for c in t) and len(t) > 3:
            return [Candidate(self.id, self.name, self.category, 0.7,
                              decoded=None,
                              notes="pigpen cipher — each symbol maps to a letter by grid position")]
        return []


class Base45Cipher(Cipher):
    """Base45 encoding (RFC 9285, used in EU Digital COVID Certificate)."""
    id = "base45"
    name = "Base45"
    category = "encoding"
    _alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 4 or not all(c in self._alphabet for c in t):
            return []
        try:
            decoded = self._b45decode(t)
            if decoded and any(c.isprintable() for c in decoded.decode("utf-8", errors="replace")):
                return [Candidate(self.id, self.name, self.category, 0.6,
                                  decoded=decoded.decode("utf-8", errors="replace"))]
        except Exception:
            pass
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            return self._b45decode(text.strip()).decode("utf-8", "replace")
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            data = text.encode("utf-8")
            result = []
            for i in range(0, len(data), 2):
                if i + 1 < len(data):
                    n = data[i] * 256 + data[i+1]
                    e = n // (45 * 45)
                    remaining = n % (45 * 45)
                    d = remaining // 45
                    c = remaining % 45
                    result.append(self._alphabet[e] + self._alphabet[d] + self._alphabet[c])
                else:
                    e = data[i] // 45
                    d = data[i] % 45
                    result.append(self._alphabet[e] + self._alphabet[d])
            return "".join(result)
        except Exception:
            return None

    @classmethod
    def _b45decode(cls, s: str) -> bytes:
        result = bytearray()
        for i in range(0, len(s), 3):
            chunk = s[i:i+3]
            if len(chunk) == 3:
                e = cls._alphabet.index(chunk[0])
                d = cls._alphabet.index(chunk[1])
                c = cls._alphabet.index(chunk[2])
                n = e * 45 * 45 + d * 45 + c
                if n > 0xFFFF:
                    raise ValueError("invalid base45")
                result.extend(n.to_bytes(2, "big"))
            elif len(chunk) == 2:
                e = cls._alphabet.index(chunk[0])
                d = cls._alphabet.index(chunk[1])
                n = e * 45 + d
                if n > 0xFF:
                    raise ValueError("invalid base45")
                result.append(n)
        return bytes(result)


class Base100Cipher(Cipher):
    """Base100 / Emoji encoding (each byte → emoji)."""
    id = "base100"
    name = "Base100 (Emoji)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t or len(t) < 4:
            return []
        # Base100 uses specific emoji blocks
        emoji_ranges = [(0x1F600, 0x1F64F), (0x1F300, 0x1F5FF), (0x1F680, 0x1F6FF),
                        (0x1F1E0, 0x1F1FF), (0x2702, 0x27B0), (0x24C2, 0x1F251)]
        emoji_count = sum(1 for c in t if any(lo <= ord(c) <= hi for lo, hi in emoji_ranges))
        if emoji_count > len(t) * 0.5:
            return [Candidate(self.id, self.name, self.category, 0.6,
                              decoded=None,
                              notes="Base100 emoji encoding — each emoji represents a byte")]
        return []


class Ascii85Z85Cipher(Cipher):
    """Ascii85 (Z85 variant, no angle brackets)."""
    id = "ascii85_z85"
    name = "Ascii85 (Z85-style)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if len(t) < 5:
            return []
        # Z85-style uses printable ASCII without <~ ~> delimiters
        if t.startswith("<~") and t.endswith("~>"):
            return []
        if all(33 <= ord(c) <= 117 for c in t) and len(t) % 5 == 0:
            try:
                import base64
                decoded = base64.a85decode(t)
                plain = decoded.decode("utf-8", errors="replace")
                if any(c.isprintable() for c in plain):
                    return [Candidate(self.id, self.name, self.category, 0.55, decoded=plain)]
            except Exception:
                pass
        return []


class UUEncodeFullCipher(Cipher):
    """UUencode (full format with begin/end markers)."""
    id = "uuencode_full"
    name = "UUencode (full)"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t.lower().startswith("begin "):
            return []
        lines = t.split("\n")
        if len(lines) < 3:
            return []
        if not lines[-1].strip().lower().startswith("end"):
            return []
        return [Candidate(self.id, self.name, self.category, 0.8,
                          decoded=None,
                          notes="UUencode file — extract content between begin/end")]


class Base2048Cipher(Cipher):
    """Base2048 encoding (compact, human-readable)."""
    id = "base2048"
    name = "Base2048"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t or len(t) < 4:
            return []
        # Base2048 uses CJK and Latin characters
        if all(0x2E80 <= ord(c) <= 0x9FFF or 0x0021 <= ord(c) <= 0x007E for c in t):
            return [Candidate(self.id, self.name, self.category, 0.3,
                              decoded=None,
                              notes="Base2048 — compact encoding using CJK + Latin")]
        return []


class AsciiHexCipher(Cipher):
    """ASCII Hex Dump format (0x prefixed hex pairs)."""
    id = "ascii_hex_dump"
    name = "ASCII Hex Dump"
    category = "encoding"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # Match patterns like "48 65 6C 6C 6F" or "0x48 0x65 0x6C"
        parts = re.split(r"[\s,]+", t)
        if len(parts) < 3:
            return []
        hex_pairs = all(re.match(r"^(?:0x)?[0-9A-Fa-f]{2}$", p) for p in parts)
        if hex_pairs:
            try:
                decoded = bytes.fromhex("".join(p.replace("0x", "") for p in parts))
                plain = decoded.decode("utf-8", errors="replace")
                return [Candidate(self.id, self.name, self.category, 0.75, decoded=plain)]
            except Exception:
                pass
        return []


ENCODING_CIPHERS = [
    Base64Cipher(), Base64UrlCipher(), Base32Cipher(), Base16Cipher(),
    Base85Cipher(), Ascii85Cipher(), Base58Cipher(), Base91Cipher(),
    URLEncodingCipher(), HtmlEntityCipher(), UnicodeEscapeCipher(),
    QuotedPrintableCipher(), UUEncodeCipher(),
    MorseCipher(), BinaryCipher(), OctalCipher(), DecimalCipher(),
    PunycodeCipher(), A1Z26Cipher(), ReverseCipher(),
    Base62Cipher(), Base36Cipher(), WhitespaceCipher(),
    ROT5Cipher(), ROT18Cipher(), ROT52Cipher(),
    XXEncodeCipher(), Z85Cipher(), TapCodeCipher(),
    Base32CrockfordCipher(), Base32HexCipher(), Ascii85ZeroMQCipher(),
    BrailleCipher(), SemaphoreCipher(), PigpenCipher(),
    Base45Cipher(), Base100Cipher(), Ascii85Z85Cipher(),
    UUEncodeFullCipher(), Base2048Cipher(), AsciiHexCipher(),
]
