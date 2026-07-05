"""Classical substitution and transposition ciphers."""
from __future__ import annotations

import re

from cipherid.cipher import Candidate, Cipher
from cipherid.heuristics import chi_square_english, looks_like_english

# Common flag prefixes we boost when found in a decode candidate.
FLAG_HINT_RE = re.compile(
    r"(?:flag|CTF|ctf|DASCTF|hkcert|n1ctf|rwctf|0ops|\w+ctf)\{",
    re.IGNORECASE,
)


def _is_alpha_dominant(text: str, min_ratio: float = 0.5, max_digit_ratio: float = 0.1) -> bool:
    """Check if text is mostly alphabetic (suitable for classical ciphers)."""
    letters = sum(1 for c in text if c.isalpha())
    digits = sum(1 for c in text if c.isdigit())
    if digits > 0 and digits >= letters * max_digit_ratio:
        return False
    return letters / max(len(text), 1) >= min_ratio


def _shift_letter(c: str, k: int) -> str:
    if "a" <= c <= "z":
        return chr((ord(c) - ord("a") + k) % 26 + ord("a"))
    if "A" <= c <= "Z":
        return chr((ord(c) - ord("A") + k) % 26 + ord("A"))
    return c


def caesar_shift(s: str, k: int) -> str:
    return "".join(_shift_letter(c, k) for c in s)


class CaesarCipher(Cipher):
    """Try all 25 shifts and report the best by English chi-square."""
    id = "caesar"
    name = "Caesar / shift cipher"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        if not any(c.isalpha() for c in text):
            return []
        if not _is_alpha_dominant(text):
            return []

        results: list[Candidate] = []
        # If a shift yields a flag-prefix, we are essentially sure.
        for k in range(1, 26):
            cand = caesar_shift(text, k)
            if FLAG_HINT_RE.search(cand):
                results.append(Candidate(self.id, f"Caesar (shift={k})", self.category,
                                         0.95, decoded=cand, key=str(k),
                                         notes="flag-prefix match"))
        if results:
            return results
        best_k, best_chi, best_plain = 0, 1e9, text
        for k in range(1, 26):
            cand = caesar_shift(text, k)
            chi = chi_square_english(cand)
            if chi < best_chi:
                best_chi, best_k, best_plain = chi, k, cand
        if looks_like_english(best_plain) and best_chi < 80:
            conf = 0.85
        elif looks_like_english(best_plain):
            conf = 0.55
        else:
            conf = 0.3
        return [Candidate(self.id, f"Caesar (shift={best_k})", self.category,
                          conf, decoded=best_plain, key=str(best_k))]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if key is None:
            best_k, best_chi = 0, 1e9
            for k in range(1, 26):
                chi = chi_square_english(caesar_shift(text, k))
                if chi < best_chi:
                    best_chi, best_k = chi, k
            return caesar_shift(text, best_k)
        try:
            return caesar_shift(text, int(key))
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        if key is None:
            return caesar_shift(text, 3)
        try:
            return caesar_shift(text, -int(key) % 26)
        except Exception:
            return None


class Rot13Cipher(Cipher):
    id = "rot13"
    name = "ROT13"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        if not any(c.isalpha() for c in text):
            return []
        if not _is_alpha_dominant(text):
            return []
        out = caesar_shift(text, 13)
        if FLAG_HINT_RE.search(out):
            return [Candidate(self.id, self.name, self.category, 0.95, decoded=out)]
        if looks_like_english(out) and not looks_like_english(text):
            return [Candidate(self.id, self.name, self.category, 0.9, decoded=out)]
        if has_common_word(out) and not has_common_word(text):
            return [Candidate(self.id, self.name, self.category, 0.8, decoded=out)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return caesar_shift(text, 13)

    def encode(self, text: str, key: str | None = None) -> str | None:
        return caesar_shift(text, 13)


class Rot47Cipher(Cipher):
    id = "rot47"
    name = "ROT47"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        if not all(33 <= ord(c) <= 126 or c in " \n\t" for c in text):
            return []
        # ROT47 only meaningful when the input has typical ASCII-printable mix.
        # If it looks like base64/hex/etc, skip.
        letters = sum(1 for c in text if c.isalpha())
        if letters / max(len(text), 1) > 0.8:
            return []  # likely base64 / hex / letters-only — leave it to other detectors
        out = self.decode(text) or ""
        if FLAG_HINT_RE.search(out):
            return [Candidate(self.id, self.name, self.category, 0.95, decoded=out)]
        if looks_like_english(out) and not looks_like_english(text):
            return [Candidate(self.id, self.name, self.category, 0.85, decoded=out)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        return "".join(
            chr(33 + (ord(c) - 33 + 47) % 94) if 33 <= ord(c) <= 126 else c
            for c in text
        )

    def encode(self, text: str, key: str | None = None) -> str | None:
        return self.decode(text)


COMMON_WORDS = {
    "the", "and", "for", "are", "but", "not", "you", "all", "any", "can",
    "had", "her", "was", "one", "our", "out", "day", "get", "has", "him",
    "his", "how", "man", "new", "now", "old", "see", "two", "way", "who",
    "boy", "did", "its", "let", "put", "say", "she", "too", "use", "hello",
    "world", "flag", "secret", "password", "ctf", "test", "data", "key",
    "name", "user", "admin", "login", "code", "this", "that", "from",
    "your", "what", "when", "where", "have", "make", "good", "with",
}


def has_common_word(s: str) -> bool:
    t = re.sub(r"[^a-z]+", " ", s.lower())
    return any(w in COMMON_WORDS for w in t.split())


class AtbashCipher(Cipher):
    id = "atbash"
    name = "Atbash"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        if not any(c.isalpha() for c in text):
            return []
        if not _is_alpha_dominant(text):
            return []
        out = self.decode(text)
        if not out:
            return []
        if FLAG_HINT_RE.search(out):
            return [Candidate(self.id, self.name, self.category, 0.95, decoded=out)]
        if looks_like_english(out) and not looks_like_english(text):
            return [Candidate(self.id, self.name, self.category, 0.85, decoded=out)]
        if has_common_word(out) and not has_common_word(text):
            return [Candidate(self.id, self.name, self.category, 0.75, decoded=out)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        def flip(c):
            if "a" <= c <= "z":
                return chr(ord("z") - (ord(c) - ord("a")))
            if "A" <= c <= "Z":
                return chr(ord("Z") - (ord(c) - ord("A")))
            return c
        return "".join(flip(c) for c in text)

    def encode(self, text: str, key: str | None = None) -> str | None:
        return self.decode(text)


class AffineCipher(Cipher):
    id = "affine"
    name = "Affine cipher (a*x+b)"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        if not any(c.isalpha() for c in text):
            return []
        if not _is_alpha_dominant(text):
            return []
        coprimes = [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25]
        best = None
        for a in coprimes:
            a_inv = pow(a, -1, 26)
            for b in range(26):
                def dec(c, a_inv=a_inv, b=b):
                    if "a" <= c <= "z":
                        return chr((a_inv * ((ord(c) - ord("a") - b)) ) % 26 + ord("a"))
                    if "A" <= c <= "Z":
                        return chr((a_inv * ((ord(c) - ord("A") - b)) ) % 26 + ord("A"))
                    return c
                out = "".join(dec(c) for c in text)
                chi = chi_square_english(out)
                if best is None or chi < best[0]:
                    best = (chi, a, b, out)
        if best and best[0] < 100:
            return [Candidate(self.id, f"Affine (a={best[1]}, b={best[2]})",
                              self.category, 0.7, decoded=best[3],
                              key=f"{best[1]},{best[2]}")]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text, key.lower())

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)]) - ord("a")
                if c.isupper():
                    out.append(chr((ord(c) - ord("A") + k) % 26 + ord("A")))
                else:
                    out.append(chr((ord(c) - ord("a") + k) % 26 + ord("a")))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    @staticmethod
    def _ioc(letters: list[str]) -> float:
        n = len(letters)
        from collections import Counter
        c = Counter(s.lower() for s in letters)
        return sum(v * (v - 1) for v in c.values()) / max(n * (n - 1), 1)

    @classmethod
    def _derive_key(cls, letters: list[str], klen: int) -> str:
        key = []
        for i in range(klen):
            col = [letters[j] for j in range(i, len(letters), klen)]
            best_k, best_chi = 0, 1e9
            for k in range(26):
                shifted = "".join(
                    chr((ord(c.lower()) - ord("a") - k) % 26 + ord("a"))
                    for c in col
                )
                chi = chi_square_english(shifted)
                if chi < best_chi:
                    best_chi, best_k = chi, k
            key.append(chr(best_k + ord("a")))
        return "".join(key)

    @staticmethod
    def _decrypt(text: str, key: str) -> str:
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)].lower()) - ord("a")
                if c.isupper():
                    out.append(chr((ord(c) - ord("A") - k) % 26 + ord("A")))
                else:
                    out.append(chr((ord(c) - ord("a") - k) % 26 + ord("a")))
                ki += 1
            else:
                out.append(c)
        return "".join(out)


class VigenereCipher(Cipher):
    """Detect plausibly-Vigenere text using IoC + Kasiski-style key length search."""
    id = "vigenere"
    name = "Vigenere"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        letters = [c for c in text if c.isalpha()]
        if len(letters) < 20:
            return []
        if not _is_alpha_dominant(text):
            return []
        ioc = self._ioc(letters)
        if ioc > 0.055:
            return []
        best = None
        for klen in range(2, min(12, len(letters) // 2)):
            key = self._derive_key(letters, klen)
            plain = self._decrypt("".join(letters).lower(), key)
            chi = chi_square_english(plain)
            if best is None or chi < best[0]:
                best = (chi, key, plain)
        if best and best[0] < 200:
            _, key, _ = best
            decoded = self._decrypt(text, key)
            return [Candidate(self.id, f"Vigenere (key={key})", self.category,
                              0.75, decoded=decoded, key=key)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text, key.lower())

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.lower()
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)]) - ord("a")
                if c.isupper():
                    out.append(chr((ord(c) - ord("A") + k) % 26 + ord("A")))
                else:
                    out.append(chr((ord(c) - ord("a") + k) % 26 + ord("a")))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    @staticmethod
    def _ioc(letters: list[str]) -> float:
        n = len(letters)
        from collections import Counter
        c = Counter(s.lower() for s in letters)
        return sum(v * (v - 1) for v in c.values()) / max(n * (n - 1), 1)

    @classmethod
    def _derive_key(cls, letters: list[str], klen: int) -> str:
        key = []
        for i in range(klen):
            col = [letters[j] for j in range(i, len(letters), klen)]
            best_k, best_chi = 0, 1e9
            for k in range(26):
                shifted = "".join(
                    chr((ord(c.lower()) - ord("a") - k) % 26 + ord("a"))
                    for c in col
                )
                chi = chi_square_english(shifted)
                if chi < best_chi:
                    best_chi, best_k = chi, k
            key.append(chr(best_k + ord("a")))
        return "".join(key)

    @staticmethod
    def _decrypt(text: str, key: str) -> str:
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)].lower()) - ord("a")
                if c.isupper():
                    out.append(chr((ord(c) - ord("A") - k) % 26 + ord("A")))
                else:
                    out.append(chr((ord(c) - ord("a") - k) % 26 + ord("a")))
                ki += 1
            else:
                out.append(c)
        return "".join(out)


class RailFenceCipher(Cipher):
    id = "railfence"
    name = "Rail fence"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        if not text or not any(c.isalpha() for c in text):
            return []
        if not _is_alpha_dominant(text):
            return []
        best = None
        for rails in range(2, min(8, len(text))):
            plain = self.decode(text, key=str(rails))
            if not plain:
                continue
            chi = chi_square_english(plain)
            if best is None or chi < best[0]:
                best = (chi, rails, plain)
        if best and best[0] < 150:
            return [Candidate(self.id, f"Rail fence (rails={best[1]})",
                              self.category, 0.6, decoded=best[2],
                              key=str(best[1]))]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            rails = int(key)
        except Exception:
            return None
        if rails < 2:
            return None
        # Build the fence pattern
        n = len(text)
        pattern = []
        for i in range(n):
            cycle = 2 * (rails - 1)
            r = i % cycle
            if r >= rails:
                r = cycle - r
            pattern.append(r)
        # Distribute characters by rail
        by_rail = [[] for _ in range(rails)]
        for r in sorted(range(rails)):
            count = pattern.count(r)
            by_rail[r] = list(text[:count])
            text = text[count:]
        out = []
        idx = [0] * rails
        for r in pattern:
            out.append(by_rail[r][idx[r]])
            idx[r] += 1
        return "".join(out)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            rails = int(key)
        except Exception:
            return None
        if rails < 2:
            return None
        n = len(text)
        cycle = 2 * (rails - 1)
        # Collect characters per rail
        by_rail = [[] for _ in range(rails)]
        for i, c in enumerate(text):
            r = i % cycle
            if r >= rails:
                r = cycle - r
            by_rail[r].append(c)
        # Read off in order
        result = []
        for r in range(rails):
            result.extend(by_rail[r])
        return "".join(result)


class BaconCipher(Cipher):
    id = "bacon"
    name = "Baconian cipher"
    category = "classical"
    _table = {
        "A": "AAAAA", "B": "AAAAB", "C": "AAABA", "D": "AAABB", "E": "AABAA",
        "F": "AABAB", "G": "AABBA", "H": "AABBB", "I": "ABAAA", "J": "ABAAB",
        "K": "ABABA", "L": "ABABB", "M": "ABBAA", "N": "ABBAB", "O": "ABBBA",
        "P": "ABBBB", "Q": "BAAAA", "R": "BAAAB", "S": "BAABA", "T": "BAABB",
        "U": "BABAA", "V": "BABAB", "W": "BABBA", "X": "BABBB", "Y": "BBAAA",
        "Z": "BBAAB",
    }
    _rev = {v: k for k, v in _table.items()}

    def identify(self, text: str) -> list[Candidate]:
        t = text.upper().replace(" ", "")
        if not re.fullmatch(r"[AB]+", t):
            return []
        if len(t) % 5 != 0:
            return []
        out = []
        for i in range(0, len(t), 5):
            chunk = t[i:i+5]
            if chunk not in self._rev:
                return []
            out.append(self._rev[chunk])
        return [Candidate(self.id, self.name, self.category, 0.9, decoded="".join(out))]

    def decode(self, text: str, key: str | None = None) -> str | None:
        t = text.upper().replace(" ", "")
        try:
            return "".join(self._rev[t[i:i+5]] for i in range(0, len(t), 5))
        except KeyError:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        try:
            return " ".join(self._table[c.upper()] for c in text if c.isalpha())
        except KeyError:
            return None


class PolybiusCipher(Cipher):
    id = "polybius"
    name = "Polybius square (5x5)"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        parts = re.split(r"[\s,]+", text.strip())
        if len(parts) < 3 or any(len(p) != 2 or not p.isdigit() for p in parts):
            return []
        if any(int(d) < 1 or int(d) > 5 for p in parts for d in p):
            return []
        square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        out = []
        for p in parts:
            r, c = int(p[0]) - 1, int(p[1]) - 1
            out.append(square[r * 5 + c])
        plain = "".join(out)
        return [Candidate(self.id, self.name, self.category, 0.6, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        parts = re.split(r"[\s,]+", text.strip())
        if len(parts) < 3 or any(len(p) != 2 or not p.isdigit() for p in parts):
            return None
        if any(int(d) < 1 or int(d) > 5 for p in parts for d in p):
            return None
        square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        out = []
        for p in parts:
            r, c = int(p[0]) - 1, int(p[1]) - 1
            out.append(square[r * 5 + c])
        return "".join(out)

    def encode(self, text: str, key: str | None = None) -> str | None:
        square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
        result = []
        for c in text.upper().replace("J", "I"):
            if c not in square:
                return None
            idx = square.index(c)
            r, col = idx // 5 + 1, idx % 5 + 1
            result.append(f"{r}{col}")
        return " ".join(result)


class BeaufortCipher(Cipher):
    """Beaufort cipher: C = (K - P) mod 26."""
    id = "beaufort"
    name = "Beaufort cipher"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        letters = [c for c in text if c.isalpha()]
        if len(letters) < 20:
            return []
        if not _is_alpha_dominant(text):
            return []
        ioc = self._ioc(letters)
        if ioc > 0.055:
            return []
        best = None
        for klen in range(2, min(12, len(letters) // 2)):
            key = self._derive_key(letters, klen)
            plain = self._decrypt("".join(letters).lower(), key)
            chi = chi_square_english(plain)
            if best is None or chi < best[0]:
                best = (chi, key, plain)
        if best and best[0] < 200:
            _, key, plain = best
            decoded = self._decrypt(text, key)
            return [Candidate(self.id, f"Beaufort (key={key})", self.category,
                              0.7, decoded=decoded, key=key)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text, key.lower())

    @staticmethod
    def _ioc(letters: list[str]) -> float:
        from collections import Counter
        n = len(letters)
        c = Counter(s.lower() for s in letters)
        return sum(v * (v - 1) for v in c.values()) / max(n * (n - 1), 1)

    @classmethod
    def _derive_key(cls, letters: list[str], klen: int) -> str:
        key = []
        for i in range(klen):
            col = [letters[j] for j in range(i, len(letters), klen)]
            best_k, best_chi = 0, 1e9
            for k in range(26):
                shifted = "".join(
                    chr((k - ord(c.lower()) + ord('a')) % 26 + ord('a'))
                    for c in col
                )
                chi = chi_square_english(shifted)
                if chi < best_chi:
                    best_chi, best_k = chi, k
            key.append(chr(best_k + ord('a')))
        return "".join(key)

    @staticmethod
    def _decrypt(text: str, key: str) -> str:
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key[ki % len(key)].lower()) - ord('a')
                if c.isupper():
                    out.append(chr((k - (ord(c) - ord('A'))) % 26 + ord('A')))
                else:
                    out.append(chr((k - (ord(c) - ord('a'))) % 26 + ord('a')))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text, key.lower())


class GronsfeldCipher(Cipher):
    """Gronsfeld cipher: numeric key Vigenere variant."""
    id = "gronsfeld"
    name = "Gronsfeld cipher"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        letters = [c for c in text if c.isalpha()]
        if len(letters) < 20:
            return []
        if not _is_alpha_dominant(text):
            return []
        # Try short numeric keys (1-4 digits only for speed)
        best = None
        for klen in range(1, 5):
            for key_num in range(10 ** klen):
                key = str(key_num).zfill(klen)
                decoded = self._decrypt(text, key)
                chi = chi_square_english(decoded)
                if best is None or chi < best[0]:
                    best = (chi, key, decoded)
        if best and best[0] < 100:
            _, key, decoded = best
            return [Candidate(self.id, f"Gronsfeld (key={key})", self.category,
                              0.65, decoded=decoded, key=key)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key or not key.isdigit():
            return None
        return self._decrypt(text, key)

    @staticmethod
    def _decrypt(text: str, key: str) -> str:
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = int(key[ki % len(key)])
                if c.isupper():
                    out.append(chr((ord(c) - ord('A') - k) % 26 + ord('A')))
                else:
                    out.append(chr((ord(c) - ord('a') - k) % 26 + ord('a')))
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key or not key.isdigit():
            return None
        out = []
        ki = 0
        for c in text:
            if c.isalpha():
                k = int(key[ki % len(key)])
                if c.isupper():
                    out.append(chr((ord(c) - ord('A') + k) % 26 + ord('A')))
                else:
                    out.append(chr((ord(c) - ord('a') + k) % 26 + ord('a')))
                ki += 1
            else:
                out.append(c)
        return "".join(out)


class AutokeyCipher(Cipher):
    """Autokey cipher: key = keyword + plaintext."""
    id = "autokey"
    name = "Autokey cipher"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        letters = [c for c in text if c.isalpha()]
        if len(letters) < 25:
            return []
        if not _is_alpha_dominant(text):
            return []
        best = None
        # Try short keyword lengths
        for klen in range(1, 6):
            for kw in [chr(i + ord('a')) for i in range(26)]:
                decoded = self._decrypt(text.lower(), kw)
                chi = chi_square_english(decoded)
                if best is None or chi < best[0]:
                    best = (chi, kw, decoded)
        if best and best[0] < 120:
            _, kw, decoded = best
            return [Candidate(self.id, f"Autokey (keyword={kw})", self.category,
                              0.6, decoded=decoded, key=kw)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text.lower(), key.lower())

    @staticmethod
    def _decrypt(text: str, keyword: str) -> str:
        out = []
        key_stream = list(keyword.lower())
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key_stream[ki]) - ord('a')
                decoded_char = chr((ord(c.lower()) - ord('a') - k) % 26 + ord('a'))
                out.append(decoded_char)
                key_stream.append(decoded_char)
                ki += 1
            else:
                out.append(c)
        return "".join(out)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        keyword = key.lower()
        out = []
        key_stream = list(keyword)
        ki = 0
        for c in text:
            if c.isalpha():
                k = ord(key_stream[ki]) - ord('a')
                encoded_char = chr((ord(c.lower()) - ord('a') + k) % 26 + ord('a'))
                out.append(encoded_char)
                key_stream.append(c.lower())
                ki += 1
            else:
                out.append(c)
        return "".join(out)


class BifidCipher(Cipher):
    """Bifid cipher: combines Polybius square with transposition."""
    id = "bifid"
    name = "Bifid cipher"
    category = "classical"
    _square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Bifid produces pairs of digits
        parts = re.split(r"[\s,]+", t)
        if len(parts) < 4 or any(len(p) != 2 or not p.isdigit() for p in parts):
            return []
        if any(int(d) < 1 or int(d) > 5 for p in parts for d in p):
            return []
        decoded = self.decode(t)
        if decoded:
            chi = chi_square_english(decoded)
            if chi < 200:
                return [Candidate(self.id, self.name, self.category, 0.6, decoded=decoded)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        """Decrypt Bifid cipher."""
        parts = re.split(r"[\s,]+", text.strip())
        try:
            nums = [int(p) for p in parts if p]
        except (ValueError, IndexError):
            return None
        n = len(nums)
        if n < 2 or n % 2 != 0:
            return None
        half = n // 2
        rows = nums[:half]
        cols = nums[half:]
        result = []
        for r, c in zip(rows, cols):
            if 1 <= r <= 5 and 1 <= c <= 5:
                idx = (r - 1) * 5 + (c - 1)
                if idx < len(self._square):
                    result.append(self._square[idx])
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        text = text.upper().replace("J", "I")
        rows = []
        cols = []
        for c in text:
            if c not in self._square:
                return None
            idx = self._square.index(c)
            rows.append(idx // 5 + 1)
            cols.append(idx % 5 + 1)
        if not rows:
            return None
        # Standard Bifid format: row digits, then col digits, space-separated
        combined = rows + cols
        return " ".join(str(d) for d in combined)


class NihilistCipher(Cipher):
    """Nihilist cipher: Polybius + Vigenere-like addition."""
    id = "nihilist"
    name = "Nihilist cipher"
    category = "classical"
    _square = "ABCDEFGHIKLMNOPQRSTUVWXYZ"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        parts = re.split(r"[\s,]+", t)
        if len(parts) < 4:
            return []
        # Nihilist outputs 2-digit numbers (11-55 typically)
        if all(len(p) == 2 and p.isdigit() and '1' <= p[0] <= '5' and '1' <= p[1] <= '5' for p in parts):
            decoded = self.decode(t)
            conf = 0.65 if decoded else 0.55
            notes = "" if decoded else "needs keyword for full decryption"
            return [Candidate(self.id, self.name, self.category, conf,
                              decoded=decoded, notes=notes)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        parts = re.split(r"[\s,]+", text.strip())
        try:
            cipher_nums = [int(p) for p in parts]
        except ValueError:
            return None
        # Encode key using Polybius
        key = key.upper().replace("J", "I")
        key_nums = []
        for c in key:
            if c in self._square:
                idx = self._square.index(c)
                r, col = idx // 5 + 1, idx % 5 + 1
                key_nums.append(r * 10 + col)
        if not key_nums:
            return None
        # Subtract key (repeating) from cipher numbers
        result = []
        for i, cn in enumerate(cipher_nums):
            kn = key_nums[i % len(key_nums)]
            diff = cn - kn
            if 11 <= diff <= 55:
                r, c = diff // 10, diff % 10
                if 1 <= r <= 5 and 1 <= c <= 5:
                    idx = (r - 1) * 5 + (c - 1)
                    if idx < len(self._square):
                        result.append(self._square[idx])
        return "".join(result) if result else None

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        text = text.upper().replace("J", "I")
        key = key.upper().replace("J", "I")
        key_nums = []
        for c in key:
            if c in self._square:
                idx = self._square.index(c)
                r, col = idx // 5 + 1, idx % 5 + 1
                key_nums.append(r * 10 + col)
        if not key_nums:
            return None
        result = []
        for i, c in enumerate(text):
            if c not in self._square:
                return None
            idx = self._square.index(c)
            r, col = idx // 5 + 1, idx % 5 + 1
            plain_num = r * 10 + col
            result.append(str(plain_num + key_nums[i % len(key_nums)]))
        return " ".join(result)


class PortaCipher(Cipher):
    """Porta cipher: polyalphabetic substitution."""
    id = "porta"
    name = "Porta cipher"
    category = "classical"

    _table = [
        "NOPQRSTUVWXYZABCDEFGHIJKLM",
        "ONPQRSTUVWXYZABCDEFGHIJKLM",
        "MNOPQRSTUVWXYZABCDEFGHIJKL",
        "LMNOPQRSTUVWXYZABCDEFGHIJK",
        "KLMNOPQRSTUVWXYZABCDEFGHIJ",
        "JKLMNOPQRSTUVWXYZABCDEFGHI",
        "IJKLMNOPQRSTUVWXYZABCDEFGH",
        "HIJKLMNOPQRSTUVWXYZABCDEFG",
        "GHIJKLMNOPQRSTUVWXYZABCDEF",
        "FGHIJKLMNOPQRSTUVWXYZABCDE",
        "EFGHIJKLMNOPQRSTUVWXYZABCD",
        "DEFGHIJKLMNOPQRSTUVWXYZABC",
        "CDEFGHIJKLMNOPQRSTUVWXYZAB",
        "BCDEFGHIJKLMNOPQRSTUVWXYZA",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    ]

    def identify(self, text: str) -> list[Candidate]:
        letters = [c for c in text if c.isalpha()]
        if len(letters) < 20:
            return []
        if not _is_alpha_dominant(text):
            return []
        ioc = self._ioc(letters)
        if ioc > 0.05:
            return []
        # Try short keys
        best = None
        for klen in range(1, 6):
            for kw_base in range(26):
                kw = chr(kw_base + ord('A')) * klen
                decoded = self._decrypt(text, kw)
                chi = chi_square_english(decoded)
                if best is None or chi < best[0]:
                    best = (chi, kw, decoded)
        if best and best[0] < 150:
            _, kw, decoded = best
            return [Candidate(self.id, f"Porta (key={kw})", self.category,
                              0.55, decoded=decoded, key=kw)]
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text, key.upper())

    def _decrypt(self, text: str, key: str) -> str:
        key = key.upper()
        result = []
        ki = 0
        for c in text:
            if c.isalpha():
                ki_mod = ki % len(key)
                row = ord(key[ki_mod]) - ord('A')
                if row >= len(self._table):
                    row = row % len(self._table)
                table_row = self._table[row]
                idx = ord(c.upper()) - ord('A')
                if 0 <= idx < 26 and idx < len(table_row):
                    plain_char = table_row[idx]
                    result.append(plain_char if c.isupper() else plain_char.lower())
                else:
                    result.append(c)
                ki += 1
            else:
                result.append(c)
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        return self._decrypt(text, key.upper())

    @staticmethod
    def _ioc(letters: list[str]) -> float:
        from collections import Counter
        n = len(letters)
        c = Counter(s.lower() for s in letters)
        return sum(v * (v - 1) for v in c.values()) / max(n * (n - 1), 1)


class PlayfairCipher(Cipher):
    """Playfair cipher — digraph substitution using 5x5 matrix."""
    id = "playfair"
    name = "Playfair cipher"
    category = "classical"

    def _build_matrix(self, key: str) -> list[list[str]]:
        key = key.upper().replace("J", "I")
        seen = set()
        matrix = []
        for c in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if c not in seen and c.isalpha():
                seen.add(c)
                matrix.append(c)
        return [matrix[i*5:(i+1)*5] for i in range(5)]

    def _find(self, matrix: list[list[str]], ch: str) -> tuple[int, int]:
        for r, row in enumerate(matrix):
            for c, val in enumerate(row):
                if val == ch:
                    return r, c
        return 0, 0

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().upper().replace("J", "I")
        if not re.fullmatch(r"[A-Z]+", t) or len(t) < 4 or len(t) % 2 != 0:
            return []
        return [Candidate(self.id, self.name, self.category, 0.4,
                          notes="digraph cipher — needs a key for decryption")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        matrix = self._build_matrix(key)
        t = text.upper().replace("J", "I")
        if len(t) % 2 != 0:
            t += "X"
        result = []
        for i in range(0, len(t), 2):
            a, b = t[i], t[i+1]
            ra, ca = self._find(matrix, a)
            rb, cb = self._find(matrix, b)
            if ra == rb:
                result.append(matrix[ra][(ca - 1) % 5])
                result.append(matrix[rb][(cb - 1) % 5])
            elif ca == cb:
                result.append(matrix[(ra - 1) % 5][ca])
                result.append(matrix[(rb - 1) % 5][cb])
            else:
                result.append(matrix[ra][cb])
                result.append(matrix[rb][ca])
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        matrix = self._build_matrix(key)
        t = text.upper().replace("J", "I")
        # Insert filler between duplicate letters in a pair
        pairs = []
        i = 0
        while i < len(t):
            a = t[i]
            if i + 1 < len(t):
                b = t[i + 1]
                if a == b:
                    pairs.append((a, "X"))
                    i += 1
                else:
                    pairs.append((a, b))
                    i += 2
            else:
                pairs.append((a, "X"))
                i += 1
        result = []
        for a, b in pairs:
            ra, ca = self._find(matrix, a)
            rb, cb = self._find(matrix, b)
            if ra == rb:
                result.append(matrix[ra][(ca + 1) % 5])
                result.append(matrix[rb][(cb + 1) % 5])
            elif ca == cb:
                result.append(matrix[(ra + 1) % 5][ca])
                result.append(matrix[(rb + 1) % 5][cb])
            else:
                result.append(matrix[ra][cb])
                result.append(matrix[rb][ca])
        return "".join(result)


class ScytaleCipher(Cipher):
    """Scytale transposition cipher — wrap text around a rod."""
    id = "scytale"
    name = "Scytale cipher"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not re.fullmatch(r"[A-Za-z]+", t) or len(t) < 4:
            return []
        return [Candidate(self.id, self.name, self.category, 0.3,
                          notes="transposition cipher — needs rod diameter (key)")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            diameter = int(key)
        except ValueError:
            return None
        if diameter < 2:
            return None
        n = len(text)
        rows = (n + diameter - 1) // diameter
        # Encode wrote column-by-column, so fill column-by-column
        grid = [[''] * diameter for _ in range(rows)]
        idx = 0
        for row in range(rows):
            for col in range(diameter):
                if idx < n:
                    grid[row][col] = text[idx]
                    idx += 1
        # Read column by column to recover plaintext
        result = []
        for col in range(diameter):
            for row in range(rows):
                if grid[row][col]:
                    result.append(grid[row][col])
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            diameter = int(key)
        except ValueError:
            return None
        if diameter < 2:
            return None
        # Write text row by row, read column by column
        rows = (len(text) + diameter - 1) // diameter
        grid = [[''] * diameter for _ in range(rows)]
        idx = 0
        for row in range(rows):
            for col in range(diameter):
                if idx < len(text):
                    grid[row][col] = text[idx]
                    idx += 1
        result = []
        for col in range(diameter):
            for row in range(rows):
                if grid[row][col]:
                    result.append(grid[row][col])
        return "".join(result)


class FourSquareCipher(Cipher):
    """Four-square cipher — digraph substitution using four 5x5 grids."""
    id = "foursquare"
    name = "Four-square cipher"
    category = "classical"

    def _build_matrix(self, key: str) -> list[list[str]]:
        key = key.upper().replace("J", "I")
        seen = set()
        matrix = []
        for c in key + "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if c not in seen and c.isalpha():
                seen.add(c)
                matrix.append(c)
        return [matrix[i*5:(i+1)*5] for i in range(5)]

    def _find(self, matrix: list[list[str]], ch: str) -> tuple[int, int]:
        for r, row in enumerate(matrix):
            for c, val in enumerate(row):
                if val == ch:
                    return r, c
        return 0, 0

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().upper().replace("J", "I")
        if not re.fullmatch(r"[A-Z]+", t) or len(t) < 4 or len(t) % 2 != 0:
            return []
        return [Candidate(self.id, self.name, self.category, 0.35,
                          notes="digraph cipher — needs two keys for decryption")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key or "," not in key:
            return None
        k1, k2 = key.split(",", 1)
        plain_sq = self._build_matrix("")
        cipher1 = self._build_matrix(k1.strip())
        cipher2 = self._build_matrix(k2.strip())
        t = text.upper().replace("J", "I")
        if len(t) % 2 != 0:
            t += "X"
        result = []
        for i in range(0, len(t), 2):
            r1, c1 = self._find(cipher1, t[i])
            r2, c2 = self._find(cipher2, t[i+1])
            result.append(plain_sq[r1][c2])
            result.append(plain_sq[r2][c1])
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key or "," not in key:
            return None
        k1, k2 = key.split(",", 1)
        plain_sq = self._build_matrix("")
        cipher1 = self._build_matrix(k1.strip())
        cipher2 = self._build_matrix(k2.strip())
        t = text.upper().replace("J", "I")
        if len(t) % 2 != 0:
            t += "X"
        result = []
        for i in range(0, len(t), 2):
            r1, c1 = self._find(plain_sq, t[i])
            r2, c2 = self._find(plain_sq, t[i+1])
            result.append(cipher1[r1][c2])
            result.append(cipher2[r2][c1])
        return "".join(result)


class HillCipher(Cipher):
    """Hill cipher — matrix multiplication modulo 26."""
    id = "hill"
    name = "Hill cipher"
    category = "classical"

    def _parse_key(self, key: str) -> list[list[int]]:
        nums = [int(x) for x in key.replace(",", " ").split()]
        n = int(len(nums) ** 0.5)
        return [nums[i*n:(i+1)*n] for i in range(n)]

    def _mat_mul(self, mat: list[list[int]], vec: list[int]) -> list[int]:
        n = len(mat)
        return [sum(mat[i][j] * vec[j] for j in range(n)) % 26 for i in range(n)]

    def _mat_inv(self, mat: list[list[int]]) -> list[list[int]]:
        n = len(mat)
        det = int(round(sum(
            mat[0][i] * (mat[1][(i+1)%n] * mat[2][(i+2)%n] - mat[1][(i+2)%n] * mat[2][(i+1)%n])
            for i in range(n)
        ))) % 26
        det_inv = pow(det, -1, 26)
        adj = [[0]*n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                minor = [row[:j] + row[j+1:] for row in (mat[:i] + mat[i+1:])]
                cofactor = minor[0][0] * minor[1][1] - minor[0][1] * minor[1][0]
                adj[j][i] = (cofactor * det_inv) % 26
        return adj

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().upper().replace("J", "I")
        if not re.fullmatch(r"[A-Z]+", t) or len(t) < 4:
            return []
        return [Candidate(self.id, self.name, self.category, 0.35,
                          notes="matrix cipher — needs key (matrix dimensions)")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            mat = self._parse_key(key)
            inv = self._mat_inv(mat)
            t = text.upper().replace("J", "I")
            n = len(mat)
            result = []
            for i in range(0, len(t), n):
                chunk = [ord(c) - ord('A') for c in t[i:i+n]]
                while len(chunk) < n:
                    chunk.append(0)
                dec = self._mat_mul(inv, chunk)
                result.extend(chr(d + ord('A')) for d in dec)
            return "".join(result[:len(t)])
        except Exception:
            return None

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            mat = self._parse_key(key)
            t = text.upper().replace("J", "I")
            n = len(mat)
            result = []
            for i in range(0, len(t), n):
                chunk = [ord(c) - ord('A') for c in t[i:i+n]]
                while len(chunk) < n:
                    chunk.append(0)
                enc = self._mat_mul(mat, chunk)
                result.extend(chr(e + ord('A')) for e in enc)
            return "".join(result)
        except Exception:
            return None


class ColumnarTranspositionCipher(Cipher):
    """Columnar transposition cipher."""
    id = "columnar"
    name = "Columnar transposition"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not re.fullmatch(r"[A-Za-z]+", t) or len(t) < 6:
            return []
        return [Candidate(self.id, self.name, self.category, 0.3,
                          notes="transposition cipher — needs keyword")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        n_cols = len(key)
        n_rows = len(text) // n_cols
        extra = len(text) % n_cols
        grid = [[''] * n_cols for _ in range(n_rows + (1 if extra else 0))]
        idx = 0
        for col in key_order:
            rows = n_rows + (1 if col < extra else 0)
            for row in range(rows):
                grid[row][col] = text[idx]
                idx += 1
        return "".join("".join(row) for row in grid)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key_order = sorted(range(len(key)), key=lambda k: key[k])
        n_cols = len(key)
        n_rows = len(text) // n_cols
        extra = len(text) % n_cols
        grid = [[''] * n_cols for _ in range(n_rows + (1 if extra else 0))]
        idx = 0
        for row in range(len(grid)):
            for col in range(n_cols):
                if idx < len(text):
                    grid[row][col] = text[idx]
                    idx += 1
        result = []
        for col in key_order:
            for row in range(len(grid)):
                if grid[row][col]:
                    result.append(grid[row][col])
        return "".join(result)


class RouteCipher(Cipher):
    """Route cipher — write in grid, read by route."""
    id = "route"
    name = "Route cipher"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not re.fullmatch(r"[A-Za-z]+", t) or len(t) < 6:
            return []
        return [Candidate(self.id, self.name, self.category, 0.25,
                          notes="transposition cipher — needs grid dimensions")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            cols = int(key)
        except ValueError:
            return None
        if cols < 2:
            return None
        rows = (len(text) + cols - 1) // cols
        grid = [[''] * cols for _ in range(rows)]
        idx = 0
        for r in range(rows):
            for c in range(cols):
                if idx < len(text):
                    grid[r][c] = text[idx]
                    idx += 1
        result = []
        for c in range(cols):
            for r in range(rows):
                if grid[r][c]:
                    result.append(grid[r][c])
        return "".join(result)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        try:
            cols = int(key)
        except ValueError:
            return None
        if cols < 2:
            return None
        rows = (len(text) + cols - 1) // cols
        grid = [[''] * cols for _ in range(rows)]
        idx = 0
        for r in range(rows):
            for c in range(cols):
                if idx < len(text):
                    grid[r][c] = text[idx]
                    idx += 1
        result = []
        for r in range(rows):
            for c in range(cols):
                if grid[r][c]:
                    result.append(grid[r][c])
        return "".join(result)


class KeywordSubstitutionCipher(Cipher):
    """Keyword substitution cipher — custom alphabet mapping."""
    id = "keyword_sub"
    name = "Keyword substitution"
    category = "classical"

    def identify(self, text: str) -> list[Candidate]:
        return []

    def decode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.upper()
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        seen = set()
        cipher_alpha = []
        for c in key + standard:
            if c not in seen and c.isalpha():
                seen.add(c)
                cipher_alpha.append(c)
        trans = str.maketrans("".join(cipher_alpha), standard)
        return text.upper().translate(trans)

    def encode(self, text: str, key: str | None = None) -> str | None:
        if not key:
            return None
        key = key.upper()
        standard = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        seen = set()
        cipher_alpha = []
        for c in key + standard:
            if c not in seen and c.isalpha():
                seen.add(c)
                cipher_alpha.append(c)
        trans = str.maketrans(standard, "".join(cipher_alpha))
        return text.upper().translate(trans)


CLASSICAL_CIPHERS = [
    CaesarCipher(), Rot13Cipher(), Rot47Cipher(), AtbashCipher(),
    AffineCipher(), VigenereCipher(), RailFenceCipher(),
    BaconCipher(), PolybiusCipher(),
    BeaufortCipher(), GronsfeldCipher(), AutokeyCipher(),
    BifidCipher(), NihilistCipher(), PortaCipher(),
    PlayfairCipher(), ScytaleCipher(), FourSquareCipher(),
    HillCipher(), ColumnarTranspositionCipher(), RouteCipher(),
    KeywordSubstitutionCipher(),
]
