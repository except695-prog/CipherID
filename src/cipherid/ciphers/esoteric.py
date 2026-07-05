"""Esoteric / programming-language-style encodings."""
from __future__ import annotations

import re
import time

from cipherid.cipher import Candidate, Cipher

MAX_BRAINFUCK_STEPS = 200000
MAX_BRAINFUCK_OUTPUT = 10000
BRAINFUCK_TIMEOUT = 5.0  # seconds


class BrainfuckCipher(Cipher):
    id = "brainfuck"
    name = "Brainfuck"
    category = "esoteric"
    _re = re.compile(r"^[\+\-<>\[\]\.,\s]+$")

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not self._re.fullmatch(t):
            return []
        # need a meaningful amount of brainfuck ops
        ops = sum(1 for c in t if c in "+-<>[].,")
        if ops < 8:
            return []
        plain = self.decode(t)
        if plain is None:
            return []
        return [Candidate(self.id, self.name, self.category, 0.95, decoded=plain)]

    def decode(self, text: str, key: str | None = None) -> str | None:
        code = [c for c in text if c in "+-<>[].,"]
        tape = [0] * 30000
        ptr = 0
        out = []
        i = 0
        pairs = {}
        stack = []
        for idx, c in enumerate(code):
            if c == "[":
                stack.append(idx)
            elif c == "]":
                if not stack:
                    return None
                j = stack.pop()
                pairs[j] = idx
                pairs[idx] = j
        if stack:
            return None
        steps = 0
        start_time = time.time()
        while i < len(code):
            steps += 1
            if steps > MAX_BRAINFUCK_STEPS:
                break
            if time.time() - start_time > BRAINFUCK_TIMEOUT:
                break
            if len(out) > MAX_BRAINFUCK_OUTPUT:
                break
            c = code[i]
            if c == ">":
                ptr = (ptr + 1) % 30000
            elif c == "<":
                ptr = (ptr - 1) % 30000
            elif c == "+":
                tape[ptr] = (tape[ptr] + 1) % 256
            elif c == "-":
                tape[ptr] = (tape[ptr] - 1) % 256
            elif c == ".":
                char = chr(tape[ptr])
                if char.isprintable() or char in "\n\r\t":
                    out.append(char)
            elif c == ",":
                tape[ptr] = 0
            elif c == "[":
                if tape[ptr] == 0:
                    i = pairs[i]
            elif c == "]":
                if tape[ptr] != 0:
                    i = pairs[i]
            i += 1
        return "".join(out) if out else None

    def encode(self, text: str, key: str | None = None) -> str | None:
        """Generate Brainfuck code that prints the input text."""
        result = []
        for ch in text:
            target = ord(ch)
            # Use simple approach: set cell to 0 then add target
            # For efficiency, use nearby values
            result.append(">" + "+" * target + ".")
        return "".join(result)


class OokCipher(Cipher):
    id = "ook"
    name = "Ook!"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        if "Ook" not in text:
            return []
        return [Candidate(self.id, self.name, self.category, 0.9, decoded=self.decode(text))]

    def decode(self, text: str, key: str | None = None) -> str | None:
        # Ook syntax: Ook. Ook? Ook!  -> translates to brainfuck
        tokens = re.findall(r"Ook[!.?]", text)
        if len(tokens) % 2 != 0:
            return None
        mapping = {
            ("Ook.", "Ook?"): ">",
            ("Ook?", "Ook."): "<",
            ("Ook.", "Ook."): "+",
            ("Ook!", "Ook!"): "-",
            ("Ook!", "Ook."): ".",
            ("Ook.", "Ook!"): ",",
            ("Ook!", "Ook?"): "[",
            ("Ook?", "Ook!"): "]",
        }
        bf = []
        for i in range(0, len(tokens), 2):
            pair = (tokens[i], tokens[i+1])
            if pair not in mapping:
                return None
            bf.append(mapping[pair])
        return BrainfuckCipher().decode("".join(bf))


class JSFuckCipher(Cipher):
    id = "jsfuck"
    name = "JSFuck"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t or len(t) < 20:
            return []
        if not all(c in "[]()!+" for c in t):
            return []
        return [Candidate(self.id, self.name, self.category, 0.9,
                          decoded=None, notes="run in a sandboxed JS engine to evaluate")]


class AAEncodeCipher(Cipher):
    id = "aaencode"
    name = "AAencode (Japanese kaomoji)"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        if "ﾟωﾟ" in text or "ﾟДﾟ" in text or "ﾟΘﾟ" in text:
            return [Candidate(self.id, self.name, self.category, 0.95,
                              decoded=None, notes="evaluate in JS to decode")]
        return []


class JJEncodeCipher(Cipher):
    id = "jjencode"
    name = "JJencode"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        if re.search(r"\$=~\[\];\$=\{", text) or "=[][" in text and "$=" in text:
            return [Candidate(self.id, self.name, self.category, 0.9,
                              decoded=None, notes="evaluate in JS to decode")]
        return []


class MalbolgeCipher(Cipher):
    """Malbolge esoteric language detection."""
    id = "malbolge"
    name = "Malbolge"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        # Malbolge uses only chars with ASCII codes 33-126, mostly weird symbols
        if not t or len(t) < 10:
            return []
        if all(33 <= ord(c) <= 126 for c in t):
            # Check for unusual character distribution
            unique_chars = len(set(t))
            if unique_chars > len(t) * 0.3:
                return [Candidate(self.id, self.name, self.category, 0.3,
                                  decoded=None,
                                  notes="Malbolge — one of the hardest esoteric languages")]
        return []


class BefungeCipher(Cipher):
    """Befunge 2D esoteric language detection."""
    id = "befunge"
    name = "Befunge"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # Befunge uses 2D grid with specific instruction chars
        befunge_chars = set("0123456789+-*/%`<>v^_@?:|\"!~&$,.;# pg")
        if all(c in befunge_chars or c == '\n' for c in t):
            lines = t.split('\n')
            if len(lines) > 1 and all(len(l) > 0 for l in lines):
                return [Candidate(self.id, self.name, self.category, 0.4,
                                  decoded=None,
                                  notes="Befunge 2D language — execute with interpreter")]
        return []


class WhitespaceEsotericCipher(Cipher):
    """Whitespace esoteric language (uses only space/tab/newline)."""
    id = "whitespace_esoteric"
    name = "Whitespace (esoteric)"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text
        if not t:
            return []
        if all(c in ' \t\n' for c in t) and len(t) > 20:
            return [Candidate(self.id, self.name, self.category, 0.6,
                              decoded=None,
                              notes="Whitespace language — only spaces, tabs, newlines")]
        return []


class ShakespeareCipher(Cipher):
    """Shakespeare Programming Language detection."""
    id = "shakespeare"
    name = "Shakespeare Programming Language"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # SPL uses dramatic phrases
        spl_markers = ["Act ", "Scene ", "Enter ", "Exit ", "Exeunt",
                       "Juliet:", "Romeo:", "Hamlet:", "Ophelia:"]
        if sum(m in t for m in spl_markers) >= 2:
            return [Candidate(self.id, self.name, self.category, 0.7,
                              decoded=None,
                              notes="Shakespeare Programming Language — theatrical code")]
        return []


class ChefCipher(Cipher):
    """Chef esoteric programming language detection."""
    id = "chef"
    name = "Chef (esoteric)"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # Chef uses recipe-like structure
        chef_markers = ["Ingredients.", "Cooking time:", "Oven time:",
                        "Preparation time:", "Method.", "Serves"]
        if sum(m in t for m in chef_markers) >= 2:
            return [Candidate(self.id, self.name, self.category, 0.7,
                              decoded=None,
                              notes="Chef language — code looks like a recipe")]
        return []


class RockCipher(Cipher):
    """Rock esoteric language detection."""
    id = "rock"
    name = "Rock (esoteric)"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # Rock uses only specific symbols
        rock_chars = set("()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`{|}~")
        if all(c in rock_chars for c in t) and len(t) > 20:
            return [Candidate(self.id, self.name, self.category, 0.3,
                              decoded=None,
                              notes="Rock language — esoteric")]
        return []


class EmojinalCipher(Cipher):
    """Emojinal (emoji-based) esoteric language detection."""
    id = "emojinal"
    name = "Emojinal"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if not t:
            return []
        # Check if mostly emoji
        emoji_count = sum(1 for c in t if ord(c) > 0x2600)
        if emoji_count > len(t) * 0.5 and len(t) > 10:
            return [Candidate(self.id, self.name, self.category, 0.5,
                              decoded=None,
                              notes="Emoji-based esoteric language")]
        return []


class BinaryFuckCipher(Cipher):
    """BinaryFuck: brainfuck-like using only 0 and 1."""
    id = "binaryfuck"
    name = "BinaryFuck"
    category = "esoteric"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip().replace(" ", "")
        if not t:
            return []
        if all(c in '01' for c in t) and len(t) >= 8 and len(t) % 8 == 0:
            return [Candidate(self.id, self.name, self.category, 0.4,
                              decoded=None,
                              notes="BinaryFuck — binary-encoded brainfuck")]
        return []


ESOTERIC_CIPHERS = [
    BrainfuckCipher(), OokCipher(), JSFuckCipher(),
    AAEncodeCipher(), JJEncodeCipher(),
    MalbolgeCipher(), BefungeCipher(), WhitespaceEsotericCipher(),
    ShakespeareCipher(), ChefCipher(), RockCipher(),
    EmojinalCipher(), BinaryFuckCipher(),
]
