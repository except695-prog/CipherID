# Adding a new cipher

Pick the right file in `src/cipherid/ciphers/` (encodings, classical, esoteric,
hashes, tokens, modern, chinese). Add a class:

```python
from cipherid.cipher import Candidate, Cipher


class MyCipher(Cipher):
    id = "mycipher"          # unique id used in CLI / JSON output
    name = "My fancy cipher" # human-readable, shown in the GUI
    category = "encoding"    # one of encoding|classical|esoteric|hash|token|modern|chinese

    def identify(self, text):
        if not _structurally_matches(text):
            return []
        decoded = self.decode(text)
        if decoded is None:
            return []
        return [Candidate(self.id, self.name, self.category,
                          confidence=0.85, decoded=decoded)]

    def decode(self, text, key=None):
        # return the plaintext, or None if it can't be decoded without a key
        return ...
```

Then append the instance to the file's exported list (e.g. `ENCODING_CIPHERS`).
Add a positive-case test in `tests/test_engine.py`:

```python
def test_mycipher_detected():
    e = Engine()
    res = e.identify("...encoded...")
    assert any(c.cipher_id == "mycipher" for c in res.candidates)
```

## Guidelines

- **Confidence**: be conservative. 0.95+ is reserved for unambiguous structural
  matches (Morse with valid chars only, PEM headers, JWT three-part). 0.5–0.8
  is appropriate when statistics back up the guess. Don't return a Candidate
  if you're below ~0.3 — it just clutters the output.
- **Never throw**. If parsing fails, return `[]`. The engine isolates exceptions
  but uncaught errors slow it down.
- **`decode()` is optional** — many ciphers (hashes, tokens) are identification-
  only. Leave it out and the engine will mark them as "no decoded payload".
- **Keep it fast**. `identify()` is called on every input by every cipher.
  Bail out early on length / charset / regex checks before doing real work.
