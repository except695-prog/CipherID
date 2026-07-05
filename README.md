# CipherID

> One-click cipher/encoding identifier, decoder & encoder for CTFs — 115 types, 71 encodable, confidence ranking, nested auto-decode, GUI & CLI.

[English](README.md) | [简体中文](README.zh-CN.md)

CipherID is a one-click cipher and encoding identifier, decoder and encoder built for CTF competitions. Paste any ciphertext and get instant confidence-ranked candidates, or let it auto-decode nested layers until the flag appears. Supports **115 cipher and encoding types** including Base encodings, classical ciphers, hashes, JWT, API tokens, cryptocurrency addresses, esoteric programming languages, and Chinese CTF ciphers. Also provides **encoding/encryption** — encode plaintext with **71 algorithms** organized by category (encoding, classical, Chinese, modern, esoteric, hash), with optional key support. Features a multi-theme PySide6 GUI (dark/light/blue/green/monokai), headless CLI, image input (QR / barcode / OCR), and single-file executable packaging.

## Quick start

### Use the prebuilt executable (recommended)

Grab the latest `CipherID.exe` / `CipherID` from the [Releases](https://github.com/except695-prog/CipherID/releases) page and double-click it. No install, no Python.

### Run from source

```bash
git clone https://github.com/except695-prog/CipherID
cd CipherID
pip install -e ".[dev]"
cipherid-gui            # launch the GUI
cipherid identify "U2FsdGVkX1+..."   # or use the CLI
```

Requires Python 3.10+.

## Features

- **115 ciphers / encodings**: see the [supported list](#supported-ciphers).
- **71 encodable algorithms**: encode plaintext with Base*, classical, Chinese, modern ciphers — `cipherid encode --list-algorithms`.
- **Confidence-ranked candidates**: every result carries a score 0–100% based on structural match, statistical features (entropy + English chi-square), and successful decode.
- **One-click auto-decode** with **user-configurable flag format**: `flag{}`, `CTF{}`, `DASCTF{}`, `hkcert{}`, or any custom regex.
- **Nested decoding**: auto-decode unwraps multi-layer wrappers (e.g. base64 → hex → rot13).
- **Image / screenshot input**: drag an image into the GUI (or pass a path to the CLI) and CipherID auto-decodes embedded QR codes, Data Matrix, PDF417, Aztec, and 1-D barcodes via `pyzbar`, then falls back to Tesseract OCR for plain screenshots. The recovered text is fed straight into the regular identify / auto-decode pipeline.
- **Drag-and-drop** files, images, and text, **paste from clipboard** shortcut.
- **Multi-theme UI**: PySide6 with dark, light, blue, green, monokai themes.
- **Single-file executable** built via PyInstaller for Windows, Linux, macOS.
- **Headless CLI** for scripting (`cipherid identify`, `cipherid auto`, `cipherid encode`, `cipherid decode`, `cipherid image`, `cipherid config`, `cipherid backends`).

## Supported ciphers

| Category | Ciphers |
| --- | --- |
| **Base encodings** | Base16 (Hex), Base32, Base32 Crockford, Base32 Hex, Base45, Base58 (Bitcoin), Base62, Base64, Base64-URLsafe, Base85 (RFC1924), Base91, Base100 (Emoji), Base2048, ASCII85 (Adobe), ASCII85 (ZeroMQ), ASCII85 (Z85), Punycode (IDNA) |
| **Other encodings** | URL / percent, HTML entities, Unicode `\uXXXX` escapes, Quoted-printable (MIME), UUencode, binary (8-bit), octal, decimal byte stream, A1Z26 letter-ordinals, reverse, Whitespace, Hex Dump |
| **Symbolic / signal** | Morse code, Braille, Semaphore, Tap code, Pigpen / Masonic |
| **Classical substitution** | Caesar / shift (all 25 brute-forced + best by chi-square), ROT5, ROT13, ROT18, ROT47, ROT52, Atbash, Affine (a·x + b), Vigenère, Baconian, Beaufort, Gronsfeld, Autokey, Playfair, Porta, Hill, Keyword substitution |
| **Classical transposition** | Rail fence, Polybius square (5×5), Bifid, Nihilist, Scytale, Four-square, Columnar transposition, Route cipher |
| **Esoteric / programming-lang** | Brainfuck (full interpreter), Ook!, JSFuck, AAencode, JJencode, Malbolge, Befunge, Whitespace (esoteric), Shakespeare, Chef, Rock, Emojinal, BinaryFuck |
| **Hash / digest** | MD5, MD4, NTLM, LM, SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, RIPEMD-160, BLAKE2, CRC32, bcrypt, scrypt, Argon2, Tiger, Keccak/SHA-3, SM3, Unix `$1$/$5$/$6$` crypt, HMAC (compute) |
| **API tokens / wire formats** | JWT (parse + show header/payload), OpenAI `sk-` / `sk-proj-`, Anthropic `sk-ant-`, GitHub PAT/PEM/server/fine-grained, Google `AIza`, AWS `AKIA`, Slack `xox*`, HuggingFace `hf_`, Replicate `r8_`, Stripe `sk_live` / `pk_live`, Discord webhook URL, GitLab, SendGrid, Heroku, DigitalOcean, Twilio, Bitcoin Legacy / Bech32 address, Ethereum, Solana, Litecoin, Ripple, Monero, Dash, Dogecoin, NEM, Stellar address, PEM certs & keys |
| **Modern crypto** | AES block (hex / base64) detection, AES-GCM blob, RSA modulus / ciphertext, DSA signature, **XOR** (encode/decode + single-byte brute force + multi-byte brute force), **RC4** stream cipher, Vigenère autokey (ciphertext & plaintext variants), HMAC (compute) |
| **Chinese CTF ciphers** | 社会主义核心价值观, 当铺密码, 中文电码, 与佛论禅 / 新约佛论禅, QWERTY 键盘密码, 五行密码, 天干地支, 注音符号, 仓颉, 拼音 |

## GUI walkthrough

1. Paste, drag a ciphertext, drag any file, or drag an **image** (QR / barcode / screenshot) into the input box. Images are decoded in a background thread and the extracted text replaces the input.
2. (Optional) type a flag format like `flag{}`, `CTF{}`, `DASCTF{}`, or a regex.
3. Click **Identify** to see ranked candidates with confidence, or **Auto-decode** to recursively unwrap until the flag pattern matches.
4. Click any candidate on the left to preview its decoded payload on the right.
5. Use **Copy** to copy the decoded text, or **Use as input** to chain another decode manually.

Open images explicitly with **File → Open image…** (Ctrl+Shift+O), or check **Help → Image backends…** if QR / OCR is silently doing nothing — it will list which optional backends (`pyzbar`, `pytesseract`, the Tesseract binary) are wired up.

The flag pattern accepts:

- A template `prefix{}` (e.g. `flag{}`, `CTF{}`, `DASCTF{}`) — the body becomes a non-greedy wildcard.
- A raw regex (e.g. `flag\{[A-Za-z0-9_]+\}`).
- Empty — falls back to a broad union of common flag formats (`flag{...}` / `CTF{...}` / `hkcert{...}` / `DASCTF{...}` / `n1ctf{...}` …).

## CLI

```bash
# rank candidates
cipherid identify "U2FsdGVkX1+..."
cipherid identify "U2FsdGVkX1+..." --flag-format "flag{}" --top 5

# emit JSON for scripting
cipherid identify "..." --json

# recursive auto-decode
cipherid auto "..." --flag-format "CTF{}" --max-depth 5

# encode plaintext with a specific algorithm
cipherid encode "Hello World" -a base64
cipherid encode "flag{test}" -a caesar -k 3
cipherid encode "Hello" -a xor -k secret
cipherid encode --list-algorithms                  # list all 65 encodable algorithms
cipherid encode --list-algorithms -c classical     # filter by category

# decode ciphertext with a specific algorithm
cipherid decode "SGVsbG8=" -a base64
cipherid decode "cixd{qbpq}" -a caesar -k 3

# image input — works for both `identify` and `auto`
cipherid identify ./screenshot.png --flag-format "flag{}"
cipherid auto ./qr.png --flag-format "flag{}"

# extract only — QR / barcode / OCR, no identification
cipherid image ./qr.png
cipherid image ./scan.jpg --no-ocr           # skip OCR; codes only
cipherid image ./qr.png --json               # JSON for scripting

# which image backends are usable on this machine?
cipherid backends

# launch the GUI
cipherid gui
```

### Image / QR / barcode / OCR

`cipherid identify` and `cipherid auto` both accept an image path. CipherID first
tries every 1-D / 2-D barcode supported by `pyzbar` (QR Code, Data Matrix, PDF417,
Aztec, EAN, Code 128, …); if nothing decodes and `--no-ocr` is not set, it falls
back to Tesseract OCR. The extracted text is then fed into the normal pipeline,
so the workflow "screenshot of base64 of a flag" reaches the flag in one
command.

Optional backends:

- `pyzbar` + the `libzbar` shared library — needed for QR / barcode decoding.
- `pytesseract` + the Tesseract binary — needed for OCR. On Windows install the
  UB-Mannheim Tesseract build and make sure `tesseract.exe` is on `PATH`.

Run `cipherid backends` to see what is wired up on the current machine.

## Project structure

```
CipherID/
├── pyproject.toml              # Build config, dependencies, entry points
├── README.md                   # English readme (this file)
├── README.zh-CN.md             # 中文说明
├── LICENSE                     # MIT
├── CHANGELOG.md                # Version history
├── .github/
│   └── workflows/
│       ├── ci.yml              # Lint + tests on Linux/Win/macOS, Python 3.10–3.12
│       └── release.yml         # Builds Win/Linux/macOS exe on tag and creates a GitHub Release
├── build_scripts/
│   ├── cipherid.spec           # PyInstaller spec (single-file, windowed)
│   └── build_exe.py            # Convenience script: `python build_scripts/build_exe.py`
├── docs/
│   └── adding_a_cipher.md      # How to add a new detector
├── tests/
│   ├── __init__.py
│   ├── test_engine.py          # End-to-end: identify + auto-decode + flag extraction
│   └── test_image.py           # QR roundtrip + image → engine pipeline
└── src/
    └── cipherid/
        ├── __init__.py         # Public API
        ├── cli.py              # Click-based CLI (identify / auto / encode / decode / image / backends / gui)
        ├── cipher.py           # Cipher base class + Candidate / DecodeResult dataclasses
        ├── engine.py           # Engine: identify, auto_decode, encode_one, decode_one, nested unwrapping
        ├── config.py           # Configuration file (cipherid.json)
        ├── flag.py             # Flag-format compiler (template OR raw regex)
        ├── heuristics.py       # Entropy + English chi-square + language guess
        ├── image.py            # QR / barcode (pyzbar) + OCR (Tesseract) extraction
        ├── plugins.py          # Plugin system for custom ciphers
        ├── ciphers/
        │   ├── __init__.py     # load_ciphers() registry
        │   ├── encodings.py    # Base*, URL, HTML, Morse, UU, binary, hex, Braille, Semaphore, …
        │   ├── classical.py    # Caesar / ROT / Atbash / Affine / Vigenère / Bacon / Polybius / Playfair / …
        │   ├── esoteric.py     # Brainfuck / Ook! / JSFuck / AAencode / JJencode / Malbolge / …
        │   ├── hashes.py       # MD5/SHA*/NTLM/bcrypt/Argon2/scrypt/Tiger/Keccak/SM3/CRC32 identifiers + hash compute
        │   ├── tokens.py       # JWT, OpenAI/Anthropic/AWS/GitHub/Stripe tokens, PEM, BTC, ETH, SOL, …
        │   ├── modern.py       # AES/GCM/RSA detection, XOR, RC4, HMAC, Vigenère autokey
        │   └── chinese.py      # 核心价值观 / 当铺 / 与佛论禅 / 中文电码 / 键盘 / 五行 / 仓颉 / 拼音
        └── gui/
            ├── __init__.py
            ├── app.py          # Main window + identify / auto-decode / image-extract workers
            └── theme.py        # Dark / Light / Blue / Green / Monokai QSS stylesheets
```

### Module responsibilities

| File | Role |
| --- | --- |
| `src/cipherid/cipher.py` | Defines `Cipher` (abstract base) plus `Candidate` and `DecodeResult` dataclasses. Every detector/encoder is a `Cipher` subclass with `identify()`, optional `decode()`, and optional `encode()`. |
| `src/cipherid/engine.py` | The `Engine` class. `identify()` runs all ciphers in parallel-friendly order and returns confidence-sorted `Candidate`s. `auto_decode()` greedily unwraps nested layers and stops on flag match / English plaintext / max depth. `encode_one()` / `decode_one()` for specific algorithm operations. |
| `src/cipherid/flag.py` | Parses user flag-format input. Accepts `prefix{}` templates, raw regexes, or empty (uses a default broad union of common flag formats). |
| `src/cipherid/heuristics.py` | Shared statistical primitives — Shannon entropy, chi-square against English letter frequency, Unicode / CJK plausibility, printable-ratio checks. Used by individual ciphers to score confidence. |
| `src/cipherid/image.py` | Image preprocessing — pulls text out of QR codes / barcodes (`pyzbar`) and screenshots (`pytesseract` / Tesseract). All backends are optional; `backend_status()` reports what is wired up. |
| `src/cipherid/config.py` | Configuration file handling — load/save `cipherid.json` with custom thresholds, disabled ciphers, flag presets. |
| `src/cipherid/plugins.py` | Plugin system — loads custom `Cipher` subclasses from `~/.cipherid/plugins/` or `./cipherid_plugins/`. |
| `src/cipherid/ciphers/` | One file per category. Each file exports a list of `Cipher` instances. The registry in `ciphers/__init__.py` concatenates them. |
| `src/cipherid/gui/app.py` | PySide6 `MainWindow`. Worker `QThread`s keep the UI responsive while heavier searches and image decoding run. Supports drag-drop (text / files / images), clipboard paste, file open, image open, copy / chain decode. |
| `src/cipherid/gui/theme.py` | Hand-tuned stylesheets: dark, light, blue, green, monokai. |
| `src/cipherid/cli.py` | Click-based CLI with subcommands: `identify`, `auto`, `encode`, `decode`, `image`, `backends`, `gui`, `config`. |

## How auto-decode works

`Engine.auto_decode()` is a small greedy search:

1. Run all ciphers against the current text.
2. For each candidate that produced a decoded value: score = `cipher.confidence + 1.0·flag_match_bonus + 0.2·language_plausibility_bonus`.
3. Pick the highest-scoring decode and recurse.
4. Stop when the flag pattern matches, the result reads as ordinary English / Chinese, no further decode succeeds, or `max_depth` is reached.

This is intentionally simple — it handles 95% of nested CTF challenges (e.g. base64 of hex of rot13) without going off the rails. For tricky cases, use **Identify** repeatedly and the **Use as input** button to manually chain.

## Build the executable

```bash
pip install -e ".[dev]"
python build_scripts/build_exe.py
# -> dist/CipherID.exe (Windows) or dist/CipherID (Linux/macOS)
```

Single file, no Python interpreter required on the target machine.

## Run tests

```bash
pytest -q
ruff check src tests
```

## Adding a new cipher

1. Subclass `Cipher` in the appropriate `src/cipherid/ciphers/*.py` file.
2. Implement `identify(text) -> list[Candidate]` and (optionally) `decode(text, key=None) -> str | None` and `encode(text, key=None) -> str | None`.
3. Add the instance to the file's exported list (e.g. `ENCODING_CIPHERS`).
4. Add a positive-case test in `tests/test_engine.py`.

The base class is intentionally tiny — see `cipher.py` and any of the existing detectors for the pattern.

## Contributing

PRs welcome — new ciphers, better confidence scoring, GUI improvements, more flag formats. Open an issue first if you want to discuss something larger.

## License

MIT
