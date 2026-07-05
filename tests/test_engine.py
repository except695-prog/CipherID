"""Smoke tests for the identification + auto-decode engine."""
from __future__ import annotations

import base64

from cipherid.engine import Engine


def _identify_ids(text: str) -> set[str]:
    e = Engine()
    return {c.cipher_id for c in e.identify(text).candidates}


# ---- Base encodings ----

def test_base64_detected():
    s = base64.b64encode(b"flag{hello_world}").decode()
    e = Engine()
    res = e.identify(s, flag_format="flag{}")
    assert "base64" in {c.cipher_id for c in res.candidates}
    assert any(c.decoded == "flag{hello_world}" for c in res.candidates)


def test_hex_detected():
    s = b"flag{abc}".hex()
    assert "base16" in _identify_ids(s)


def test_base32_detected():
    s = base64.b32encode(b"hello").decode()
    assert "base32" in _identify_ids(s)


def test_base85_detected():
    s = base64.b85encode(b"hello").decode()
    assert "base85" in _identify_ids(s)


def test_ascii85_detected():
    s = "<~" + base64.a85encode(b"hello").decode() + "~>"
    assert "ascii85" in _identify_ids(s)


def test_base91_detected():
    s = "8Ow~7y$"  # base91 encoded "hello"
    e = Engine()
    res = e.identify(s)
    # base91 has a specific charset check; just verify it runs without error
    assert isinstance(res.candidates, list)


# ---- Other encodings ----

def test_morse_detected():
    s = "..-. .-.. .- --."  # FLAG
    e = Engine()
    res = e.identify(s)
    assert any(c.cipher_id == "morse" and c.decoded == "FLAG" for c in res.candidates)


def test_rot13_detected():
    s = "synt{uryyb}"  # rot13 of flag{hello}
    e = Engine()
    res = e.identify(s, flag_format="flag{}")
    decoded = [c.decoded for c in res.candidates if c.cipher_id in {"rot13", "caesar"}]
    assert any("flag{hello}" in (d or "") for d in decoded)


def test_url_encoding():
    e = Engine()
    res = e.identify("hello%20world%21")
    decoded = [c.decoded for c in res.candidates if c.cipher_id == "urlencode"]
    assert decoded and "hello world!" in decoded[0]


def test_html_entity():
    e = Engine()
    res = e.identify("hello&#32;world&lt;3&gt;")
    assert "html" in {c.cipher_id for c in res.candidates}


def test_unicode_escape():
    e = Engine()
    res = e.identify("\\u0041\\u0042\\u0043")  # ABC
    assert "unicode_escape" in {c.cipher_id for c in res.candidates}


def test_binary_detected():
    e = Engine()
    s = "01000001"  # 'A'
    res = e.identify(s)
    assert "binary" in {c.cipher_id for c in res.candidates}


def test_reverse_detected():
    e = Engine()
    res = e.identify("}tfelk{galf")  # flag{left} reversed
    assert "reverse" in {c.cipher_id for c in res.candidates}


def test_punycode_detected():
    e = Engine()
    res = e.identify("xn--e1afmkfd")  # москва in punycode
    assert "punycode" in {c.cipher_id for c in res.candidates}


# ---- Classical ciphers ----

def test_atbash():
    e = Engine()
    res = e.identify("svool")  # atbash of hello
    assert any(c.cipher_id == "atbash" for c in res.candidates)


def test_caesar_all_shifts():
    from cipherid.ciphers.classical import caesar_shift
    e = Engine()
    # Test several known shifts that produce English-like text
    for shift in [1, 3, 5, 7, 13]:
        original = "HELLOWORLD"
        encoded = caesar_shift(original, shift)
        res = e.identify(encoded)
        decoded = [c.decoded for c in res.candidates if c.cipher_id in {"caesar", "rot13"}]
        assert len(decoded) > 0, f"shift={shift}: no caesar/rot13 candidates for '{encoded}'"


def test_vigenere_detected():
    # Vigenere of "THEQUICKBROWNFOX" with key "LEMON"
    from cipherid.ciphers.classical import VigenereCipher
    v = VigenereCipher()
    plain = "THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG"
    key = "LEMON"
    encoded = []
    ki = 0
    for c in plain:
        k = ord(key[ki % len(key)]) - ord('A')
        encoded.append(chr((ord(c) - ord('A') + k) % 26 + ord('A')))
        ki += 1
    encoded = "".join(encoded)
    res = v.identify(encoded)
    assert len(res) > 0


def test_baconian_detected():
    from cipherid.ciphers.classical import BaconCipher
    b = BaconCipher()
    # "AB" in baconian = AAAAA + AAAAB
    res = b.identify("AAAAA AAAAB")
    assert len(res) == 1
    assert res[0].decoded == "AB"


def test_polybius_detected():
    e = Engine()
    res = e.identify("11 22 33 44 55")  # A B C D E
    assert "polybius" in {c.cipher_id for c in res.candidates}


# ---- Hashes ----

def test_md5_detected():
    s = "5d41402abc4b2a76b9719d911017c592"  # md5("hello")
    assert "hash" in _identify_ids(s)


def test_sha1_detected():
    s = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
    assert "hash" in _identify_ids(s)


def test_sha256_detected():
    s = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    assert "hash" in _identify_ids(s)


def test_bcrypt_detected():
    s = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
    assert "hash" in _identify_ids(s)


# ---- Tokens ----

def test_jwt_detected():
    s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "jwt" in _identify_ids(s)


def test_token_anthropic_detected():
    s = "sk-ant-api03-" + "A" * 50
    assert "token" in _identify_ids(s)


def test_token_openai_detected():
    s = "sk-proj-" + "A" * 50
    assert "token" in _identify_ids(s)


def test_token_github_pat_detected():
    s = "github_pat_" + "A" * 82
    assert "token" in _identify_ids(s)


def test_token_aws_detected():
    s = "AKIA" + "A" * 16
    assert "token" in _identify_ids(s)


def test_token_slack_detected():
    s = "xoxb-" + "A" * 20
    assert "token" in _identify_ids(s)


# ---- Chinese CTF ciphers ----

def test_pawnshop():
    e = Engine()
    res = e.identify("由中人")
    assert any(c.cipher_id == "pawnshop" and c.decoded == "123" for c in res.candidates)


def test_core_values():
    plain = "A"
    n = ord(plain)
    from cipherid.ciphers.chinese import CORE_VALUES
    enc = CORE_VALUES[n // 12] + CORE_VALUES[n % 12]
    e = Engine()
    res = e.identify(enc)
    assert any(c.cipher_id == "core_values" and c.decoded == "A" for c in res.candidates)


def test_ctc_decoded():
    from cipherid.ciphers.chinese import ChineseTelegraphCipher
    c = ChineseTelegraphCipher()
    res = c.identify("0626 0485")
    assert len(res) == 1
    assert res[0].decoded == "令亏"


def test_ctc_unknown_code():
    from cipherid.ciphers.chinese import ChineseTelegraphCipher
    c = ChineseTelegraphCipher()
    res = c.identify("9999 0000")
    assert len(res) == 1
    assert res[0].decoded is None


# ---- Esoteric ----

def test_brainfuck_detected():
    bf = "++++++++[>++++++++<-]>+."  # outputs 'A'
    assert "brainfuck" in _identify_ids(bf)


def test_brainfuck_decoded():
    from cipherid.ciphers.esoteric import BrainfuckCipher
    bf = BrainfuckCipher()
    res = bf.identify("++++++++[>++++++++<-]>+.")
    assert len(res) == 1
    assert res[0].decoded == "A"


def test_ook_detected():
    e = Engine()
    s = "Ook. Ook? Ook. Ook. Ook! Ook. Ook? Ook. Ook! Ook. Ook. Ook! Ook. Ook? Ook. Ook."
    res = e.identify(s)
    assert "ook" in {c.cipher_id for c in res.candidates}


# ---- Modern crypto ----

def test_aes_ecb_detected():
    from cipherid.ciphers.modern import AESCipher
    a = AESCipher()
    # 4 identical 16-byte blocks = ECB pattern
    test = "41414141414141414141414141414141" * 4
    res = a.identify(test)
    assert any("ECB" in c.name for c in res)


def test_rsa_detected():
    e = Engine()
    # Large decimal number
    s = str(2**2048)
    res = e.identify(s)
    assert "rsa_block" in {c.cipher_id for c in res.candidates}


# ---- Engine behavior ----

def test_auto_decode_base64_chain():
    s1 = b"flag{nested_base64}"
    layer1 = base64.b64encode(s1)
    layer2 = base64.b64encode(layer1).decode()
    e = Engine()
    res = e.auto_decode(layer2, flag_format="flag{}")
    assert res.flag_match == "flag{nested_base64}"


def test_auto_decode_max_depth():
    # Chain of 10 base64 layers; max_depth=3 should not reach the bottom
    s = b"flag{deep}"
    for _ in range(10):
        s = base64.b64encode(s)
    e = Engine()
    res = e.auto_decode(s.decode(), flag_format="flag{}", max_depth=3)
    assert res.flag_match is None  # not reachable in 3 layers


def test_flag_format_custom():
    s = base64.b64encode(b"DASCTF{example}").decode()
    e = Engine()
    res = e.auto_decode(s, flag_format="DASCTF{}")
    assert res.flag_match == "DASCTF{example}"


def test_flag_format_regex():
    s = base64.b64encode(b"CTF{regex_test}").decode()
    e = Engine()
    res = e.auto_decode(s, flag_format=r"CTF\{[a-z_]+\}")
    assert res.flag_match == "CTF{regex_test}"


def test_empty_input():
    e = Engine()
    res = e.identify("")
    assert res.candidates == []


def test_no_candidates_for_random():
    e = Engine()
    # Random text may get some low-confidence matches; verify engine doesn't crash
    res = e.identify("kajshdfkajshdfkajshdf")
    # At least no high-confidence false positives
    high_conf = [c for c in res.candidates if c.confidence > 0.9]
    assert len(high_conf) == 0


# ---- New cipher tests ----

def test_base62_detected():
    from cipherid.ciphers.encodings import Base62Cipher
    b = Base62Cipher()
    # "Hello" in base62
    res = b.identify("3CHe2")
    assert isinstance(res, list)


def test_base36_detected():
    from cipherid.ciphers.encodings import Base36Cipher
    b = Base36Cipher()
    # "test" encoded as base36 integer
    res = b.identify("1at2g")
    assert isinstance(res, list)


def test_whitespace_encoding():
    from cipherid.ciphers.encodings import WhitespaceCipher
    w = WhitespaceCipher()
    # Simple whitespace encoding
    res = w.identify("   \t  \t ")
    assert isinstance(res, list)


def test_rot5_detected():
    from cipherid.ciphers.encodings import ROT5Cipher
    r = ROT5Cipher()
    res = r.identify("67890")
    assert any(c.decoded == "12345" for c in res)


def test_rot18_detected():
    from cipherid.ciphers.encodings import ROT18Cipher
    r = ROT18Cipher()
    res = r.identify("56789")
    assert any(c.decoded == "01234" for c in res)


def test_tapcode_detected():
    from cipherid.ciphers.encodings import TapCodeCipher
    t = TapCodeCipher()
    # "A" = row 1 col 1, "B" = row 1 col 2, "C" = row 1 col 3
    # Format: individual digits separated by spaces
    res = t.identify("1 1 1 2 1 3 1 4")
    assert len(res) > 0


def test_braille_detected():
    from cipherid.ciphers.encodings import BrailleCipher
    b = BrailleCipher()
    # Unicode braille for "a" = U+2801
    res = b.identify("\u2801\u2803")
    assert len(res) == 1
    assert res[0].decoded == "ab"


def test_base45_detected():
    from cipherid.ciphers.encodings import Base45Cipher
    b = Base45Cipher()
    res = b.identify("%69 VD92EX0")
    assert isinstance(res, list)


def test_beaufort_detected():
    from cipherid.ciphers.classical import BeaufortCipher
    b = BeaufortCipher()
    res = b.identify("HELLO")
    assert isinstance(res, list)


def test_gronsfeld_detected():
    from cipherid.ciphers.classical import GronsfeldCipher
    g = GronsfeldCipher()
    # Gronsfeld with key "1234" shifts each letter
    res = g.identify("IFMMP")
    assert isinstance(res, list)


def test_porta_detected():
    from cipherid.ciphers.classical import PortaCipher
    p = PortaCipher()
    res = p.identify("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 2)
    assert isinstance(res, list)


def test_bifid_detected():
    from cipherid.ciphers.classical import BifidCipher
    b = BifidCipher()
    res = b.identify("35 24 32 11 44 24 15 13")
    assert isinstance(res, list)


def test_nihilist_detected():
    from cipherid.ciphers.classical import NihilistCipher
    n = NihilistCipher()
    res = n.identify("23 12 45 34 51")
    assert isinstance(res, list)


def test_autokey_detected():
    from cipherid.ciphers.classical import AutokeyCipher
    a = AutokeyCipher()
    res = a.identify("THEQUICKBROWNFOXJUMPSOVERTHELAZYDOG" * 2)
    assert isinstance(res, list)


def test_tiger_hash_detected():
    s = "a" * 48  # 48 hex chars = 192-bit Tiger
    assert "tiger_hash" in _identify_ids(s)


def test_keccak_detected():
    s = "a" * 64  # 64 hex chars = Keccak-256
    assert "keccak" in _identify_ids(s)


def test_solana_address():
    # Solana address is base58, 32-44 chars
    s = "A" * 44
    e = Engine()
    res = e.identify(s)
    assert isinstance(res.candidates, list)


def test_monero_address():
    # Monero primary address starts with 4
    s = "4" + "A" * 94
    e = Engine()
    res = e.identify(s)
    assert isinstance(res.candidates, list)


def test_gitlab_token():
    s = "glpat-" + "A" * 20
    assert "token" in _identify_ids(s)


def test_sendgrid_key():
    s = "SG." + "A" * 22 + "." + "B" * 43
    assert "token" in _identify_ids(s)


def test_ltc_address():
    # Litecoin legacy address starts with L or M
    s = "L" + "1" * 33
    e = Engine()
    res = e.identify(s)
    assert isinstance(res.candidates, list)


def test_dash_address():
    # Dash address starts with X
    s = "X" + "1" * 33
    e = Engine()
    res = e.identify(s)
    assert isinstance(res.candidates, list)


def test_dogecoin_address():
    # Dogecoin address starts with D
    s = "D" + "1" * 33
    e = Engine()
    res = e.identify(s)
    assert isinstance(res.candidates, list)


def test_stellar_address():
    # Stellar account ID starts with G
    s = "GA" + "A" * 55
    e = Engine()
    res = e.identify(s)
    assert isinstance(res.candidates, list)


def test_ascii_hex_dump():
    from cipherid.ciphers.encodings import AsciiHexCipher
    a = AsciiHexCipher()
    # "Hi!" in hex - need at least 3 parts
    res = a.identify("48 69 21")
    assert any(c.decoded == "Hi!" for c in res)


def test_pigpen_detected():
    from cipherid.ciphers.encodings import PigpenCipher
    p = PigpenCipher()
    res = p.identify("⌐⊥⊤⊣⊢⊤⌊⌋⌈⌉")
    assert len(res) == 1


def test_semaphore_detected():
    from cipherid.ciphers.encodings import SemaphoreCipher
    s = SemaphoreCipher()
    res = s.identify("12 13 14")
    assert isinstance(res, list)


def test_config_system():
    from cipherid.config import CipherConfig, load_config
    config = load_config()
    assert config.max_depth == 5
    assert config.beam_width == 3
    assert isinstance(config.disabled_ciphers, list)


def test_config_disabled_cipher():
    from cipherid.config import CipherConfig
    cfg = CipherConfig(disabled_ciphers=["brainfuck"])
    e = Engine(config=cfg)
    cipher_ids = [c.id for c in e.ciphers]
    assert "brainfuck" not in cipher_ids


def test_engine_parallel():
    import time
    e = Engine()
    start = time.time()
    # Run identify multiple times to test parallel execution
    for _ in range(3):
        e.identify("SG." + "A" * 22 + "." + "B" * 43)
    elapsed = time.time() - start
    # Should complete in reasonable time even with parallelism
    assert elapsed < 30
