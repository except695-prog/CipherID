"""Identifiers for API tokens, JWTs, keys, and well-known wire formats."""
from __future__ import annotations

import base64
import json
import re

from cipherid.cipher import Candidate, Cipher

TOKEN_PATTERNS = [
    (r"^sk-ant-api03-[A-Za-z0-9_\-]{20,}$", "Anthropic API key", 0.99),
    (r"^sk-proj-[A-Za-z0-9_\-]{20,}$",      "OpenAI project API key", 0.99),
    (r"^sk-[A-Za-z0-9]{20,}$",              "OpenAI API key (legacy)", 0.95),
    (r"^ghp_[A-Za-z0-9]{36}$",              "GitHub personal access token", 0.99),
    (r"^gho_[A-Za-z0-9]{36}$",              "GitHub OAuth token", 0.99),
    (r"^ghs_[A-Za-z0-9]{36}$",              "GitHub server token", 0.99),
    (r"^ghu_[A-Za-z0-9]{36}$",              "GitHub user-to-server token", 0.99),
    (r"^github_pat_[A-Za-z0-9_]{82}$",      "GitHub fine-grained PAT", 0.99),
    (r"^AIza[0-9A-Za-z_\-]{35}$",           "Google API key", 0.99),
    (r"^AKIA[0-9A-Z]{16}$",                 "AWS access key id", 0.99),
    (r"^xox[bpoa]-[A-Za-z0-9-]{10,}$",      "Slack token", 0.99),
    (r"^hf_[A-Za-z0-9]{30,}$",              "HuggingFace token", 0.95),
    (r"^r8_[A-Za-z0-9]{30,}$",              "Replicate token", 0.95),
    (r"^sk_live_[A-Za-z0-9]{20,}$",         "Stripe live secret key", 0.99),
    (r"^pk_live_[A-Za-z0-9]{20,}$",         "Stripe live publishable key", 0.99),
    (r"^discord(?:app)?\.com/api/webhooks/\d+/[\w-]+$", "Discord webhook URL", 0.95),
    (r"^glpat-[A-Za-z0-9\-_]{20,}$",       "GitLab personal access token", 0.99),
    (r"^glptt-[A-Za-z0-9\-_]{20,}$",       "GitLab pipeline token", 0.99),
    (r"^glfbt-[A-Za-z0-9\-_]{20,}$",       "GitLab feature flag token", 0.99),
    (r"^heroku[0-9]{13}$",                  "Heroku API key", 0.90),
    (r"^dop_v1_[a-f0-9]{64}$",              "DigitalOcean personal access token", 0.99),
    (r"^do_permanent_access_token_[A-Za-z0-9]{43}$", "DigitalOcean legacy token", 0.99),
    (r"^AC[0-9a-f]{32}$",                   "Twilio Account SID", 0.90),
    (r"^(?:SG|RG)\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}$", "SendGrid API key", 0.99),
    (r"^xox[eprs]-[A-Za-z0-9\-]{10,}$",    "Slack extended token", 0.95),
    (r"^sk-[a-zA-Z0-9]{48}$",              "Anthropic API key (v2)", 0.95),
    (r"^AKIA[0-9A-Z]{16}$",                "AWS STS access key", 0.99),
    (r"^ASIA[0-9A-Z]{16}$",                "AWS STS temporary credentials", 0.99),
    (r"^(?:ghr|ghu|ghs|ghp)_[A-Za-z0-9]{36,}$", "GitHub token (any type)", 0.95),
    (r"^eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+$", "JWT (generic)", 0.90),
]


class TokenIdentifier(Cipher):
    id = "token"
    name = "API / access token"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        out = []
        for pat, label, conf in TOKEN_PATTERNS:
            if re.fullmatch(pat, t):
                out.append(Candidate(self.id, label, self.category, conf,
                                     decoded=None, notes="rotate immediately if leaked"))
        return out


class JWTCipher(Cipher):
    id = "jwt"
    name = "JSON Web Token"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        parts = t.split(".")
        if len(parts) != 3:
            return []
        try:
            header_raw = base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
            payload_raw = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
            header = json.loads(header_raw)
            payload = json.loads(payload_raw)
        except Exception:
            return []
        alg = header.get("alg", "?")
        decoded_blob = json.dumps({"header": header, "payload": payload}, indent=2, ensure_ascii=False)
        return [Candidate(self.id, f"JWT (alg={alg})", self.category, 0.99,
                          decoded=decoded_blob,
                          notes="check 'alg' value; alg=none and weak HS256 keys are common pitfalls")]

    def decode(self, text: str, key: str | None = None) -> str | None:
        try:
            parts = text.strip().split(".")
            payload = base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
            return payload.decode("utf-8", "replace")
        except Exception:
            return None


class PEMCipher(Cipher):
    id = "pem"
    name = "PEM-encoded key / certificate"
    category = "modern"

    def identify(self, text: str) -> list[Candidate]:
        m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----", text)
        if not m:
            return []
        label = m.group(1).title()
        return [Candidate(self.id, f"PEM: {label}", self.category, 0.99,
                          notes="parse with cryptography / openssl x509")]


class BitcoinAddressCipher(Cipher):
    id = "bitcoin_address"
    name = "Bitcoin address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", t):
            return [Candidate(self.id, "Bitcoin Legacy/P2SH address", self.category, 0.9)]
        if re.fullmatch(r"bc1[a-z0-9]{25,90}", t):
            return [Candidate(self.id, "Bitcoin Bech32 (SegWit)", self.category, 0.95)]
        return []


class EthereumAddressCipher(Cipher):
    id = "eth_address"
    name = "Ethereum address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        if re.fullmatch(r"0x[a-fA-F0-9]{40}", text.strip()):
            return [Candidate(self.id, "Ethereum address (0x...)", self.category, 0.99)]
        return []


class SolanaAddressCipher(Cipher):
    """Solana address detection (base58, 32-44 chars)."""
    id = "solana_address"
    name = "Solana address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        if 32 <= len(t) <= 44 and all(c in b58 for c in t):
            return [Candidate(self.id, "Solana address (base58)", self.category, 0.6)]
        return []


class LitecoinAddressCipher(Cipher):
    """Litecoin address detection."""
    id = "litecoin_address"
    name = "Litecoin address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"[LM][1-9A-HJ-NP-Za-km-z]{26,34}", t):
            return [Candidate(self.id, "Litecoin address", self.category, 0.85)]
        return []


class RippleAddressCipher(Cipher):
    """Ripple/XRP address detection."""
    id = "ripple_address"
    name = "Ripple (XRP) address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"r[1-9A-HJ-NP-Za-km-z]{24,34}", t):
            return [Candidate(self.id, "Ripple (XRP) address", self.category, 0.85)]
        return []


class MoneroAddressCipher(Cipher):
    """Monero address detection."""
    id = "monero_address"
    name = "Monero (XMR) address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}", t):
            return [Candidate(self.id, "Monero (XMR) primary address", self.category, 0.9)]
        if re.fullmatch(r"8[0-9AB][1-9A-HJ-NP-Za-km-z]{93}", t):
            return [Candidate(self.id, "Monero (XMR) subaddress", self.category, 0.9)]
        return []


class DashAddressCipher(Cipher):
    """Dash address detection."""
    id = "dash_address"
    name = "Dash address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"X[1-9A-HJ-NP-Za-km-z]{25,34}", t):
            return [Candidate(self.id, "Dash address", self.category, 0.8)]
        return []


class DogecoinAddressCipher(Cipher):
    """Dogecoin address detection."""
    id = "dogecoin_address"
    name = "Dogecoin address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"D[5-9A-HJ-NP-Za-km-z]{33}", t):
            return [Candidate(self.id, "Dogecoin address", self.category, 0.85)]
        return []


class NEMAddressCipher(Cipher):
    """NEM address detection."""
    id = "nem_address"
    name = "NEM address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"N[A-Z0-9]{38,40}", t):
            return [Candidate(self.id, "NEM address", self.category, 0.7)]
        return []


class StellarAddressCipher(Cipher):
    """Stellar address detection (starts with G or A)."""
    id = "stellar_address"
    name = "Stellar address"
    category = "token"

    def identify(self, text: str) -> list[Candidate]:
        t = text.strip()
        if re.fullmatch(r"GA[0-9A-Z]{55}", t):
            return [Candidate(self.id, "Stellar account ID", self.category, 0.9)]
        if re.fullmatch(r"SA[0-9A-Z]{55}", t):
            return [Candidate(self.id, "Stellar seed (secret key)", self.category, 0.9)]
        return []


TOKEN_CIPHERS = [
    TokenIdentifier(), JWTCipher(), PEMCipher(),
    BitcoinAddressCipher(), EthereumAddressCipher(),
    SolanaAddressCipher(), LitecoinAddressCipher(), RippleAddressCipher(),
    MoneroAddressCipher(), DashAddressCipher(), DogecoinAddressCipher(),
    NEMAddressCipher(), StellarAddressCipher(),
]
