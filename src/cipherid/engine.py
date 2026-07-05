"""Identification + decoding engine.

The engine runs every registered cipher against the input, sorts results by
confidence, optionally tries to decode, and can chain decoders together to
unwrap nested encodings (e.g. base64 of hex of rot13).
"""
from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from cipherid.cipher import Candidate, Cipher, DecodeResult
from cipherid.ciphers import load_ciphers
from cipherid.config import CipherConfig, load_config
from cipherid.flag import compile_flag_pattern, find_flag
from cipherid.heuristics import looks_like_chinese, looks_like_english, stripped

_WORKERS = min(os.cpu_count() or 4, 8)
MAX_INPUT_SIZE = 10 * 1024 * 1024  # 10MB limit


@dataclass
class IdentifyResult:
    text: str
    candidates: list[Candidate] = field(default_factory=list)
    flag: str | None = None


class Engine:
    def __init__(self, ciphers: list[Cipher] | None = None, config: CipherConfig | None = None) -> None:
        self.config = config or load_config()
        all_ciphers = ciphers if ciphers is not None else load_ciphers()
        self.ciphers: list[Cipher] = [
            c for c in all_ciphers if c.id not in self.config.disabled_ciphers
        ]

    def identify(self, text: str, flag_format: str | None = None) -> IdentifyResult:
        text = stripped(text)

        # Input size protection
        encoded = text.encode("utf-8", errors="replace")
        if len(encoded) > MAX_INPUT_SIZE:
            text = text[:MAX_INPUT_SIZE // 4]  # Truncate to ~2.5MB of chars

        candidates: list[Candidate] = []

        def _run_cipher(cipher: Cipher) -> list[Candidate]:
            try:
                return cipher.identify(text)
            except Exception:
                return []

        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = {pool.submit(_run_cipher, c): c for c in self.ciphers}
            for future in as_completed(futures):
                try:
                    candidates.extend(future.result())
                except Exception:
                    continue

        candidates.sort(key=lambda c: c.confidence, reverse=True)
        flag_pattern = compile_flag_pattern(flag_format)
        flag = find_flag(text, flag_pattern)
        return IdentifyResult(text=text, candidates=candidates, flag=flag)

    def decode_one(self, text: str, cipher_id: str, key: str | None = None) -> str | None:
        for c in self.ciphers:
            if c.id == cipher_id:
                try:
                    return c.decode(text, key=key)
                except Exception:
                    return None
        return None

    def encode_one(self, text: str, cipher_id: str, key: str | None = None) -> str | None:
        for c in self.ciphers:
            if c.id == cipher_id:
                try:
                    return c.encode(text, key=key)
                except Exception:
                    return None
        return None

    def get_encodable_ciphers(self) -> list[Cipher]:
        """Return ciphers that support encode (override the base class method)."""
        return [c for c in self.ciphers if type(c).encode is not Cipher.encode]

    def auto_decode(
        self,
        text: str,
        flag_format: str | None = None,
        max_depth: int | None = None,
    ) -> DecodeResult:
        """Beam-search nested-decode with look-ahead.

        At each depth, evaluates top-K candidates and explores each path one
        step further, picking the path with the highest combined score.
        This avoids greedy local optima while keeping the search tractable.
        """
        if max_depth is None:
            max_depth = self.config.max_depth
        flag_pattern = compile_flag_pattern(flag_format)
        current = stripped(text)
        best_result = self._decode_path(current, flag_pattern, max_depth, [])
        return best_result

    def _decode_path(
        self,
        text: str,
        flag_pattern: re.Pattern[str],
        depth: int,
        chain: list[Candidate],
        seen: set[str] | None = None,
    ) -> DecodeResult:
        if seen is None:
            seen = {text}

        for _ in range(depth):
            m = find_flag(text, flag_pattern)
            if m:
                return DecodeResult(final_plaintext=text, chain=chain, flag_match=m)

            if chain and (looks_like_english(text) or looks_like_chinese(text)):
                break

            candidates = self._get_decode_candidates(text, flag_pattern, seen)
            if not candidates:
                break

            # Beam: evaluate top-K candidates with 1-step look-ahead
            beam_width = min(self.config.beam_width, len(candidates))
            best_score = -1.0
            best_next: tuple[float, Candidate, str] | None = None

            for score, cand, decoded in candidates[:beam_width]:
                # 1-step look-ahead: what score does the next step yield?
                future_score = score
                if find_flag(decoded, flag_pattern):
                    future_score += 2.0
                elif looks_like_english(decoded) or looks_like_chinese(decoded):
                    future_score += 0.3
                else:
                    next_cands = self._get_decode_candidates(
                        decoded, flag_pattern, seen | {decoded}
                    )
                    if next_cands:
                        future_score += next_cands[0][0] * 0.5

                if future_score > best_score:
                    best_score = future_score
                    best_next = (score, cand, decoded)

            if best_next is None:
                break

            _, cand, decoded = best_next
            cand.decoded = decoded
            chain.append(cand)
            seen.add(decoded)
            text = decoded

        flag = find_flag(text, flag_pattern)
        return DecodeResult(final_plaintext=text, chain=chain, flag_match=flag)

    def _get_decode_candidates(
        self,
        text: str,
        flag_pattern: re.Pattern[str],
        seen: set[str],
    ) -> list[tuple[float, Candidate, str]]:
        results: list[tuple[float, Candidate, str]] = []

        def _run_cipher(cipher: Cipher) -> list[tuple[float, Candidate, str]]:
            out = []
            try:
                cands = cipher.identify(text)
            except Exception:
                return out
            for cand in cands:
                if cand.decoded is None:
                    try:
                        decoded = cipher.decode(text)
                    except Exception:
                        decoded = None
                else:
                    decoded = cand.decoded
                if not decoded or decoded == text or decoded in seen:
                    continue
                score = cand.confidence
                if find_flag(decoded, flag_pattern):
                    score += 1.0
                if looks_like_english(decoded) or looks_like_chinese(decoded):
                    score += 0.2
                out.append((score, cand, decoded))
            return out

        with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
            futures = {pool.submit(_run_cipher, c): c for c in self.ciphers}
            for future in as_completed(futures):
                try:
                    results.extend(future.result())
                except Exception:
                    continue

        results.sort(key=lambda x: x[0], reverse=True)
        return results
