"""Shannon entropy-based high-entropy string detection."""

from __future__ import annotations

import math
import re

from secret_scanner.config import EntropyConfig
from secret_scanner.engines.base import BaseEngine, LineMatch
from secret_scanner.models import MatchType, Severity

# Characters used in common secret encodings
_BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEX_CHARS = "0123456789abcdefABCDEF"

# Tokenizer: split on whitespace, path separators, and common delimiters.
# Splitting on '/' avoids treating full file-system paths as single high-entropy tokens.
# Real secrets (AWS keys, GH PATs, etc.) are alphanumeric and don't span path separators.
_TOKEN_PATTERN = re.compile(r'[^\s\'"`,;(){}\[\]<>\\/=:]+')


def _shannon_entropy(s: str, charset: str) -> float:
    """Compute Shannon entropy of `s` restricted to characters in `charset`."""
    filtered = [c for c in s if c in charset]
    if not filtered:
        return 0.0
    length = len(filtered)
    freq = {}
    for c in filtered:
        freq[c] = freq.get(c, 0) + 1
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _best_entropy(token: str) -> tuple[float, str]:
    """Return the highest entropy measured across supported charsets."""
    base64_e = _shannon_entropy(token, _BASE64_CHARS)
    hex_e = _shannon_entropy(token, _HEX_CHARS)
    if base64_e >= hex_e:
        return base64_e, "base64"
    return hex_e, "hex"


class EntropyEngine(BaseEngine):
    """Flags tokens whose Shannon entropy exceeds the configured threshold."""

    def __init__(self, config: EntropyConfig) -> None:
        self._config = config

    def scan_line(self, line: str) -> list[LineMatch]:
        if not self._config.enabled:
            return []

        matches: list[LineMatch] = []
        for m in _TOKEN_PATTERN.finditer(line):
            token = m.group(0)
            if not (self._config.min_length <= len(token) <= self._config.max_length):
                continue

            entropy, _ = _best_entropy(token)
            if entropy >= self._config.threshold:
                matches.append(
                    LineMatch(
                        rule_id="high-entropy-string",
                        rule_name="High Entropy String",
                        severity=Severity.MEDIUM,
                        match_type=MatchType.ENTROPY,
                        raw_value=token,
                        column_start=m.start(),
                        column_end=m.end(),
                    )
                )
        return matches
