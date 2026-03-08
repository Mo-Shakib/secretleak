"""Tests for the Shannon entropy detection engine."""

from __future__ import annotations

import pytest

from secret_scanner.config import EntropyConfig
from secret_scanner.engines.entropy_engine import EntropyEngine, _shannon_entropy, _BASE64_CHARS
from secret_scanner.models import MatchType


class TestShannonEntropy:
    def test_uniform_distribution_max_entropy(self) -> None:
        # A string using every character once has maximum entropy
        s = "abcdefghijklmnop"
        e = _shannon_entropy(s, "abcdefghijklmnop")
        assert e == pytest.approx(4.0, abs=0.01)

    def test_single_char_zero_entropy(self) -> None:
        assert _shannon_entropy("aaaaaaa", "a") == pytest.approx(0.0)

    def test_empty_string(self) -> None:
        assert _shannon_entropy("", _BASE64_CHARS) == 0.0

    def test_chars_not_in_charset_ignored(self) -> None:
        # Only 'a' and 'b' are in charset; others ignored
        e = _shannon_entropy("aabb!!@@", "ab")
        assert e == pytest.approx(1.0, abs=0.01)


class TestEntropyEngine:
    def _engine(self, threshold: float = 4.5, min_len: int = 20) -> EntropyEngine:
        return EntropyEngine(EntropyConfig(enabled=True, threshold=threshold, min_len=min_len))

    def test_high_entropy_string_detected(self) -> None:
        engine = self._engine(threshold=4.0, min_len=16)
        # A random-looking alphanumeric token (no slashes so tokenizer keeps it whole)
        line = 'secret = "wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"'
        matches = engine.scan_line(line)
        assert len(matches) >= 1
        assert all(m.match_type == MatchType.ENTROPY for m in matches)

    def test_normal_prose_not_flagged(self) -> None:
        engine = self._engine()
        line = "This is just a normal sentence with no secrets at all."
        matches = engine.scan_line(line)
        assert matches == []

    def test_disabled_engine_returns_empty(self) -> None:
        engine = EntropyEngine(EntropyConfig(enabled=False))
        line = 'key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        assert engine.scan_line(line) == []

    def test_short_token_not_flagged(self) -> None:
        engine = self._engine(min_len=20)
        # Only 8 chars – below min_length
        matches = engine.scan_line("tok_abcd")
        assert matches == []

    def test_token_too_long_not_flagged(self) -> None:
        engine = EntropyEngine(EntropyConfig(enabled=True, max_length=50, min_length=20))
        long_token = "A" * 300
        matches = engine.scan_line(long_token)
        assert matches == []

    def test_low_entropy_token_not_flagged(self) -> None:
        engine = self._engine(threshold=4.5, min_len=20)
        # Repetitive string has low entropy
        matches = engine.scan_line("a" * 40)
        assert matches == []
