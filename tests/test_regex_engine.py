"""Tests for the regex detection engine."""

from __future__ import annotations

from secret_scanner.config import RegexRule
from secret_scanner.engines.regex_engine import RegexEngine
from secret_scanner.models import MatchType, Severity


def _make_engine(*patterns: tuple[str, str, str]) -> RegexEngine:
    """Helper: (id, pattern, severity) → RegexEngine."""
    rules = [
        RegexRule(id=p[0], name=p[0], pattern=p[1], severity=p[2])
        for p in patterns
    ]
    return RegexEngine(rules)


class TestRegexEngine:
    def test_no_match_returns_empty(self) -> None:
        engine = _make_engine(("aws", r"AKIA[A-Z0-9]{16}", "critical"))
        assert engine.scan_line("hello world no secrets here") == []

    def test_simple_match(self) -> None:
        engine = _make_engine(("aws", r"AKIA[A-Z0-9]{16}", "critical"))
        matches = engine.scan_line("key = AKIAIOSFODNN7EXAMPLE")
        assert len(matches) == 1
        assert matches[0].rule_id == "aws"
        assert matches[0].severity == Severity.CRITICAL
        assert matches[0].match_type == MatchType.REGEX
        assert matches[0].raw_value == "AKIAIOSFODNN7EXAMPLE"

    def test_capture_group_extracts_value(self) -> None:
        engine = _make_engine(
            ("secret", r'(?i)password\s*=\s*["\x27]([A-Za-z0-9]{8,})["\x27]', "high")
        )
        matches = engine.scan_line("password = 'hunter2ab'")
        assert len(matches) == 1
        assert matches[0].raw_value == "hunter2ab"

    def test_multiple_matches_on_same_line(self) -> None:
        engine = _make_engine(("token", r"tok_[a-z]{6}", "medium"))
        matches = engine.scan_line("a=tok_aaaaaa b=tok_bbbbbb")
        assert len(matches) == 2

    def test_column_positions(self) -> None:
        engine = _make_engine(("key", r"KEY[0-9]{4}", "low"))
        line = "prefix KEY1234 suffix"
        matches = engine.scan_line(line)
        assert len(matches) == 1
        m = matches[0]
        assert line[m.column_start : m.column_end] == "KEY1234"

    def test_invalid_pattern_skipped(self) -> None:
        # Should not raise even with a broken regex (validated at load time)
        rules = [RegexRule(id="good", name="good", pattern=r"AKIA[A-Z]{16}", severity="high")]
        engine = RegexEngine(rules)
        assert engine.scan_line("AKIAIOSFODNN7EXAMPLE1234") == []  # pattern doesn't match

    def test_github_pat_classic(self) -> None:
        engine = _make_engine(
            ("github-pat", r"ghp_[A-Za-z0-9]{36}", "critical")
        )
        fake_token = "ghp_" + "A" * 36
        matches = engine.scan_line(f'token = "{fake_token}"')
        assert len(matches) == 1
        assert matches[0].raw_value == fake_token

    def test_stripe_secret_key(self) -> None:
        engine = _make_engine(
            ("stripe", r"sk_(?:live|test)_[A-Za-z0-9]{24,}", "critical")
        )
        # Constructed at runtime so the source file contains no credential literal
        fake_key = "sk_" + "test" + "_" + "A" * 24
        matches = engine.scan_line(f"STRIPE_SECRET={fake_key}")
        assert len(matches) == 1

    def test_empty_line(self) -> None:
        engine = _make_engine(("x", r"X[0-9]+", "low"))
        assert engine.scan_line("") == []

    def test_severity_mapping(self) -> None:
        for sev in ("critical", "high", "medium", "low"):
            engine = _make_engine(("r", r"TOKEN", sev))
            matches = engine.scan_line("TOKEN")
            assert matches[0].severity == Severity(sev)
