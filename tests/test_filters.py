"""Tests for false-positive filtering."""

from __future__ import annotations

import json
from pathlib import Path

from secretleak.engines.base import LineMatch
from secretleak.filters import FindingFilter, load_baseline, save_baseline
from secretleak.models import Finding, MatchType, ScanMode, Severity


def _make_match(value: str = "secretvalue") -> LineMatch:
    return LineMatch(
        rule_id="test",
        rule_name="Test",
        severity=Severity.HIGH,
        match_type=MatchType.REGEX,
        raw_value=value,
        column_start=0,
        column_end=len(value),
    )


def _make_finding(file_path: str = "src/app.py", masked: str = "secr****lue") -> Finding:
    return Finding(
        rule_id="test",
        rule_name="Test",
        severity=Severity.HIGH,
        file_path=file_path,
        line_number=1,
        column_start=0,
        column_end=10,
        match_type=MatchType.REGEX,
        secret_masked=masked,
        line_preview="redacted",
        scan_mode=ScanMode.WORKING_TREE,
    )


class TestPathFilter:
    def test_exact_path_ignored(self) -> None:
        f = FindingFilter([], ["tests/fixtures/fake_secrets.py"])
        assert f.should_skip_path("tests/fixtures/fake_secrets.py") is True

    def test_glob_star_matches(self) -> None:
        f = FindingFilter([], ["**/*.env"])
        assert f.should_skip_path("config/.env") is True
        assert f.should_skip_path(".env") is True

    def test_filename_glob(self) -> None:
        f = FindingFilter([], ["*.test.ts"])
        assert f.should_skip_path("src/auth.test.ts") is True

    def test_non_matching_path_not_ignored(self) -> None:
        f = FindingFilter([], ["secrets/**"])
        assert f.should_skip_path("src/config.py") is False


class TestAllowlistFilter:
    def test_exact_pattern_match_suppressed(self) -> None:
        f = FindingFilter(["^EXAMPLE_KEY$"], [])
        match = _make_match("EXAMPLE_KEY")
        assert f.is_allowlisted_match(match.raw_value) is True

    def test_partial_pattern_match(self) -> None:
        f = FindingFilter(["placeholder"], [])
        assert f.is_allowlisted_match("my_placeholder_value") is True

    def test_non_matching_value_not_suppressed(self) -> None:
        f = FindingFilter(["placeholder"], [])
        assert f.is_allowlisted_match("AKIAIOSFODNN7EXAMPLE") is False

    def test_multiple_patterns(self) -> None:
        f = FindingFilter(["^fake_", "example", "test_"], [])
        assert f.is_allowlisted_match("fake_token_1234567890") is True
        assert f.is_allowlisted_match("real_token_xyz") is False


class TestBaselineFilter:
    def test_suppresses_known_fingerprint(self) -> None:
        finding = _make_finding()
        fp = finding.fingerprint
        f = FindingFilter([], [], baseline_fingerprints={fp})
        assert f.is_suppressed_by_baseline(finding) is True

    def test_new_finding_not_suppressed(self) -> None:
        finding = _make_finding()
        f = FindingFilter([], [], baseline_fingerprints={"differenthash1234"})
        assert f.is_suppressed_by_baseline(finding) is False


class TestBaselineIO:
    def test_save_and_load_roundtrip(self, tmp_path: Path) -> None:
        findings = [_make_finding("a.py"), _make_finding("b.py", "diff****xxx")]
        bl_path = tmp_path / "baseline.json"
        save_baseline(findings, bl_path)

        loaded = load_baseline(bl_path)
        assert {f.fingerprint for f in findings} == loaded

    def test_load_missing_file_returns_empty(self, tmp_path: Path) -> None:
        assert load_baseline(tmp_path / "nonexistent.json") == set()

    def test_load_malformed_json_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("not json {{")
        assert load_baseline(p) == set()

    def test_baseline_file_has_description(self, tmp_path: Path) -> None:
        save_baseline([], tmp_path / "bl.json")
        data = json.loads((tmp_path / "bl.json").read_text())
        assert "description" in data
        assert data["version"] == 1
