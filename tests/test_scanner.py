"""Integration tests for the Scanner orchestrator."""

from __future__ import annotations

from pathlib import Path

from secret_scanner.config import AllowlistConfig, EntropyConfig, RegexRule, ScanConfig
from secret_scanner.models import ScanMode, Severity
from secret_scanner.scanner import Scanner


def _scanner_with_rules(*patterns: tuple[str, str, str]) -> Scanner:
    rules = [RegexRule(id=p[0], name=p[0], pattern=p[1], severity=p[2]) for p in patterns]
    config = ScanConfig(rules=rules, entropy=EntropyConfig(enabled=False))
    return Scanner(config)


class TestScanWorkingTree:
    def test_detects_secret_in_file(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "config.py"
        secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"\n')

        scanner = _scanner_with_rules(("aws", r"AKIA[A-Z0-9]{16}", "critical"))
        # We can't use iter_working_tree without git, so test via scanner internals
        from secret_scanner.git_utils import ScannableLine
        from secret_scanner.models import ScanMode

        lines = [
            ScannableLine(
                file_path="config.py", line_number=1, content='AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"'
            )  # noqa: E501
        ]
        result = scanner._build_result(lines, ScanMode.WORKING_TREE, str(tmp_path))

        assert result.has_findings
        assert result.findings[0].rule_id == "aws"
        assert result.findings[0].severity == Severity.CRITICAL

    def test_secret_is_masked_in_finding(self, tmp_path: Path) -> None:
        from secret_scanner.git_utils import ScannableLine

        scanner = _scanner_with_rules(("aws", r"AKIA[A-Z0-9]{16}", "critical"))
        lines = [ScannableLine(file_path="cfg.py", line_number=1, content="AKIAIOSFODNN7EXAMPLE")]
        result = scanner._build_result(lines, ScanMode.WORKING_TREE, ".")

        assert result.findings
        finding = result.findings[0]
        # Masked value should not contain the full secret
        assert "AKIAIOSFODNN7EXAMPLE" not in finding.secret_masked
        assert finding.secret_masked.startswith("AKIA")

    def test_allowlist_suppresses_finding(self) -> None:
        from secret_scanner.git_utils import ScannableLine

        config = ScanConfig(
            rules=[
                RegexRule(id="aws", name="AWS", pattern=r"AKIA[A-Z0-9]{16}", severity="critical")
            ],  # noqa: E501
            entropy=EntropyConfig(enabled=False),
            allowlist=AllowlistConfig(patterns=["^AKIAIOSFODNN7EXAMPLE$"]),
        )
        scanner = Scanner(config)
        lines = [ScannableLine(file_path="cfg.py", line_number=1, content="AKIAIOSFODNN7EXAMPLE")]
        result = scanner._build_result(lines, ScanMode.WORKING_TREE, ".")

        assert not result.has_findings
        assert result.suppressed_count == 1

    def test_ignored_path_skipped(self) -> None:
        from secret_scanner.git_utils import ScannableLine

        config = ScanConfig(
            rules=[
                RegexRule(id="aws", name="AWS", pattern=r"AKIA[A-Z0-9]{16}", severity="critical")
            ],  # noqa: E501
            entropy=EntropyConfig(enabled=False),
            ignore_paths=["tests/fixtures/*"],
        )
        scanner = Scanner(config)
        lines = [
            ScannableLine(
                file_path="tests/fixtures/fake.py",
                line_number=1,
                content="AKIAIOSFODNN7EXAMPLE",
            )
        ]
        result = scanner._build_result(lines, ScanMode.WORKING_TREE, ".")
        assert not result.has_findings

    def test_no_duplicate_findings_from_entropy_and_regex(self) -> None:
        """Entropy matches that overlap a regex match should be suppressed."""
        from secret_scanner.git_utils import ScannableLine

        config = ScanConfig(
            rules=[
                RegexRule(
                    id="aws",
                    name="AWS",
                    pattern=r"AKIA[A-Z0-9]{16}",
                    severity="critical",
                )
            ],
            entropy=EntropyConfig(enabled=True, threshold=3.0, min_length=10),
        )
        scanner = Scanner(config)
        token = "AKIAIOSFODNN7EXAMPLE"
        lines = [ScannableLine(file_path="f.py", line_number=1, content=token)]
        result = scanner._build_result(lines, ScanMode.WORKING_TREE, ".")

        # Should have at most 1 finding for the same span
        assert len(result.findings) <= 1
        if result.findings:
            assert result.findings[0].rule_id == "aws"

    def test_stats_populated(self) -> None:
        from secret_scanner.git_utils import ScannableLine

        scanner = _scanner_with_rules(("x", r"TOKEN", "low"))
        lines = [
            ScannableLine(file_path="a.py", line_number=1, content="no secret"),
            ScannableLine(file_path="b.py", line_number=1, content="TOKEN found here"),
        ]
        result = scanner._build_result(lines, ScanMode.WORKING_TREE, ".")

        assert result.scanned_lines == 2
        assert result.scanned_files == 2
