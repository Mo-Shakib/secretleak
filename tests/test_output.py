"""Tests for output formatters."""

from __future__ import annotations

import json
from io import StringIO

import pytest

from secret_scanner.models import Finding, MatchType, ScanMode, ScanResult, Severity
from secret_scanner.output.console import ConsoleOutput
from secret_scanner.output.json_output import JsonOutput
from secret_scanner.output.sarif import SarifOutput


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        scan_mode=ScanMode.WORKING_TREE,
        target=".",
        findings=findings or [],
        suppressed_count=0,
        scanned_files=10,
        scanned_lines=200,
    )


def _make_finding(
    rule_id: str = "aws-access-key-id",
    severity: Severity = Severity.CRITICAL,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        rule_name="AWS Access Key ID",
        severity=severity,
        file_path="src/config.py",
        line_number=5,
        column_start=10,
        column_end=30,
        match_type=MatchType.REGEX,
        secret_masked="AKIA****MPLE",
        line_preview="AWS_KEY = AKIA****MPLE",
        scan_mode=ScanMode.WORKING_TREE,
        commit_hash=None,
        author=None,
    )


class TestJsonOutput:
    def test_no_findings_structure(self) -> None:
        out = StringIO()
        JsonOutput().write(_make_result(), out)
        data = json.loads(out.getvalue())
        assert data["summary"]["total"] == 0
        assert data["findings"] == []
        assert "version" in data
        assert "generated_at" in data

    def test_finding_serialized(self) -> None:
        result = _make_result([_make_finding()])
        out = StringIO()
        JsonOutput().write(result, out)
        data = json.loads(out.getvalue())
        assert data["summary"]["total"] == 1
        assert data["summary"]["critical"] == 1
        f = data["findings"][0]
        assert f["rule_id"] == "aws-access-key-id"
        assert f["severity"] == "critical"
        # Secret must be masked – never the full value
        assert f["secret_masked"] == "AKIA****MPLE"
        assert "fingerprint" in f

    def test_secret_never_in_full_json(self) -> None:
        """The raw secret must not appear anywhere in JSON output."""
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        finding = _make_finding()
        # Ensure secret_masked doesn't contain the full raw value
        result = _make_result([finding])
        out = StringIO()
        JsonOutput().write(result, out)
        assert raw_secret not in out.getvalue()

    def test_write_file(self, tmp_path: Any) -> None:
        p = tmp_path / "report.json"
        JsonOutput().write_file(_make_result(), p)
        data = json.loads(p.read_text())
        assert "findings" in data


class TestSarifOutput:
    def test_sarif_schema_version(self) -> None:
        out = StringIO()
        SarifOutput().write(_make_result(), out)
        data = json.loads(out.getvalue())
        assert data["version"] == "2.1.0"
        assert "$schema" in data

    def test_finding_in_sarif_results(self) -> None:
        result = _make_result([_make_finding()])
        out = StringIO()
        SarifOutput().write(result, out)
        data = json.loads(out.getvalue())
        run = data["runs"][0]
        assert len(run["results"]) == 1
        sarif_result = run["results"][0]
        assert sarif_result["ruleId"] == "aws-access-key-id"
        assert sarif_result["level"] == "error"  # critical → error

    def test_sarif_rule_definitions(self) -> None:
        result = _make_result([_make_finding()])
        out = StringIO()
        SarifOutput().write(result, out)
        data = json.loads(out.getvalue())
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "aws-access-key-id"

    def test_sarif_location_columns(self) -> None:
        result = _make_result([_make_finding()])
        out = StringIO()
        SarifOutput().write(result, out)
        data = json.loads(out.getvalue())
        region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 5
        # SARIF is 1-indexed
        assert region["startColumn"] == 11  # col_start=10 + 1

    def test_sarif_fingerprints(self) -> None:
        result = _make_result([_make_finding()])
        out = StringIO()
        SarifOutput().write(result, out)
        data = json.loads(out.getvalue())
        fps = data["runs"][0]["results"][0]["fingerprints"]
        assert "secret-scanner/v1" in fps

    def test_no_secret_in_sarif_message(self) -> None:
        raw_secret = "AKIAIOSFODNN7EXAMPLE"
        result = _make_result([_make_finding()])
        out = StringIO()
        SarifOutput().write(result, out)
        assert raw_secret not in out.getvalue()


class TestConsoleOutput:
    def test_no_crash_on_empty_result(self) -> None:
        from rich.console import Console

        buf = StringIO()
        c = Console(file=buf, no_color=True)
        ConsoleOutput(console=c).print_result(_make_result())
        assert "No secrets found" in buf.getvalue()

    def test_findings_appear_in_output(self) -> None:
        from rich.console import Console

        buf = StringIO()
        c = Console(file=buf, no_color=True, width=200)
        result = _make_result([_make_finding()])
        ConsoleOutput(console=c).print_result(result)
        out = buf.getvalue()
        assert "aws-access-key-id" in out or "AWS Access Key ID" in out

    def test_masked_secret_in_output(self) -> None:
        from rich.console import Console

        buf = StringIO()
        c = Console(file=buf, no_color=True, width=200)
        result = _make_result([_make_finding()])
        ConsoleOutput(console=c).print_result(result)
        # Console replaces '*' with '•' to avoid Rich markup interpretation
        assert "AKIA" in buf.getvalue() and "MPLE" in buf.getvalue()


# Make Any available for type hints in tests
from typing import Any  # noqa: E402
