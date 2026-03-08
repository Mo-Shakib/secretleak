"""CLI integration tests using Typer's test client."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from secret_scanner.cli import app

runner = CliRunner()


class TestScanCommand:
    def test_scan_clean_directory(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 1\nprint(x)\n")
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 0

    def test_scan_with_secret_exits_1(self, tmp_path: Path) -> None:
        (tmp_path / "secrets.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"\n'
        )
        result = runner.invoke(app, ["scan", str(tmp_path)])
        assert result.exit_code == 1

    def test_scan_no_fail_flag(self, tmp_path: Path) -> None:
        (tmp_path / "secrets.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"\n'
        )
        result = runner.invoke(app, ["scan", str(tmp_path), "--no-fail"])
        assert result.exit_code == 0

    def test_scan_json_output(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert "findings" in data
        assert "summary" in data

    def test_scan_sarif_output(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 1\n")
        result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["version"] == "2.1.0"

    def test_scan_json_output_to_file(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 1\n")
        out_file = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["scan", str(tmp_path), "--format", "json", "--output", str(out_file)],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        data = json.loads(out_file.read_text())
        assert "findings" in data

    def test_scan_nonexistent_path(self) -> None:
        result = runner.invoke(app, ["scan", "/nonexistent/path/xyz"])
        assert result.exit_code == 2

    def test_version_flag(self) -> None:
        result = runner.invoke(app, ["scan", "--version"])
        assert result.exit_code == 0
        assert "secret-scanner" in result.output

    def test_scan_with_allowlist_config(self, tmp_path: Path) -> None:
        """Config file with allowlist should suppress the known fake key."""
        (tmp_path / "secrets.py").write_text(
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"\n'
        )
        config_file = tmp_path / ".secret-scanner.yaml"
        config_file.write_text(
            "allowlist:\n  patterns:\n    - AKIAIOSFODNN7EXAMPLE\n"
        )
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--config", str(config_file)]
        )
        assert result.exit_code == 0

    def test_commit_range_requires_git(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--commit-range", "HEAD~1..HEAD"]
        )
        # Should fail with git error (not a repo), exit 2
        assert result.exit_code == 2

    def test_commit_range_invalid_format(self, tmp_path: Path) -> None:
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--commit-range", "invalid"]
        )
        assert result.exit_code == 2


class TestRulesCommand:
    def test_lists_rules(self) -> None:
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "aws-access-key-id" in result.output.lower() or "AWS" in result.output

    def test_lists_entropy_status(self) -> None:
        result = runner.invoke(app, ["rules"])
        assert result.exit_code == 0
        assert "entropy" in result.output.lower() or "Entropy" in result.output


class TestGenerateBaselineCommand:
    def test_generates_baseline_file(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 1\n")
        bl = tmp_path / "baseline.json"
        result = runner.invoke(
            app, ["generate-baseline", str(tmp_path), "--baseline", str(bl)]
        )
        assert result.exit_code == 0
        assert bl.exists()
        data = json.loads(bl.read_text())
        assert "fingerprints" in data

    def test_baseline_suppresses_findings(self, tmp_path: Path) -> None:
        """After generating baseline, re-scan should show 0 findings."""
        secret_file = tmp_path / "secrets.py"
        secret_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE1"\n')
        bl = tmp_path / "baseline.json"

        # Generate baseline
        runner.invoke(
            app, ["generate-baseline", str(tmp_path), "--baseline", str(bl)]
        )
        assert bl.exists()

        # Create config pointing to the baseline
        config_file = tmp_path / ".secret-scanner.yaml"
        config_file.write_text(f"baseline_file: {bl}\n")

        # Re-scan: findings should be suppressed
        result = runner.invoke(
            app, ["scan", str(tmp_path), "--config", str(config_file)]
        )
        assert result.exit_code == 0


class TestInstallHookCommand:
    def test_install_hook_in_non_git_dir(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["install-hook", str(tmp_path)])
        assert result.exit_code == 2  # RuntimeError → exit 2

    def test_install_and_uninstall_hook(self, tmp_path: Path) -> None:
        # Initialize a git repo
        import subprocess

        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        result = runner.invoke(app, ["install-hook", str(tmp_path)])
        assert result.exit_code == 0
        hook = tmp_path / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        assert hook.stat().st_mode & 0o111  # executable

        # Uninstall
        result2 = runner.invoke(app, ["uninstall-hook", str(tmp_path)])
        assert result2.exit_code == 0
        assert not hook.exists()

    def test_install_hook_force_flag(self, tmp_path: Path) -> None:
        import subprocess

        subprocess.run(["git", "init", str(tmp_path)], capture_output=True)
        hook = tmp_path / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/bash\necho existing")

        # Without force: should fail
        result = runner.invoke(app, ["install-hook", str(tmp_path)])
        assert result.exit_code == 1

        # With force: should succeed
        result2 = runner.invoke(app, ["install-hook", str(tmp_path), "--force"])
        assert result2.exit_code == 0
        assert "secret-scanner pre-commit hook" in hook.read_text()
