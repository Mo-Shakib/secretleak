"""Shared pytest fixtures."""

from __future__ import annotations

import pytest

from secret_scanner.config import EntropyConfig, RegexRule, ScanConfig
from secret_scanner.models import Finding, MatchType, ScanMode, Severity


@pytest.fixture()
def minimal_config() -> ScanConfig:
    return ScanConfig(
        rules=[
            RegexRule(
                id="test-api-key",
                name="Test API Key",
                pattern=r"test_key_[A-Za-z0-9]{16}",
                severity="high",
            ),
            RegexRule(
                id="aws-access-key-id",
                name="AWS Access Key ID",
                pattern=r"(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}",
                severity="critical",
            ),
        ],
        entropy=EntropyConfig(enabled=False),
    )


@pytest.fixture()
def sample_finding() -> Finding:
    return Finding(
        rule_id="test-api-key",
        rule_name="Test API Key",
        severity=Severity.HIGH,
        file_path="src/config.py",
        line_number=42,
        column_start=15,
        column_end=47,
        match_type=MatchType.REGEX,
        secret_masked="test****5678",
        line_preview='API_KEY = "test****5678"',
        scan_mode=ScanMode.WORKING_TREE,
    )
