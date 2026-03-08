"""Core data models for secret-scanner findings."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, computed_field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


class ScanMode(StrEnum):
    WORKING_TREE = "working_tree"
    STAGED = "staged"
    COMMIT_RANGE = "commit_range"


class MatchType(StrEnum):
    REGEX = "regex"
    ENTROPY = "entropy"


class Finding(BaseModel):
    """A single detected secret or high-entropy string."""

    rule_id: str
    rule_name: str
    severity: Severity
    file_path: str
    line_number: int
    column_start: int
    column_end: int
    match_type: MatchType
    # Never store the raw secret – only the masked version
    secret_masked: str
    # Surrounding line content with the secret masked out
    line_preview: str
    scan_mode: ScanMode
    commit_hash: str | None = None
    author: str | None = None

    @computed_field  # type: ignore[prop-decorator]
    @property
    def fingerprint(self) -> str:
        """Stable identifier for suppression/baseline purposes."""
        import hashlib

        raw = f"{self.rule_id}:{self.file_path}:{self.secret_masked}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)


class ScanResult(BaseModel):
    """Aggregated result of a scan run."""

    scan_mode: ScanMode
    target: str
    findings: list[Finding] = Field(default_factory=list)
    suppressed_count: int = 0
    scanned_files: int = 0
    scanned_lines: int = 0

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
