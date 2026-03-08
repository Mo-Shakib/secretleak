"""False-positive filtering: allowlist, ignore paths, and baseline suppression."""

from __future__ import annotations

import fnmatch
import json
import re
from pathlib import Path

from .engines.base import LineMatch
from .models import Finding


class FindingFilter:
    """Applies allowlist, path ignore, and baseline suppression rules."""

    def __init__(
        self,
        allowlist_patterns: list[str],
        ignore_path_globs: list[str],
        baseline_fingerprints: set[str] | None = None,
    ) -> None:
        self._allowlist_re: list[re.Pattern[str]] = []
        for p in allowlist_patterns:
            try:
                self._allowlist_re.append(re.compile(p))
            except re.error:
                pass

        self._ignore_globs = ignore_path_globs
        self._baseline = baseline_fingerprints or set()

    def should_skip_path(self, file_path: str) -> bool:
        """Return True if the file path matches any ignore glob."""
        filename = Path(file_path).name
        for glob in self._ignore_globs:
            # 1. Direct fnmatch on the full path (handles simple globs)
            if fnmatch.fnmatch(file_path, glob):
                return True
            # 2. For ** patterns, also check the tail portion against path/filename
            if "**" in glob:
                tail = glob.rsplit("**", 1)[-1].lstrip("/")
                if tail:
                    if fnmatch.fnmatch(file_path, tail):
                        return True
                    if fnmatch.fnmatch(filename, tail):
                        return True
        return False

    def is_allowlisted_match(self, raw_value: str) -> bool:
        """Return True if the raw secret value matches any allowlist pattern."""
        return any(r.search(raw_value) for r in self._allowlist_re)

    def is_suppressed_by_baseline(self, finding: Finding) -> bool:
        """Return True if the finding's fingerprint is in the baseline."""
        return finding.fingerprint in self._baseline

    def filter_match(self, match: LineMatch, file_path: str) -> bool:
        """Return True if the match should be KEPT (not filtered out)."""
        if self.should_skip_path(file_path):
            return False
        if self.is_allowlisted_match(match.raw_value):
            return False
        return True

    def filter_finding(self, finding: Finding) -> bool:
        """Return True if the finding should be KEPT (not suppressed)."""
        if self.should_skip_path(finding.file_path):
            return False
        if self.is_suppressed_by_baseline(finding):
            return False
        return True


def load_baseline(baseline_path: Path) -> set[str]:
    """Load a set of fingerprints from a baseline JSON file."""
    if not baseline_path.exists():
        return set()
    try:
        data = json.loads(baseline_path.read_text())
        if isinstance(data, list):
            return {str(fp) for fp in data}
        if isinstance(data, dict) and "fingerprints" in data:
            return {str(fp) for fp in data["fingerprints"]}
    except (json.JSONDecodeError, OSError):
        pass
    return set()


def save_baseline(findings: list[Finding], baseline_path: Path) -> None:
    """Write current finding fingerprints to a baseline file."""
    fingerprints = sorted({f.fingerprint for f in findings})
    data = {
        "version": 1,
        "description": "secretleak baseline – commit to suppress known findings",
        "fingerprints": fingerprints,
    }
    baseline_path.write_text(json.dumps(data, indent=2) + "\n")
