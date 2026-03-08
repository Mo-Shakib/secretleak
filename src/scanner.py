"""Scan orchestrator: wires together engines, git utils, filters, and output."""

from __future__ import annotations

from pathlib import Path

from .config import ScanConfig, load_config
from .engines.base import LineMatch
from .engines.entropy_engine import EntropyEngine
from .engines.regex_engine import RegexEngine
from .filters import FindingFilter, load_baseline
from .git_utils import (
    GitError,
    ScannableLine,
    get_repo_root,
    iter_commit_range,
    iter_staged_diff,
    iter_working_tree,
)
from .models import Finding, ScanMode, ScanResult
from .redact import mask_secret, redact_line


class Scanner:
    """Orchestrates all scanning modes."""

    def __init__(self, config: ScanConfig | None = None) -> None:
        self._config = config or load_config()
        self._regex_engine = RegexEngine(self._config.rules)
        self._entropy_engine = EntropyEngine(self._config.entropy)

        # Build the filter
        baseline: set[str] = set()
        if self._config.baseline_file:
            baseline = load_baseline(Path(self._config.baseline_file))

        self._filter = FindingFilter(
            allowlist_patterns=self._config.allowlist.patterns,
            ignore_path_globs=self._config.allowlist.paths + self._config.ignore_paths,
            baseline_fingerprints=baseline,
        )

    # ── Public scanning entry points ────────────────────────────────────────────

    def scan_working_tree(self, target: Path) -> ScanResult:
        """Scan all files in the working tree of `target`."""
        repo_root = get_repo_root(target) or target
        lines = list(iter_working_tree(repo_root))
        return self._build_result(lines, ScanMode.WORKING_TREE, str(target))

    def scan_staged(self, target: Path) -> ScanResult:
        """Scan only the lines added in the git staging area."""
        repo_root = get_repo_root(target)
        if repo_root is None:
            raise GitError(f"'{target}' is not inside a git repository")
        lines = list(iter_staged_diff(repo_root))
        return self._build_result(lines, ScanMode.STAGED, str(target))

    def scan_commit_range(self, target: Path, from_ref: str, to_ref: str) -> ScanResult:
        """Scan all additions between `from_ref` and `to_ref`."""
        repo_root = get_repo_root(target)
        if repo_root is None:
            raise GitError(f"'{target}' is not inside a git repository")
        lines = list(iter_commit_range(repo_root, from_ref, to_ref))
        return self._build_result(
            lines, ScanMode.COMMIT_RANGE, f"{from_ref}..{to_ref}"
        )

    # ── Internal helpers ────────────────────────────────────────────────────────

    def _build_result(
        self,
        lines: list[ScannableLine],
        mode: ScanMode,
        target: str,
    ) -> ScanResult:
        findings: list[Finding] = []
        suppressed = 0
        files_seen: set[str] = set()

        for sl in lines:
            if self._filter.should_skip_path(sl.file_path):
                continue
            files_seen.add(sl.file_path)
            for match in self._scan_line(sl.content):
                if not self._filter.filter_match(match, sl.file_path):
                    suppressed += 1
                    continue

                finding = Finding(
                    rule_id=match.rule_id,
                    rule_name=match.rule_name,
                    severity=match.severity,
                    file_path=sl.file_path,
                    line_number=sl.line_number,
                    column_start=match.column_start,
                    column_end=match.column_end,
                    match_type=match.match_type,
                    secret_masked=mask_secret(match.raw_value),
                    line_preview=redact_line(sl.content, match.column_start, match.column_end),
                    scan_mode=mode,
                    commit_hash=sl.commit_hash,
                    author=sl.author,
                )

                if not self._filter.filter_finding(finding):
                    suppressed += 1
                    continue

                findings.append(finding)

        return ScanResult(
            scan_mode=mode,
            target=target,
            findings=findings,
            suppressed_count=suppressed,
            scanned_files=len(files_seen),
            scanned_lines=len(lines),
        )

    def _scan_line(self, line: str) -> list[LineMatch]:
        """Run all enabled engines on a single line and deduplicate by span."""
        all_matches = self._regex_engine.scan_line(line)
        entropy_matches = self._entropy_engine.scan_line(line)

        # Suppress entropy hits that overlap with a regex match (regex wins)
        regex_spans = {(m.column_start, m.column_end) for m in all_matches}
        for em in entropy_matches:
            overlaps = any(
                em.column_start < end and em.column_end > start
                for start, end in regex_spans
            )
            if not overlaps:
                all_matches.append(em)

        return all_matches
