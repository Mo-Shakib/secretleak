"""Regex-based secret detection engine."""

from __future__ import annotations

import re

from ..config import RegexRule
from ..models import MatchType, Severity
from .base import BaseEngine, LineMatch


class RegexEngine(BaseEngine):
    """Applies a set of compiled regex patterns to each line."""

    def __init__(self, rules: list[RegexRule]) -> None:
        self._compiled: list[tuple[RegexRule, re.Pattern[str]]] = []
        for rule in rules:
            try:
                compiled = re.compile(rule.pattern)
                self._compiled.append((rule, compiled))
            except re.error:
                # Already validated in config; skip silently in production
                continue

    def scan_line(self, line: str) -> list[LineMatch]:
        matches: list[LineMatch] = []
        for rule, pattern in self._compiled:
            for m in pattern.finditer(line):
                # Use group(1) if a capture group exists, otherwise full match
                value = m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                col_start = m.start(1) if m.lastindex and m.lastindex >= 1 else m.start()
                col_end = m.end(1) if m.lastindex and m.lastindex >= 1 else m.end()
                matches.append(
                    LineMatch(
                        rule_id=rule.id,
                        rule_name=rule.name,
                        severity=Severity(rule.severity),
                        match_type=MatchType.REGEX,
                        raw_value=value,
                        column_start=col_start,
                        column_end=col_end,
                    )
                )
        return matches
