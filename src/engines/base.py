"""Abstract base class for detection engines."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from secret_scanner.models import MatchType, Severity


@dataclass
class LineMatch:
    """Raw match result from an engine before filtering/enrichment."""

    rule_id: str
    rule_name: str
    severity: Severity
    match_type: MatchType
    # The matched secret value – used internally only; never logged as-is
    raw_value: str
    column_start: int
    column_end: int


class BaseEngine(ABC):
    """Common interface for all detection engines."""

    @abstractmethod
    def scan_line(self, line: str) -> list[LineMatch]:
        """Return all matches found in a single line of text."""
        ...
