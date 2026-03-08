"""JSON report output."""

from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from .. import __version__
from ..models import ScanResult


class JsonOutput:
    """Serializes a ScanResult to JSON, safe for stdout or file output."""

    def write(self, result: ScanResult, dest: IO[str] | None = None) -> None:
        """Write JSON report to `dest` (defaults to stdout)."""
        payload = self._build_payload(result)
        output = dest or sys.stdout
        json.dump(payload, output, indent=2, default=str)
        output.write("\n")

    def write_file(self, result: ScanResult, path: Path) -> None:
        with path.open("w") as fh:
            self.write(result, fh)

    def _build_payload(self, result: ScanResult) -> dict[str, Any]:
        return {
            "version": __version__,
            "generated_at": datetime.now(tz=UTC).isoformat(),
            "scan_mode": result.scan_mode.value,
            "target": result.target,
            "summary": {
                "total": len(result.findings),
                "critical": result.critical_count,
                "high": result.high_count,
                "suppressed": result.suppressed_count,
                "scanned_files": result.scanned_files,
                "scanned_lines": result.scanned_lines,
            },
            "findings": [self._finding_to_dict(f) for f in result.findings],
        }

    @staticmethod
    def _finding_to_dict(f: Any) -> dict[str, Any]:
        return {
            "fingerprint": f.fingerprint,
            "rule_id": f.rule_id,
            "rule_name": f.rule_name,
            "severity": f.severity.value,
            "match_type": f.match_type.value,
            "file_path": f.file_path,
            "line_number": f.line_number,
            "column_start": f.column_start,
            "column_end": f.column_end,
            # Secret is NEVER included in full – only the masked form
            "secret_masked": f.secret_masked,
            "line_preview": f.line_preview,
            "scan_mode": f.scan_mode.value,
            "commit_hash": f.commit_hash,
            "author": f.author,
        }
