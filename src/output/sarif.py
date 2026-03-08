"""SARIF 2.1.0 output compatible with GitHub Code Scanning."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import IO, Any

from secret_scanner import __version__
from secret_scanner.models import Finding, ScanResult, Severity

_SEVERITY_TO_SARIF_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}

_SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)


class SarifOutput:
    """Produces SARIF 2.1.0 output for GitHub Code Scanning integration."""

    def write(self, result: ScanResult, dest: IO[str] | None = None) -> None:
        payload = self._build_sarif(result)
        output = dest or sys.stdout
        json.dump(payload, output, indent=2)
        output.write("\n")

    def write_file(self, result: ScanResult, path: Path) -> None:
        with path.open("w") as fh:
            self.write(result, fh)

    def _build_sarif(self, result: ScanResult) -> dict[str, Any]:
        rules = self._collect_rules(result.findings)
        return {
            "version": "2.1.0",
            "$schema": _SARIF_SCHEMA,
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "secret-scanner",
                            "version": __version__,
                            "informationUri": "https://github.com/example/secret-scanner",
                            "rules": rules,
                        }
                    },
                    "results": [self._finding_to_result(f) for f in result.findings],
                    "properties": {
                        "scanMode": result.scan_mode.value,
                        "target": result.target,
                        "suppressedCount": result.suppressed_count,
                    },
                }
            ],
        }

    def _collect_rules(self, findings: list[Finding]) -> list[dict[str, Any]]:
        seen: dict[str, dict[str, Any]] = {}
        for f in findings:
            if f.rule_id not in seen:
                seen[f.rule_id] = {
                    "id": f.rule_id,
                    "name": f.rule_name,
                    "shortDescription": {"text": f.rule_name},
                    "fullDescription": {
                        "text": f"Detected by secret-scanner rule '{f.rule_id}' "
                        f"({f.match_type.value})"
                    },
                    "defaultConfiguration": {
                        "level": _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
                    },
                    "properties": {
                        "tags": ["security", "secret-detection"],
                        "severity": f.severity.value,
                        "matchType": f.match_type.value,
                    },
                }
        return list(seen.values())

    @staticmethod
    def _finding_to_result(f: Finding) -> dict[str, Any]:
        level = _SEVERITY_TO_SARIF_LEVEL.get(f.severity, "warning")
        return {
            "ruleId": f.rule_id,
            "level": level,
            "message": {
                "text": (
                    f"{f.rule_name} detected. "
                    f"Secret (masked): {f.secret_masked}. "
                    "Review and rotate this credential immediately."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": f.line_number,
                            "startColumn": f.column_start + 1,  # SARIF is 1-indexed
                            "endColumn": f.column_end + 1,
                            "snippet": {"text": f.line_preview},
                        },
                    }
                }
            ],
            "fingerprints": {"secret-scanner/v1": f.fingerprint},
            "properties": {
                "severity": f.severity.value,
                "matchType": f.match_type.value,
                "secretMasked": f.secret_masked,
                "author": f.author,
                "commitHash": f.commit_hash,
            },
        }
