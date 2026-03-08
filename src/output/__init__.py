"""Output formatters for scan results."""

from secret_scanner.output.console import ConsoleOutput
from secret_scanner.output.json_output import JsonOutput
from secret_scanner.output.sarif import SarifOutput

__all__ = ["ConsoleOutput", "JsonOutput", "SarifOutput"]
