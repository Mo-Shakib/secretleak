"""Human-friendly Rich console output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from secret_scanner.models import Finding, ScanResult, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
}

_SEVERITY_ICONS: dict[Severity, str] = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "⚪",
}


class ConsoleOutput:
    def __init__(self, console: Console | None = None) -> None:
        self._console = console or Console(stderr=False)

    def print_result(self, result: ScanResult) -> None:
        if not result.findings:
            self._print_clean(result)
            return

        self._print_summary_header(result)
        self._print_findings_table(result.findings)
        self._print_stats(result)

    def _print_clean(self, result: ScanResult) -> None:
        self._console.print(
            Panel(
                Text("No secrets found.", style="bold green"),
                title=f"[bold]secret-scanner[/bold] — {result.scan_mode.value}",
                border_style="green",
            )
        )
        self._console.print(
            f"  Scanned [bold]{result.scanned_files}[/bold] files, "
            f"[bold]{result.scanned_lines}[/bold] lines. "
            f"[dim]{result.suppressed_count} suppressed.[/dim]"
        )

    def _print_summary_header(self, result: ScanResult) -> None:
        count = len(result.findings)
        crit = result.critical_count
        high = result.high_count
        title = f"[bold red]secret-scanner — {count} finding(s) detected![/bold red]"
        body = (
            f"  [red]Critical: {crit}[/red]  "
            f"[yellow]High: {high}[/yellow]  "
            f"Other: {count - crit - high}"
        )
        self._console.print(Panel(body, title=title, border_style="red"))

    def _print_findings_table(self, findings: list[Finding]) -> None:
        table = Table(
            box=box.ROUNDED,
            show_lines=True,
            title="Findings",
            title_style="bold",
        )
        table.add_column("Sev", style="bold", no_wrap=True, width=6)
        table.add_column("Rule", no_wrap=True)
        table.add_column("File", no_wrap=False)
        table.add_column("Line", justify="right", width=6)
        table.add_column("Secret (masked)", no_wrap=False)
        table.add_column("Preview", no_wrap=False)

        sorted_findings = sorted(findings, key=lambda f: (-f.severity_rank(), f.file_path))

        for f in sorted_findings:
            style = _SEVERITY_STYLES.get(f.severity, "")
            icon = _SEVERITY_ICONS.get(f.severity, "")
            table.add_row(
                Text(f"{icon} {f.severity.value.upper()}", style=style),
                f.rule_name,
                f.file_path,
                str(f.line_number),
                Text(f.secret_masked.replace("*", "•"), style="bold magenta"),
                Text(f.line_preview.strip()[:80], style="dim"),
            )

        self._console.print(table)

    def _print_stats(self, result: ScanResult) -> None:
        self._console.print(
            f"\n  Scanned [bold]{result.scanned_files}[/bold] files, "
            f"[bold]{result.scanned_lines}[/bold] lines. "
            f"[dim]{result.suppressed_count} suppressed.[/dim]\n"
        )

    def print_finding(self, finding: Finding) -> None:
        """Print a single finding (used in hook mode for incremental output)."""
        style = _SEVERITY_STYLES.get(finding.severity, "")
        icon = _SEVERITY_ICONS.get(finding.severity, "")
        self._console.print(
            f"{icon} [{style}]{finding.severity.value.upper()}[/{style}] "
            f"[bold]{finding.rule_name}[/bold] — "
            f"{finding.file_path}:{finding.line_number} — "
            f"[magenta]{finding.secret_masked}[/magenta]"
        )
