"""CLI entry point for secret-scanner using Typer."""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from . import __version__
from .config import load_config
from .filters import save_baseline
from .git_utils import GitError
from .hooks import install_pre_commit_hook, uninstall_pre_commit_hook
from .models import ScanResult
from .output.console import ConsoleOutput
from .output.json_output import JsonOutput
from .output.sarif import SarifOutput
from .scanner import Scanner

app = typer.Typer(
    name="secret-scanner",
    help="Scan Git repositories for leaked secrets, API keys, and tokens.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console(stderr=True)
err_console = Console(stderr=True)


class OutputFormat(StrEnum):
    console = "console"
    json = "json"
    sarif = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"secret-scanner {__version__}")
        raise typer.Exit()


@app.command()
def scan(
    target: Annotated[
        Path,
        typer.Argument(
            help="Directory or git repo to scan. Defaults to current directory.",
            show_default=True,
        ),
    ] = Path(),
    staged: Annotated[
        bool,
        typer.Option("--staged", help="Scan only staged (git diff --staged) changes."),
    ] = False,
    commit_range: Annotated[
        str | None,
        typer.Option(
            "--commit-range",
            metavar="FROM..TO",
            help="Scan a git commit range, e.g. HEAD~5..HEAD.",
        ),
    ] = None,
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to a .secret-scanner.yaml config file."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", "-f", help="Output format."),
    ] = OutputFormat.console,
    output_file: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write output to this file instead of stdout."),
    ] = None,
    no_color: Annotated[
        bool,
        typer.Option("--no-color", help="Disable color output."),
    ] = False,
    fail_on_findings: Annotated[
        bool,
        typer.Option("--fail/--no-fail", help="Exit with code 1 when findings are detected."),
    ] = True,
    version: Annotated[
        bool | None,
        typer.Option("--version", "-v", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """Scan a repository or directory for leaked secrets."""
    target = target.resolve()
    if not target.exists():
        err_console.print(f"[red]Error:[/red] target path does not exist: {target}")
        raise typer.Exit(2)

    # Auto-detect config file
    if config is None:
        for candidate in [
            target / ".secret-scanner.yaml",
            target / ".secret-scanner.yml",
            Path.cwd() / ".secret-scanner.yaml",
        ]:
            if candidate.exists():
                config = candidate
                break

    try:
        scan_config = load_config(config)
    except Exception as e:
        err_console.print(f"[red]Config error:[/red] {e}")
        raise typer.Exit(2) from e

    scanner = Scanner(scan_config)

    try:
        if commit_range:
            parts = commit_range.split("..", 1)
            if len(parts) != 2:
                err_console.print(
                    "[red]Error:[/red] --commit-range must be in FROM..TO format"
                )
                raise typer.Exit(2)
            result = scanner.scan_commit_range(target, parts[0], parts[1])
        elif staged:
            result = scanner.scan_staged(target)
        else:
            result = scanner.scan_working_tree(target)
    except GitError as e:
        err_console.print(f"[red]Git error:[/red] {e}")
        raise typer.Exit(2) from e

    _write_output(result, output_format, output_file, no_color)

    if fail_on_findings and result.has_findings:
        raise typer.Exit(1)


@app.command(name="install-hook")
def install_hook(
    target: Annotated[
        Path,
        typer.Argument(help="Git repository root. Defaults to current directory."),
    ] = Path(),
    force: Annotated[
        bool,
        typer.Option("--force", "-f", help="Overwrite an existing pre-commit hook."),
    ] = False,
) -> None:
    """Install a pre-commit git hook that blocks commits containing secrets."""
    target = target.resolve()
    try:
        hook_path = install_pre_commit_hook(target, force=force)
        console.print(f"[green]✓[/green] Pre-commit hook installed at [bold]{hook_path}[/bold]")
    except FileExistsError as e:
        err_console.print(f"[yellow]Warning:[/yellow] {e}")
        raise typer.Exit(1) from e
    except RuntimeError as e:
        err_console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(2) from e


@app.command(name="uninstall-hook")
def uninstall_hook(
    target: Annotated[
        Path,
        typer.Argument(help="Git repository root. Defaults to current directory."),
    ] = Path(),
) -> None:
    """Remove the secret-scanner pre-commit hook."""
    target = target.resolve()
    removed = uninstall_pre_commit_hook(target)
    if removed:
        console.print("[green]✓[/green] Pre-commit hook removed.")
    else:
        console.print("[dim]No secret-scanner hook found; nothing to remove.[/dim]")


@app.command(name="generate-baseline")
def generate_baseline(
    target: Annotated[
        Path,
        typer.Argument(help="Directory or git repo to scan."),
    ] = Path(),
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to a .secret-scanner.yaml config file."),
    ] = None,
    baseline_file: Annotated[
        Path,
        typer.Option("--baseline", "-b", help="Output baseline file path."),
    ] = Path(".secret-scanner-baseline.json"),
) -> None:
    """Scan the working tree and write a baseline to suppress existing findings."""
    target = target.resolve()
    scan_config = load_config(config)
    scanner = Scanner(scan_config)

    try:
        result = scanner.scan_working_tree(target)
    except GitError as e:
        err_console.print(f"[red]Git error:[/red] {e}")
        raise typer.Exit(2) from e

    save_baseline(result.findings, baseline_file)
    count = len(result.findings)
    console.print(
        f"[green]✓[/green] Baseline written to [bold]{baseline_file}[/bold] "
        f"({count} finding(s) suppressed)."
    )


@app.command(name="rules")
def list_rules(
    config: Annotated[
        Path | None,
        typer.Option("--config", "-c", help="Path to a .secret-scanner.yaml config file."),
    ] = None,
) -> None:
    """List all active detection rules."""
    from rich import box
    from rich.table import Table

    scan_config = load_config(config)
    table = Table(box=box.ROUNDED, title="Active Rules")
    table.add_column("ID")
    table.add_column("Name")
    table.add_column("Severity")
    table.add_column("Description")

    for rule in scan_config.rules:
        table.add_row(rule.id, rule.name, rule.severity, rule.description or "—")

    rich_console = Console()
    rich_console.print(table)
    rich_console.print(
        f"\n  Entropy detection: "
        f"{'[green]enabled[/green]' if scan_config.entropy.enabled else '[dim]disabled[/dim]'} "
        f"(threshold={scan_config.entropy.threshold})"
    )


def _write_output(
    result: ScanResult,
    fmt: OutputFormat,
    output_file: Path | None,
    no_color: bool,
) -> None:
    if fmt == OutputFormat.json:
        jout = JsonOutput()
        if output_file:
            jout.write_file(result, output_file)
        else:
            jout.write(result)
    elif fmt == OutputFormat.sarif:
        sout = SarifOutput()
        if output_file:
            sout.write_file(result, output_file)
        else:
            sout.write(result)
    else:
        rich_console = Console(no_color=no_color)
        cout = ConsoleOutput(console=rich_console)
        cout.print_result(result)


if __name__ == "__main__":
    app()
