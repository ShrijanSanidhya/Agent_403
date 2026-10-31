"""Command-line interface for agent403."""

from enum import Enum
from pathlib import Path
from typing import Annotated

import requests
import typer
from rich.console import Console
from rich.table import Table

from agent403 import __version__
from agent403.deps import load_dependencies
from agent403.net import HttpClient, OfflineError
from agent403.osv import OsvClient

app = typer.Typer(no_args_is_help=True)
console = Console()


class OutputFormat(str, Enum):
    table = "table"
    json = "json"


class FailOn(str, Enum):
    reachable = "reachable"
    uncertain = "uncertain"
    never = "never"


@app.command()
def version() -> None:
    """Print the agent403 version."""
    typer.echo(f"agent403 {__version__}")


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Project directory to scan.")],
    requirements: Annotated[
        Path | None,
        typer.Option("--requirements", help="Requirements file to read."),
    ] = None,
    output_format: Annotated[
        OutputFormat,
        typer.Option("--format", help="Output format."),
    ] = OutputFormat.table,
    json_out: Annotated[
        Path | None,
        typer.Option("--json-out", help="Write the JSON report to this file."),
    ] = None,
    vex_out: Annotated[
        Path | None,
        typer.Option("--vex-out", help="Write the OpenVEX document to this file."),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Use only the local cache."),
    ] = False,
    no_llm: Annotated[
        bool,
        typer.Option("--no-llm", help="Do not call a model."),
    ] = False,
    refresh_symbols: Annotated[
        bool,
        typer.Option("--refresh-symbols", help="Ignore the shipped symbol cache."),
    ] = False,
    include_tests: Annotated[
        bool,
        typer.Option("--include-tests", help="Include test files in the call graph."),
    ] = False,
    fail_on: Annotated[
        FailOn,
        typer.Option("--fail-on", help="Exit 1 when a finding is at least this severe."),
    ] = FailOn.reachable,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Print extra detail."),
    ] = False,
) -> None:
    """Scan a Python project for reachable vulnerable functions."""
    del (
        output_format,
        json_out,
        vex_out,
        no_llm,
        refresh_symbols,
        include_tests,
        fail_on,
        verbose,
    )
    if not path.exists() or not path.is_dir():
        console.print(f"[red]Error:[/red] {path} is not a directory.")
        raise typer.Exit(code=2)
    try:
        dependencies, warnings = load_dependencies(path, requirements)
        client = OsvClient(HttpClient(offline=offline), offline=offline)
        advisories, osv_warnings = client.fetch_advisories(dependencies)
    except (OfflineError, requests.RequestException, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    warnings.extend(osv_warnings)
    table = Table()
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Advisory")
    table.add_column("Aliases")
    table.add_column("Fixed in")
    for advisory in advisories:
        table.add_row(
            advisory.package,
            advisory.version,
            advisory.id,
            ", ".join(advisory.aliases),
            ", ".join(advisory.fixed_versions),
        )
    console.print(table)
    for warning in warnings:
        console.print(f"[yellow]Warning:[/yellow] {warning}")
    console.print("Reachability analysis not implemented yet")
    raise typer.Exit(code=2)
