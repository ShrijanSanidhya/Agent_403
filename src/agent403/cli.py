"""Command-line interface for agent403."""

from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from agent403 import __version__

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
        requirements,
        output_format,
        json_out,
        vex_out,
        offline,
        no_llm,
        refresh_symbols,
        include_tests,
        fail_on,
        verbose,
    )
    if not path.exists() or not path.is_dir():
        console.print(f"[red]Error:[/red] {path} is not a directory.")
        raise typer.Exit(code=2)
    console.print("scan pipeline not implemented yet")
    raise typer.Exit(code=2)
