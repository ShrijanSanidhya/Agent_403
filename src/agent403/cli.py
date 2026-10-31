"""Command-line interface for agent403."""

import json
from enum import Enum
from pathlib import Path
from typing import Annotated

import requests
import typer
from rich.console import Console

from agent403 import __version__
from agent403.analyzer import ScanResult, analyze
from agent403.models import Verdict
from agent403.net import OfflineError
from agent403.report import dump_json, render_table, to_json
from agent403.vex import dump_vex

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
    site_packages: Annotated[
        list[Path] | None,
        typer.Option("--site-packages", help="Read dependency source from this directory."),
    ] = None,
    osv_cache: Annotated[
        list[Path] | None,
        typer.Option("--osv-cache", help="Extra OSV cache directory."),
    ] = None,
    symbols_cache: Annotated[
        list[Path] | None,
        typer.Option("--symbols-cache", help="Extra symbols cache file."),
    ] = None,
) -> None:
    """Scan a Python project for reachable vulnerable functions."""
    del no_llm, refresh_symbols
    if not path.exists() or not path.is_dir():
        console.print(f"[red]Error:[/red] {path} is not a directory.")
        raise typer.Exit(code=2)
    try:
        result = analyze(
            path,
            requirements=requirements,
            offline=offline,
            site_dirs=site_packages or [],
            osv_dirs=osv_cache or [],
            symbol_files=symbols_cache or [],
            include_tests=include_tests,
        )
    except (OfflineError, requests.RequestException, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    _emit(result, output_format, json_out, vex_out, verbose)
    raise typer.Exit(code=_exit_code(result, fail_on))


def _emit(
    result: ScanResult,
    output_format: OutputFormat,
    json_out: Path | None,
    vex_out: Path | None,
    verbose: bool,
) -> None:
    if output_format == OutputFormat.json:
        typer.echo(json.dumps(to_json(result), indent=2))
        err = Console(stderr=True)
        for warning in result.warnings:
            err.print(f"[yellow]Warning:[/yellow] {warning}")
    else:
        render_table(result, console, verbose)
        for warning in result.warnings:
            console.print(f"[yellow]Warning:[/yellow] {warning}")
    if json_out is not None:
        with json_out.open("w", encoding="utf-8") as handle:
            dump_json(result, handle)
    if vex_out is not None:
        with vex_out.open("w", encoding="utf-8") as handle:
            dump_vex(result, handle)


_RANK = {Verdict.REACHABLE: 2, Verdict.UNCERTAIN: 1, Verdict.NOT_AFFECTED: 0}


def _exit_code(result: ScanResult, fail_on: FailOn) -> int:
    if fail_on == FailOn.never:
        return 0
    threshold = _RANK[Verdict.REACHABLE if fail_on == FailOn.reachable else Verdict.UNCERTAIN]
    for finding in result.findings:
        if _RANK[finding.verdict] >= threshold:
            return 1
    return 0
