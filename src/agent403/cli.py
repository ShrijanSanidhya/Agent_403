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
from agent403.callgraph import Index, Root
from agent403.llm import from_env
from agent403.models import Verdict
from agent403.net import HttpClient, OfflineError
from agent403.pypi import fetch
from agent403.report import dump_json, render_table, to_json
from agent403.symbols import load_advisory, resolve_symbols
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
            use_llm=not no_llm,
            refresh_symbols=refresh_symbols,
        )
    except (OfflineError, requests.RequestException, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    _emit(result, output_format, json_out, vex_out, verbose)
    raise typer.Exit(code=_exit_code(result, fail_on))


@app.command()
def symbols(
    advisory_id: Annotated[str, typer.Argument(help="OSV advisory id, for example GHSA-...")],
    package: Annotated[str, typer.Option("--package", help="Distribution as name==version.")],
    refresh: Annotated[bool, typer.Option("--refresh", help="Ignore cached symbols.")] = False,
    no_llm: Annotated[bool, typer.Option("--no-llm", help="Do not call a model.")] = False,
    verbose: Annotated[
        bool,
        typer.Option("-v", "--verbose", help="Print the diff excerpt."),
    ] = False,
) -> None:
    """Find the public symbols a user must call to trigger one advisory."""
    if "==" not in package:
        console.print("[red]Error:[/red] --package must look like name==version.")
        raise typer.Exit(code=2)
    name, version = package.split("==", 1)
    http = HttpClient()
    try:
        advisory = load_advisory(advisory_id, name, version, http)
        dist = fetch(name, version, offline=False, http=http)
    except (OfflineError, requests.RequestException, OSError) as exc:
        console.print(f"[red]Error:[/red] {exc}")
        raise typer.Exit(code=2) from None
    llm = None
    if not no_llm:
        llm, warning = from_env(True)
        if warning:
            console.print(f"[yellow]Warning:[/yellow] {warning}")
    index = Index.build([Root(dist.root, "dep", list(dist.import_names))])
    result = resolve_symbols(
        advisory,
        index,
        dist,
        http=http,
        llm=llm,
        offline=False,
        refresh=refresh,
    )
    _print_symbols(result, verbose)


def _print_symbols(result, verbose: bool) -> None:
    provenance = result.provenance
    _print_names("changed functions:", _joined(provenance, "changed", "context"))
    _print_names("candidates:", _as_list(provenance.get("candidates")))
    console.print("vulnerable symbols:")
    for name in result.symbols:
        console.print(f"  {name}{_because(provenance, name, 'vulnerable')}")
    console.print("safe symbols:")
    for name in result.safe_symbols:
        console.print(f"  {name}{_because(provenance, name, 'safe')}")
    _print_names("rejected:", result.rejected)
    console.print(f"source: {result.source}")
    console.print(f"confidence: {result.confidence}")
    if not verbose:
        return
    _print_names("fix refs:", _as_list(provenance.get("fix_refs_used")))
    _print_names("public API:", _as_list(provenance.get("public")))


def _joined(provenance: dict[str, object], *keys: str) -> list[str]:
    names: list[str] = []
    for key in keys:
        names.extend(_as_list(provenance.get(key)))
    return names


def _as_list(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _because(provenance: dict[str, object], name: str, role: str) -> str:
    raw = provenance.get("why")
    if not isinstance(raw, list):
        return ""
    for item in raw:
        if not isinstance(item, dict) or item.get("symbol") != name:
            continue
        if item.get("role") not in {role, None, ""}:
            continue
        why = item.get("why")
        if why:
            return f" — {why}"
    return ""


def _print_names(title: str, names: list[str]) -> None:
    console.print(title)
    for name in names:
        console.print(f"  {name}")


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
