"""Render a scan as a rich table or the JSON report from the plan."""

import json
from typing import TextIO

from rich.console import Console
from rich.table import Table

from agent403 import __version__
from agent403.analyzer import ScanResult
from agent403.models import Finding, PathHop, Verdict

_COLORS = {
    Verdict.REACHABLE: "red",
    Verdict.NOT_AFFECTED: "green",
    Verdict.UNCERTAIN: "yellow",
}
_LABELS = {
    Verdict.REACHABLE: "REACHABLE",
    Verdict.NOT_AFFECTED: "NOT AFFECTED",
    Verdict.UNCERTAIN: "UNCERTAIN",
}


def render_table(result: ScanResult, console: Console, verbose: bool) -> None:
    """Print the summary table, reachable paths, and one totals line."""
    table = Table()
    table.add_column("Package")
    table.add_column("Version")
    table.add_column("Advisory")
    table.add_column("Verdict")
    table.add_column("Why")
    for finding in result.findings:
        color = _COLORS[finding.verdict]
        label = _LABELS[finding.verdict]
        why = finding.evidence.reasons[0] if finding.evidence.reasons else ""
        table.add_row(
            finding.advisory.package,
            finding.advisory.version,
            _advisory_label(finding),
            f"[{color}]{label}[/{color}]",
            why,
        )
    console.print(table)
    for finding in result.findings:
        if finding.verdict != Verdict.REACHABLE:
            continue
        for path in finding.evidence.paths:
            _print_path(console, path)
    counts = summary(result)
    console.print(
        f"{counts['reachable']} reachable, {counts['uncertain']} uncertain, "
        f"{counts['not_affected']} not affected"
    )
    if verbose:
        _print_verbose(console, result)


def to_json(result: ScanResult) -> dict[str, object]:
    """Return the report object described in the plan."""
    counts = summary(result)
    return {
        "tool": {"name": "agent403", "version": __version__},
        "project": str(result.project),
        "generated_at": result.generated_at,
        "llm": dict(result.llm),
        "dependencies": [
            {"name": dep.name, "version": dep.version, "pinned": dep.pinned}
            for dep in result.dependencies
        ],
        "findings": [finding.to_dict() for finding in result.findings],
        "summary": counts,
    }


def dump_json(result: ScanResult, handle: TextIO) -> None:
    """Write the JSON report."""
    json.dump(to_json(result), handle, indent=2)
    handle.write("\n")


def summary(result: ScanResult) -> dict[str, int]:
    """Count findings by verdict."""
    counts = {"reachable": 0, "not_affected": 0, "uncertain": 0}
    for finding in result.findings:
        counts[finding.verdict.value] += 1
    return counts


def _advisory_label(finding: Finding) -> str:
    cve = next((alias for alias in finding.advisory.aliases if alias.startswith("CVE-")), "")
    if cve:
        return f"{finding.advisory.id} {cve}"
    return finding.advisory.id


def _print_path(console: Console, path: list[PathHop]) -> None:
    for index, hop in enumerate(path):
        place = f"  ({hop.file}:{hop.line})" if hop.file else ""
        if index == 0:
            console.print(f"  {hop.symbol}{place}")
        else:
            console.print(f"  -> {hop.symbol}{place}")


def _print_verbose(console: Console, result: ScanResult) -> None:
    for finding in result.findings:
        console.print(f"{finding.advisory.id}:")
        for reason in finding.evidence.reasons:
            console.print(f"  {reason}")
        for symbol in finding.vulnerable_symbols:
            console.print(f"  {symbol['symbol']} ({symbol['source']}, {symbol['confidence']})")
