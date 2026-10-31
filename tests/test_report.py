"""JSON report shape and a table that renders."""

from pathlib import Path

from rich.console import Console

from agent403.analyzer import analyze
from agent403.report import render_table, to_json

FIXTURES = Path(__file__).parent / "fixtures"
APPS = FIXTURES / "apps"


def _result():
    return analyze(
        APPS / "direct_call",
        offline=True,
        site_dirs=(FIXTURES / "site",),
        osv_dirs=(FIXTURES / "osv",),
        symbol_files=(FIXTURES / "symbols" / "symbols_cache.json",),
    )


def test_json_schema_and_summary() -> None:
    result = _result()
    data = to_json(result)
    assert set(data) == {
        "tool",
        "project",
        "generated_at",
        "llm",
        "dependencies",
        "findings",
        "summary",
    }
    assert data["llm"] == {"enabled": False}
    assert data["tool"]["name"] == "agent403"
    assert data["summary"] == {"reachable": 1, "not_affected": 0, "uncertain": 0}
    finding = data["findings"][0]
    assert finding["verdict"] == "reachable"
    assert finding["evidence"]["paths"]
    assert set(finding) >= {"vuln_id", "vex_status", "vulnerable_symbols"}


def test_table_renders() -> None:
    console = Console(record=True)
    render_table(_result(), console, verbose=True)
    text = console.export_text()
    assert "REACHABLE" in text
    assert "vulnlib.parser.unsafe_parse" in text
    assert "1 reachable, 0 uncertain, 0 not affected" in text
