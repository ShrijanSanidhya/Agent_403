"""JSON report shape and a table that renders."""

from pathlib import Path

from rich.console import Console

from agent403.analyzer import ScanResult, analyze
from agent403.models import Advisory, Evidence, Finding, Verdict
from agent403.report import render_table, summary, to_json

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
    assert data["llm"]["enabled"] is False
    assert data["llm"]["available"] is False
    assert data["tool"]["name"] == "agent403"
    assert data["summary"] == {
        "reachable": 1,
        "not_affected": 0,
        "uncertain": 0,
        "total": 1,
        "noise_removed_pct": 0,
    }
    finding = data["findings"][0]
    assert finding["verdict"] == "reachable"
    assert finding["evidence"]["paths"]
    assert set(finding) >= {"vuln_id", "vex_status", "vulnerable_symbols"}


def test_table_renders() -> None:
    console = Console(record=True, width=200)
    render_table(_result(), console, verbose=True)
    text = _flat(console.export_text())
    assert "REACHABLE" in text
    assert "vulnlib.parser.unsafe_parse" in text
    assert "1 reachable, 0 uncertain, 0 not affected" in text
    assert "1 advisories found by package-level scanning -> 1 actually reachable" in text
    assert "(0% of alerts need no action)" in text
    assert "🔧 Fix: upgrade vulnlib to 1.0.1 or later (TEST-0001)" in text


def test_empty_scan_reports_zero_noise() -> None:
    result = _bare([])
    assert summary(result)["total"] == 0
    assert summary(result)["noise_removed_pct"] == 0
    text = _rendered(result)
    assert "0 advisories found by package-level scanning -> 0 actually reachable" in text
    assert "(0% of alerts need no action)" in text
    assert "need manual review" not in text


def test_uncertain_findings_need_review_and_are_not_noise() -> None:
    result = _bare([_finding(Verdict.UNCERTAIN)])
    assert summary(result)["noise_removed_pct"] == 0
    text = _rendered(result)
    assert "1 need manual review" in text
    assert "(0% of alerts need no action)" in text
    assert "🔧 Fix:" not in text


def test_reachable_finding_prints_the_first_fixed_version() -> None:
    result = _bare([_finding(Verdict.REACHABLE, fixed=["5.4", "5.4.1"])])
    text = _rendered(result)
    assert "🔧 Fix: upgrade demo to 5.4 or later (GHSA-test)" in text


def _flat(text: str) -> str:
    return " ".join(text.split())


def _rendered(result: ScanResult) -> str:
    console = Console(record=True, width=200)
    render_table(result, console, verbose=False)
    return _flat(console.export_text())


def _bare(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        project=Path("app"),
        generated_at="2026-01-01T00:00:00+00:00",
        dependencies=[],
        findings=findings,
    )


def _finding(verdict: Verdict, fixed: list[str] | None = None) -> Finding:
    return Finding(
        advisory=Advisory(
            id="GHSA-test",
            aliases=[],
            summary="example",
            details="",
            package="demo",
            version="1.0.0",
            fixed_versions=list(fixed or []),
            fix_refs=[],
        ),
        verdict=verdict,
        vulnerable_symbols=[],
        evidence=Evidence([], [], ["because"]),
        vex_status="not_affected",
    )
