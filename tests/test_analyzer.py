"""Verdicts for the fixture apps, unknown symbols, and a failed fetch."""

import json
from pathlib import Path

import pytest

from agent403.analyzer import analyze
from agent403.models import Verdict
from agent403.net import OfflineError

FIXTURES = Path(__file__).parent / "fixtures"
APPS = FIXTURES / "apps"
SITE = FIXTURES / "site"
OSV = FIXTURES / "osv"
SYMBOLS = FIXTURES / "symbols" / "symbols_cache.json"


def _scan(app: Path, symbol_files: tuple[Path, ...] = (SYMBOLS,)):
    return analyze(
        app,
        offline=True,
        site_dirs=(SITE,),
        osv_dirs=(OSV,),
        symbol_files=symbol_files,
    )


def test_fixture_apps_match_expected() -> None:
    for app in sorted(path for path in APPS.iterdir() if path.is_dir()):
        expected = json.loads((app / "expected.json").read_text(encoding="utf-8"))["vulnlib"]
        result = _scan(app)
        assert result.findings, app.name
        finding = result.findings[0]
        assert finding.verdict.value == expected, app.name
        if expected == "reachable":
            assert finding.evidence.paths, app.name
            assert finding.evidence.reasons, app.name
            assert finding.vex_status == "affected"


def test_unknown_symbols_follow_imports(tmp_path: Path) -> None:
    empty = tmp_path / "symbols_cache.json"
    empty.write_text("{}\n", encoding="utf-8")
    imported = _scan(APPS / "direct_call", symbol_files=(empty,))
    assert imported.findings[0].verdict == Verdict.UNCERTAIN
    assert "unknown" in imported.findings[0].evidence.reasons[0]
    missing = _scan(APPS / "no_import", symbol_files=(empty,))
    assert missing.findings[0].verdict == Verdict.NOT_AFFECTED
    assert "never imported" in missing.findings[0].evidence.reasons[0]


def test_fetch_failure_is_uncertain(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise OfflineError("offline mode: vulnlib==1.0.0 is not available locally")

    monkeypatch.setattr("agent403.analyzer.fetch", boom)
    result = _scan(APPS / "direct_call")
    assert result.findings[0].verdict == Verdict.UNCERTAIN
    assert result.findings[0].verdict != Verdict.NOT_AFFECTED
    assert result.warnings
