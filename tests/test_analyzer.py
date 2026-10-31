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
        if app.name == "indirect_chain":
            hops = [hop.symbol for hop in finding.evidence.paths[0]]
            assert hops == [
                "main.main",
                "helpers.process",
                "vulnlib.parser.unsafe_parse",
            ]


def test_unknown_symbols_follow_imports(tmp_path: Path) -> None:
    empty = tmp_path / "symbols_cache.json"
    empty.write_text("{}\n", encoding="utf-8")
    imported = _scan(APPS / "direct_call", symbol_files=(empty,))
    assert imported.findings[0].verdict == Verdict.UNCERTAIN
    assert "unknown" in imported.findings[0].evidence.reasons[0]
    missing = _scan(APPS / "no_import", symbol_files=(empty,))
    assert missing.findings[0].verdict == Verdict.NOT_AFFECTED
    assert "never imported" in missing.findings[0].evidence.reasons[0]


def test_subclass_of_a_vulnerable_class_is_reachable(tmp_path: Path) -> None:
    site = tmp_path / "site"
    package = site / "lib"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        "class Base:\n    pass\n\n\nclass Child(Base):\n    pass\n",
        encoding="utf-8",
    )
    dist_info = site / "lib-1.0.0.dist-info"
    dist_info.mkdir()
    (dist_info / "METADATA").write_text("Name: lib\nVersion: 1.0.0\n", encoding="utf-8")
    (dist_info / "top_level.txt").write_text("lib\n", encoding="utf-8")
    osv = tmp_path / "osv"
    (osv / "vulns").mkdir(parents=True)
    (osv / "index.json").write_text('{"lib==1.0.0": ["TEST-SUB"]}\n', encoding="utf-8")
    (osv / "vulns" / "TEST-SUB.json").write_text(
        json.dumps(
            {
                "id": "TEST-SUB",
                "summary": "Base is vulnerable",
                "details": "Calling a subclass of Base reaches the flaw.",
                "aliases": [],
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "lib"},
                        "ranges": [
                            {
                                "type": "ECOSYSTEM",
                                "events": [{"introduced": "0"}, {"fixed": "1.0.1"}],
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    symbols = tmp_path / "symbols.json"
    symbols.write_text(
        json.dumps(
            {
                "TEST-SUB": {
                    "package": "lib",
                    "symbols": ["lib.Base"],
                    "safe_symbols": [],
                    "confidence": "high",
                    "generated_by": "test",
                }
            }
        ),
        encoding="utf-8",
    )
    app = tmp_path / "app"
    app.mkdir()
    (app / "requirements.txt").write_text("lib==1.0.0\n", encoding="utf-8")
    (app / "main.py").write_text(
        "import lib\n\n\ndef main() -> None:\n    lib.Child()\n",
        encoding="utf-8",
    )
    result = analyze(
        app,
        offline=True,
        site_dirs=(site,),
        osv_dirs=(osv,),
        symbol_files=(symbols,),
        use_llm=False,
    )
    assert result.findings
    finding = result.findings[0]
    assert finding.verdict == Verdict.REACHABLE
    assert "lib.Child is a subclass of Base" in finding.evidence.reasons
    assert [row["symbol"] for row in finding.vulnerable_symbols] == ["lib.Base"]


def test_fetch_failure_is_uncertain(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_args: object, **_kwargs: object) -> None:
        raise OfflineError("offline mode: vulnlib==1.0.0 is not available locally")

    monkeypatch.setattr("agent403.analyzer.fetch", boom)
    result = _scan(APPS / "direct_call")
    assert result.findings[0].verdict == Verdict.UNCERTAIN
    assert result.findings[0].verdict != Verdict.NOT_AFFECTED
    assert result.warnings
