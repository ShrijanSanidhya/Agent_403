"""Scan exit codes and written report files."""

import json
from pathlib import Path

from typer.testing import CliRunner

from agent403.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
APPS = FIXTURES / "apps"
runner = CliRunner()


def _args(app_name: str, *extra: str) -> list[str]:
    return [
        "scan",
        str(APPS / app_name),
        "--offline",
        "--site-packages",
        str(FIXTURES / "site"),
        "--osv-cache",
        str(FIXTURES / "osv"),
        "--symbols-cache",
        str(FIXTURES / "symbols" / "symbols_cache.json"),
        *extra,
    ]


def test_exit_codes(tmp_path: Path) -> None:
    assert runner.invoke(app, _args("direct_call")).exit_code == 1
    assert runner.invoke(app, _args("safe_only")).exit_code == 0
    assert runner.invoke(app, _args("dynamic_getattr", "--fail-on", "uncertain")).exit_code == 1
    assert runner.invoke(app, _args("dynamic_getattr", "--fail-on", "never")).exit_code == 0
    missing = runner.invoke(app, ["scan", "/does/not/exist"])
    assert missing.exit_code == 2


def test_json_and_vex_files(tmp_path: Path) -> None:
    json_out = tmp_path / "report.json"
    vex_out = tmp_path / "vex.json"
    result = runner.invoke(
        app,
        _args("direct_call", "--json-out", str(json_out), "--vex-out", str(vex_out)),
    )
    assert result.exit_code == 1
    report = json.loads(json_out.read_text(encoding="utf-8"))
    document = json.loads(vex_out.read_text(encoding="utf-8"))
    assert report["summary"]["reachable"] == 1
    assert document["statements"][0]["status"] == "affected"
