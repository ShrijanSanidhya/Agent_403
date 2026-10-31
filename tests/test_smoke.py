from pathlib import Path

from typer.testing import CliRunner

from agent403.cli import app
from agent403.models import Advisory, Evidence, Finding, PathHop, Verdict

runner = CliRunner()

FINDING_KEYS = {
    "vuln_id",
    "aliases",
    "package",
    "version",
    "fixed_in",
    "summary",
    "verdict",
    "vulnerable_symbols",
    "evidence",
    "vex_status",
}


def test_version() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "agent403 0.1.0" in result.stdout


def test_scan_missing_path() -> None:
    result = runner.invoke(app, ["scan", "/does/not/exist"])
    assert result.exit_code == 2


def test_scan_directory_not_implemented(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 2
    assert "Reachability analysis not implemented yet" in result.output


def test_scan_offline_lists_pyyaml(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("pyyaml==5.3.1\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(project), "--offline"])
    assert result.exit_code == 2
    assert "CVE-2020-14343" in result.output
    assert "Reachability analysis not implemented yet" in result.output


def test_finding_to_dict_schema() -> None:
    finding = Finding(
        advisory=Advisory(
            id="GHSA-test",
            aliases=["CVE-0000-0000"],
            summary="example",
            details="details",
            package="pyyaml",
            version="5.3.1",
            fixed_versions=["5.4"],
            fix_refs=[],
        ),
        verdict=Verdict.REACHABLE,
        vulnerable_symbols=[{"symbol": "yaml.full_load", "source": "llm", "confidence": "high"}],
        evidence=Evidence(
            paths=[[PathHop(symbol="app.main.load_config", file="app/main.py", line=4)]],
            dynamic_sites=[],
            reasons=["direct call at app/main.py:4"],
        ),
        vex_status="affected",
    )
    data = finding.to_dict()
    assert set(data) == FINDING_KEYS
    assert set(data["evidence"]) == {"paths", "dynamic_sites", "reasons"}
    assert data["verdict"] == "reachable"
    assert data["vex_status"] == "affected"
