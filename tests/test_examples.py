"""Re-run the shipped examples and compare verdicts with the saved reports."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
EXAMPLES = ROOT / "examples"
NAMES = [
    "pyyaml_reachable",
    "pyyaml_safe",
    "pyyaml_dynamic",
    "jinja2_sandbox",
    "jinja2_plain",
]


def _verdicts(payload: dict[str, object]) -> list[tuple[str, str]]:
    findings = payload["findings"]
    assert isinstance(findings, list)
    rows: list[tuple[str, str]] = []
    for finding in findings:
        assert isinstance(finding, dict)
        rows.append((str(finding["vuln_id"]), str(finding["verdict"])))
    return rows


@pytest.mark.network
@pytest.mark.parametrize("name", NAMES)
def test_example_verdicts_match_the_saved_report(name: str, tmp_path: Path) -> None:
    saved = json.loads((EXAMPLES / name / "report.json").read_text(encoding="utf-8"))
    output = tmp_path / "report.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "agent403",
            "scan",
            str(EXAMPLES / name),
            "--json-out",
            str(output),
            "--no-llm",
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert output.is_file(), result.stderr
    fresh = json.loads(output.read_text(encoding="utf-8"))
    assert _verdicts(fresh) == _verdicts(saved)
