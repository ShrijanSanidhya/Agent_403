"""OpenVEX status, justification, and action mapping."""

from pathlib import Path

from agent403.analyzer import analyze
from agent403.vex import to_vex

FIXTURES = Path(__file__).parent / "fixtures"


def _vex(app: str) -> dict[str, object]:
    result = analyze(
        FIXTURES / "apps" / app,
        offline=True,
        site_dirs=(FIXTURES / "site",),
        osv_dirs=(FIXTURES / "osv",),
        symbol_files=(FIXTURES / "symbols" / "symbols_cache.json",),
    )
    return to_vex(result)


def test_openvex_fields_and_statuses() -> None:
    affected = _vex("direct_call")
    assert affected["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert str(affected["@id"]).startswith("https://openvex.dev/docs/agent403/")
    assert affected["author"] == "agent403"
    assert affected["version"] == 1
    assert affected["timestamp"]
    statement = affected["statements"][0]
    assert statement["status"] == "affected"
    assert statement["vulnerability"]["name"] == "TEST-0001"
    assert "CVE-0000-0001" in statement["vulnerability"]["aliases"]
    assert statement["action_statement"] == "Upgrade vulnlib to 1.0.1 or later"
    product = statement["products"][0]
    assert product["@id"] == "pkg:pypi/direct_call"
    assert product["subcomponents"][0]["@id"] == "pkg:pypi/vulnlib@1.0.0"

    safe = _vex("safe_only")["statements"][0]
    assert safe["status"] == "not_affected"
    assert safe["justification"] == "vulnerable_code_not_in_execute_path"
    assert safe["impact_statement"]

    unsure = _vex("dynamic_getattr")["statements"][0]
    assert unsure["status"] == "under_investigation"
    assert "getattr" in unsure["status_notes"]
