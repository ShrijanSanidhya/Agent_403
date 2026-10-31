from pathlib import Path

import pytest

from agent403.cache import read_json, shipped_data_dir, write_json
from agent403.models import Advisory, Dependency
from agent403.net import HttpClient
from agent403.osv import OsvClient, dedupe, parse_record

FIXTURE = Path(__file__).parent / "fixtures" / "osv" / "osv_cache"


def _dep(name: str = "demo", version: str = "1.0") -> Dependency:
    return Dependency(name, version, True, "")


def test_parse_fix_refs() -> None:
    record = {
        "id": "GHSA-test",
        "aliases": ["CVE-1"],
        "summary": "summary",
        "details": "details",
        "affected": [
            {
                "package": {"name": "Demo_Pkg", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}],
            }
        ],
        "references": [
            {"type": "FIX", "url": "https://example.com/fix"},
            {"type": "WEB", "url": "https://github.com/o/r/commit/abcdef"},
            {"type": "WEB", "url": "https://github.com/o/r/pull/12"},
            {"type": "WEB", "url": "https://example.com/not-a-fix"},
        ],
    }
    advisory = parse_record(record, _dep("demo-pkg", "1.0"))
    assert advisory.package == "demo-pkg"
    assert advisory.fixed_versions == ["2.0"]
    assert advisory.fix_refs == [
        "https://example.com/fix",
        "https://github.com/o/r/commit/abcdef",
        "https://github.com/o/r/pull/12",
    ]


def test_dedupe_prefers_ghsa() -> None:
    pysec = Advisory(
        id="PYSEC-1",
        aliases=["CVE-9"],
        summary="pysec",
        details="short",
        package="demo",
        version="1.0",
        fixed_versions=["1.1"],
        fix_refs=["https://example.com/a"],
    )
    ghsa = Advisory(
        id="GHSA-1",
        aliases=["CVE-9"],
        summary="ghsa",
        details="a much longer explanation",
        package="demo",
        version="1.0",
        fixed_versions=["1.2"],
        fix_refs=["https://example.com/b"],
    )
    merged = dedupe([pysec, ghsa])
    assert len(merged) == 1
    assert merged[0].id == "GHSA-1"
    assert "PYSEC-1" in merged[0].aliases
    assert "CVE-9" in merged[0].aliases
    assert merged[0].details == ghsa.details
    assert merged[0].fixed_versions == ["1.1", "1.2"]
    assert merged[0].fix_refs == ["https://example.com/a", "https://example.com/b"]


def test_withdrawn_is_skipped(tmp_path: Path) -> None:
    cache = tmp_path / "osv_cache"
    (cache / "vulns").mkdir(parents=True)
    write_json(cache / "index.json", {"demo==1.0": ["GONE-1", "TEST-9"]})
    write_json(
        cache / "vulns" / "GONE-1.json",
        {"id": "GONE-1", "withdrawn": "2020-01-01", "aliases": []},
    )
    write_json(
        cache / "vulns" / "TEST-9.json",
        {"id": "TEST-9", "summary": "kept", "aliases": [], "affected": [], "references": []},
    )
    client = OsvClient(HttpClient(offline=True), offline=True, extra_dirs=[cache])
    advisories, warnings = client.fetch_advisories([_dep()])
    assert [item.id for item in advisories] == ["TEST-9"]
    assert warnings == []


def test_offline_fixture_and_missing() -> None:
    client = OsvClient(HttpClient(offline=True), offline=True, extra_dirs=[FIXTURE])
    found, warnings = client.fetch_advisories([_dep("vulnlib", "1.0.0")])
    assert warnings == []
    assert found[0].id == "TEST-0001"
    assert found[0].fixed_versions == ["1.0.1"]
    assert "CVE-0000-0001" in found[0].aliases
    _missing, missing_warnings = client.fetch_advisories([_dep("missing", "9.9.9")])
    assert any("no cached advisory data" in warning for warning in missing_warnings)


def test_recorded_pyyaml_record() -> None:
    folder = shipped_data_dir() / "osv_cache"
    index = read_json(folder / "index.json")
    dep = Dependency("pyyaml", "5.3.1", True, "")
    matched = None
    for vuln_id in index["pyyaml==5.3.1"]:
        record = read_json(folder / "vulns" / f"{vuln_id}.json")
        advisory = parse_record(record, dep)
        if "CVE-2020-14343" in advisory.aliases or advisory.id == "CVE-2020-14343":
            matched = advisory
            break
    assert matched is not None
    assert "5.4" in matched.fixed_versions


def test_offline_shipped_pyyaml() -> None:
    client = OsvClient(HttpClient(offline=True), offline=True)
    advisories, warnings = client.fetch_advisories([Dependency("pyyaml", "5.3.1", True, "")])
    assert not any("no cached advisory data" in warning for warning in warnings)
    assert any(
        "CVE-2020-14343" in advisory.aliases or advisory.id == "CVE-2020-14343"
        for advisory in advisories
    )


@pytest.mark.network
def test_live_osv_pyyaml(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT403_CACHE_DIR", str(tmp_path / "live-cache"))
    advisories, _warnings = OsvClient(HttpClient()).fetch_advisories(
        [Dependency("pyyaml", "5.3.1", True, "")]
    )
    assert any(
        "CVE-2020-14343" in advisory.aliases or advisory.id == "CVE-2020-14343"
        for advisory in advisories
    )
