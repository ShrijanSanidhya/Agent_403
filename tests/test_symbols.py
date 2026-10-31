"""Symbol pipeline: validation, static candidates, and cache order."""

from pathlib import Path

from agent403.cache import cache_root, read_json
from agent403.callgraph import Index, Root
from agent403.models import Advisory
from agent403.pypi import DistSource
from agent403.symbols import (
    ChangeSet,
    candidate_symbols,
    public_api,
    resolve_symbols,
)

FIXTURES = Path(__file__).parent / "fixtures"
SITE = FIXTURES / "site"
TARGET = "vulnlib.parser.unsafe_parse"
SAFE = "vulnlib.parser.safe_parse"
CHANGED = "vulnlib.parser._decode"


class FakeLLM:
    def __init__(self, payload: dict[str, object]) -> None:
        self.name = "fake"
        self.backend = "ollama"
        self.payload = payload
        self.calls = 0

    def complete_json(self, system: str, user: str) -> dict[str, object]:
        self.calls += 1
        assert system
        assert user
        return self.payload

    def describe(self) -> dict[str, object]:
        return {"enabled": True, "backend": self.backend, "model": self.name, "available": True}


def _advisory(advisory_id: str = "TEST-0001") -> Advisory:
    return Advisory(
        id=advisory_id,
        aliases=["CVE-0000-0001"],
        summary="Unsafe parsing allows code execution",
        details="details",
        package="vulnlib",
        version="1.0.0",
        fixed_versions=["1.0.1"],
        fix_refs=[],
    )


def _world() -> tuple[Index, DistSource]:
    index = Index.build([Root(SITE, "dep", ["vulnlib"])])
    dist = DistSource("vulnlib", "1.0.0", SITE, ["vulnlib"], [], "local")
    return index, dist


def test_fake_llm_rejects_invented_names() -> None:
    index, dist = _world()
    llm = FakeLLM(
        {
            "vulnerable_symbols": [
                {"symbol": TARGET, "why": "calls the helper"},
                {"symbol": "vulnlib.not_real", "why": "invented"},
            ],
            "safe_symbols": [{"symbol": SAFE, "why": "does not decode"}],
            "confidence": "high",
        }
    )
    result = resolve_symbols(_advisory("LLM-1"), index, dist, llm=llm, refresh=True)
    assert result.source == "llm"
    assert result.symbols == [TARGET]
    assert SAFE in result.safe_symbols
    assert "vulnlib.not_real" in result.rejected
    assert llm.calls == 1


def test_subclass_and_its_caller_are_candidates(tmp_path: Path) -> None:
    package = tmp_path / "lib"
    package.mkdir()
    (package / "__init__.py").write_text("from .api import Child, entry\n", encoding="utf-8")
    (package / "api.py").write_text(
        "class Base:\n"
        "    def changed(self):\n"
        "        return 1\n"
        "\n"
        "\n"
        "class Child(Base):\n"
        "    pass\n"
        "\n"
        "\n"
        "def entry():\n"
        "    return Child()\n"
        "\n"
        "\n"
        "def other():\n"
        "    return 1\n",
        encoding="utf-8",
    )
    index = Index.build([Root(tmp_path, "dep", ["lib"])])
    assert index.subclasses_of("lib.api.Base") == ["lib.api.Child"]
    public = public_api(index, ["lib"])
    found = candidate_symbols(index, ["lib"], ["lib.api.Base.changed"], public)
    assert "lib.api.entry" in found
    assert "lib.api.Child" in found
    assert "lib.api.other" not in found


def test_public_api_ranks_relevant_submodules_first(tmp_path: Path) -> None:
    package = tmp_path / "lib"
    (package / "sandbox").mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "sandbox" / "__init__.py").write_text("", encoding="utf-8")
    (package / "sandbox" / "env.py").write_text(
        "class SandboxedEnvironment:\n    pass\n",
        encoding="utf-8",
    )
    (package / "plain.py").write_text("class Template:\n    pass\n", encoding="utf-8")
    index = Index.build([Root(tmp_path, "dep", ["lib"])])
    ranked = public_api(index, ["lib"], "sandbox escape in the environment")
    assert ranked[0] == "lib.sandbox.env.SandboxedEnvironment"
    assert "lib.plain.Template" in ranked


def test_static_candidates_follow_decode_not_safe_parse() -> None:
    index, _dist = _world()
    public = public_api(index, ["vulnlib"])
    found = candidate_symbols(index, ["vulnlib"], [CHANGED], public)
    assert TARGET in found
    assert SAFE not in found


def test_cache_hit_skips_the_model() -> None:
    index, dist = _world()
    cache_root().mkdir(parents=True, exist_ok=True)
    (cache_root() / "symbols_cache.json").write_text(
        '{"TEST-0001": {"package": "vulnlib", "symbols": ["vulnlib.parser.safe_parse"],'
        ' "safe_symbols": [], "confidence": "high", "generated_by": "manual",'
        ' "generated_at": "2026-11-01T00:00:00+00:00", "reviewed": true, "notes": ""}}\n',
        encoding="utf-8",
    )

    class Boom:
        name = "boom"
        backend = "ollama"

        def complete_json(self, system: str, user: str) -> dict[str, object]:
            raise AssertionError("model should not be called")

        def describe(self) -> dict[str, object]:
            return {}

    result = resolve_symbols(_advisory(), index, dist, llm=Boom(), offline=False)
    assert result.source == "cache"
    assert result.symbols == [SAFE]


def test_refresh_offline_static_and_none(monkeypatch) -> None:
    index, dist = _world()
    payload = {
        "vulnerable_symbols": [{"symbol": TARGET, "why": "entry"}],
        "safe_symbols": [],
        "confidence": "medium",
    }
    llm = FakeLLM(payload)
    (cache_root() / "symbols_cache.json").write_text(
        '{"REFRESH-1": {"package": "vulnlib", "symbols": ["old.symbol"],'
        ' "safe_symbols": [], "confidence": "low", "generated_by": "manual",'
        ' "generated_at": "2026-11-01T00:00:00+00:00", "reviewed": false, "notes": ""}}\n',
        encoding="utf-8",
    )
    refreshed = resolve_symbols(_advisory("REFRESH-1"), index, dist, llm=llm, refresh=True)
    assert refreshed.source == "llm"
    assert refreshed.symbols == [TARGET]
    assert llm.calls == 1

    skipped = FakeLLM(payload)
    missed = resolve_symbols(_advisory("MISSING"), index, dist, llm=skipped, offline=True)
    assert missed.source == "none"
    assert skipped.calls == 0

    def changes(*_args, **_kwargs) -> ChangeSet:
        return ChangeSet(existing=[CHANGED])

    monkeypatch.setattr("agent403.symbols.collect_changes", changes)
    static = resolve_symbols(_advisory("STATIC-1"), index, dist, llm=None, refresh=True)
    assert static.source == "static"
    assert static.confidence == "low"
    assert TARGET in static.symbols
    assert SAFE not in static.symbols
    saved = read_json(cache_root() / "symbols_cache.json")
    assert "STATIC-1" in saved

    def empty(*_args, **_kwargs) -> ChangeSet:
        return ChangeSet()

    monkeypatch.setattr("agent403.symbols.collect_changes", empty)
    nothing = resolve_symbols(_advisory("NONE-1"), index, dist, llm=None, refresh=True)
    assert nothing.source == "none"
    assert "NONE-1" not in read_json(cache_root() / "symbols_cache.json")
