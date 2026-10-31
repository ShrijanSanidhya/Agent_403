"""Open-model client: fences, retry, and a live Ollama call when one is running."""

import json

import pytest
import requests

from agent403.callgraph import Index, Root
from agent403.llm import LLMError, _complete_with_retry, from_env, parse_model_json
from agent403.net import HttpClient
from agent403.pypi import fetch
from agent403.symbols import load_advisory, resolve_symbols


def test_fence_stripping_and_retry() -> None:
    assert parse_model_json('```json\n{"a": 1}\n```') == {"a": 1}
    seen: list[str] = []

    def call(user: str) -> str:
        seen.append(user)
        if len(seen) == 1:
            return "not json"
        return '{"ok": true}'

    assert _complete_with_retry(call, "question") == {"ok": True}
    assert seen[1].endswith("Return ONLY valid JSON.")
    with pytest.raises(LLMError):
        parse_model_json("still not json")


def test_from_env_off_and_unreachable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT403_LLM", "off")
    client, warning = from_env(True)
    assert client is None
    assert warning is None

    monkeypatch.setenv("AGENT403_LLM", "on")
    monkeypatch.delenv("AGENT403_LLM_BASE_URL", raising=False)

    def boom(*_args: object, **_kwargs: object) -> None:
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr("agent403.llm.requests.get", boom)
    client, warning = from_env(True)
    assert client is None
    assert warning is not None
    assert warning.startswith("open model not available")


@pytest.mark.llm
@pytest.mark.network
def test_live_ollama_validates_pyyaml_symbols() -> None:
    http = HttpClient()
    advisory = load_advisory("GHSA-8q59-q68h-6hv4", "pyyaml", "5.3.1", http)
    dist = fetch("pyyaml", "5.3.1", http=http)
    index = Index.build([Root(dist.root, "dep", list(dist.import_names))])
    client, warning = from_env(True)
    assert client is not None, warning
    result = resolve_symbols(
        advisory,
        index,
        dist,
        http=http,
        llm=client,
        offline=False,
        refresh=True,
    )
    assert result.source == "llm"
    assert result.symbols
    for name in result.symbols:
        assert name in index.symbols
    assert json.dumps(result.provenance)
