"""Ask a local open-weight model for JSON. Never calls a closed API."""

import json
import os
import re
from typing import Protocol

import requests

_DEFAULT_MODEL = "qwen2.5-coder:7b"
_RETRY_LINE = "Return ONLY valid JSON."
_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE)


class LLMError(Exception):
    """The model replied, but the reply was not usable JSON."""


class LLM(Protocol):
    """One open-weight backend."""

    name: str
    backend: str

    def complete_json(self, system: str, user: str) -> dict[str, object]:
        """Return one JSON object. Raises LLMError after a single retry."""

    def describe(self) -> dict[str, object]:
        """Report whether this client can be called."""


class OllamaLLM:
    """Ollama /api/chat with JSON mode."""

    def __init__(self, model: str, host: str) -> None:
        self.name = model
        self.backend = "ollama"
        self.host = host.rstrip("/")

    def complete_json(self, system: str, user: str) -> dict[str, object]:
        return _complete_with_retry(lambda text: self._once(system, text), user)

    def describe(self) -> dict[str, object]:
        return _described(True, self.backend, self.name, True)

    def _once(self, system: str, user: str) -> str:
        payload = {
            "model": self.name,
            "stream": False,
            "format": "json",
            "options": {"temperature": 0, "num_ctx": 8192},
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            response = requests.post(f"{self.host}/api/chat", json=payload, timeout=180)
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise LLMError("model request failed") from exc
        message = body.get("message") if isinstance(body, dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LLMError("model request failed")
        return content


class OpenAICompatLLM:
    """An OpenAI-compatible chat server. The key stays in the request header."""

    def __init__(self, model: str, base_url: str, api_key: str | None) -> None:
        self.name = model
        self.backend = "openai-compatible"
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key

    def complete_json(self, system: str, user: str) -> dict[str, object]:
        return _complete_with_retry(lambda text: self._once(system, text), user)

    def describe(self) -> dict[str, object]:
        return _described(True, self.backend, self.name, True)

    def _once(self, system: str, user: str) -> str:
        headers = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        payload = {
            "model": self.name,
            "temperature": 0,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        url = f"{self.base_url}/v1/chat/completions"
        try:
            response = requests.post(url, json=payload, headers=headers, timeout=180)
            response.raise_for_status()
            body = response.json()
        except (requests.RequestException, ValueError) as exc:
            raise LLMError("model request failed") from exc
        choices = body.get("choices") if isinstance(body, dict) else None
        if not isinstance(choices, list) or not choices:
            raise LLMError("model request failed")
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise LLMError("model request failed")
        return content


def from_env(enabled: bool) -> tuple[LLM | None, str | None]:
    """Build a client, or (None, warning) when the open model cannot be used."""
    if not enabled or os.environ.get("AGENT403_LLM", "").lower() == "off":
        return None, None
    model = os.environ.get("AGENT403_MODEL") or _DEFAULT_MODEL
    base = os.environ.get("AGENT403_LLM_BASE_URL")
    if base:
        key = os.environ.get("AGENT403_LLM_API_KEY") or None
        return OpenAICompatLLM(model, base, key), None
    host = os.environ.get("OLLAMA_HOST") or "http://localhost:11434"
    try:
        response = requests.get(f"{host.rstrip('/')}/api/tags", timeout=10)
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError) as exc:
        return None, _unavailable(str(exc))
    names = _listed_models(payload)
    if model not in names:
        return None, _unavailable(f"model {model} is not listed")
    return OllamaLLM(model, host), None


def disabled_status(enabled: bool) -> dict[str, object]:
    """describe() shape used when no client was created."""
    model = os.environ.get("AGENT403_MODEL") or _DEFAULT_MODEL
    return _described(enabled, None, model, False)


def parse_model_json(text: str) -> dict[str, object]:
    """Strip a markdown fence and parse one JSON object."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = _FENCE.sub("", cleaned).strip()
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError as exc:
        raise LLMError("model did not return JSON") from exc
    if not isinstance(data, dict):
        raise LLMError("model did not return a JSON object")
    return data


def _complete_with_retry(call, user: str) -> dict[str, object]:
    try:
        return parse_model_json(call(user))
    except LLMError:
        return parse_model_json(call(f"{user}\n{_RETRY_LINE}"))


def _listed_models(payload: object) -> set[str]:
    names: set[str] = set()
    models = payload.get("models") if isinstance(payload, dict) else None
    if not isinstance(models, list):
        return names
    for item in models:
        if not isinstance(item, dict):
            continue
        for key in ("name", "model"):
            value = item.get(key)
            if isinstance(value, str) and value:
                names.add(value)
    return names


def _unavailable(reason: str) -> str:
    return f"open model not available ({reason}); using static analysis fallback"


def _described(
    enabled: bool,
    backend: str | None,
    model: str,
    available: bool,
) -> dict[str, object]:
    return {"enabled": enabled, "backend": backend, "model": model, "available": available}
