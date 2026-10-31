"""HTTP helper with a short timeout and a few retries."""

import time

import requests

from agent403 import __version__


class OfflineError(Exception):
    """Raised when a network call is attempted in offline mode."""


class HttpClient:
    """Small wrapper around requests.Session."""

    def __init__(self, offline: bool = False, timeout: float = 20.0) -> None:
        self.offline = offline
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"agent403/{__version__}"

    def get_json(self, url: str) -> object:
        return self._request("GET", url).json()

    def post_json(self, url: str, payload: object) -> object:
        return self._request("POST", url, json_body=payload).json()

    def get_bytes(self, url: str) -> bytes:
        return self._request("GET", url).content

    def get_text(self, url: str) -> str:
        return self._request("GET", url).text

    def _request(
        self,
        method: str,
        url: str,
        json_body: object | None = None,
    ) -> requests.Response:
        if self.offline:
            raise OfflineError("offline mode: network is disabled")
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = self.session.request(
                    method,
                    url,
                    json=json_body,
                    timeout=self.timeout,
                )
            except (requests.ConnectionError, requests.Timeout) as exc:
                last_error = exc
                if attempt < 2:
                    time.sleep(0.2 * (attempt + 1))
                    continue
                raise
            if response.status_code >= 500 and attempt < 2:
                time.sleep(0.2 * (attempt + 1))
                continue
            response.raise_for_status()
            return response
        if last_error is not None:
            raise last_error
        raise requests.RequestException(f"request failed: {url}")
