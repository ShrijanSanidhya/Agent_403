import pytest


@pytest.fixture(autouse=True)
def isolated_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT403_CACHE_DIR", str(tmp_path / "cache"))
