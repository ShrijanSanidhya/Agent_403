"""Read and write the on-disk cache under the user cache directory."""

import importlib.resources
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def cache_root() -> Path:
    """Return the cache directory, creating it if needed."""
    override = os.environ.get("AGENT403_CACHE_DIR")
    root = Path(override) if override else Path.home() / ".cache" / "agent403"
    root.mkdir(parents=True, exist_ok=True)
    return root


def read_json(path: Path) -> Any:
    """Load a JSON file."""
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def write_json(path: Path, data: Any) -> None:
    """Write JSON atomically via a temp file in the same directory."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, indent=2)
            handle.write("\n")
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def shipped_data_dir() -> Path:
    """Return the packaged data directory (agent403/data)."""
    resource = importlib.resources.files("agent403").joinpath("data")
    return Path(str(resource))
