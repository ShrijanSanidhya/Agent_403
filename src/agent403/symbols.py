"""Look up vulnerable symbols from a reviewed cache.

The model and fix-diff parts of this module arrive in a later change. This
version only reads JSON caches and never calls a model.
"""

from pathlib import Path

from agent403.cache import cache_root, read_json, shipped_data_dir
from agent403.models import Advisory, VulnSymbols


def resolve_symbols(
    advisory: Advisory,
    extra_cache_files: tuple[Path, ...] | list[Path] = (),
) -> VulnSymbols:
    """Return cached symbols for an advisory id or alias, or an empty result."""
    for path in _cache_files(extra_cache_files):
        entry = _lookup(path, advisory)
        if entry is not None:
            return _from_entry(entry)
    return VulnSymbols(
        symbols=[],
        safe_symbols=[],
        source="none",
        confidence="low",
        provenance={},
        rejected=[],
    )


def _cache_files(extra_cache_files: tuple[Path, ...] | list[Path]) -> list[Path]:
    files = [cache_root() / "symbols_cache.json"]
    files.extend(Path(path) for path in extra_cache_files)
    shipped = shipped_data_dir() / "symbols_cache.json"
    if shipped.is_file():
        files.append(shipped)
    return files


def _lookup(path: Path, advisory: Advisory) -> dict[str, object] | None:
    if not path.is_file():
        return None
    data = read_json(path)
    if not isinstance(data, dict):
        return None
    for key in (advisory.id, *advisory.aliases):
        entry = data.get(key)
        if isinstance(entry, dict):
            return entry
    return None


def _from_entry(entry: dict[str, object]) -> VulnSymbols:
    confidence = entry.get("confidence")
    return VulnSymbols(
        symbols=_strings(entry.get("symbols")),
        safe_symbols=_strings(entry.get("safe_symbols")),
        source="cache",
        confidence=str(confidence) if confidence else "low",
        provenance={
            "package": entry.get("package") or "",
            "generated_by": entry.get("generated_by") or "",
            "generated_at": entry.get("generated_at") or "",
            "reviewed": bool(entry.get("reviewed")),
            "notes": entry.get("notes") or "",
        },
        rejected=[],
    )


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]
