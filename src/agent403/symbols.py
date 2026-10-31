"""Decide which public symbols of a package are vulnerable for an advisory.

Cache first. Then a fix diff, then static candidates, then an open-weight model.
Every model answer is checked against the real index. Invented names are rejected.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

from agent403.cache import cache_root, read_json, shipped_data_dir, write_json
from agent403.callgraph import Index
from agent403.fixdiff import (
    changed_functions,
    fetch_diff,
    fetch_new_source,
    github_diff_urls,
    map_to_module,
    parse_unified_diff,
)
from agent403.llm import LLM, LLMError
from agent403.models import Advisory, Dependency, VulnSymbols
from agent403.net import HttpClient, OfflineError
from agent403.osv import parse_record
from agent403.pypi import DistSource

SYSTEM_PROMPT = (
    "You are a Python security engineer. You identify which PUBLIC functions or classes "
    "of a library a user must call to trigger a vulnerability. "
    "If the advisory is an escape from a protective wrapper, that wrapper and its subclasses "
    "are vulnerable entry points, not safe alternatives. Answer with JSON only."
)
_PROMPT_PUBLIC = 40
_MAX_CANDIDATES = 60
_MAX_DEPTH = 6
_MAX_DETAILS = 3000
_MAX_DIFF = 5000
_MAX_PUBLIC = 300
_SKIP_MODULES = {"tests", "test", "compat", "vendored"}


@dataclass
class ChangeSet:
    """Functions touched by the fix, and the diff text shown to the model."""

    existing: list[str] = field(default_factory=list)
    context: list[str] = field(default_factory=list)
    diff_text: str = ""
    fix_refs_used: list[str] = field(default_factory=list)


def load_advisory(advisory_id: str, name: str, version: str, http: HttpClient) -> Advisory:
    """Load one OSV record from the cache, or download it."""
    dep = Dependency(name, version, True, "")
    folders = (cache_root() / "osv_cache", shipped_data_dir() / "osv_cache")
    for folder in folders:
        path = folder / "vulns" / f"{advisory_id}.json"
        if not path.is_file():
            continue
        record = read_json(path)
        if isinstance(record, dict):
            return parse_record(record, dep)
    record = http.get_json(f"https://api.osv.dev/v1/vulns/{advisory_id}")
    if not isinstance(record, dict):
        raise OSError(f"advisory {advisory_id} was not found")
    return parse_record(record, dep)


def resolve_symbols(
    advisory: Advisory,
    index: Index | None = None,
    dist: DistSource | None = None,
    *,
    http: HttpClient | None = None,
    llm: LLM | None = None,
    offline: bool = False,
    refresh: bool = False,
    extra_cache_files: tuple[Path, ...] | list[Path] = (),
) -> VulnSymbols:
    """Return vulnerable symbols for one advisory. Offline never calls a model."""
    if not refresh:
        cached = _read_cache(advisory, extra_cache_files)
        if cached is not None:
            return cached
    if index is None or dist is None or offline:
        return _none()
    changes = collect_changes(advisory, index, dist, http)
    imports = list(dist.import_names)
    text = f"{advisory.summary}\n{advisory.details}"
    public = public_api(index, imports, text)
    candidates = candidate_symbols(index, imports, changes.existing, public, text)
    if llm is not None:
        try:
            chosen = _ask_model(llm, advisory, dist, changes, candidates, public, index)
        except LLMError:
            chosen = None
        if chosen is not None:
            result = _validated(advisory, index, imports, chosen, changes, candidates, public, llm)
            if result.symbols:
                _save(advisory, result)
                return result
    if candidates:
        result = _static_result(advisory, candidates, changes, public)
        _save(advisory, result)
        return result
    missed = _none()
    missed.provenance = _provenance(advisory, changes, candidates, public, "", "", [], [])
    return missed


def collect_changes(
    advisory: Advisory,
    index: Index,
    dist: DistSource,
    http: HttpClient | None,
) -> ChangeSet:
    """Download fix diffs and map touched functions onto this package version."""
    urls = github_diff_urls(advisory.fix_refs)
    if http is None or not urls:
        return ChangeSet()
    existing: list[str] = []
    context: list[str] = []
    excerpts: list[str] = []
    used: list[str] = []
    for url in urls:
        try:
            text = fetch_diff(http, url)
        except (OfflineError, requests.RequestException, OSError):
            continue
        used.append(url)
        excerpts.append(text)
        for change in parse_unified_diff(text):
            source = fetch_new_source(http, url, change.path)
            local_names = changed_functions(change, source)
            module = map_to_module(change.path, index, list(dist.import_names))
            for name in local_names:
                bound = _bind_name(index, module, name) if module else []
                if bound:
                    for canonical in bound:
                        if canonical not in existing:
                            existing.append(canonical)
                    continue
                qual = f"{module}.{name}" if module else name
                if qual not in context:
                    context.append(qual)
    return ChangeSet(existing, context, "\n".join(excerpts), used)


def public_api(index: Index, import_names: list[str], text: str = "") -> list[str]:
    """Public names of the package, relevance to the advisory first."""
    names: list[str] = []
    for root in import_names:
        info = index.modules.get(root)
        if info is None:
            continue
        exported = list(info.all_names or [])
        exported.extend(name for name in info.defs if not name.startswith("_"))
        exported.extend(name for name in info.aliases if not name.startswith("_"))
        for name in exported:
            if name.startswith("_") or name in {"__all__"}:
                continue
            target = info.aliases.get(name, f"{root}.{name}")
            canonical = index.canonical(target)
            if canonical not in names and not _leaf(canonical).startswith("_"):
                names.append(canonical)
    for module, info in index.modules.items():
        if not _under(module, import_names) or not _public_module(module, info.file):
            continue
        for name in sorted(info.defs):
            if name.startswith("_"):
                continue
            qual = f"{module}.{name}"
            symbol = index.symbols.get(qual)
            if symbol is None or symbol.kind not in {"class", "function"}:
                continue
            if qual not in names:
                names.append(qual)
    return _rank(names, text, import_names)[:_MAX_PUBLIC]


def candidate_symbols(
    index: Index,
    import_names: list[str],
    changed: list[str],
    public: list[str],
    text: str = "",
) -> list[str]:
    """Public symbols that can reach a changed function or an affected class."""
    affected = _affected_classes(index, changed)
    targets = set(changed) | affected
    found: list[str] = []
    for name in public:
        seeds = _seeds(index, name)
        if any(_reaches(index, seed, targets, import_names) for seed in seeds):
            _add(found, name)
    for name in changed:
        if name in public:
            _add(found, name)
        owner = name.rsplit(".", 1)[0]
        symbol = index.symbols.get(owner)
        if symbol is not None and symbol.kind == "class" and not _leaf(owner).startswith("_"):
            _add(found, owner)
    for name in sorted(affected):
        _add(found, name)
    return _rank(found, text, import_names)[:_MAX_CANDIDATES]


def _affected_classes(index: Index, changed: list[str]) -> set[str]:
    """Classes that own a changed method, plus every subclass of those classes."""
    owners: set[str] = set()
    for name in changed:
        owner = name.rsplit(".", 1)[0]
        symbol = index.symbols.get(owner)
        if symbol is not None and symbol.kind == "class":
            owners.add(owner)
        if index.symbols.get(name) is not None and index.symbols[name].kind == "class":
            owners.add(name)
    affected: set[str] = set()
    for owner in owners:
        if not _leaf(owner).startswith("_"):
            affected.add(owner)
        for child in index.subclasses_of(owner):
            if not _leaf(child).startswith("_"):
                affected.add(child)
    return affected


def _seeds(index: Index, name: str) -> list[str]:
    seeds = [name]
    symbol = index.symbols.get(name)
    if symbol is not None and symbol.kind == "class":
        prefix = f"{name}."
        seeds.extend(sorted(qual for qual in index.symbols if qual.startswith(prefix)))
    return seeds


def _reaches(index: Index, start: str, targets: set[str], import_names: list[str]) -> bool:
    if start in targets:
        return True
    seen = {start}
    frontier = [start]
    for _depth in range(_MAX_DEPTH):
        nxt: list[str] = []
        for node in frontier:
            for edge in index.edges.get(node, []):
                if edge.dst in seen or not _under(edge.dst, import_names):
                    continue
                if edge.dst in targets:
                    return True
                seen.add(edge.dst)
                nxt.append(edge.dst)
        if not nxt:
            break
        frontier = nxt
    return False


def _ask_model(
    llm: LLM,
    advisory: Advisory,
    dist: DistSource,
    changes: ChangeSet,
    candidates: list[str],
    public: list[str],
    index: Index,
) -> dict[str, object]:
    user = _user_prompt(advisory, dist, changes, candidates, public, index)
    return llm.complete_json(SYSTEM_PROMPT, user)


def _user_prompt(
    advisory: Advisory,
    dist: DistSource,
    changes: ChangeSet,
    candidates: list[str],
    public: list[str],
    index: Index,
) -> str:
    changed = [*changes.existing, *changes.context]
    details = advisory.details[:_MAX_DETAILS]
    diff = changes.diff_text[:_MAX_DIFF]
    roots = list(dist.import_names)
    focus = ", ".join(_focus_words(advisory.summary, advisory.details, roots))
    shown = public[:_PROMPT_PUBLIC]
    summary_classes = _summary_classes(index, public, advisory.summary, roots)
    lines = [
        f"advisory: {advisory.id}",
        f"aliases: {', '.join(advisory.aliases)}",
        f"package: {dist.name}=={dist.version}",
        f"summary: {advisory.summary}",
        f"focus words: {focus}",
        *(
            [
                "These classes match the summary and are vulnerable entry points:",
                *[f"- {name}" for name in summary_classes],
            ]
            if summary_classes
            else []
        ),
        *(
            ["Every class in that list is vulnerable. Do not put any of them in safe_symbols."]
            if summary_classes
            else []
        ),
        "Rules: choose ONLY names from the candidate or public API lists.",
        "Prefer symbols whose names contain a focus word.",
        "Choose library entry points a user calls, not builtins such as str.format.",
        "If the advisory is an escape from a protective wrapper, that wrapper is vulnerable.",
        "Do not put that wrapper, or a subclass of it, in safe_symbols.",
        "Do not choose a symbol only because untrusted data could be passed to it.",
        "A line like 'Name (subclass of Base)' means Name inherits Base's changed behavior.",
        "If a class is vulnerable, its subclasses are vulnerable too",
        "unless the diff shows they override that behavior.",
        "Do not list a subclass of a vulnerable class as a safe alternative.",
        "Prefer the functions and classes a user calls.",
        "List safe alternatives the user should call instead.",
        'If unsure set confidence to "low".',
        f"details: {details}",
        f"fixed versions: {', '.join(advisory.fixed_versions)}",
        "functions changed by the fix:",
        *([f"- {name}" for name in changed] or ["- none"]),
        "diff excerpt:",
        diff or "(no diff available)",
        "static candidates (prefer these entry points):",
        *([_candidate_line(index, name) for name in candidates] or ["- none"]),
        f"public API, most relevant first ({len(shown)} of {len(public)}):",
        *([_candidate_line(index, name) for name in shown] or ["- none"]),
        'Return {"vulnerable_symbols":[{"symbol":"...","why":"..."}],'
        '"safe_symbols":[{"symbol":"...","why":"..."}],'
        '"confidence":"high|medium|low"}',
    ]
    return "\n".join(lines)


def _validated(
    advisory: Advisory,
    index: Index,
    import_names: list[str],
    payload: dict[str, object],
    changes: ChangeSet,
    candidates: list[str],
    public: list[str],
    llm: LLM,
) -> VulnSymbols:
    kept: list[str] = []
    safe: list[str] = []
    rejected: list[str] = []
    why: list[dict[str, str]] = []
    for symbol, reason in _items(payload.get("vulnerable_symbols")):
        accepted = _accept(symbol, index, import_names)
        if accepted is None:
            rejected.append(symbol)
            continue
        if accepted not in kept:
            kept.append(accepted)
            why.append({"symbol": accepted, "why": reason, "role": "vulnerable"})
    summary_classes = set(
        _summary_classes(index, [*candidates, *public], advisory.summary, import_names)
    )
    for symbol, reason in _items(payload.get("safe_symbols")):
        accepted = _accept(symbol, index, import_names)
        if accepted is None:
            rejected.append(symbol)
            continue
        if accepted in summary_classes:
            if accepted not in kept:
                kept.append(accepted)
                why.append({"symbol": accepted, "why": reason, "role": "vulnerable"})
            continue
        if accepted not in safe:
            safe.append(accepted)
            why.append({"symbol": accepted, "why": reason, "role": "safe"})
    return VulnSymbols(
        symbols=kept,
        safe_symbols=safe,
        source="llm",
        confidence=_confidence(payload.get("confidence")),
        provenance=_provenance(
            advisory, changes, candidates, public, llm.name, llm.backend, why, rejected
        ),
        rejected=rejected,
    )


def _static_result(
    advisory: Advisory,
    candidates: list[str],
    changes: ChangeSet,
    public: list[str],
) -> VulnSymbols:
    return VulnSymbols(
        symbols=list(candidates),
        safe_symbols=[],
        source="static",
        confidence="low",
        provenance=_provenance(advisory, changes, candidates, public, "static", "", [], []),
        rejected=[],
    )


def _bind_name(index: Index, module: str, local: str) -> list[str]:
    """Map a diff name onto symbols that exist in this module."""
    direct = index.canonical(f"{module}.{local}")
    if direct in index.symbols:
        return [direct]
    leaf = local.rsplit(".", 1)[-1]
    prefix = f"{module}."
    return sorted(
        name
        for name in index.symbols
        if name.startswith(prefix) and name.rsplit(".", 1)[-1] == leaf
    )


def _accept(name: str, index: Index, import_names: list[str]) -> str | None:
    canonical = index.canonical(name)
    symbol = index.symbols.get(canonical)
    if symbol is None:
        return None
    module = index.module_of(canonical) or canonical
    if _under(module, import_names) or _under(canonical, import_names):
        return canonical
    return None


def _items(value: object) -> list[tuple[str, str]]:
    if not isinstance(value, list):
        return []
    found: list[tuple[str, str]] = []
    for item in value:
        if isinstance(item, str):
            found.append((item, ""))
        elif isinstance(item, dict) and isinstance(item.get("symbol"), str):
            why = item.get("why")
            found.append((item["symbol"], str(why) if why else ""))
    return found


def _provenance(
    advisory: Advisory,
    changes: ChangeSet,
    candidates: list[str],
    public: list[str],
    generated_by: str,
    backend: str,
    why: list[dict[str, str]],
    rejected: list[str],
) -> dict[str, object]:
    payload = {
        "id": advisory.id,
        "package": advisory.package,
        "version": advisory.version,
        "fix_refs": list(changes.fix_refs_used),
        "candidates": list(candidates),
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {
        "package": advisory.package,
        "generated_by": generated_by,
        "backend": backend,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "inputs_sha256": digest,
        "fix_refs_used": list(changes.fix_refs_used),
        "changed": list(changes.existing),
        "context": list(changes.context),
        "candidates": list(candidates),
        "public": list(public),
        "why": why,
        "rejected": list(rejected),
        "reviewed": False,
        "notes": "",
    }


def _save(advisory: Advisory, result: VulnSymbols) -> None:
    if result.source == "none":
        return
    path = cache_root() / "symbols_cache.json"
    data = read_json(path) if path.is_file() else {}
    if not isinstance(data, dict):
        data = {}
    data[advisory.id] = {
        "package": advisory.package,
        "symbols": list(result.symbols),
        "safe_symbols": list(result.safe_symbols),
        "confidence": result.confidence,
        "generated_by": result.provenance.get("generated_by") or result.source,
        "generated_at": result.provenance.get("generated_at") or "",
        "reviewed": False,
        "notes": result.provenance.get("notes") or "",
        "backend": result.provenance.get("backend") or "",
        "inputs_sha256": result.provenance.get("inputs_sha256") or "",
        "fix_refs_used": result.provenance.get("fix_refs_used") or [],
        "changed": result.provenance.get("changed") or [],
        "context": result.provenance.get("context") or [],
        "candidates": result.provenance.get("candidates") or [],
        "public": result.provenance.get("public") or [],
        "why": result.provenance.get("why") or [],
        "rejected": list(result.rejected),
    }
    write_json(path, data)


def _read_cache(
    advisory: Advisory,
    extra_cache_files: tuple[Path, ...] | list[Path],
) -> VulnSymbols | None:
    for path in _cache_files(extra_cache_files):
        entry = _lookup(path, advisory)
        if entry is not None:
            return _from_entry(entry)
    return None


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
    rejected = _strings(entry.get("rejected"))
    return VulnSymbols(
        symbols=_strings(entry.get("symbols")),
        safe_symbols=_strings(entry.get("safe_symbols")),
        source="cache",
        confidence=str(confidence) if confidence else "low",
        provenance={
            "package": entry.get("package") or "",
            "generated_by": entry.get("generated_by") or "",
            "backend": entry.get("backend") or "",
            "generated_at": entry.get("generated_at") or "",
            "reviewed": bool(entry.get("reviewed")),
            "notes": entry.get("notes") or "",
            "inputs_sha256": entry.get("inputs_sha256") or "",
            "fix_refs_used": entry.get("fix_refs_used") or [],
            "changed": entry.get("changed") or [],
            "context": entry.get("context") or [],
            "candidates": entry.get("candidates") or [],
            "public": entry.get("public") or [],
            "why": entry.get("why") or [],
            "rejected": rejected,
        },
        rejected=rejected,
    )


def _none() -> VulnSymbols:
    return VulnSymbols([], [], "none", "low", {}, [])


def _strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _confidence(value: object) -> str:
    text = str(value or "").lower()
    if text in {"high", "medium", "low"}:
        return text
    return "low"


def _add(found: list[str], name: str) -> None:
    if name not in found and not _leaf(name).startswith("_"):
        found.append(name)


def _leaf(name: str) -> str:
    return name.rsplit(".", 1)[-1]


def _candidate_line(index: Index, name: str) -> str:
    symbol = index.symbols.get(name)
    bases = index.class_bases.get(name) or []
    if symbol is None or symbol.kind != "class" or not bases:
        return f"- {name}"
    return f"- {name} (subclass of {', '.join(bases)})"


def _public_module(module: str, file: str) -> bool:
    parts = module.split(".")
    if any(part.startswith("_") or part in _SKIP_MODULES for part in parts):
        return False
    text = file.replace("\\", "/")
    markers = ("tests/", "compat/", "vendored/")
    return not any(marker in f"/{text}" for marker in markers)


def _rank(names: list[str], text: str, roots: list[str] | None = None) -> list[str]:
    ignore: set[str] = set()
    for root in roots or []:
        ignore.add(root.lower())
        ignore.update(_name_parts(root))
    words = _words(text) - ignore

    def key(name: str) -> tuple[int, str]:
        return (0 if _relevant(name, words) else 1, name)

    return sorted(names, key=key)


_STOP_WORDS = {
    "about",
    "after",
    "allows",
    "before",
    "code",
    "could",
    "detail",
    "from",
    "have",
    "however",
    "input",
    "issue",
    "method",
    "other",
    "python",
    "release",
    "string",
    "that",
    "their",
    "there",
    "these",
    "this",
    "used",
    "user",
    "using",
    "when",
    "which",
    "with",
}


def _summary_classes(index: Index, public: list[str], summary: str, roots: list[str]) -> list[str]:
    """Public classes whose names contain a word from the advisory summary."""
    ignore: set[str] = set()
    for root in roots:
        ignore.add(root.lower())
        ignore.update(_name_parts(root))
    words = _words(summary) - ignore
    found: list[str] = []
    for name in public:
        symbol = index.symbols.get(name)
        if symbol is None or symbol.kind != "class" or not _relevant(name, words):
            continue
        if name not in found:
            found.append(name)
    return found[:8]


def _focus_words(summary: str, details: str, roots: list[str]) -> list[str]:
    ignore = set()
    for root in roots:
        ignore.add(root.lower())
        ignore.update(_name_parts(root))
    summary_words = _words(summary) - ignore
    detail_words = _words(details) - ignore

    def order(word: str) -> tuple[int, int, str]:
        return (0 if "_" in word else 1, -len(word), word)

    first = sorted(summary_words, key=order)
    rest = sorted(detail_words - summary_words, key=order)
    return [*first, *rest][:8]


def _words(text: str) -> set[str]:
    """Advisory words worth matching. Identifiers count; common English does not."""
    found: set[str] = set()
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
        lower = token.lower()
        if "_" in token:
            found.add(lower)
            found.update(part for part in lower.split("_") if len(part) >= 4)
            continue
        if len(lower) >= 4 and lower not in _STOP_WORDS:
            found.add(lower)
    return found


def _name_parts(name: str) -> list[str]:
    parts: list[str] = []
    for token in name.replace(".", "_").split("_"):
        parts.extend(re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+", token))
    return [part.lower() for part in parts if part]


def _relevant(name: str, words: set[str]) -> bool:
    parts = _name_parts(name)
    for word in words:
        for part in parts:
            if part == word:
                return True
            rest = part[len(word) :]
            if part.startswith(word) and rest in {"s", "es", "ed", "er", "ing"}:
                return True
    return False


def _under(name: str, roots: list[str]) -> bool:
    return any(name == root or name.startswith(root + ".") for root in roots)
