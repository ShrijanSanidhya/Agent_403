"""Turn a call graph and a symbol list into a reachability verdict."""

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import requests

from agent403.callgraph import (
    DynamicSite,
    Index,
    ParseError,
    Root,
    UnresolvedCall,
    find_path,
)
from agent403.deps import load_dependencies
from agent403.llm import LLM, disabled_status, from_env
from agent403.models import Advisory, Dependency, Evidence, Finding, PathHop, Verdict, VulnSymbols
from agent403.net import HttpClient, OfflineError
from agent403.osv import OsvClient
from agent403.pypi import DigestMismatchError, DistSource, UnsafeArchiveError, fetch
from agent403.symbols import resolve_symbols

_VEX = {
    Verdict.REACHABLE: "affected",
    Verdict.NOT_AFFECTED: "not_affected",
    Verdict.UNCERTAIN: "under_investigation",
}


@dataclass
class ScanResult:
    """One scan of a project directory."""

    project: Path
    generated_at: str
    dependencies: list[Dependency]
    findings: list[Finding]
    warnings: list[str] = field(default_factory=list)
    llm: dict[str, object] = field(default_factory=lambda: {"enabled": False})


def analyze(
    project: Path,
    *,
    requirements: Path | None = None,
    offline: bool = False,
    site_dirs: tuple[Path, ...] | list[Path] = (),
    osv_dirs: tuple[Path, ...] | list[Path] = (),
    symbol_files: tuple[Path, ...] | list[Path] = (),
    include_tests: bool = False,
    use_llm: bool = False,
    refresh_symbols: bool = False,
) -> ScanResult:
    """Scan a project. Offline scans never call a model."""
    dependencies, warnings = load_dependencies(project, requirements)
    http = HttpClient(offline=offline)
    llm = None
    if use_llm and not offline:
        llm, llm_warning = from_env(True)
        if llm_warning:
            warnings.append(llm_warning)
        status = llm.describe() if llm is not None else disabled_status(True)
    else:
        status = disabled_status(False)
    client = OsvClient(http, offline=offline, extra_dirs=_osv_dirs(osv_dirs))
    advisories, osv_warnings = client.fetch_advisories(dependencies)
    warnings.extend(osv_warnings)
    sources, failures = _fetch_sources(dependencies, offline, site_dirs, warnings)
    findings = _findings(
        project,
        advisories,
        sources,
        failures,
        symbol_files,
        include_tests,
        http,
        llm,
        offline,
        refresh_symbols,
    )
    return ScanResult(
        project=project,
        generated_at=datetime.now(timezone.utc).isoformat(),
        dependencies=dependencies,
        findings=findings,
        warnings=warnings,
        llm=status,
    )


def _osv_dirs(paths: tuple[Path, ...] | list[Path]) -> list[Path]:
    """Accept either an OSV cache directory or a parent that contains osv_cache/."""
    resolved: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if (path / "index.json").is_file():
            resolved.append(path)
        elif (path / "osv_cache" / "index.json").is_file():
            resolved.append(path / "osv_cache")
        else:
            resolved.append(path)
    return resolved


def _fetch_sources(
    dependencies: list[Dependency],
    offline: bool,
    site_dirs: tuple[Path, ...] | list[Path],
    warnings: list[str],
) -> tuple[dict[str, DistSource], dict[str, str]]:
    sources: dict[str, DistSource] = {}
    failures: dict[str, str] = {}
    sites = [Path(path) for path in site_dirs]
    for dep in dependencies:
        if not dep.pinned or not dep.version:
            continue
        try:
            sources[dep.name] = fetch(dep.name, dep.version, offline=offline, sites=sites)
        except (
            OfflineError,
            requests.RequestException,
            OSError,
            UnsafeArchiveError,
            DigestMismatchError,
        ) as exc:
            failures[dep.name] = str(exc)
            warnings.append(f"could not read {dep.name}=={dep.version}: {exc}")
    return sources, failures


def _findings(
    project: Path,
    advisories: list[Advisory],
    sources: dict[str, DistSource],
    failures: dict[str, str],
    symbol_files: tuple[Path, ...] | list[Path],
    include_tests: bool,
    http: HttpClient,
    llm: LLM | None,
    offline: bool,
    refresh_symbols: bool,
) -> list[Finding]:
    grouped: dict[str, list[Advisory]] = {}
    for advisory in advisories:
        grouped.setdefault(advisory.package, []).append(advisory)
    indexes: dict[str, Index] = {}
    findings: list[Finding] = []
    for package, package_advisories in grouped.items():
        dist = sources.get(package)
        if dist is None:
            reason = failures.get(package, f"could not read {package}")
            for advisory in package_advisories:
                findings.append(
                    _unscanned(advisory, reason, symbol_files, offline, refresh_symbols)
                )
            continue
        index = indexes.get(package)
        if index is None:
            index = _build_index(project, package, sources, include_tests)
            indexes[package] = index
        blocked = _other_failures(package, failures)
        for advisory in package_advisories:
            finding = _judge(
                advisory,
                index,
                dist,
                sources,
                symbol_files,
                http,
                llm,
                offline,
                refresh_symbols,
            )
            if finding.verdict == Verdict.NOT_AFFECTED and blocked:
                finding = _replace(finding, Verdict.UNCERTAIN, [blocked])
            findings.append(finding)
    return findings


def _other_failures(package: str, failures: dict[str, str]) -> str | None:
    others = [
        f"could not read {name}: {message}"
        for name, message in sorted(failures.items())
        if name != package
    ]
    if not others:
        return None
    return f"{others[0]}; an intermediate dependency may be missing"


def _build_index(
    project: Path,
    package: str,
    sources: dict[str, DistSource],
    include_tests: bool,
) -> Index:
    roots = [Root(project, "app")]
    dist = sources[package]
    roots.append(Root(dist.root, "dep", list(dist.import_names)))
    for name in _intermediates(package, sources):
        other = sources[name]
        roots.append(Root(other.root, "dep", list(other.import_names)))
    return Index.build(roots, include_tests=include_tests)


def _intermediates(package: str, sources: dict[str, DistSource]) -> list[str]:
    """Pinned deps that require package, directly or through other fetched deps."""
    reverse: dict[str, list[str]] = {}
    for name, dist in sources.items():
        for required in dist.requires_dist:
            reverse.setdefault(required, []).append(name)
    found: list[str] = []
    seen: set[str] = set()
    queue = [package]
    while queue:
        current = queue.pop()
        for parent in reverse.get(current, []):
            if parent == package or parent in seen or parent not in sources:
                continue
            seen.add(parent)
            found.append(parent)
            queue.append(parent)
    return sorted(found)


def _entry_points(index: Index) -> list[str]:
    """App module bodies, and app functions nothing else in the app calls."""
    app = set(index.app_functions())
    incoming: set[str] = set()
    for src, edges in index.edges.items():
        if src not in app:
            continue
        for edge in edges:
            if edge.dst in app and edge.dst != src:
                incoming.add(edge.dst)
    return sorted(name for name in app if name.endswith(".<module>") or name not in incoming)


def _first_path(index: Index, is_target, can_enter):
    """Prefer a path from an entry point. Fall back to every app function."""
    path = find_path(index, _entry_points(index), is_target, can_enter)
    if path is not None:
        return path
    return find_path(index, index.app_functions(), is_target, can_enter)


def _judge(
    advisory: Advisory,
    index: Index,
    dist: DistSource,
    sources: dict[str, DistSource],
    symbol_files: tuple[Path, ...] | list[Path],
    http: HttpClient,
    llm: LLM | None,
    offline: bool,
    refresh_symbols: bool,
) -> Finding:
    resolved = resolve_symbols(
        advisory,
        index,
        dist,
        http=http,
        llm=llm,
        offline=offline,
        refresh=refresh_symbols,
        extra_cache_files=symbol_files,
    )
    names = _canonical(index, resolved)
    listed = _listed(names, resolved)
    rejected = list(resolved.rejected)
    explanations = _explanations(resolved)
    imports = list(dist.import_names)
    intermediates = _import_names(_intermediates(advisory.package, sources), sources)
    targets, via_subclass = _with_subclasses(index, names, imports)

    def is_target(name: str) -> bool:
        return any(name == symbol or name.startswith(symbol + ".") for symbol in targets)

    def can_enter(name: str) -> bool:
        return not _inside(name, imports)

    if names:
        path = _first_path(index, is_target, can_enter)
        if path is not None:
            shown = " -> ".join(hop.symbol for hop in path)
            reasons = [f"call path found: {shown}"]
            note = _subclass_note(path[-1].symbol, via_subclass)
            if note:
                reasons.append(note)
            return _make(
                advisory,
                Verdict.REACHABLE,
                listed,
                reasons,
                paths=[path],
                rejected=rejected,
                explanations=explanations,
            )

    referenced = _references(index, imports, intermediates)
    if resolved.source == "none":
        if referenced:
            reason = "vulnerable functions for this advisory are unknown"
            return _make(
                advisory,
                Verdict.UNCERTAIN,
                listed,
                [reason],
                rejected=rejected,
                explanations=explanations,
            )
        return _make(
            advisory,
            Verdict.NOT_AFFECTED,
            listed,
            ["package is never imported by the project"],
            rejected=rejected,
            explanations=explanations,
        )

    reached = _reachable(index, can_enter)
    dynamic = _dynamic(index, reached, imports)
    if dynamic:
        reasons = [f"dynamic {site.kind} at {site.file}:{site.line}" for site in dynamic]
        return _make(
            advisory,
            Verdict.UNCERTAIN,
            listed,
            reasons,
            dynamic=dynamic,
            rejected=rejected,
            explanations=explanations,
        )

    unresolved = _unresolved(index, reached, names)
    if unresolved:
        reasons = [
            f"unresolved call {call.method_name} at {call.file}:{call.line}" for call in unresolved
        ]
        return _make(
            advisory,
            Verdict.UNCERTAIN,
            listed,
            reasons,
            rejected=rejected,
            explanations=explanations,
        )

    problems = _parse_and_truncation(index, imports, intermediates)
    if problems:
        return _make(
            advisory,
            Verdict.UNCERTAIN,
            listed,
            problems,
            rejected=rejected,
            explanations=explanations,
        )

    reasons = [f"no call path from project code to {', '.join(names)}"]
    if not referenced:
        reasons.append("package is never imported by the project")
    return _make(
        advisory,
        Verdict.NOT_AFFECTED,
        listed,
        reasons,
        rejected=rejected,
        explanations=explanations,
    )


def _with_subclasses(
    index: Index, names: list[str], imports: list[str]
) -> tuple[list[str], dict[str, str]]:
    """Add in-dist subclasses of a vulnerable class. They are match targets only."""
    targets = list(names)
    via: dict[str, str] = {}
    for name in names:
        symbol = index.symbols.get(name)
        if symbol is None or symbol.kind != "class":
            continue
        for child in index.subclasses_of(name):
            if child in names or not _inside(child, imports):
                continue
            if child not in targets:
                targets.append(child)
            via.setdefault(child, name)
    return targets, via


def _subclass_note(target: str, via: dict[str, str]) -> str | None:
    matches = [child for child in via if target == child or target.startswith(child + ".")]
    if not matches:
        return None
    child = max(matches, key=len)
    base = via[child].rsplit(".", 1)[-1]
    return f"{child} is a subclass of {base}"


def _canonical(index: Index, resolved: VulnSymbols) -> list[str]:
    names: list[str] = []
    for symbol in resolved.symbols:
        canonical = index.canonical(symbol)
        if canonical not in names:
            names.append(canonical)
    return names


def _listed(names: list[str], resolved: VulnSymbols) -> list[dict[str, str]]:
    reasons = _why_map(resolved)
    rows: list[dict[str, str]] = []
    for name in names:
        row = {"symbol": name, "source": resolved.source, "confidence": resolved.confidence}
        if name in reasons:
            row["why"] = reasons[name]
        rows.append(row)
    return rows


def _why_map(resolved: VulnSymbols) -> dict[str, str]:
    raw = resolved.provenance.get("why")
    found: dict[str, str] = {}
    if not isinstance(raw, list):
        return found
    for item in raw:
        if isinstance(item, dict) and isinstance(item.get("symbol"), str):
            found[str(item["symbol"])] = str(item.get("why") or "")
    return found


def _explanations(resolved: VulnSymbols) -> list[dict[str, str]]:
    raw = resolved.provenance.get("why")
    if not isinstance(raw, list):
        return []
    return [dict(item) for item in raw if isinstance(item, dict)]


def _import_names(packages: list[str], sources: dict[str, DistSource]) -> list[str]:
    names: list[str] = []
    for package in packages:
        for name in sources[package].import_names:
            if name not in names:
                names.append(name)
    return names


def _inside(name: str, roots: list[str]) -> bool:
    return any(name == root or name.startswith(root + ".") for root in roots)


def _references(index: Index, imports: list[str], intermediates: list[str]) -> bool:
    for info in index.modules.values():
        if info.root_kind != "app" and not _inside(info.qualname, intermediates):
            continue
        for target in (*info.aliases.values(), *info.star_imports):
            if _inside(target, imports):
                return True
    for edges in index.edges.values():
        for edge in edges:
            module = index.module_of(edge.src)
            if module is None:
                continue
            info = index.modules[module]
            if info.root_kind != "app" and not _inside(module, intermediates):
                continue
            if _inside(edge.dst, imports):
                return True
    return False


def _reachable(index: Index, can_enter) -> set[str]:
    reached = {name for name in index.app_functions() if can_enter(name)}
    seen = set(reached)
    queue: deque[str] = deque(sorted(reached))
    while queue:
        current = queue.popleft()
        for edge in index.edges.get(current, []):
            if edge.dst in seen or not can_enter(edge.dst):
                continue
            seen.add(edge.dst)
            reached.add(edge.dst)
            if index.edges.get(edge.dst):
                queue.append(edge.dst)
    return reached


def _dynamic(index: Index, reached: set[str], imports: list[str]) -> list[DynamicSite]:
    found: list[DynamicSite] = []
    for site in index.dynamic_sites:
        if site.func not in reached:
            continue
        if site.kind in {"getattr", "setattr"} and _getattr_relevant(index, site, imports):
            found.append(site)
        elif site.kind in {"import_module", "__import__", "eval", "exec"}:
            found.append(site)
    return found


def _getattr_relevant(index: Index, site: DynamicSite, imports: list[str]) -> bool:
    if site.target_module and _inside(site.target_module, imports):
        return True
    if site.target_module is not None:
        return False
    module = index.module_of(site.func)
    if module is None:
        return False
    info = index.modules[module]
    return any(_inside(target, imports) for target in info.aliases.values())


def _unresolved(index: Index, reached: set[str], names: list[str]) -> list[UnresolvedCall]:
    tails = {name.rsplit(".", 1)[-1] for name in names}
    return [
        call
        for call in index.unresolved_calls
        if call.func in reached and call.method_name in tails
    ]


def _parse_and_truncation(index: Index, imports: list[str], intermediates: list[str]) -> list[str]:
    reasons: list[str] = []
    for error in index.parse_errors:
        if _error_matters(index, error, imports, intermediates):
            reasons.append(f"could not parse {error.file}")
    watched = [*imports, *intermediates]
    for package in sorted(index.truncated):
        if package in watched:
            reasons.append(f"truncated package {package}")
    return reasons


def _error_matters(
    index: Index,
    error: ParseError,
    imports: list[str],
    intermediates: list[str],
) -> bool:
    info = index.modules.get(error.module)
    if info is None:
        # A file that failed to parse never became a module. This index only
        # contains the app, the vulnerable package, and intermediates.
        return True
    if info.root_kind == "app":
        return True
    return _inside(error.module, imports) or _inside(error.module, intermediates)


def _unscanned(
    advisory: Advisory,
    reason: str,
    symbol_files: tuple[Path, ...] | list[Path],
    offline: bool,
    refresh_symbols: bool,
) -> Finding:
    resolved = resolve_symbols(
        advisory,
        offline=offline,
        refresh=refresh_symbols,
        extra_cache_files=symbol_files,
    )
    listed = _listed(resolved.symbols, resolved)
    return _make(
        advisory,
        Verdict.UNCERTAIN,
        listed,
        [reason],
        rejected=resolved.rejected,
        explanations=_explanations(resolved),
    )


def _make(
    advisory: Advisory,
    verdict: Verdict,
    symbols: list[dict[str, str]],
    reasons: list[str],
    paths: list[list[PathHop]] | None = None,
    dynamic: list[DynamicSite] | None = None,
    rejected: list[str] | None = None,
    explanations: list[dict[str, str]] | None = None,
) -> Finding:
    sites = [
        {
            "func": site.func,
            "file": site.file,
            "line": site.line,
            "kind": site.kind,
            "detail": site.detail,
            "target_module": site.target_module,
        }
        for site in dynamic or []
    ]
    return Finding(
        advisory=advisory,
        verdict=verdict,
        vulnerable_symbols=symbols,
        evidence=Evidence(paths=list(paths or []), dynamic_sites=sites, reasons=list(reasons)),
        vex_status=_VEX[verdict],
        rejected=list(rejected or []),
        explanations=list(explanations or []),
    )


def _replace(finding: Finding, verdict: Verdict, reasons: list[str]) -> Finding:
    return Finding(
        advisory=finding.advisory,
        verdict=verdict,
        vulnerable_symbols=finding.vulnerable_symbols,
        evidence=Evidence(
            paths=finding.evidence.paths,
            dynamic_sites=finding.evidence.dynamic_sites,
            reasons=reasons,
        ),
        vex_status=_VEX[verdict],
        rejected=list(finding.rejected),
        explanations=list(finding.explanations),
    )
