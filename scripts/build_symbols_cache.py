"""Rebuild src/agent403/data/symbols_cache.json with the open model.

Run this by hand when Ollama is available. It is not part of CI.

With no arguments it walks the shipped OSV index. With --packages it asks OSV
for advisories, indexes one vulnerable version of each, and merges model
answers into the shipped cache.
"""

import argparse
import time
from datetime import datetime, timezone

from packaging.version import InvalidVersion, Version

from agent403.cache import read_json, shipped_data_dir, write_json
from agent403.callgraph import Index, Root
from agent403.deps import normalize_name
from agent403.llm import from_env
from agent403.models import Advisory, Dependency
from agent403.net import HttpClient
from agent403.osv import dedupe, parse_record
from agent403.pypi import fetch
from agent403.symbols import load_advisory, resolve_symbols

_QUERY_URL = "https://api.osv.dev/v1/query"
_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
_BUDGET_SECONDS = 75 * 60
_REVIEWED = {"GHSA-8q59-q68h-6hv4", "GHSA-462w-v97r-4m45"}


def main() -> None:
    args = _parse_args()
    if args.packages:
        build_packages(args.packages, args.max_per_package, _since(args.since))
        return
    build_from_index()


def build_from_index() -> None:
    folder = shipped_data_dir() / "osv_cache"
    index = read_json(folder / "index.json")
    if not isinstance(index, dict):
        raise SystemExit("osv cache index is missing")
    http = HttpClient()
    llm, warning = from_env(True)
    if warning:
        print(warning, flush=True)
    cache: dict[str, object] = {}
    print("| advisory | source | symbols | confidence |", flush=True)
    print("|---|---|---|---|", flush=True)
    for key in sorted(index):
        name, version = str(key).split("==", 1)
        dist = fetch(name, version, http=http)
        graph = Index.build([Root(dist.root, "dep", list(dist.import_names))])
        for advisory_id in index[key]:
            advisory = load_advisory(str(advisory_id), name, version, http)
            result = resolve_symbols(
                advisory,
                graph,
                dist,
                http=http,
                llm=llm,
                offline=False,
                refresh=True,
            )
            cache[advisory.id] = _entry(advisory, result, version)
            count = len(result.symbols)
            line = f"| {advisory.id} | {result.source} | {count} | {result.confidence} |"
            print(line, flush=True)
    write_json(shipped_data_dir() / "symbols_cache.json", cache)


def build_packages(packages: list[str], limit: int, since: datetime) -> None:
    """Query OSV, keep validated model answers, and merge them into the cache."""
    http = HttpClient()
    llm, warning = from_env(True)
    if llm is None:
        raise SystemExit(warning or "open model is not available")
    if warning:
        print(warning, flush=True)
    cache = _load_cache()
    started = time.monotonic()
    deadline = started + _BUDGET_SECONDS
    rows: list[tuple[str, int, int, int]] = []
    stopped = False
    graphs: dict[tuple[str, str], tuple[object, Index]] = {}
    for package in packages:
        if time.monotonic() >= deadline:
            stopped = True
            break
        try:
            records = query_package(http, package)
        except Exception as exc:  # noqa: BLE001
            print(f"{package} query failed: {exc}", flush=True)
            rows.append((package, 0, 0, 1))
            continue
        chosen = select_advisories(records, package, limit=limit, since=since, cache=cache)
        ok = 0
        failed = 0
        print(f"{package}: {len(chosen)} advisories", flush=True)
        for advisory, record in chosen:
            if time.monotonic() >= deadline:
                stopped = True
                break
            _save_record(advisory.id, record)
            version = indexed_version(record, package)
            if version is None:
                failed += 1
                print(f"{package} {advisory.id} skipped: no indexable version", flush=True)
                continue
            try:
                dist, graph = _dist_for(graphs, http, package, version)
                result = resolve_symbols(
                    _at_version(advisory, version),
                    graph,
                    dist,
                    http=http,
                    llm=llm,
                    offline=False,
                    refresh=True,
                )
            except Exception as exc:  # noqa: BLE001
                failed += 1
                print(f"{package} {advisory.id} failed: {exc}", flush=True)
                continue
            if result.source != "llm":
                failed += 1
                print(f"{package} {advisory.id} {result.source} (not kept)", flush=True)
                continue
            cache[advisory.id] = _entry(advisory, result, version)
            write_json(shipped_data_dir() / "symbols_cache.json", cache)
            ok += 1
            print(
                f"{package} {advisory.id} llm {len(result.symbols)} {result.confidence}",
                flush=True,
            )
        rows.append((package, len(chosen), ok, failed))
        if stopped:
            break
    write_json(shipped_data_dir() / "symbols_cache.json", cache)
    if stopped:
        print("stopped: 75 minute budget", flush=True)
    _print_table(rows)


def query_package(http: HttpClient, name: str) -> list[dict[str, object]]:
    """Return every OSV record for a PyPI package."""
    records: list[dict[str, object]] = []
    token: str | None = None
    while True:
        payload: dict[str, object] = {"package": {"name": name, "ecosystem": "PyPI"}}
        if token:
            payload["page_token"] = token
        data = http.post_json(_QUERY_URL, payload)
        if not isinstance(data, dict):
            break
        for item in data.get("vulns") or []:
            record = _full_record(http, item)
            if record is not None:
                records.append(record)
        next_token = data.get("next_page_token")
        token = str(next_token) if next_token else None
        if not token:
            break
    return records


def select_advisories(
    records: list[dict[str, object]],
    package: str,
    *,
    limit: int,
    since: datetime,
    cache: dict[str, object] | None = None,
) -> list[tuple[Advisory, dict[str, object]]]:
    """Dedupe, drop old and reviewed ids, and keep the most useful advisories."""
    by_id: dict[str, dict[str, object]] = {}
    advisories: list[Advisory] = []
    dep = Dependency(package, "0", True, "")
    for record in records:
        if record.get("withdrawn") or not _published_since(record, since):
            continue
        ident = str(record.get("id") or "")
        if not ident:
            continue
        by_id[ident] = record
        advisories.append(parse_record(record, dep))
    ranked = sorted(dedupe(advisories), key=lambda advisory: _rank(advisory, by_id))
    chosen: list[tuple[Advisory, dict[str, object]]] = []
    for advisory in ranked:
        if _protected(advisory.id, cache):
            continue
        record = by_id.get(advisory.id)
        if record is None:
            continue
        chosen.append((advisory, record))
        if len(chosen) == limit:
            break
    return chosen


def indexed_version(record: dict[str, object], package: str) -> str | None:
    """Highest listed version below the first fix, or the highest listed version."""
    versions: list[str] = []
    fixed: list[Version] = []
    wanted = normalize_name(package)
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        info = affected.get("package") or {}
        if not isinstance(info, dict):
            continue
        ecosystem = info.get("ecosystem")
        if ecosystem not in (None, "PyPI"):
            continue
        if normalize_name(str(info.get("name") or "")) != wanted:
            continue
        for raw in affected.get("versions") or []:
            versions.append(str(raw))
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if isinstance(event, dict) and "fixed" in event:
                    parsed = _version(str(event["fixed"]))
                    if parsed is not None:
                        fixed.append(parsed)
    parsed_versions = [(item, raw) for raw in versions if (item := _version(raw)) is not None]
    if not parsed_versions:
        return None
    if fixed:
        first = min(fixed)
        parsed_versions = [item for item in parsed_versions if item[0] < first]
    if not parsed_versions:
        return None
    return max(parsed_versions, key=lambda item: item[0])[1]


def _rank(advisory: Advisory, by_id: dict[str, dict[str, object]]) -> tuple[int, float]:
    has_fix = 0 if advisory.fix_refs else 1
    published = _published_at(by_id.get(advisory.id, {}))
    return (has_fix, -published.timestamp())


def _protected(advisory_id: str, cache: dict[str, object] | None) -> bool:
    if advisory_id in _REVIEWED:
        return True
    if cache is None:
        return False
    current = cache.get(advisory_id)
    return isinstance(current, dict) and current.get("reviewed") is True


def _published_since(record: dict[str, object], since: datetime) -> bool:
    return _published_at(record) >= since


def _published_at(record: dict[str, object]) -> datetime:
    raw = str(record.get("published") or "")
    stamp = _parse_time(raw)
    if stamp is None:
        return datetime.min.replace(tzinfo=timezone.utc)
    return stamp


def _parse_time(raw: str) -> datetime | None:
    if not raw:
        return None
    try:
        stamp = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return stamp


def _version(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _full_record(http: HttpClient, item: object) -> dict[str, object] | None:
    if isinstance(item, str):
        ident: str | None = item
        record: dict[str, object] | None = None
    elif isinstance(item, dict):
        if any(key in item for key in ("affected", "summary", "details")):
            return item
        ident = str(item.get("id") or "") or None
        record = item
    else:
        return None
    if not ident:
        return record
    fetched = http.get_json(_VULN_URL.format(vuln_id=ident))
    if isinstance(fetched, dict):
        return fetched
    return record


def _dist_for(graphs, http: HttpClient, package: str, version: str):
    key = (package, version)
    if key not in graphs:
        dist = fetch(package, version, http=http)
        graph = Index.build([Root(dist.root, "dep", list(dist.import_names))])
        graphs[key] = (dist, graph)
    return graphs[key]


def _at_version(advisory: Advisory, version: str) -> Advisory:
    return Advisory(
        id=advisory.id,
        aliases=list(advisory.aliases),
        summary=advisory.summary,
        details=advisory.details,
        package=advisory.package,
        version=version,
        fixed_versions=list(advisory.fixed_versions),
        fix_refs=list(advisory.fix_refs),
    )


def _entry(advisory: Advisory, result, version: str) -> dict[str, object]:
    return {
        "package": advisory.package,
        "symbols": list(result.symbols),
        "safe_symbols": list(result.safe_symbols),
        "confidence": result.confidence,
        "generated_by": result.provenance.get("generated_by") or result.source,
        "generated_at": result.provenance.get("generated_at") or "",
        "reviewed": False,
        "notes": "",
        "backend": result.provenance.get("backend") or "",
        "inputs_sha256": result.provenance.get("inputs_sha256") or "",
        "fix_refs_used": result.provenance.get("fix_refs_used") or [],
        "rejected": list(result.rejected),
        "indexed_version": version,
    }


def _load_cache() -> dict[str, object]:
    path = shipped_data_dir() / "symbols_cache.json"
    data = read_json(path) if path.is_file() else {}
    if not isinstance(data, dict):
        return {}
    return data


def _save_record(advisory_id: str, record: dict[str, object]) -> None:
    folder = shipped_data_dir() / "osv_cache" / "vulns"
    write_json(folder / f"{advisory_id}.json", record)


def _print_table(rows: list[tuple[str, int, int, int]]) -> None:
    print("| package | advisories | llm ok | failed |", flush=True)
    print("|---|---|---|---|", flush=True)
    for package, advisories, ok, failed in rows:
        print(f"| {package} | {advisories} | {ok} | {failed} |", flush=True)


def _since(text: str) -> datetime:
    if len(text) == 4 and text.isdigit():
        return datetime(int(text), 1, 1, tzinfo=timezone.utc)
    stamp = _parse_time(text)
    if stamp is None:
        raise SystemExit(f"could not read --since {text}")
    return stamp


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Fill the shipped symbol cache from the model.")
    parser.add_argument("--packages", nargs="+", help="PyPI packages to query on OSV.")
    parser.add_argument("--max-per-package", type=int, default=12)
    parser.add_argument(
        "--since",
        default="2018",
        help="Keep advisories published on or after this.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    main()
