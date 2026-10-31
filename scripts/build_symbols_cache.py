"""Rebuild src/agent403/data/symbols_cache.json with the open model.

Run this by hand when Ollama is available. It is not part of CI.
"""

from agent403.cache import read_json, shipped_data_dir, write_json
from agent403.callgraph import Index, Root
from agent403.llm import from_env
from agent403.net import HttpClient
from agent403.pypi import fetch
from agent403.symbols import load_advisory, resolve_symbols


def main() -> None:
    folder = shipped_data_dir() / "osv_cache"
    index = read_json(folder / "index.json")
    if not isinstance(index, dict):
        raise SystemExit("osv cache index is missing")
    http = HttpClient()
    llm, warning = from_env(True)
    if warning:
        print(warning)
    cache: dict[str, object] = {}
    print("| advisory | source | symbols | confidence |")
    print("|---|---|---|---|")
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
            cache[advisory.id] = {
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
            }
            count = len(result.symbols)
            print(f"| {advisory.id} | {result.source} | {count} | {result.confidence} |")
    write_json(shipped_data_dir() / "symbols_cache.json", cache)


if __name__ == "__main__":
    main()
