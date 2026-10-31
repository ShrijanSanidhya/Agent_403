"""Fetch OSV advisories for pinned PyPI packages and cache them on disk."""

import re
from pathlib import Path

from agent403.cache import cache_root, read_json, shipped_data_dir, write_json
from agent403.deps import normalize_name
from agent403.models import Advisory, Dependency
from agent403.net import HttpClient

_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
_GITHUB_REF = re.compile(r"https?://github\.com/[^/\s]+/[^/\s]+/(?:commit/[0-9A-Fa-f]+|pull/\d+)")


class OsvClient:
    """Look up advisories online, or from the cache when offline."""

    def __init__(
        self,
        http: HttpClient,
        offline: bool = False,
        extra_dirs: tuple[Path, ...] | list[Path] = (),
    ) -> None:
        self.http = http
        self.offline = offline
        self.extra_dirs = [Path(path) for path in extra_dirs]

    def fetch_advisories(
        self,
        deps: list[Dependency],
    ) -> tuple[list[Advisory], list[str]]:
        """Return advisories for pinned dependencies, plus warnings."""
        warnings: list[str] = []
        pinned = [dep for dep in deps if dep.pinned and dep.version]
        if not pinned:
            return [], warnings
        found: list[Advisory] = []
        if self.offline:
            for dep in pinned:
                ids, folder = self._offline_ids(dep)
                if ids is None or folder is None:
                    warnings.append(f"no cached advisory data for {dep.name}=={dep.version}")
                    continue
                found.extend(self._advisories_from_ids(dep, ids, folder))
            return dedupe(found), warnings

        id_lists = self._query_batch(pinned)
        for dep, ids in zip(pinned, id_lists, strict=True):
            records: list[dict[str, object]] = []
            for vuln_id in ids:
                record = self.http.get_json(_VULN_URL.format(vuln_id=vuln_id))
                if isinstance(record, dict):
                    records.append(record)
                    write_json(self._user_dir() / "vulns" / f"{vuln_id}.json", record)
            self._write_index(dep, ids)
            for record in records:
                if record.get("withdrawn"):
                    continue
                found.append(parse_record(record, dep))
        return dedupe(found), warnings

    def _query_batch(self, deps: list[Dependency]) -> list[list[str]]:
        queries = [
            {"package": {"name": dep.name, "ecosystem": "PyPI"}, "version": dep.version}
            for dep in deps
        ]
        collected: list[list[str]] = [[] for _ in deps]
        token: str | None = None
        while True:
            payload: dict[str, object] = {"queries": queries}
            if token:
                payload["page_token"] = token
            data = self.http.post_json(_BATCH_URL, payload)
            if not isinstance(data, dict):
                break
            for index, result in enumerate(data.get("results") or []):
                if index >= len(collected) or not isinstance(result, dict):
                    continue
                for vuln in result.get("vulns") or []:
                    vuln_id = vuln.get("id") if isinstance(vuln, dict) else None
                    if vuln_id and vuln_id not in collected[index]:
                        collected[index].append(str(vuln_id))
            next_token = data.get("next_page_token")
            token = str(next_token) if next_token else None
            if not token:
                break
        return collected

    def _advisories_from_ids(
        self,
        dep: Dependency,
        ids: list[str],
        folder: Path,
    ) -> list[Advisory]:
        advisories: list[Advisory] = []
        for vuln_id in ids:
            record = self._read_record(vuln_id, folder)
            if record is None or record.get("withdrawn"):
                continue
            advisories.append(parse_record(record, dep))
        return advisories

    def _offline_ids(self, dep: Dependency) -> tuple[list[str] | None, Path | None]:
        key = f"{dep.name}=={dep.version}"
        for folder in self._search_dirs():
            index_path = folder / "index.json"
            if not index_path.is_file():
                continue
            index = read_json(index_path)
            if isinstance(index, dict) and key in index:
                return [str(item) for item in index[key]], folder
        return None, None

    def _read_record(self, vuln_id: str, preferred: Path) -> dict[str, object] | None:
        folders = [preferred]
        for folder in self._search_dirs():
            if folder not in folders:
                folders.append(folder)
        for folder in folders:
            path = folder / "vulns" / f"{vuln_id}.json"
            if not path.is_file():
                continue
            record = read_json(path)
            if isinstance(record, dict):
                return record
        return None

    def _user_dir(self) -> Path:
        return cache_root() / "osv_cache"

    def _search_dirs(self) -> list[Path]:
        return [self._user_dir(), shipped_data_dir() / "osv_cache", *self.extra_dirs]

    def _write_index(self, dep: Dependency, ids: list[str]) -> None:
        folder = self._user_dir()
        index_path = folder / "index.json"
        index = read_json(index_path) if index_path.is_file() else {}
        if not isinstance(index, dict):
            index = {}
        index[f"{dep.name}=={dep.version}"] = ids
        write_json(index_path, index)


def parse_record(record: dict[str, object], dep: Dependency) -> Advisory:
    """Turn one OSV record into an Advisory for this dependency."""
    aliases = [str(item) for item in record.get("aliases") or []]
    return Advisory(
        id=str(record.get("id") or ""),
        aliases=aliases,
        summary=str(record.get("summary") or ""),
        details=str(record.get("details") or ""),
        package=dep.name,
        version=dep.version,
        fixed_versions=_fixed_versions(record, dep.name),
        fix_refs=_fix_refs(record),
    )


def dedupe(advisories: list[Advisory]) -> list[Advisory]:
    """Merge advisories for the same dependency that share an id or alias."""
    grouped: dict[tuple[str, str], list[Advisory]] = {}
    order: list[tuple[str, str]] = []
    for advisory in advisories:
        key = (advisory.package, advisory.version)
        if key not in grouped:
            grouped[key] = []
            order.append(key)
        grouped[key].append(advisory)
    merged: list[Advisory] = []
    for key in order:
        merged.extend(_merge_related(grouped[key]))
    return merged


def _fixed_versions(record: dict[str, object], dep_name: str) -> list[str]:
    found: list[str] = []
    for affected in record.get("affected") or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package") or {}
        if not isinstance(package, dict):
            continue
        ecosystem = package.get("ecosystem")
        if ecosystem not in (None, "PyPI"):
            continue
        raw_name = str(package.get("name") or "")
        if normalize_name(raw_name) != normalize_name(dep_name):
            continue
        for rng in affected.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            for event in rng.get("events") or []:
                if not isinstance(event, dict) or "fixed" not in event:
                    continue
                version = str(event["fixed"])
                if version not in found:
                    found.append(version)
    return found


def _fix_refs(record: dict[str, object]) -> list[str]:
    refs: list[str] = []
    for ref in record.get("references") or []:
        if not isinstance(ref, dict):
            continue
        url = str(ref.get("url") or "")
        if not url:
            continue
        if ref.get("type") == "FIX" or _GITHUB_REF.search(url):
            if url not in refs:
                refs.append(url)
    return refs


def _merge_related(advisories: list[Advisory]) -> list[Advisory]:
    parent = list(range(len(advisories)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[root_right] = root_left

    for left, advisory in enumerate(advisories):
        keys = _keys(advisory)
        for right in range(left + 1, len(advisories)):
            if keys & _keys(advisories[right]):
                union(left, right)
    clusters: dict[int, list[Advisory]] = {}
    for index, advisory in enumerate(advisories):
        clusters.setdefault(find(index), []).append(advisory)
    return [_merge_cluster(cluster) for cluster in clusters.values()]


def _keys(advisory: Advisory) -> set[str]:
    return {advisory.id, *advisory.aliases}


def _id_rank(advisory_id: str) -> tuple[int, str]:
    if advisory_id.startswith("GHSA-"):
        return (0, advisory_id)
    if advisory_id.startswith("PYSEC-"):
        return (1, advisory_id)
    return (2, advisory_id)


def _merge_cluster(cluster: list[Advisory]) -> Advisory:
    primary = min(cluster, key=lambda advisory: _id_rank(advisory.id))
    aliases: list[str] = []
    fix_refs: list[str] = []
    fixed_versions: list[str] = []
    details = primary.details
    for advisory in cluster:
        if len(advisory.details) > len(details):
            details = advisory.details
        for alias in (advisory.id, *advisory.aliases):
            if alias != primary.id and alias not in aliases:
                aliases.append(alias)
        for ref in advisory.fix_refs:
            if ref not in fix_refs:
                fix_refs.append(ref)
        for version in advisory.fixed_versions:
            if version not in fixed_versions:
                fixed_versions.append(version)
    return Advisory(
        id=primary.id,
        aliases=aliases,
        summary=primary.summary,
        details=details,
        package=primary.package,
        version=primary.version,
        fixed_versions=fixed_versions,
        fix_refs=fix_refs,
    )
