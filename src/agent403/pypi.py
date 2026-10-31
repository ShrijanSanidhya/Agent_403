"""Download a package wheel and map its distribution name to import names."""

import hashlib
import os
import shutil
import stat
import tarfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.version import InvalidVersion, Version

from agent403.cache import cache_root
from agent403.deps import normalize_name
from agent403.net import HttpClient, OfflineError

_PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
_IGNORE_DIRS = {"tests", "docs", "examples", "benchmarks"}


class UnsafeArchiveError(Exception):
    """Raised when an archive member would escape the destination."""


class DigestMismatchError(Exception):
    """Raised when a download does not match the published sha256."""


@dataclass
class DistSource:
    name: str
    version: str
    root: Path
    import_names: list[str]
    requires_dist: list[str]
    origin: str


def find_local(name: str, version: str, sites: list[Path]) -> DistSource | None:
    """Find an already-unpacked distribution in a site-packages style directory."""
    wanted = normalize_name(name)
    for site in sites:
        if not site.is_dir():
            continue
        for dist_info in site.glob("*.dist-info"):
            parsed = _split_dist_info(dist_info.name)
            if parsed is None:
                continue
            found_name, found_version = parsed
            if normalize_name(found_name) != wanted or not _same_version(found_version, version):
                continue
            return DistSource(
                name=wanted,
                version=version,
                root=site,
                import_names=_import_names_from_dist_info(dist_info),
                requires_dist=requires_dist_from_text(_read_text(dist_info / "METADATA")),
                origin="local",
            )
    return None


def fetch(
    name: str,
    version: str,
    offline: bool = False,
    sites: list[Path] | None = None,
    http: HttpClient | None = None,
) -> DistSource:
    """Return a local install, or download and extract a wheel or sdist."""
    local = find_local(name, version, list(sites or []))
    if local is not None:
        return local
    normalized = normalize_name(name)
    if offline:
        raise OfflineError(f"offline mode: {normalized}=={version} is not available locally")
    client = http if http is not None else HttpClient()
    return _download(client, normalized, version)


def safe_extract_zip(archive: Path, dest: Path) -> None:
    """Extract a zip, rejecting path escapes, symlinks, and hard links."""
    dest.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            _ensure_safe_path(info.filename, dest)
            if stat.S_ISLNK(info.external_attr >> 16):
                raise UnsafeArchiveError(info.filename)
            target = dest / _relative(info.filename)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)


def safe_extract_tar(archive: Path, dest: Path) -> None:
    """Extract a tar, rejecting path escapes, symlinks, and hard links."""
    dest.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as bundle:
        for member in bundle.getmembers():
            _ensure_safe_path(member.name, dest)
            if member.issym() or member.islnk():
                raise UnsafeArchiveError(member.name)
            target = dest / _relative(member.name)
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise UnsafeArchiveError(member.name)
            extracted = bundle.extractfile(member)
            if extracted is None:
                raise UnsafeArchiveError(member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            with extracted, target.open("wb") as out:
                shutil.copyfileobj(extracted, out)


def requires_dist_from_text(text: str) -> list[str]:
    """Return normalized names from Requires-Dist lines."""
    names: list[str] = []
    for line in text.splitlines():
        if not line.startswith("Requires-Dist:"):
            continue
        raw = line.split(":", 1)[1].strip()
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            continue
        name = normalize_name(req.name)
        if name not in names:
            names.append(name)
    return names


def _download(http: HttpClient, name: str, version: str) -> DistSource:
    dest = cache_root() / "src" / f"{name}-{version}"
    if dest.is_dir() and any(dest.iterdir()):
        origin = "wheel" if any(dest.glob("*.dist-info")) else "sdist"
        return _describe(name, version, dest, origin)
    payload = http.get_json(_PYPI_JSON.format(name=name, version=version))
    if not isinstance(payload, dict):
        raise DigestMismatchError(f"unexpected PyPI response for {name}=={version}")
    chosen = _choose_file(list(payload.get("urls") or []))
    filename = str(chosen.get("filename") or "")
    expected = str((chosen.get("digests") or {}).get("sha256") or "")
    data = http.get_bytes(str(chosen.get("url") or ""))
    actual = hashlib.sha256(data).hexdigest()
    if not expected or actual != expected:
        raise DigestMismatchError(f"sha256 mismatch for {filename}")
    archive_path = cache_root() / "dists" / filename
    archive_path.parent.mkdir(parents=True, exist_ok=True)
    archive_path.write_bytes(data)
    dest.mkdir(parents=True, exist_ok=True)
    packagetype = str(chosen.get("packagetype") or "")
    if packagetype == "bdist_wheel" or filename.endswith(".whl"):
        safe_extract_zip(archive_path, dest)
        origin = "wheel"
    elif filename.endswith((".tar.gz", ".tgz")):
        safe_extract_tar(archive_path, dest)
        origin = "sdist"
    else:
        safe_extract_zip(archive_path, dest)
        origin = "sdist"
    return _describe(name, version, dest, origin)


def _choose_file(urls: list[dict[str, object]]) -> dict[str, object]:
    wheels = [item for item in urls if item.get("packagetype") == "bdist_wheel"]
    pure = [
        item
        for item in wheels
        if "py3-none-any" in str(item.get("filename"))
        or "py2.py3-none-any" in str(item.get("filename"))
    ]
    if pure:
        return pure[0]
    # A cp27 Windows wheel is not this package's Python 3 source. Prefer the sdist.
    for item in urls:
        if item.get("packagetype") != "sdist":
            continue
        filename = str(item.get("filename") or "")
        if filename.endswith((".tar.gz", ".tgz", ".zip")):
            return item
    py3 = [item for item in wheels if _is_py3_wheel(str(item.get("filename") or ""))]
    if py3:
        return py3[0]
    if wheels:
        return wheels[0]
    raise DigestMismatchError("no usable wheel or sdist in the PyPI response")


def _is_py3_wheel(filename: str) -> bool:
    return "-cp3" in filename or "-py3" in filename


def _describe(name: str, version: str, dest: Path, origin: str) -> DistSource:
    dist_infos = sorted(dest.glob("*.dist-info"))
    if origin == "wheel" and dist_infos:
        dist_info = dist_infos[0]
        return DistSource(
            name=name,
            version=version,
            root=dest,
            import_names=_import_names_from_dist_info(dist_info),
            requires_dist=requires_dist_from_text(_read_text(dist_info / "METADATA")),
            origin=origin,
        )
    root, names = _sdist_packages(dest)
    return DistSource(
        name=name,
        version=version,
        root=root,
        import_names=names,
        requires_dist=_requires_from_tree(dest),
        origin=origin,
    )


def _import_names_from_dist_info(dist_info: Path) -> list[str]:
    names = _nonempty_lines(dist_info / "top_level.txt")
    if names:
        return names
    record = dist_info / "RECORD"
    if record.is_file():
        return _names_from_record(_read_text(record))
    return []


def _names_from_record(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        path = line.split(",", 1)[0].strip()
        if not path or ".dist-info" in path:
            continue
        first = path.split("/", 1)[0]
        name = first[:-3] if first.endswith(".py") else first
        if name and name not in names:
            names.append(name)
    return names


def _sdist_packages(dest: Path) -> tuple[Path, list[str]]:
    found: list[tuple[Path, str]] = []
    for init in dest.rglob("__init__.py"):
        package = init.parent
        relative = package.relative_to(dest)
        if any(part in _IGNORE_DIRS for part in relative.parts):
            continue
        if (package.parent / "__init__.py").is_file():
            continue
        found.append((package.parent, package.name))
    if not found:
        return dest, []
    parents = {parent for parent, _name in found}
    if len(parents) == 1:
        return parents.pop(), _unique(name for _parent, name in found)
    lib3 = [parent for parent in parents if parent.name == "lib3"]
    if len(lib3) == 1:
        parent = lib3[0]
        return parent, _unique(name for found_parent, name in found if found_parent == parent)
    return dest, _unique(name for _parent, name in found)


def _unique(names) -> list[str]:
    found: list[str] = []
    for name in names:
        if name not in found:
            found.append(name)
    return found


def _requires_from_tree(dest: Path) -> list[str]:
    for metadata in dest.rglob("METADATA"):
        if metadata.parent.name.endswith(".dist-info"):
            return requires_dist_from_text(_read_text(metadata))
    for pkg_info in sorted(dest.rglob("PKG-INFO")):
        return requires_dist_from_text(_read_text(pkg_info))
    return []


def _split_dist_info(dirname: str) -> tuple[str, str] | None:
    if not dirname.endswith(".dist-info"):
        return None
    base = dirname[: -len(".dist-info")]
    parts = base.split("-")
    for index in range(len(parts) - 1, 0, -1):
        version = "-".join(parts[index:])
        try:
            Version(version)
        except InvalidVersion:
            continue
        return "-".join(parts[:index]), version
    return None


def _same_version(left: str, right: str) -> bool:
    try:
        return Version(left) == Version(right)
    except InvalidVersion:
        return left == right


def _ensure_safe_path(name: str, dest: Path) -> None:
    cleaned = name.replace("\\", "/")
    if cleaned.startswith("/") or (len(cleaned) >= 2 and cleaned[1] == ":"):
        raise UnsafeArchiveError(name)
    if any(part == ".." for part in Path(cleaned).parts):
        raise UnsafeArchiveError(name)
    dest_resolved = dest.resolve()
    target = (dest / _relative(cleaned)).resolve()
    if os.path.commonpath([str(dest_resolved), str(target)]) != str(dest_resolved):
        raise UnsafeArchiveError(name)


def _relative(name: str) -> Path:
    return Path(name.replace("\\", "/"))


def _read_text(path: Path) -> str:
    if not path.is_file():
        return ""
    return path.read_text(encoding="utf-8")


def _nonempty_lines(path: Path) -> list[str]:
    names: list[str] = []
    for line in _read_text(path).splitlines():
        item = line.strip()
        if item and item not in names:
            names.append(item)
    return names
