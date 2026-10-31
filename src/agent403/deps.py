"""Parse requirements files and pyproject.toml into pinned dependencies."""

import re
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement

from agent403.models import Dependency

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib

_PEP503 = re.compile(r"[-_.]+")
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")


def normalize_name(name: str) -> str:
    """Normalize a distribution name per PEP 503."""
    return _PEP503.sub("-", name).lower()


def find_dependency_files(project: Path, override: Path | None = None) -> list[Path]:
    """Return requirement files for a project, or the override if one was given."""
    if override is not None:
        return [override]
    files = sorted(path for path in project.glob("requirements*.txt") if path.is_file())
    pyproject = project / "pyproject.toml"
    if pyproject.is_file():
        files.append(pyproject)
    return files


def parse_requirements(path: Path) -> tuple[list[Dependency], list[str]]:
    """Parse a requirements file, following -r includes without looping."""
    return _parse_requirements(path, seen=set())


def parse_pyproject(path: Path) -> tuple[list[Dependency], list[str]]:
    """Parse pinned and unpinned dependencies from [project].dependencies."""
    with path.open("rb") as handle:
        data = tomllib.load(handle)
    raw_deps = (data.get("project") or {}).get("dependencies") or []
    dependencies: list[Dependency] = []
    warnings: list[str] = []
    for item in raw_deps:
        dep, warning = _from_requirement_text(str(item), path)
        if dep is not None:
            dependencies.append(dep)
        if warning:
            warnings.append(warning)
    return dependencies, warnings


def load_dependencies(
    project: Path,
    override: Path | None = None,
) -> tuple[list[Dependency], list[str]]:
    """Load dependencies from discovered files. The first version of a name wins."""
    dependencies: list[Dependency] = []
    warnings: list[str] = []
    seen: dict[str, Dependency] = {}
    for path in find_dependency_files(project, override):
        if path.suffix == ".toml":
            found, file_warnings = parse_pyproject(path)
        else:
            found, file_warnings = parse_requirements(path)
        warnings.extend(file_warnings)
        for dep in found:
            current = seen.get(dep.name)
            if current is None:
                seen[dep.name] = dep
                dependencies.append(dep)
                continue
            if current.version != dep.version:
                warnings.append(
                    f"{dep.name} version conflict: keeping {current.version or 'unpinned'}, "
                    f"ignoring {dep.version or 'unpinned'} from {dep.source_file}"
                )
    return dependencies, warnings


def _parse_requirements(path: Path, seen: set[Path]) -> tuple[list[Dependency], list[str]]:
    resolved = path.resolve()
    if resolved in seen:
        return [], [f"skipping repeated requirements file: {resolved}"]
    seen.add(resolved)
    dependencies: list[Dependency] = []
    warnings: list[str] = []
    text = path.read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        line = _strip_comment(raw_line).strip()
        if not line:
            continue
        include = _requirement_include(line)
        if include is not None:
            included, include_warnings = _parse_requirements(path.parent / include, seen)
            dependencies.extend(included)
            warnings.extend(include_warnings)
            continue
        if _is_option_line(line):
            continue
        dep, warning = _from_requirement_text(line, path)
        if dep is not None:
            dependencies.append(dep)
        if warning:
            warnings.append(warning)
    return dependencies, warnings


def _strip_comment(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    if " #" in line:
        return line.split(" #", 1)[0]
    return line


def _requirement_include(line: str) -> str | None:
    if line.startswith("--requirement="):
        return line.split("=", 1)[1].strip() or None
    parts = line.split(maxsplit=1)
    flag = parts[0]
    if flag in {"-r", "--requirement"} and len(parts) == 2:
        return parts[1].strip()
    if flag.startswith("-r") and not flag.startswith("--") and flag != "-r":
        return flag[2:]
    return None


def _is_option_line(line: str) -> bool:
    return line.startswith("-")


def _looks_like_url(line: str) -> bool:
    lowered = line.lower()
    return "://" in line or lowered.startswith(_VCS_PREFIXES)


def _egg_name(line: str) -> str | None:
    marker = "egg="
    if marker not in line:
        return None
    return line.split(marker, 1)[1].split("&", 1)[0].strip() or None


def _from_requirement_text(line: str, source: Path) -> tuple[Dependency | None, str | None]:
    if _looks_like_url(line):
        name = _egg_name(line) or line.split()[0]
        try:
            parsed = Requirement(line)
            name = parsed.name
        except InvalidRequirement:
            pass
        return (
            Dependency(normalize_name(name), "", False, str(source)),
            f"URL or VCS requirement is unpinned: {line}",
        )
    try:
        req = Requirement(line)
    except InvalidRequirement:
        return None, f"could not parse requirement: {line}"
    if req.url:
        return (
            Dependency(normalize_name(req.name), "", False, str(source)),
            f"URL or VCS requirement is unpinned: {line}",
        )
    pinned, version = _pin(req)
    warning = None if pinned else f"{normalize_name(req.name)} is not pinned"
    return Dependency(normalize_name(req.name), version, pinned, str(source)), warning


def _pin(req: Requirement) -> tuple[bool, str]:
    specs = list(req.specifier)
    if len(specs) != 1:
        return False, str(req.specifier)
    spec = specs[0]
    if spec.operator not in {"==", "==="} or "*" in spec.version:
        return False, spec.version
    return True, spec.version
