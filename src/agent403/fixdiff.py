"""Read a GitHub fix diff and name the functions it touches. AST only."""

import ast
import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

import requests

from agent403.callgraph import Index
from agent403.net import HttpClient, OfflineError

_MAX_DIFF = 400_000
_MAX_URLS = 3
_COMMIT = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9A-Fa-f]+)")
_PULL = re.compile(r"https?://github\.com/([^/\s]+)/([^/\s]+)/pull/(\d+)")
_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$")
_DEF = re.compile(r"^(?:async\s+def|def|class)\s+(\w+)")


@dataclass
class Hunk:
    new_start: int
    new_len: int
    header_context: str
    added_lines: list[int]
    removed_count: int
    text: str
    deletion_lines: list[int] = field(default_factory=list)


@dataclass
class FileChange:
    path: str
    hunks: list[Hunk]


def github_diff_urls(fix_refs: list[str]) -> list[str]:
    """Turn GitHub commit and pull links into .diff URLs. At most three."""
    urls: list[str] = []
    for ref in fix_refs:
        base = ref.split("?", 1)[0].split("#", 1)[0]
        if base.endswith(".diff"):
            base = base[: -len(".diff")]
        match = _COMMIT.search(base) or _PULL.search(base)
        if match is None:
            continue
        url = f"{match.group(0)}.diff"
        if url not in urls:
            urls.append(url)
        if len(urls) == _MAX_URLS:
            break
    return urls


def fetch_diff(http: HttpClient, url: str) -> str:
    """Download a diff and cut it at 400 KB.

    A GitHub pull diff that returns 403 or 429 is retried through the public
    patch-diff mirror. Commit diffs are left to the caller.
    """
    text = _download_diff(http, url)
    if len(text) > _MAX_DIFF:
        return text[:_MAX_DIFF]
    return text


def _download_diff(http: HttpClient, url: str) -> str:
    try:
        return http.get_text(url)
    except requests.HTTPError as exc:
        status = exc.response.status_code if exc.response is not None else None
        mirror = _pull_mirror(url) if status in {403, 429} else None
        if mirror is None:
            raise
        return http.get_text(mirror)


def _pull_mirror(url: str) -> str | None:
    base = url.split("?", 1)[0].split("#", 1)[0]
    match = _PULL.search(base)
    if match is None:
        return None
    owner, repo, number = match.group(1), match.group(2), match.group(3)
    return f"https://patch-diff.githubusercontent.com/raw/{owner}/{repo}/pull/{number}.diff"


def parse_unified_diff(text: str) -> list[FileChange]:
    """Parse a unified diff, skipping tests, docs, and non-Python files."""
    changes: list[FileChange] = []
    current: FileChange | None = None
    hunk: Hunk | None = None
    lines: list[str] = []
    new_line = 0
    for raw in text.splitlines():
        if raw.startswith("diff --git "):
            _flush(hunk, lines, current)
            hunk = None
            lines = []
            path = _new_path(raw)
            current = None if path is None or _skipped(path) else FileChange(path, [])
            if current is not None:
                changes.append(current)
            continue
        if current is None:
            continue
        header = _HUNK.match(raw)
        if header:
            _flush(hunk, lines, current)
            lines = []
            new_start = int(header.group(1))
            new_len = int(header.group(2) or "1")
            hunk = Hunk(new_start, new_len, header.group(3).strip(), [], 0, "")
            new_line = new_start
            continue
        if hunk is None or raw.startswith(("+++", "---", "index ", "@@")):
            continue
        if raw.startswith("+"):
            hunk.added_lines.append(new_line)
            new_line += 1
        elif raw.startswith("-"):
            hunk.removed_count += 1
            hunk.deletion_lines.append(new_line)
        elif raw.startswith("\\"):
            continue
        else:
            new_line += 1
        lines.append(raw)
    _flush(hunk, lines, current)
    return [change for change in changes if change.hunks]


def changed_functions(file_change: FileChange, new_source: str | None) -> list[str]:
    """Local names such as func or Class.method touched by this file."""
    found: list[str] = []
    if new_source:
        found.extend(_from_source(file_change, new_source))
    for name in _from_headers(file_change):
        if name not in found:
            found.append(name)
    return found


def fetch_new_source(http: HttpClient, diff_url: str, repo_path: str) -> str | None:
    """Fetch the new file for a commit diff. Pull diffs and errors return None."""
    match = _COMMIT.search(diff_url)
    if match is None:
        return None
    owner, repo, sha = match.group(1), match.group(2), match.group(3)
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{sha}/{repo_path}"
    try:
        return http.get_text(url)
    except (OfflineError, requests.RequestException, OSError):
        return None


def map_to_module(repo_path: str, index: Index, dist_import_names: list[str]) -> str | None:
    """Longest suffix match of a repo path against indexed module files."""
    repo_parts = PurePosixPath(repo_path).parts
    best: str | None = None
    best_len = -1
    for qualname, info in index.modules.items():
        if not _under(qualname, dist_import_names):
            continue
        file_parts = PurePosixPath(info.file).parts
        if not file_parts or len(file_parts) > len(repo_parts):
            continue
        if repo_parts[-len(file_parts) :] != file_parts:
            continue
        if len(file_parts) > best_len:
            best = qualname
            best_len = len(file_parts)
    return best


def _flush(hunk: Hunk | None, lines: list[str], current: FileChange | None) -> None:
    if hunk is None or current is None:
        return
    hunk.text = "\n".join(lines)
    current.hunks.append(hunk)


def _new_path(header: str) -> str | None:
    parts = header.split()
    if len(parts) < 4:
        return None
    path = parts[3]
    if path.startswith("b/"):
        path = path[2:]
    if path == "/dev/null":
        return None
    return path


def _skipped(path: str) -> bool:
    text = path.replace("\\", "/")
    if not text.endswith(".py"):
        return True
    markers = ("tests/", "docs/", "examples/", "benchmarks/", "test_")
    return any(marker in text for marker in markers)


def _from_source(file_change: FileChange, source: str) -> list[str]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    ranges = _ranges(tree)
    names: list[str] = []
    for hunk in file_change.hunks:
        for line in [*hunk.added_lines, *hunk.deletion_lines]:
            name = _enclosing(ranges, line)
            if name and name not in names:
                names.append(name)
    return names


def _ranges(tree: ast.AST) -> list[tuple[str, int, int]]:
    found: list[tuple[str, int, int]] = []

    def visit(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                qual = f"{prefix}.{child.name}" if prefix else child.name
                end = getattr(child, "end_lineno", None) or child.lineno
                found.append((qual, child.lineno, end))
                visit(child, qual)
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _enclosing(ranges: list[tuple[str, int, int]], line: int) -> str | None:
    best: tuple[str, int, int] | None = None
    for item in ranges:
        _name, start, end = item
        if start <= line <= end and (best is None or start >= best[1]):
            best = item
    if best is None:
        return None
    return best[0]


def _from_headers(file_change: FileChange) -> list[str]:
    names: list[str] = []
    for hunk in file_change.hunks:
        _add_def(hunk.header_context, names)
        for line in hunk.text.splitlines():
            body = line[1:] if line.startswith(("+", "-", " ")) else line
            _add_def(body.strip(), names)
    return names


def _add_def(text: str, names: list[str]) -> None:
    match = _DEF.match(text.strip())
    if match and match.group(1) not in names:
        names.append(match.group(1))


def _under(name: str, roots: list[str]) -> bool:
    return any(name == root or name.startswith(root + ".") for root in roots)
