"""Index functions, imports, calls, and references with the Python AST."""

import ast
import os
from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from agent403.models import PathHop

_SKIP_DIRS = {
    ".venv",
    "venv",
    "env",
    ".git",
    "site-packages",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
    ".tox",
    ".mypy_cache",
    ".ruff_cache",
}
_TEST_DIRS = {"tests", "test"}


@dataclass
class Root:
    path: Path
    kind: str
    packages: list[str] | None = None


@dataclass
class Symbol:
    qualname: str
    kind: str
    file: str
    line: int


@dataclass
class Edge:
    src: str
    dst: str
    file: str
    line: int
    kind: str


@dataclass
class DynamicSite:
    func: str
    file: str
    line: int
    kind: str
    detail: str
    target_module: str | None


@dataclass
class UnresolvedCall:
    func: str
    method_name: str
    file: str
    line: int


@dataclass
class ParseError:
    file: str
    module: str
    message: str


@dataclass
class ModuleInfo:
    qualname: str
    file: str
    root_kind: str
    aliases: dict[str, str] = field(default_factory=dict)
    defs: set[str] = field(default_factory=set)
    all_names: list[str] | None = None
    star_imports: list[str] = field(default_factory=list)
    star_unresolved: bool = False


class Index:
    """Symbols and edges for one scan."""

    def __init__(self) -> None:
        self.symbols: dict[str, Symbol] = {}
        self.edges: dict[str, list[Edge]] = {}
        self.modules: dict[str, ModuleInfo] = {}
        self.dynamic_sites: list[DynamicSite] = []
        self.unresolved_calls: list[UnresolvedCall] = []
        self.parse_errors: list[ParseError] = []
        self.truncated: set[str] = set()
        self.methods: dict[str, set[str]] = {}
        self.class_bases: dict[str, list[str]] = {}

    @classmethod
    def build(
        cls,
        roots: list[Root],
        include_tests: bool = False,
        max_files_per_dep: int = 3000,
    ) -> "Index":
        index = cls()
        _Indexer(index).run(roots, include_tests, max_files_per_dep)
        return index

    def app_functions(self) -> list[str]:
        """Every function, method, and module body defined under an app root."""
        names: list[str] = []
        for qualname, symbol in self.symbols.items():
            module = self.module_of(qualname)
            if module is None or self.modules[module].root_kind != "app":
                continue
            if symbol.kind in {"function", "method", "module"}:
                names.append(qualname)
        return sorted(names)

    def module_of(self, qualname: str) -> str | None:
        """Return the indexed module that contains this qualname."""
        if qualname in self.modules:
            return qualname
        parts = qualname.split(".")
        for length in range(len(parts) - 1, 0, -1):
            candidate = ".".join(parts[:length])
            if candidate in self.modules:
                return candidate
        return None

    def canonical(self, dotted: str) -> str:
        """Follow re-export aliases, longest-prefix first, at most 10 steps.

        vulnlib/__init__.py does `from .parser import unsafe_parse`, so
        canonical("vulnlib.unsafe_parse") is "vulnlib.parser.unsafe_parse".
        A real function or class definition stops the walk.
        """
        current = dotted
        for _ in range(10):
            parts = current.split(".")
            if len(parts) < 2:
                break
            matched = 0
            for length in range(len(parts) - 1, 0, -1):
                if ".".join(parts[:length]) in self.modules:
                    matched = length
                    break
            if not matched:
                break
            module_name = ".".join(parts[:matched])
            name = parts[matched]
            rest = parts[matched + 1 :]
            info = self.modules[module_name]
            if name in info.defs:
                break
            alias = info.aliases.get(name)
            if not alias:
                break
            updated = alias if not rest else f"{alias}.{'.'.join(rest)}"
            if updated == current:
                break
            current = updated
        return current


def find_path(
    index: Index,
    sources: Iterable[str],
    is_target: Callable[[str], bool],
    can_enter: Callable[[str], bool],
) -> list[PathHop] | None:
    """Shortest path from any source to a target symbol.

    The first hop is the source function at its definition. Later hops use the
    call site. A method just inside a package we must not explore is still
    checked for a direct call to the target, so Parser.unsafe() can reach
    unsafe_parse. Plain functions are not entered: safe_func() calling
    vuln_func() must not mark callers of safe_func as reachable.
    """
    queue: deque[str] = deque(sorted(sources))
    seen = set(queue)
    parent: dict[str, tuple[str, Edge]] = {}

    def rebuild(target: str) -> list[PathHop]:
        hops: list[tuple[str, str | None, int | None]] = []
        node = target
        while node in parent:
            previous, edge = parent[node]
            hops.append((node, edge.file, edge.line))
            node = previous
        symbol = index.symbols.get(node)
        hops.append((node, symbol.file if symbol else None, symbol.line if symbol else None))
        hops.reverse()
        return [PathHop(name, file, line) for name, file, line in hops]

    def edge_key(edge: Edge) -> tuple[str, str, int, str]:
        return (edge.dst, edge.file, edge.line, edge.kind)

    while queue:
        current = queue.popleft()
        if not can_enter(current):
            continue
        for edge in sorted(index.edges.get(current, []), key=edge_key):
            if is_target(edge.dst):
                parent[edge.dst] = (current, edge)
                return rebuild(edge.dst)
            if not can_enter(edge.dst):
                # Only methods. Peeking into safe_load() would flag it when it calls load().
                symbol = index.symbols.get(edge.dst)
                if symbol is not None and symbol.kind == "method":
                    for inner in sorted(index.edges.get(edge.dst, []), key=edge_key):
                        if is_target(inner.dst):
                            parent[edge.dst] = (current, edge)
                            parent[inner.dst] = (edge.dst, inner)
                            return rebuild(inner.dst)
                continue
            if edge.dst in seen or not index.edges.get(edge.dst):
                continue
            seen.add(edge.dst)
            parent[edge.dst] = (current, edge)
            queue.append(edge.dst)
    return None


class _Indexer:
    def __init__(self, index: Index) -> None:
        self.index = index

    def run(self, roots: list[Root], include_tests: bool, max_files_per_dep: int) -> None:
        files = self._collect(roots, include_tests, max_files_per_dep)
        parsed: list[tuple[ast.AST, str, str]] = []
        for path, module, rel_file, is_package, kind in files:
            tree = self._read(path, module, rel_file)
            if tree is None:
                continue
            self._define(tree, module, rel_file, is_package, kind)
            parsed.append((tree, module, rel_file))
        self._resolve_stars()
        for tree, module, rel_file in parsed:
            _Visitor(self.index, module, rel_file).run(tree)

    def _collect(
        self,
        roots: list[Root],
        include_tests: bool,
        max_files_per_dep: int,
    ) -> list[tuple[Path, str, str, bool, str]]:
        collected: list[tuple[Path, str, str, bool, str]] = []
        for root in roots:
            if root.kind == "dep" and root.packages:
                for package in root.packages:
                    files, truncated = _package_files(
                        root.path, package, include_tests, max_files_per_dep
                    )
                    if truncated:
                        self.index.truncated.add(package)
                    for path in files:
                        described = _described(root, path)
                        collected.append((*described, root.kind))
                continue
            for path in _py_files(root.path, include_tests):
                described = _described(root, path)
                collected.append((*described, root.kind))
        return collected

    def _read(self, path: Path, module: str, rel_file: str) -> ast.AST | None:
        try:
            source = path.read_text(encoding="utf-8")
            return ast.parse(source, filename=str(path))
        except (SyntaxError, UnicodeDecodeError) as exc:
            self.index.parse_errors.append(ParseError(rel_file, module, str(exc)))
            return None

    def _define(
        self,
        tree: ast.AST,
        module: str,
        rel_file: str,
        is_package: bool,
        kind: str,
    ) -> None:
        info = ModuleInfo(module, rel_file, kind)
        self.index.modules[module] = info
        self.index.symbols[f"{module}.<module>"] = Symbol(
            f"{module}.<module>", "module", rel_file, 1
        )
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                _record_import(node, info, module, is_package)
        for statement in tree.body:
            if isinstance(statement, ast.ClassDef):
                self._define_class(statement, module, rel_file, module)
            elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._define_function(statement, f"{module}.{statement.name}", rel_file)
            elif isinstance(statement, ast.Assign):
                names = _literal_all(statement)
                if names is not None:
                    info.all_names = names

    def _define_class(self, node: ast.ClassDef, module: str, rel_file: str, prefix: str) -> None:
        qualname = f"{prefix}.{node.name}"
        info = self.index.modules[module]
        if prefix == module:
            info.defs.add(node.name)
        self.index.symbols[qualname] = Symbol(qualname, "class", rel_file, node.lineno)
        bases: list[str] = []
        for base in node.bases:
            text = _dotted_name(base)
            if text:
                bases.append(text)
        self.index.class_bases[qualname] = bases
        methods: set[str] = set()
        for item in node.body:
            if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method = f"{qualname}.{item.name}"
                self.index.symbols[method] = Symbol(method, "method", rel_file, item.lineno)
                methods.add(item.name)
            elif isinstance(item, ast.ClassDef):
                self._define_class(item, module, rel_file, qualname)
        self.index.methods[qualname] = methods

    def _define_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        qualname: str,
        rel_file: str,
    ) -> None:
        name = qualname.rsplit(".", 1)[-1]
        self.index.modules[qualname.rsplit(".", 1)[0]].defs.add(name)
        self.index.symbols[qualname] = Symbol(qualname, "function", rel_file, node.lineno)

    def _resolve_stars(self) -> None:
        for info in self.index.modules.values():
            for target in info.star_imports:
                other = self.index.modules.get(target)
                if other is None:
                    info.star_unresolved = True
                    continue
                names = other.all_names
                if names is None:
                    names = [
                        name for name in (*other.defs, *other.aliases) if not name.startswith("_")
                    ]
                for name in names:
                    if name in info.defs or name in info.aliases:
                        continue
                    info.aliases[name] = other.aliases.get(name, f"{target}.{name}")


class _Visitor(ast.NodeVisitor):
    """Second pass: edges, dynamic sites, and a little local type inference."""

    def __init__(self, index: Index, module: str, rel_file: str) -> None:
        self.index = index
        self.module = module
        self.file = rel_file
        self.info = index.modules[module]
        self.owner = f"{module}.<module>"
        self.scope: list[tuple[str, str]] = [("module", module)]
        self.class_stack: list[str] = []
        self.types: dict[str, dict[str, str]] = {}
        self.module_vars: dict[str, dict[str, str]] = {}
        self._seen: set[tuple[str, str, str, int, str]] = set()

    def run(self, tree: ast.AST) -> None:
        for statement in tree.body:
            self.visit(statement)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        self.scope.append(("class", node.name))
        for statement in node.body:
            self.visit(statement)
        self.scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        # Lambdas stay in the enclosing top-level function.
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        self.visit(node.value)
        if len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            if isinstance(node.value, ast.Call):
                self._infer(node.targets[0].id, node.value)

    def visit_Call(self, node: ast.Call) -> None:
        if self._handle_dynamic(node):
            for arg in node.args:
                self.visit(arg)
            for keyword in node.keywords:
                self.visit(keyword.value)
            return
        resolved = self._resolve(node.func)
        if resolved:
            self._emit("call", resolved, node.lineno)
            self._emit_init(resolved, node.lineno)
        elif isinstance(node.func, ast.Attribute):
            self.index.unresolved_calls.append(
                UnresolvedCall(self.owner, node.func.attr, self.file, node.lineno)
            )
        elif isinstance(node.func, ast.Call):
            self.visit(node.func)
        for arg in node.args:
            self.visit(arg)
        for keyword in node.keywords:
            self.visit(keyword.value)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # Only the outermost attribute chain becomes an edge.
        if isinstance(getattr(node, "_agent403_inner", None), bool):
            return
        self._mark_inner(node.value)
        if isinstance(node.ctx, ast.Load):
            resolved = self._resolve(node)
            if resolved:
                self._emit("ref", resolved, node.lineno)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(getattr(node, "_agent403_inner", None), bool):
            return
        if isinstance(node.ctx, ast.Load):
            resolved = self._resolve(node)
            if resolved:
                self._emit("ref", resolved, node.lineno)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_arguments(node.args)
        parent = self.scope[-1][0]
        if parent == "func":
            for statement in node.body:
                self.visit(statement)
            return
        if parent == "class":
            class_name = self._class_qualname()
            qualname = f"{class_name}.{node.name}"
            self.class_stack.append(class_name)
        else:
            qualname = f"{self.module}.{node.name}"
            class_name = ""
        previous = self.owner
        self.owner = qualname
        self.scope.append(("func", qualname))
        for statement in node.body:
            self.visit(statement)
        self.scope.pop()
        self.owner = previous
        if parent == "class":
            self.class_stack.pop()

    def _visit_arguments(self, args: ast.arguments) -> None:
        for default in [*args.defaults, *args.kw_defaults]:
            if default is not None:
                self.visit(default)

    def _infer(self, name: str, call: ast.Call) -> None:
        imported = _constant_module_call(call)
        if imported and _is_import_module(call):
            self.module_vars.setdefault(self.owner, {})[name] = imported
            return
        resolved = self._resolve(call.func)
        if not resolved:
            return
        canonical = self.index.canonical(resolved)
        symbol = self.index.symbols.get(canonical)
        last = canonical.rsplit(".", 1)[-1]
        if (symbol and symbol.kind == "class") or last[:1].isupper():
            self.types.setdefault(self.owner, {})[name] = canonical

    def _handle_dynamic(self, node: ast.Call) -> bool:
        kind = _dynamic_kind(node)
        if kind is None:
            return False
        if kind == "getattr" and len(node.args) >= 2:
            constant = _constant_str(node.args[1])
            if constant is not None:
                fake = ast.Attribute(value=node.args[0], attr=constant, ctx=ast.Load())
                resolved = self._resolve(fake)
                if resolved:
                    self._emit("ref", resolved, node.lineno)
                return True
            self._add_dynamic(
                "getattr", ast.unparse(node.args[1]), self._as_module(node.args[0]), node.lineno
            )
            return True
        if kind in {"import_module", "__import__"}:
            constant = _constant_str(node.args[0]) if node.args else None
            if constant is not None:
                self._emit("ref", constant, node.lineno)
            else:
                detail = ast.unparse(node.args[0]) if node.args else ""
                self._add_dynamic(kind, detail, None, node.lineno)
            return True
        if kind in {"eval", "exec"}:
            self._add_dynamic(kind, kind, None, node.lineno)
            return True
        if kind == "setattr" and node.args:
            target = self._as_module(node.args[0])
            if target is not None:
                detail = ast.unparse(node.args[1]) if len(node.args) > 1 else ""
                self._add_dynamic("setattr", detail, target, node.lineno)
                return True
        return False

    def _add_dynamic(self, kind: str, detail: str, target: str | None, line: int) -> None:
        self.index.dynamic_sites.append(
            DynamicSite(self.owner, self.file, line, kind, detail, target)
        )

    def _emit(self, kind: str, dst: str, line: int) -> None:
        canonical = self.index.canonical(dst)
        if canonical not in self.index.symbols and canonical not in self.index.modules:
            return
        key = (self.owner, canonical, self.file, line, kind)
        if key in self._seen:
            return
        self._seen.add(key)
        self.index.edges.setdefault(self.owner, []).append(
            Edge(self.owner, canonical, self.file, line, kind)
        )

    def _emit_init(self, dst: str, line: int) -> None:
        canonical = self.index.canonical(dst)
        symbol = self.index.symbols.get(canonical)
        if symbol and symbol.kind == "class" and f"{canonical}.__init__" in self.index.symbols:
            self._emit("call", f"{canonical}.__init__", line)

    def _resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if not isinstance(node.ctx, ast.Load):
                return None
            if node.id in self.types.get(self.owner, {}):
                return None
            bound = self.module_vars.get(self.owner, {}).get(node.id)
            if bound:
                return bound
            if node.id in self.info.defs:
                return f"{self.module}.{node.id}"
            return self.info.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id in {"self", "cls"}:
                if self.class_stack:
                    return self._resolve_method(self.class_stack[-1], node.attr)
                return None
            if isinstance(node.value, ast.Name) and node.value.id in self.types.get(self.owner, {}):
                return f"{self.types[self.owner][node.value.id]}.{node.attr}"
            head = self._resolve(node.value)
            if head is None:
                return None
            return f"{head}.{node.attr}"
        return None

    def _resolve_method(self, class_qual: str, method: str) -> str | None:
        if method in self.index.methods.get(class_qual, set()):
            return f"{class_qual}.{method}"
        for base in self._bases(class_qual):
            found = self._resolve_method(base, method)
            if found:
                return found
        return None

    def _bases(self, class_qual: str) -> list[str]:
        module = self.index.module_of(class_qual) or self.module
        found: list[str] = []
        for raw in self.index.class_bases.get(class_qual, []):
            resolved = _resolve_base(raw, module, self.index)
            if resolved and resolved not in found:
                found.append(resolved)
        return found

    def _as_module(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            bound = self.module_vars.get(self.owner, {}).get(node.id)
            if bound and (bound in self.index.modules or "." not in bound):
                return bound if bound in self.index.modules else bound
        resolved = self._resolve(node)
        if not resolved:
            return None
        canonical = self.index.canonical(resolved)
        if canonical in self.index.modules:
            return canonical
        return None

    def _class_qualname(self) -> str:
        names = [name for kind, name in self.scope if kind == "class"]
        return ".".join([self.module, *names])

    def _mark_inner(self, node: ast.AST) -> None:
        if isinstance(node, (ast.Attribute, ast.Name)):
            node._agent403_inner = True  # type: ignore[attr-defined]
            if isinstance(node, ast.Attribute):
                self._mark_inner(node.value)


def _record_import(
    node: ast.Import | ast.ImportFrom,
    info: ModuleInfo,
    module: str,
    is_package: bool,
) -> None:
    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                info.aliases[alias.asname] = alias.name
            else:
                head = alias.name.split(".", 1)[0]
                info.aliases[head] = head
        return
    base = node.module or ""
    if node.level:
        base = _relative_module(module, is_package, node.level, node.module)
    for alias in node.names:
        if alias.name == "*":
            info.star_imports.append(base)
            continue
        local = alias.asname or alias.name
        info.aliases[local] = f"{base}.{alias.name}" if base else alias.name


def _relative_module(current: str, is_package: bool, level: int, module: str | None) -> str:
    parts = [part for part in current.split(".") if part]
    if not is_package and parts:
        parts = parts[:-1]
    drop = level - 1
    if drop:
        parts = parts[:-drop] if drop <= len(parts) else []
    if module:
        parts.extend(module.split("."))
    return ".".join(parts)


def _resolve_base(raw: str, module: str, index: Index) -> str | None:
    info = index.modules.get(module)
    if info is None:
        return None
    parts = raw.split(".")
    head = parts[0]
    if head in info.aliases:
        resolved = info.aliases[head]
    elif head in info.defs:
        resolved = f"{module}.{head}"
    else:
        resolved = head
    if len(parts) > 1:
        resolved = f"{resolved}.{'.'.join(parts[1:])}"
    canonical = index.canonical(resolved)
    symbol = index.symbols.get(canonical)
    if symbol and symbol.kind == "class":
        return canonical
    return None


def _literal_all(node: ast.Assign) -> list[str] | None:
    targets = [target for target in node.targets if isinstance(target, ast.Name)]
    if not any(target.id == "__all__" for target in targets):
        return None
    if not isinstance(node.value, (ast.List, ast.Tuple)):
        return None
    names: list[str] = []
    for item in node.value.elts:
        if not isinstance(item, ast.Constant) or not isinstance(item.value, str):
            return None
        names.append(item.value)
    return names


def _dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        head = _dotted_name(node.value)
        if head:
            return f"{head}.{node.attr}"
    return None


def _constant_str(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _constant_module_call(node: ast.Call) -> str | None:
    if not node.args:
        return None
    return _constant_str(node.args[0])


def _is_import_module(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        return True
    return isinstance(func, ast.Name) and func.id == "__import__"


def _dynamic_kind(node: ast.Call) -> str | None:
    func = node.func
    dynamic_names = {"getattr", "eval", "exec", "setattr", "__import__"}
    if isinstance(func, ast.Name) and func.id in dynamic_names:
        return "__import__" if func.id == "__import__" else func.id
    if isinstance(func, ast.Attribute) and func.attr == "import_module":
        return "import_module"
    if isinstance(func, ast.Name) and func.id == "import_module":
        return "import_module"
    return None


def _package_files(
    root: Path,
    package: str,
    include_tests: bool,
    limit: int,
) -> tuple[list[Path], bool]:
    directory = root / package
    module_file = root / f"{package}.py"
    if directory.is_dir():
        files = _py_files(directory, include_tests)
    elif module_file.is_file():
        files = [module_file]
    else:
        return [], False
    return files[:limit], len(files) > limit


def _py_files(folder: Path, include_tests: bool) -> list[Path]:
    if not folder.is_dir():
        return []
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(folder):
        dirnames[:] = [
            name
            for name in sorted(dirnames)
            if name not in _SKIP_DIRS and (include_tests or name not in _TEST_DIRS)
        ]
        for filename in sorted(filenames):
            if not filename.endswith(".py"):
                continue
            path = Path(dirpath) / filename
            if not include_tests and _is_test_file(path):
                continue
            found.append(path)
    return found


def _is_test_file(path: Path) -> bool:
    name = path.name
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


def _described(root: Root, path: Path) -> tuple[Path, str, str, bool]:
    rel = path.relative_to(root.path)
    parts = list(rel.parts)
    if root.kind == "app" and parts[:1] == ["src"]:
        parts = parts[1:]
    is_package = bool(parts) and parts[-1] == "__init__.py"
    if is_package:
        parts = parts[:-1]
    elif parts and parts[-1].endswith(".py"):
        parts[-1] = parts[-1][:-3]
    return path, ".".join(parts), rel.as_posix(), is_package
