"""Call graph: fake apps, aliases, and the limits that keep a scan honest."""

import json
from pathlib import Path

from agent403.callgraph import Index, Root, find_path
from agent403.models import PathHop

FIXTURES = Path(__file__).parent / "fixtures"
SITE = FIXTURES / "site"
APPS = FIXTURES / "apps"
TARGET = "vulnlib.parser.unsafe_parse"


def _roots(app: Path, *, dep: Path = SITE) -> list[Root]:
    return [Root(app, "app"), Root(dep, "dep", ["vulnlib", "wrapperlib"])]


def _is_target(name: str) -> bool:
    return name == TARGET or name.startswith(TARGET + ".")


def _can_enter(name: str) -> bool:
    return name != "vulnlib" and not name.startswith("vulnlib.")


def _index(app_name: str) -> Index:
    return Index.build(_roots(APPS / app_name))


def _path(index: Index) -> list[PathHop] | None:
    return find_path(index, index.app_functions(), _is_target, _can_enter)


def _line(path: Path, text: str) -> int:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if text in line:
            return number
    raise AssertionError(f"{text!r} not in {path}")


def test_expected_labels_match_the_graph() -> None:
    for app in sorted(APPS.iterdir()):
        if not app.is_dir():
            continue
        expected = json.loads((app / "expected.json").read_text(encoding="utf-8"))["vulnlib"]
        index = _index(app.name)
        found = _path(index)
        if expected == "reachable":
            assert found, app.name
        else:
            assert found is None, app.name
        if expected == "not_affected":
            assert index.dynamic_sites == []
            assert index.unresolved_calls == []
            assert index.parse_errors == []


def test_indirect_chain_hops() -> None:
    app = APPS / "indirect_chain"
    index = _index("indirect_chain")
    found = find_path(index, ["main.main"], _is_target, _can_enter)
    assert found is not None
    assert [hop.symbol for hop in found] == ["main.main", "helpers.process", TARGET]
    assert (found[0].file, found[0].line) == ("main.py", _line(app / "main.py", "def main"))
    assert (found[1].file, found[1].line) == ("main.py", _line(app / "main.py", "process(data)"))
    assert (found[2].file, found[2].line) == (
        "helpers.py",
        _line(app / "helpers.py", "unsafe_parse"),
    )


def test_transitive_hops_go_through_wrapperlib() -> None:
    app = APPS / "transitive"
    found = _path(_index("transitive"))
    assert found is not None
    assert [hop.symbol for hop in found] == ["main.main", "wrapperlib.load", TARGET]
    assert found[0].file == "main.py"
    assert found[0].line == _line(app / "main.py", "def main")
    assert found[1].file == "main.py"
    assert found[1].line == _line(app / "main.py", "wrapperlib.load")
    assert found[2].file == "wrapperlib/__init__.py"
    assert found[2].line == _line(SITE / "wrapperlib" / "__init__.py", "unsafe_parse(data)")


def test_dynamic_getattr_is_uncertain() -> None:
    index = _index("dynamic_getattr")
    assert _path(index) is None
    sites = [site for site in index.dynamic_sites if site.kind == "getattr"]
    assert len(sites) == 1
    assert sites[0].target_module == "vulnlib"
    assert sites[0].line == _line(APPS / "dynamic_getattr" / "main.py", "getattr")


def test_unknown_receiver_is_unresolved() -> None:
    index = _index("unknown_receiver")
    assert _path(index) is None
    names = [call.method_name for call in index.unresolved_calls]
    assert "unsafe" in names


def test_syntax_error_is_recorded() -> None:
    index = _index("syntax_error")
    assert any(error.file == "broken.py" for error in index.parse_errors)
    assert "valid" in index.modules
    assert "broken" not in index.modules


def test_callback_and_class_method_reach_the_target() -> None:
    callback = _path(_index("callback_ref"))
    assert callback is not None
    assert callback[-1].symbol == TARGET
    callback_edges = _index("callback_ref").edges.values()
    assert any(edge.kind == "ref" for edges in callback_edges for edge in edges)

    method = _path(_index("class_method"))
    assert method is not None
    assert [hop.symbol for hop in method][-1] == TARGET
    assert any(hop.symbol.endswith(".unsafe") for hop in method)


def test_canonical_follows_reexport() -> None:
    index = _index("direct_call")
    assert index.canonical("vulnlib.unsafe_parse") == TARGET
    assert index.canonical("vulnlib.Parser") == "vulnlib.parser.Parser"
    assert "main.main" in index.app_functions()
    assert "vulnlib.parser.unsafe_parse" not in index.app_functions()


def test_relative_import_resolution(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    nested = package / "nested"
    nested.mkdir(parents=True)
    (package / "__init__.py").write_text("from .util import run\n", encoding="utf-8")
    (package / "util.py").write_text("def run() -> None:\n    return None\n", encoding="utf-8")
    (nested / "__init__.py").write_text("", encoding="utf-8")
    (nested / "mod.py").write_text("from ..util import run\n", encoding="utf-8")
    index = Index.build([Root(tmp_path, "app")])
    assert index.modules["pkg"].aliases["run"] == "pkg.util.run"
    assert index.modules["pkg.nested.mod"].aliases["run"] == "pkg.util.run"


def test_import_a_b_binds_the_head(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text("import a.b\nimport a.b as c\n", encoding="utf-8")
    index = Index.build([Root(tmp_path, "app")])
    assert index.modules["main"].aliases["a"] == "a"
    assert index.modules["main"].aliases["c"] == "a.b"


def test_star_import_copies_public_names(tmp_path: Path) -> None:
    (tmp_path / "lib.py").write_text(
        "def public() -> None:\n    return None\n\ndef _private() -> None:\n    return None\n",
        encoding="utf-8",
    )
    (tmp_path / "use.py").write_text(
        "from lib import *\n\ndef main() -> None:\n    public()\n",
        encoding="utf-8",
    )
    (tmp_path / "missing.py").write_text("from missing_mod import *\n", encoding="utf-8")
    index = Index.build([Root(tmp_path, "app")])
    assert index.modules["use"].aliases["public"] == "lib.public"
    assert "_private" not in index.modules["use"].aliases
    assert index.modules["missing"].star_unresolved is True
    edges = index.edges["use.main"]
    assert any(edge.dst == "lib.public" and edge.kind == "call" for edge in edges)


def test_constant_getattr_is_a_reference(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "import vulnlib\n\ndef main() -> None:\n    getattr(vulnlib, 'unsafe_parse')\n",
        encoding="utf-8",
    )
    index = Index.build(_roots(tmp_path))
    edges = index.edges["main.main"]
    assert any(edge.dst == TARGET and edge.kind == "ref" for edge in edges)
    assert not any(site.kind == "getattr" for site in index.dynamic_sites)


def test_import_module_constant_is_an_alias(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        "import importlib\n\n"
        "def main() -> None:\n"
        '    mod = importlib.import_module("vulnlib")\n'
        '    mod.unsafe_parse("x")\n',
        encoding="utf-8",
    )
    index = Index.build(_roots(tmp_path))
    edges = index.edges["main.main"]
    assert any(edge.dst == "vulnlib" and edge.kind == "ref" for edge in edges)
    assert any(edge.dst == TARGET and edge.kind == "call" for edge in edges)


def test_self_method_edge(tmp_path: Path) -> None:
    (tmp_path / "box.py").write_text(
        "class Box:\n"
        "    def run(self) -> None:\n"
        "        self.work()\n"
        "    def work(self) -> None:\n"
        "        return None\n",
        encoding="utf-8",
    )
    index = Index.build([Root(tmp_path, "app")])
    edges = index.edges["box.Box.run"]
    assert any(edge.dst == "box.Box.work" and edge.kind == "call" for edge in edges)


def test_instantiation_edges_to_init(tmp_path: Path) -> None:
    (tmp_path / "box.py").write_text(
        "class Box:\n"
        "    def __init__(self) -> None:\n"
        "        return None\n"
        "\ndef main() -> None:\n"
        "    Box()\n",
        encoding="utf-8",
    )
    index = Index.build([Root(tmp_path, "app")])
    dsts = {edge.dst for edge in index.edges["box.main"]}
    assert dsts == {"box.Box", "box.Box.__init__"}


def test_maximal_attribute_chain_has_one_edge(tmp_path: Path) -> None:
    (tmp_path / "main.py").write_text(
        'import vulnlib.parser\n\ndef main() -> None:\n    vulnlib.parser.unsafe_parse("x")\n',
        encoding="utf-8",
    )
    index = Index.build(_roots(tmp_path))
    dsts = [edge.dst for edge in index.edges["main.main"]]
    assert dsts == [TARGET]


def test_include_tests_flag(tmp_path: Path) -> None:
    (tmp_path / "mod.py").write_text("def app_func() -> None:\n    return None\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    body = "def {name}() -> None:\n    return None\n"
    (tests / "test_mod.py").write_text(body.format(name="test_func"), encoding="utf-8")
    (tmp_path / "test_root.py").write_text(body.format(name="test_root"), encoding="utf-8")
    (tmp_path / "conftest.py").write_text(body.format(name="helper"), encoding="utf-8")
    hidden = Index.build([Root(tmp_path, "app")])
    shown = Index.build([Root(tmp_path, "app")], include_tests=True)
    assert "mod" in hidden.modules
    assert "tests.test_mod" not in hidden.modules
    assert "test_root" not in hidden.modules
    assert "conftest" not in hidden.modules
    assert "tests.test_mod" in shown.modules
    assert "test_root" in shown.modules
    assert "conftest" in shown.modules


def test_skip_dirs(tmp_path: Path) -> None:
    (tmp_path / "mod.py").write_text("def visible() -> None:\n    return None\n", encoding="utf-8")
    venv = tmp_path / ".venv" / "pkg"
    venv.mkdir(parents=True)
    (venv / "hidden.py").write_text("def hidden() -> None:\n    return None\n", encoding="utf-8")
    index = Index.build([Root(tmp_path, "app")])
    assert "mod" in index.modules
    assert "hidden" not in index.symbols
    assert all(".venv" not in symbol.file for symbol in index.symbols.values())


def test_max_files_truncates_a_dependency(tmp_path: Path) -> None:
    package = tmp_path / "big"
    package.mkdir()
    body = "def {name}() -> None:\n    return None\n"
    for name in ("a", "b", "c", "d"):
        (package / f"{name}.py").write_text(body.format(name=name), encoding="utf-8")
    index = Index.build([Root(tmp_path, "dep", ["big"])], max_files_per_dep=2)
    assert index.truncated == {"big"}
    assert len([name for name in index.modules if name == "big" or name.startswith("big.")]) == 2


def test_src_layout_strips_the_prefix(tmp_path: Path) -> None:
    source = tmp_path / "src" / "pkg"
    source.mkdir(parents=True)
    (source / "mod.py").write_text("def run() -> None:\n    return None\n", encoding="utf-8")
    index = Index.build([Root(tmp_path, "app")])
    assert "pkg.mod" in index.modules
    assert index.modules["pkg.mod"].file == "src/pkg/mod.py"


def test_function_inside_package_is_not_peeked(tmp_path: Path) -> None:
    site = tmp_path / "site"
    package = site / "fakelib"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        "def vuln_func() -> int:\n"
        "    return 1\n"
        "\n"
        "def safe_func() -> int:\n"
        "    return vuln_func()\n",
        encoding="utf-8",
    )
    app = tmp_path / "app"
    app.mkdir()
    (app / "main.py").write_text(
        "import fakelib\n\ndef main() -> int:\n    return fakelib.safe_func()\n",
        encoding="utf-8",
    )
    index = Index.build([Root(app, "app"), Root(site, "dep", ["fakelib"])])

    def is_target(name: str) -> bool:
        return name == "fakelib.vuln_func" or name.startswith("fakelib.vuln_func.")

    def can_enter(name: str) -> bool:
        return name != "fakelib" and not name.startswith("fakelib.")

    assert find_path(index, ["main.main"], is_target, can_enter) is None
