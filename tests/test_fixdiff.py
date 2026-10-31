"""Fix-diff parsing, function mapping, and one real PyYAML diff."""

import pytest

from agent403.callgraph import Index, ModuleInfo
from agent403.fixdiff import (
    changed_functions,
    fetch_diff,
    github_diff_urls,
    map_to_module,
    parse_unified_diff,
)
from agent403.net import HttpClient

DIFF = """diff --git a/vulnlib/parser.py b/vulnlib/parser.py
--- a/vulnlib/parser.py
+++ b/vulnlib/parser.py
@@ -1,2 +1,2 @@ def _decode(data)
 def _decode(data: str) -> str:
-    return data
+    return data.strip()
diff --git a/tests/test_parser.py b/tests/test_parser.py
--- a/tests/test_parser.py
+++ b/tests/test_parser.py
@@ -1,1 +1,2 @@
+def test_decode():
+    pass
"""

SOURCE = """def _decode(data: str) -> str:
    return data.strip()


def unsafe_parse(data: str) -> str:
    return _decode(data)
"""

PYYAML_DIFF = "https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc.diff"


def test_github_diff_urls_drop_noise() -> None:
    refs = [
        "https://github.com/yaml/pyyaml/commit/a001f2782501ad2d24986959f0239a354675f9dc?w=1",
        "https://example.com/not-github",
        "https://github.com/pallets/jinja/pull/1343",
    ]
    urls = github_diff_urls(refs)
    assert urls[0].endswith(".diff")
    assert "a001f278" in urls[0]
    assert urls[1].endswith("/pull/1343.diff")
    assert len(urls) == 2


def test_parse_ignores_tests_and_maps_functions() -> None:
    changes = parse_unified_diff(DIFF)
    assert [change.path for change in changes] == ["vulnlib/parser.py"]
    names = changed_functions(changes[0], SOURCE)
    assert names == ["_decode"]
    fallback = changed_functions(changes[0], None)
    assert "_decode" in fallback


def test_map_to_module_uses_the_longest_suffix() -> None:
    index = Index()
    index.modules["yaml.constructor"] = ModuleInfo("yaml.constructor", "yaml/constructor.py", "dep")
    index.modules["yaml"] = ModuleInfo("yaml", "yaml/__init__.py", "dep")
    found = map_to_module("lib3/yaml/constructor.py", index, ["yaml"])
    assert found == "yaml.constructor"


@pytest.mark.network
def test_pyyaml_fix_diff_fetches() -> None:
    text = fetch_diff(HttpClient(), PYYAML_DIFF)
    assert "diff --git" in text
    assert parse_unified_diff(text)
