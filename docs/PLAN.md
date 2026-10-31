# Agent 403 — Master Plan & Context (Team 403, Problem 03)

> This file is the single source of truth for the build. Put it in the repo as `docs/PLAN.md`
> so Cursor can read it in every prompt. Tool name: **Agent 403** (CLI command and Python package: `agent403`).

---

## 0. Hard constraints (from the PPT + Problem Statement doc)

| Item | Rule |
|---|---|
| Hack window | 31 Oct 6:30 PM → **1 Nov 6:30 AM**. Repos are fetched at 6:30 AM; later pushes don't count. |
| First commit | Only `HACKATHON.md`, directly on `main` (done). |
| After that | **Every change through a PR.** No direct pushes to `main`. Every PR runs CI and uses the PR template. |
| Every PR must state | What it does · Models the product uses in this PR · AI coding assistants used (Claude Code / Cursor / none) · How we tested it. |
| Required files | `LICENSE` (MIT), `HACKATHON.md`, `.github/pull_request_template.md`, `.github/workflows/ci.yml`, `README.md`, `examples/` (real input + real output). |
| CI | Installs project + runs tests on every PR. **Must be green on the final commit** or we lose correctness points. |
| Secrets | No API keys / `.env` in the repo, ever. Scanner checks full git history. |
| Models | Product must use an **open-weight model at runtime** (local Ollama or organizers' model server). Closed APIs = 0 AI points and fail on test machines (no keys there). Claiming an unused model = 0 AI points and −5 overall. |
| Test machines | Organizers run our tool themselves. **No API keys there.** Network/model availability unknown, so the tool must still work with no model and ideally offline. |
| Safety | Never run code from the analyzed project or its dependencies. Never post on real repos. Public data only. |
| Presentation | 8:30 AM: 8 min pitch + 4 min Q&A. Live demo. Any member can be questioned on any code. |

### Scoring (100)
- Automated 70: Functional correctness **30** · Open-source AI use **15** · Testing & evidence **15** · PR/CI workflow **10**
- Panel 30: Design & trade-offs Q&A **10** · Live demo & usability **10** · Problem understanding **10**

---

## 1. The problem, in depth

Scanners such as `pip-audit` and OSV-Scanner say "package X version Y has CVE Z". They work at the **package** level.
Most of those alerts are noise: the app never calls the vulnerable function. Go has `govulncheck`, which checks
**symbol-level reachability** because the Go vuln DB lists vulnerable symbols. Python has no maintained equivalent, because:

1. **Python advisories rarely name the vulnerable function** (PyPA / GHSA entries are prose plus a fix commit link).
2. **Python is dynamic**: `getattr`, `importlib`, monkey-patching, duck typing and callbacks make static call graphs approximate.
3. **Import name ≠ distribution name** (`PyYAML` → `yaml`, `Pillow` → `PIL`), plus re-exports (`requests.get` is really `requests.api.get`).
4. **Transitive paths**: the app may call library A, which calls the vulnerable function in library B.

**The organizers' test:** small Python apps pinned to vulnerable versions. Some call the vulnerable function, some don't.
We must label each correctly **with evidence**. The doc explicitly says: *"Prioritize avoiding incorrect claims that a project is safe."*

### Our core principle: asymmetric safety
- **REACHABLE**: we found a concrete path from app code to a vulnerable symbol. Show the path with file:line for each hop.
- **NOT_AFFECTED**: only when the vulnerable symbols are known **and** no resolved path exists **and** no dynamic or unresolved code could reach them.
- **UNCERTAIN**: everything else, with listed reasons. *We never say "safe" when we are not sure.*

### Running example (use everywhere: tests, README, demo)
PyYAML 5.3.1 has CVE-2020-14343: arbitrary code execution through `full_load` / `FullLoader`.
- `yaml.full_load(f)` → **REACHABLE**
- `yaml.load(f, Loader=yaml.FullLoader)` → **REACHABLE** (a *reference* to `FullLoader` counts as a use)
- `yaml.safe_load(f)` only → **NOT_AFFECTED**
- `getattr(yaml, fn_name)(f)` → **UNCERTAIN**

Second real example: Jinja2 2.10, CVE-2019-10906 (sandbox escape via `str.format_map`). An app using
`jinja2.sandbox.SandboxedEnvironment` → REACHABLE; an app using only a plain `Environment`/`Template` → NOT_AFFECTED.
*(Verify both advisories through OSV during the build; never hardcode IDs we haven't checked.)*

---

## 2. Architecture

```
project dir
   │
   ▼
[1] deps.py ── parse requirements.txt / pyproject.toml → [(dist_name, version)]
   │
   ▼
[2] osv.py ── OSV API (querybatch + /v1/vulns/{id}) → advisories (cached)
   │
   ▼
[3] pypi.py ── download the WHEEL of each relevant dist from PyPI JSON API (never pip install,
   │           never run setup.py) → extract to cache → map dist → import names (top_level.txt / RECORD)
   ▼
[4] callgraph.py ── AST index of app code + relevant dependency code → symbols, imports, call/reference edges,
   │                dynamic sites
   ▼
[5] symbols.py ── which symbols are vulnerable?
   │   a. shipped cache (data/symbols_cache.json, generated by OUR pipeline + model, with provenance)
   │   b. fix-commit diff (OSV FIX refs → GitHub .diff) → changed functions → map to package qualnames
   │   c. static candidates = public API symbols of the package that reach the changed functions
   │   d. OPEN MODEL (Ollama / OpenAI-compatible server): advisory text + diff excerpt + candidates
   │      → JSON list of vulnerable public entry symbols + safe symbols
   │   e. VALIDATE: drop any symbol not present in the vulnerable version's AST index (anti-hallucination)
   │   f. fallback: no model → static candidates (conservative superset); nothing → "unknown"
   ▼
[6] analyzer.py ── BFS from app entry points → path to vulnerable symbol? + dynamic/unresolved checks → verdict
   │
   ▼
[7] report.py / vex.py ── rich table, JSON report, OpenVEX 0.2.0 document; exit codes
```

### Where the open model does real work (Open-Source AI Use, 15 pts)
Step 5d. The model reads the advisory prose and the fix diff and decides **which public functions a user would call to trigger the bug**
(e.g., `full_load` and `FullLoader` yes, `safe_load` no). Static analysis alone can't make this judgment well,
because fix diffs touch internal helpers. The model's output is **validated** against real symbols, and its provenance
(model name, time, inputs hash) is recorded in the cache and the report.

---

## 3. Module specs (what Cursor must build)

Python ≥ 3.10. Runtime deps: `requests`, `packaging`, `typer`, `rich`, `tomli` (py<3.11). Dev: `pytest`, `ruff`.
Package layout: `src/agent403/…`, console script `agent403 = agent403.cli:app`.

### 3.1 `deps.py`
- Parse `requirements*.txt`: `name==version`, ignore comments, `-r` includes (recursive), env markers (keep), extras `pkg[x]==1`.
- Parse `pyproject.toml` `[project].dependencies` (only `==` pins) and Poetry lock if present (stretch).
- Unpinned deps → a warning in the report (`"unpinned": true`), skipped for OSV (or latest: no).
- Normalize names per PEP 503 (`re.sub(r"[-_.]+", "-", name).lower()`).

### 3.2 `osv.py`
- `POST https://api.osv.dev/v1/querybatch` with `{"queries":[{"package":{"name":n,"ecosystem":"PyPI"},"version":v}]}` → vuln ids.
- `GET https://api.osv.dev/v1/vulns/{id}` → full record (summary, details, aliases, affected ranges, references).
- Extract: `id`, `aliases`, `summary`, `details`, `fixed_versions`, `fix_refs` (references with type `FIX`, plus any URL that looks like a GitHub commit or PR).
- Disk cache: `~/.cache/agent403/osv/{id}.json`. `--offline` reads only the cache plus `data/osv_cache/` shipped in the repo.
- Dedupe: PYSEC and GHSA often describe the same CVE → merge by shared alias, keep one finding.

### 3.3 `pypi.py`
- `GET https://pypi.org/pypi/{name}/{version}/json` → pick a `py3-none-any` wheel, else any wheel for the current platform, else the sdist tarball.
- Download to `~/.cache/agent403/dists/`, extract with **zip-slip / tar path-traversal protection**. Never execute anything.
- Import names: wheel `*.dist-info/top_level.txt`, else top-level dirs/modules in `RECORD`.
- `Requires-Dist` from `METADATA` → used to find intermediate deps (deps of the app that depend on the vulnerable dist).
- Offline: use `tests/fixtures/site/` or cache only.

### 3.4 `callgraph.py` (the heart; most care here)
Build an index over a set of **roots**: the app dir plus extracted dependency packages.
- **Module names** from paths (handle `src/` layouts and `__init__.py`).
- **Definitions**: functions `mod.f`, classes `mod.C`, methods `mod.C.m`, module body `mod.<module>`. Nested functions are folded into their enclosing top-level function. Record file + line.
- **Imports per module**: `import a.b as c` → `c ↦ a.b`; `from a.b import x as y` → `y ↦ a.b.x`; relative imports resolved; `from m import *` → star import (resolved lazily from the target module's names/`__all__` if indexed; otherwise an "unresolved" marker).
- **Canonicalization**: resolve `requests.get` → `requests.api.get` by following re-export aliases in package `__init__` files (loop-safe, max depth 10).
- **Edges** from each function to:
  - **Calls**: `f()`, `a.b.c()` via import aliases; `self.m()` / `cls.m()` → own class (plus resolvable base classes); `C()` → `C` and `C.__init__`.
  - **Simple local type inference**: `x = C(...)` or `x = mod.C(...)` then `x.m()` → `C.m` (same function scope only).
  - **References** (not just calls): any load of a name/attribute that resolves to an indexed symbol is an edge. This catches callbacks (`map(yaml.full_load, xs)`), aliasing (`fn = yaml.full_load`) and arguments (`Loader=yaml.FullLoader`).
- **Dynamic sites** (recorded with file:line and kind): `getattr(x, non_constant)`, `importlib.import_module(non_constant)`, `__import__`, `eval`, `exec`, `setattr` on modules. `getattr(x, "const")` → treated as attribute access `x.const`.
- **Unresolved attribute calls**: `obj.m()` where `obj` is unknown → record `(method_name, file, line)`.
- Skip dirs: `.venv`, `venv`, `env`, `.git`, `site-packages`, `__pycache__`, `build`, `dist`, `node_modules`. Tests excluded by default (`tests/`, `test_*.py`, `*_test.py`); `--include-tests` flag.
- Parse errors in a file → recorded as a "parse_error" reason (the result for anything touching it becomes UNCERTAIN, never NOT_AFFECTED).
- Limits: max files per dependency (e.g., 3000) and time budget; if hit → reason "analysis_truncated" → UNCERTAIN.

### 3.5 `symbols.py`
Output for each vuln: `VulnSymbols(symbols=[...], safe_symbols=[...], source="cache|llm|static|none", confidence="high|medium|low", provenance={...}, rejected=[...])`.
1. **Shipped cache** `data/symbols_cache.json` keyed by advisory id **and** aliases. Every entry includes `generated_by` (model name or "static"), `generated_at`, `reviewed: true|false`.
2. **Fix diff**: for GitHub commit or PR URLs, fetch `<url>.diff`. Ignore test/doc files. Changed functions come from (a) new-side line numbers mapped onto the file fetched from `raw.githubusercontent.com/{o}/{r}/{sha}/{path}` via AST, falling back to (b) `@@ … @@ def name` hunk headers and `def`/`class` lines inside hunks. Map repo paths to package modules by **longest path-suffix match** against the wheel's files (handles `lib/`, `lib3/`, `src/`).
3. **Static candidates**: public symbols of the package (in `__init__`/`__all__`, not starting with `_`) that reach a changed function through the package-internal call graph, plus changed functions that are themselves public.
4. **LLM** (`llm.py`): `temperature=0`, JSON output. Prompt contains: advisory id/summary/details (truncated ~3k chars), package + version, the candidate list, and a diff excerpt (~5k chars). Ask for:
   `{"vulnerable_symbols":[{"symbol":"yaml.full_load","why":"..."}],"safe_symbols":[{"symbol":"yaml.safe_load","why":"..."}],"confidence":"high|medium|low"}`
5. **Validate**: keep only symbols that canonicalize to a real symbol in the vulnerable version's index; put the rest in `rejected`. If nothing is valid → use static candidates with `confidence=low`.
6. Within the **vulnerable package** we do **not** traverse internal calls. Its public entry symbols are the boundary. (This prevents false positives such as `safe_load → load` in PyYAML.)

### 3.6 `llm.py`
- Backends: **Ollama** (`OLLAMA_HOST`, default `http://localhost:11434`, `/api/chat` with `"format":"json"`) and an **OpenAI-compatible** server (`AGENT403_LLM_BASE_URL`, optional `AGENT403_LLM_API_KEY` read from env only, never committed). This lets us use the organizers' model server.
- Model from `AGENT403_MODEL` (default `qwen2.5-coder:7b`). `--no-llm` or `AGENT403_LLM=off` disables it.
- Health check with a short timeout; if the model is unreachable, log once and fall back (never crash).
- Retry once on invalid JSON; strip code fences before parsing.

### 3.7 `analyzer.py` (verdict logic)
For each (finding = vuln in dist D with symbols S):
1. Entry points = every app function + module body (an app may be a library; conservative).
2. BFS over edges through app code and **intermediate** dependency code (deps whose `Requires-Dist` chain includes D). Stop when an edge hits a symbol in S (match exact canonical name **or** prefix, e.g., `yaml.FullLoader` matches `yaml.FullLoader.__init__`). Keep parent pointers to rebuild the **shortest path**.
3. Verdict:
   - path found → **REACHABLE** (evidence: list of hops `{symbol, file, line}`)
   - S unknown (`source=none`) and D's import names are referenced anywhere → **UNCERTAIN** ("vulnerable symbols unknown")
   - no path, but a dynamic site exists in a reachable function that touches D's module (alias in scope) or uses non-constant `importlib`/`__import__` → **UNCERTAIN**
   - no path, but an unresolved `obj.m()` where `m` equals the last name part of any symbol in S → **UNCERTAIN**
   - parse error or truncation in relevant code → **UNCERTAIN**
   - otherwise → **NOT_AFFECTED** (justification `vulnerable_code_not_in_execute_path`; if D is never imported at all, say so in the impact statement)
4. Every verdict carries a human-readable `reasons[]`.

### 3.8 `report.py`, `vex.py`, `cli.py`
- `agent403 scan PATH [--requirements FILE] [--format table|json] [--json-out FILE] [--vex-out FILE] [--offline] [--no-llm] [--refresh-symbols] [--include-tests] [--fail-on reachable|uncertain|never] [-v]`
- Exit codes: `0` = no finding at/above the fail-on level, `1` = such findings exist (default `--fail-on reachable`), `2` = tool error.
- Rich table: Package · Version · Advisory · Verdict (colored) · Symbol source · Evidence (first path, shortened).
- JSON report schema:
```json
{
  "tool": {"name": "agent403", "version": "0.1.0"},
  "project": "path", "generated_at": "ISO-8601",
  "llm": {"enabled": true, "backend": "ollama", "model": "qwen2.5-coder:7b"},
  "dependencies": [{"name": "pyyaml", "version": "5.3.1", "pinned": true}],
  "findings": [{
    "vuln_id": "GHSA-…", "aliases": ["CVE-2020-14343"], "package": "pyyaml", "version": "5.3.1",
    "fixed_in": ["5.4"], "summary": "…",
    "verdict": "reachable|not_affected|uncertain",
    "vulnerable_symbols": [{"symbol": "yaml.full_load", "source": "llm", "confidence": "high"}],
    "evidence": {"paths": [[{"symbol": "app.main.load_config", "file": "app/main.py", "line": 4},
                            {"symbol": "yaml.full_load", "file": null, "line": null}]],
                 "dynamic_sites": [], "reasons": ["direct call at app/main.py:4"]},
    "vex_status": "affected|not_affected|under_investigation"
  }],
  "summary": {"reachable": 1, "not_affected": 0, "uncertain": 0}
}
```
- **OpenVEX 0.2.0**: `@context: https://openvex.dev/ns/v0.2.0`, `@id`, `author: "agent403"`, `timestamp`, `version: 1`, `statements[]` with `vulnerability.name` (+ aliases), `products[{"@id": "pkg:pypi/<app>", "subcomponents":[{"@id":"pkg:pypi/pyyaml@5.3.1"}]}]`, mapping reachable→`affected` (+`action_statement`: "Upgrade to ≥ fixed"), not_affected→`not_affected` + `justification: vulnerable_code_not_in_execute_path` + `impact_statement`, uncertain→`under_investigation`.

---

## 4. Testing & evidence plan (15 pts + protects the 30)

**Offline fixture world** (CI never needs network or a model):
- `tests/fixtures/site/vulnlib/` — a tiny fake vulnerable library: `vulnlib.parser.unsafe_parse` (vulnerable), `vulnlib.parser.safe_parse`, `vulnlib.Parser` class with `.unsafe()` method, re-exports in `__init__`.
- `tests/fixtures/site/wrapperlib/` — calls `vulnlib.unsafe_parse` inside `wrapperlib.load()` (transitive case).
- `tests/fixtures/osv/` — recorded OSV JSON for a fake advisory `TEST-0001` (vulnlib 1.0) plus real recorded records for PyYAML/Jinja2.
- `tests/fixtures/apps/` with a `expected.json` per app:

| App | Code pattern | Expected |
|---|---|---|
| `direct_call` | `vulnlib.unsafe_parse(x)` | reachable |
| `safe_only` | `vulnlib.safe_parse(x)` | not_affected |
| `alias_import` | `from vulnlib.parser import unsafe_parse as up; up(x)` | reachable |
| `indirect_chain` | `main → helpers.process → unsafe_parse` across files | reachable (3-hop path) |
| `dead_import` | imports vulnlib, never uses unsafe | not_affected |
| `dynamic_getattr` | `getattr(vulnlib, name)(x)` | uncertain |
| `callback_ref` | `list(map(vulnlib.unsafe_parse, xs))` | reachable |
| `class_method` | `p = vulnlib.Parser(); p.unsafe()` | reachable |
| `unknown_receiver` | `def f(obj): obj.unsafe()` | uncertain |
| `no_import` | never imports vulnlib | not_affected |
| `transitive` | `wrapperlib.load(x)` | reachable (through wrapperlib) |
| `relative_imports` | package with `from .util import run` | reachable |
| `syntax_error` | one broken file that imports vulnlib | uncertain |

- Unit tests: deps parsing, OSV parsing/dedupe, wheel import-name mapping, zip-slip guard, call-graph resolution, diff→function mapping, LLM JSON parsing + validation (with a **mock** LLM), VEX schema shape, CLI exit codes.
- `scripts/evaluate.py` — runs all fixture apps and prints an accuracy table (TP/FP/FN, and **"wrongly-safe count" which must be 0**). Put its output in the README as evidence.
- Real-world examples (with network + model) live in `examples/`: `pyyaml_reachable/`, `pyyaml_safe/`, `jinja2_sandbox/`, each with `app/`, `requirements.txt`, `report.json`, `vex.json`, `output.txt` (the real terminal output) and `README.md`.

**CI (`.github/workflows/ci.yml`)**: on `pull_request` + push to `main`; Python 3.10 and 3.12; `pip install -e .[dev]`; `ruff check`; `pytest -q`; then `agent403 scan tests/fixtures/apps/direct_call --offline --no-llm --format json` as a smoke test (expect exit 1). Fast, deterministic, no secrets.

---

## 5. PR roadmap & timeline (now → 6:30 AM)

Branch per PR: `feat/<name>`. Push the branch, open the PR on GitHub with the template filled in, wait for green CI, merge (squash). Each team member reviews or merges some PRs.

| # | Time | PR | Contents |
|---|---|---|---|
| 1 | 8:45–9:15 PM | `chore/setup` | LICENSE (MIT), PR template, CI, pyproject, `src/agent403` skeleton + CLI stub, `.gitignore`, README stub, `docs/PLAN.md`, one smoke test |
| 2 | 9:15–10:30 | `feat/deps-osv-pypi` | deps.py, osv.py, pypi.py, cache, offline mode + tests with recorded fixtures |
| 3 | 10:30–12:15 AM | `feat/callgraph` | callgraph.py + fake `vulnlib`/`wrapperlib` + fixture apps + tests (**ask mentors before midnight if stuck**) |
| 4 | 12:15–1:45 | `feat/analyzer-reports` | analyzer.py verdicts, report.py, vex.py, full CLI, exit codes, evaluate.py |
| 5 | 1:45–3:15 | `feat/symbols-llm` | fix-diff parsing, static candidates, llm.py (Ollama + OpenAI-compatible), validation, symbols cache, mock-LLM tests |
| 6 | 3:15–4:30 | `feat/real-examples` | real PyYAML + Jinja2 runs with the model → `examples/`, regenerate `data/symbols_cache.json` with the model, verify OSV IDs |
| 7 | 4:30–5:30 | `docs/final` | full README (quickstart, how judges run it, architecture diagram, trade-offs, eval table, model usage), HACKATHON.md final model update |
| — | 5:30–6:15 | buffer | bug fixes, CI green on `main`, secret check (`git log -p | grep -i key`), OrganizerHQ submission + add members, demo rehearsal |
| — | **6:30 AM** | freeze | — |

Install the model early: `ollama pull qwen2.5-coder:7b` (fallback: `gemma4:e4b`). Whatever we finally use must match HACKATHON.md, the PRs and the README.

---

## 6. Design trade-offs (for the Q&A, 10 pts)
- **Custom AST call graph instead of PyCG/Jedi**: PyCG is archived; Jedi is slow and heavy. Our own indexer is small, explainable and tuned to the asymmetric-safety rule. Cost: weaker type inference → more UNCERTAIN, never fewer.
- **References count as uses**: catches callbacks and `Loader=FullLoader`. Cost: possible false positives (acceptable: safe side).
- **Stop at the vulnerable package's public API**: avoids `safe_load → load` style false positives. Cost: relies on correct entry symbols → hence model + validation + review flag.
- **Function-level, not argument-level**: `yaml.load(f, Loader=SafeLoader)` in 5.3.1 is flagged only if `load` is listed as vulnerable. We prefer a false alarm over a false "safe".
- **Wheels only, no install**: zero code execution from untrusted packages. Cost: C-extension internals are invisible (treated as boundary).
- **Model with validation + cache**: the model does the semantic part (advisory → symbols); hallucinated names are rejected; results are cached with provenance so CI and offline runs are deterministic.
- **All app functions are entry points**: right for libraries and unknown frameworks (Flask routes, CLI hooks). Cost: dead app code still counts as reachable.

## 7. Roadmap (say "roadmap", never claim built)
SARIF output for GitHub code scanning · GitHub Action wrapper · argument-sensitive checks (e.g., which Loader) · better type inference via Jedi · uv/poetry lock files · contributing reviewed symbols upstream to OSV.

## 8. Demo script (8 minutes)
1. (1 min) Problem: `pip-audit` on the demo app → many alerts. "Which ones matter?"
2. (3 min) `agent403 scan examples/pyyaml_reachable` → REACHABLE with a 3-hop path. `agent403 scan examples/pyyaml_safe` → NOT_AFFECTED + VEX. Dynamic app → UNCERTAIN with the reason.
3. (1.5 min) Show `ollama ps` + `--refresh-symbols -v`: the model reading the fix diff and choosing `full_load`/`FullLoader`; show a rejected hallucination if any.
4. (1.5 min) Architecture + evaluation table (0 wrongly-safe) + CI/PR workflow.
5. (1 min) Trade-offs + roadmap.

## 9. Ownership (each person must explain their part + the whole flow)
- **Shrijan**: callgraph.py + analyzer.py (BFS, verdicts)
- **Gourav**: deps.py, osv.py, pypi.py, report/vex, CI
- **Alok**: symbols.py, llm.py, evaluation, examples, README/demo
