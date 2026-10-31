# Agent 403

Agent 403 checks whether a Python project can actually reach a known vulnerable function in a dependency.

Package scanners raise one alert per vulnerable package. Most of those alerts are noise, because the project never calls the vulnerable function. Go has govulncheck for this question. Python has no maintained equivalent.

## What it tells you

- **REACHABLE**: there is a call path from the project to a vulnerable symbol. The path is the proof.
- **NOT AFFECTED**: the vulnerable symbols are known, and no call path reaches them. The tool also writes an OpenVEX statement.
- **UNCERTAIN**: the code is too dynamic to judge, or the source or the symbols could not be read.

We never guess: when we are not sure, we say UNCERTAIN.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
```

Online scan:

```bash
agent403 scan examples/pyyaml_reachable
```

The same scan offline, after that online run has cached the package source:

```bash
agent403 scan examples/pyyaml_reachable --offline
```

Fixture scan, with no network and no model:

```bash
agent403 scan tests/fixtures/apps/direct_call --offline \
  --site-packages tests/fixtures/site \
  --osv-cache tests/fixtures/osv \
  --symbols-cache tests/fixtures/symbols/symbols_cache.json
```

This is the real output of `agent403 scan examples/pyyaml_reachable -v`, saved in `examples/pyyaml_reachable/output.txt`:

```
┏━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Package ┃ Version ┃ Advisory             ┃ Verdict   ┃ Why                   ┃
┡━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ pyyaml  │ 5.3.1   │ GHSA-8q59-q68h-6hv4  │ REACHABLE │ call path found:      │
│         │         │ CVE-2020-14343       │           │ main.main ->          │
│         │         │                      │           │ config.load_config -> │
│         │         │                      │           │ yaml.full_load        │
└─────────┴─────────┴──────────────────────┴───────────┴───────────────────────┘
  main.main  (main.py:4)
  -> config.load_config  (main.py:5)
  -> yaml.full_load  (config.py:6)
1 reachable, 0 uncertain, 0 not affected
```

The full file also lists each symbol the model kept and each symbol it marked safe.

## Use in CI

```yaml
- run: pip install git+https://github.com/ShrijanSanidhya/Agent_403.git
- run: agent403 scan . --vex-out vex.json
```

The job fails (exit 1) when a vulnerable function is reachable.

## Using the open model

```bash
ollama pull qwen2.5-coder:7b
```

The default model is `qwen2.5-coder:7b` on Ollama at `http://localhost:11434`.

| variable | effect |
|---|---|
| `AGENT403_MODEL` | model name, when you do not want the default |
| `OLLAMA_HOST` | Ollama server, when it is not on localhost port 11434 |
| `AGENT403_LLM_BASE_URL` | use an OpenAI-compatible server instead of Ollama |
| `AGENT403_LLM=off` | do not call a model |

Ask the model which public symbols trigger one advisory:

```bash
agent403 symbols GHSA-8q59-q68h-6hv4 --package pyyaml==5.3.1 -v
```

`--refresh` ignores a saved answer and asks again. `--no-llm` skips the model. A scan accepts `--no-llm` and `--refresh-symbols` for the same choices.

## How it works

1. Read pinned dependencies from `requirements.txt`.
2. Fetch OSV advisories for those packages.
3. Download the PyPI sdist or wheel, or reuse a copy already in the cache.
4. Build a call graph with the Python `ast` module. The tool does not import or run the code.
5. Choose vulnerable symbols from the fix diff, a static search, and the open model. Every model name is checked against the AST index. Unknown names are rejected.
6. Decide REACHABLE, NOT AFFECTED, or UNCERTAIN.
7. Print a table and, when asked, write JSON and OpenVEX.

```mermaid
flowchart LR
  deps[Dependencies] --> osv[OSV]
  osv --> source[PyPI source]
  source --> graph[Call graph]
  graph --> symbols[Vulnerable symbols]
  symbols --> verdict[Verdict]
  verdict --> reports[Table JSON OpenVEX]
```

A class in the symbol list also matches its subclasses inside that package. A call to `yaml.FullLoader` matches when `yaml.constructor.FullConstructor` is vulnerable, and the finding says that `yaml.loader.FullLoader` is a subclass of `FullConstructor`.

## CLI reference

```bash
agent403 scan PATH
```

| option | meaning |
|---|---|
| `--requirements` | requirements file to read |
| `--format table\|json` | output format, default `table` |
| `--json-out` | write the JSON report to this file |
| `--vex-out` | write the OpenVEX document to this file |
| `--offline` | use only the local cache |
| `--no-llm` | do not call a model |
| `--refresh-symbols` | ignore the shipped symbol cache |
| `--include-tests` | include test files in the call graph |
| `--fail-on reachable\|uncertain\|never` | which findings cause exit 1, default `reachable` |
| `-v` | print the path and the symbol list |
| `--site-packages` | read dependency source from this directory |
| `--osv-cache` | extra OSV cache directory |
| `--symbols-cache` | extra symbols cache file |

`agent403 symbols ADVISORY --package name==version` prints the vulnerable and safe symbols for one advisory. `--refresh` ignores the cache. `-v` also prints the fix refs and the public API.

Exit codes:

| code | meaning |
|---|---|
| 0 | no finding is as severe as `--fail-on` |
| 1 | a finding meets `--fail-on` |
| 2 | the path is not a directory, `--package` is malformed, or a fetch failed |

With the default `--fail-on reachable`, UNCERTAIN and NOT AFFECTED exit 0.

## Examples

| example | verdict | why |
|---|---|---|
| pyyaml_reachable | REACHABLE | `main.main` calls `config.load_config`, which calls `yaml.full_load` |
| pyyaml_safe | NOT AFFECTED | the same loader calls `yaml.safe_load` |
| pyyaml_dynamic | UNCERTAIN | `getattr(yaml, loader_name)` chooses the loader from argv |
| pyyaml_fullloader | REACHABLE | `load_with_loader` calls `yaml.load` with `Loader=yaml.FullLoader` |
| jinja2_sandbox | REACHABLE | `main.main` constructs `jinja2.sandbox.SandboxedEnvironment` |
| jinja2_plain | NOT AFFECTED | a fixed `jinja2.Template` does not reach the recorded symbols |

Each directory has the app, `output.txt`, `report.json`, and `vex.json` from a real scan. See [examples/README.md](examples/README.md).

## Evaluation

These are 13 synthetic fixture apps. The tool also has 6 real examples in `examples/`. There are no other accuracy claims.

The shipped symbols cache covers 122 advisories across 15 packages, generated by qwen2.5-coder:7b during the hackathon; only the PyYAML and Jinja2 key entries were manually reviewed.

| app | expected | got | ok |
|---|---|---|---|
| alias_import | reachable | reachable | yes |
| callback_ref | reachable | reachable | yes |
| class_method | reachable | reachable | yes |
| dead_import | not_affected | not_affected | yes |
| direct_call | reachable | reachable | yes |
| dynamic_getattr | uncertain | uncertain | yes |
| indirect_chain | reachable | reachable | yes |
| no_import | not_affected | not_affected | yes |
| relative_imports | reachable | reachable | yes |
| safe_only | not_affected | not_affected | yes |
| syntax_error | uncertain | uncertain | yes |
| transitive | reachable | reachable | yes |
| unknown_receiver | uncertain | uncertain | yes |

correct 13 / 13

false reachable: 0

missed reachable: 0

wrongly marked safe: 0

## Design trade-offs

- Custom AST call graph instead of PyCG or Jedi. PyCG is archived, and Jedi is slow. The cost is weaker type inference, which means more UNCERTAIN results.
- A reference counts as a use, so a callback or `Loader=FullLoader` is seen. That can flag a name that is only mentioned.
- The search stops at the vulnerable package's public API, so an internal call from `safe_load` to `load` is not a hit. The symbol list has to name the real entry points.
- The check is function-level, not argument-level. `yaml.load(f, Loader=SafeLoader)` is flagged when `load` itself is listed.
- Wheels and sdists are read, not installed. Code inside a C extension is not visible.
- The model result is validated and cached. A name that is not in the AST index is rejected, and later runs can reuse the cache.
- Every application function with no caller inside the app is an entry point, so library code and framework hooks are included. Dead application code still counts.

## Safety

The analyzer never runs or imports the code it scans. It only parses it with `ast`. Wheels and sdists are extracted with path checks that reject escapes, symlinks, and hard links. No API key is needed for the local model, and no key is stored.

## Limitations and roadmap

Not built yet:

- SARIF output
- a GitHub Action wrapper
- argument-sensitive checks, such as which YAML `Loader` was passed
- better type inference
- lock files

## Team 403

- Shrijan Sanidhya
- Gourav Tanwar
- Alok Kumar

## License

MIT
