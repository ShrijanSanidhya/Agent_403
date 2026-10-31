# 8-minute demo

Run these from the repository root, with the virtualenv active and Ollama
already serving `qwen2.5-coder:7b`.

## 1. The problem (1 min)

A package scanner reports PyYAML 5.3.1 because the package is vulnerable.
It does not say whether this project calls the vulnerable function.
`examples/pyyaml_reachable/requirements.txt` pins `pyyaml==5.3.1`.

## 2. Three scans (3 min)

```bash
agent403 scan examples/pyyaml_reachable
agent403 scan examples/pyyaml_safe
agent403 scan examples/pyyaml_dynamic
```

The first is REACHABLE, with the path `main.main -> config.load_config -> yaml.full_load`.
The second is NOT AFFECTED, because the app calls `yaml.safe_load`.
The third is UNCERTAIN, because the loader name comes from `getattr`.

## 3. The open model (1.5 min)

```bash
ollama ps
agent403 symbols GHSA-8q59-q68h-6hv4 --package pyyaml==5.3.1 --refresh -v
```

`ollama ps` shows the local model. The symbols command reads the advisory and
the fix diff, then prints the names it kept and any name it rejected.

## 4. Architecture and evaluation (1.5 min)

Walk the pipeline in the README: dependencies, OSV, PyPI source, call graph,
vulnerable symbols, verdict, reports. Then show the evaluation table:
13 synthetic fixture apps, 13 correct, 0 wrongly marked safe.

## 5. Trade-offs and roadmap (1 min)

We stop at the public API of the vulnerable package, so `safe_load` calling
`load` inside PyYAML is not treated as a hit. We say UNCERTAIN when the call
is dynamic. Not built yet: SARIF, a GitHub Action, argument-sensitive checks,
stronger type inference, and lock files.
