# pyyaml_dynamic

`main` takes a loader name from `sys.argv` and calls `getattr(yaml, loader_name)` on the open file.

```
COLUMNS=120 NO_COLOR=1 agent403 scan examples/pyyaml_dynamic -v \
  --json-out examples/pyyaml_dynamic/report.json \
  --vex-out examples/pyyaml_dynamic/vex.json
```

Verdict: **UNCERTAIN**. The loader is chosen with `getattr` at `main.py:9`, so the call target is not a fixed symbol. Exit code 0, because the default failure threshold is reachable.
