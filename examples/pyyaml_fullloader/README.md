# pyyaml_fullloader

`load_with_loader` calls `yaml.load` with `Loader=yaml.FullLoader`. `read_single` constructs `yaml.FullLoader` and calls `get_single_data`. The package is PyYAML 5.3.1.

```
COLUMNS=120 NO_COLOR=1 agent403 scan examples/pyyaml_fullloader -v \
  --json-out examples/pyyaml_fullloader/report.json \
  --vex-out examples/pyyaml_fullloader/vex.json
```

Verdict: **REACHABLE**. The call path is `main.load_with_loader -> yaml.load` for GHSA-8q59-q68h-6hv4. Exit code 1.
