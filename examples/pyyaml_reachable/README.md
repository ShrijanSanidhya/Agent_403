# pyyaml_reachable

`main.main` calls `config.load_config`, which calls `yaml.full_load` on PyYAML 5.3.1.

```
COLUMNS=120 NO_COLOR=1 agent403 scan examples/pyyaml_reachable -v \
  --json-out examples/pyyaml_reachable/report.json \
  --vex-out examples/pyyaml_reachable/vex.json
```

Verdict: **REACHABLE**. The call path is `main.main -> config.load_config -> yaml.full_load` for GHSA-8q59-q68h-6hv4. Exit code 1.
