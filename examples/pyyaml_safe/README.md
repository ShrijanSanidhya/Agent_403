# pyyaml_safe

Same two-file loader as `pyyaml_reachable`, but `config.load_config` calls `yaml.safe_load`.

```
COLUMNS=120 NO_COLOR=1 agent403 scan examples/pyyaml_safe -v \
  --json-out examples/pyyaml_safe/report.json \
  --vex-out examples/pyyaml_safe/vex.json
```

Verdict: **NOT AFFECTED**. There is no call path to `yaml.load`, `yaml.full_load`, or the other symbols recorded for GHSA-8q59-q68h-6hv4. `yaml.safe_load` is a safe symbol for that advisory. Exit code 0.
