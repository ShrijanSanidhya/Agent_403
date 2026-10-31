# jinja2_plain

Renders one fixed template with `jinja2.Template` only.

```
COLUMNS=120 NO_COLOR=1 agent403 scan examples/jinja2_plain -v \
  --json-out examples/jinja2_plain/report.json \
  --vex-out examples/jinja2_plain/vex.json
```

Verdict: **NOT AFFECTED** for every Jinja2 2.10 advisory in the shipped cache, including the sandbox escape GHSA-462w-v97r-4m45. `Template` is not one of the recorded vulnerable symbols. Exit code 0.
