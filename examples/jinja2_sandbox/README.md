# jinja2_sandbox

Renders a caller-supplied template with `jinja2.sandbox.SandboxedEnvironment` from Jinja2 2.10.

```
COLUMNS=120 NO_COLOR=1 agent403 scan examples/jinja2_sandbox -v \
  --json-out examples/jinja2_sandbox/report.json \
  --vex-out examples/jinja2_sandbox/vex.json
```

Verdict: **REACHABLE** for GHSA-462w-v97r-4m45 and GHSA-q2x7-8rv6-6q7h. Both paths are `main.main -> jinja2.sandbox.SandboxedEnvironment`. The other four Jinja2 2.10 advisories are not affected. Exit code 1.
