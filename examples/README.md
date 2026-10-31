# Examples

These scans were produced by `agent403` against the shipped symbol cache. `output.txt` is the command output. `report.json` and `vex.json` are the files that command wrote.

| example | verdict | why |
|---|---|---|
| pyyaml_reachable | REACHABLE | `main.main` calls `config.load_config`, which calls `yaml.full_load` |
| pyyaml_safe | NOT AFFECTED | the same loader calls `yaml.safe_load` |
| pyyaml_dynamic | UNCERTAIN | `getattr(yaml, loader_name)` chooses the loader from argv |
| jinja2_sandbox | REACHABLE | `main.main` constructs `jinja2.sandbox.SandboxedEnvironment` |
| jinja2_plain | NOT AFFECTED | a fixed `jinja2.Template` does not reach the recorded symbols |
