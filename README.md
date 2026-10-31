# Agent 403

Security scanners warn when a dependency package has a known vulnerability. They look at the package, not at the function. Agent 403 checks whether your Python code can actually reach that vulnerable function. A result is **reachable** when the tool can show the call path, **not affected** when it can say so in an OpenVEX statement, or **uncertain** when the code is too dynamic to judge. We never guess.

**Status: under active development during Hacktoberfest Hack Day 2026.**

The scan pipeline is planned. What works today is installing the package, printing the version, and refusing a scan with a clear error.

## Install for development

```bash
python -m venv .venv && source .venv/bin/activate && pip install -e ".[dev]"
```

## Usage (planned)

```bash
agent403 scan ./your-project
```

## Team

- Shrijan Sanidhya
- Gourav Tanwar
- Alok Kumar

## License

MIT
