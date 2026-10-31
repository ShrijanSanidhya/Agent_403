"""Score the fixture apps and write docs/EVALUATION.md.

Exits 1 when any app is wrong or a reachable/uncertain app was marked not affected.
"""

import json
import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APPS = ROOT / "tests" / "fixtures" / "apps"
SITE = ROOT / "tests" / "fixtures" / "site"
OSV = ROOT / "tests" / "fixtures" / "osv"
SYMBOLS = ROOT / "tests" / "fixtures" / "symbols" / "symbols_cache.json"
OUTPUT = ROOT / "docs" / "EVALUATION.md"


def main() -> int:
    os.environ["AGENT403_CACHE_DIR"] = tempfile.mkdtemp(prefix="agent403-eval-")
    from agent403.analyzer import analyze

    rows: list[tuple[str, str, str, bool]] = []
    for app in sorted(path for path in APPS.iterdir() if path.is_dir()):
        expected = json.loads((app / "expected.json").read_text(encoding="utf-8"))["vulnlib"]
        result = analyze(
            app,
            offline=True,
            site_dirs=(SITE,),
            osv_dirs=(OSV,),
            symbol_files=(SYMBOLS,),
        )
        got = result.findings[0].verdict.value if result.findings else "missing"
        rows.append((app.name, expected, got, expected == got))

    false_reachable = sum(
        got == "reachable" and expected != "reachable" for _, expected, got, _ in rows
    )
    missed = sum(expected == "reachable" and got != "reachable" for _, expected, got, _ in rows)
    wrongly_safe = sum(
        expected in {"reachable", "uncertain"} and got == "not_affected"
        for _, expected, got, _ in rows
    )
    correct = sum(ok for *_, ok in rows)
    lines = [
        "# Evaluation",
        "",
        "| app | expected | got | ok |",
        "|---|---|---|---|",
    ]
    for name, expected, got, ok in rows:
        lines.append(f"| {name} | {expected} | {got} | {'yes' if ok else 'no'} |")
    lines.extend(
        [
            "",
            f"correct {correct} / {len(rows)}",
            f"false reachable: {false_reachable}",
            f"missed reachable: {missed}",
            f"wrongly marked safe: {wrongly_safe}",
            "",
        ]
    )
    text = "\n".join(lines)
    OUTPUT.write_text(text, encoding="utf-8")
    sys.stdout.write(text)
    if correct != len(rows) or wrongly_safe:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
