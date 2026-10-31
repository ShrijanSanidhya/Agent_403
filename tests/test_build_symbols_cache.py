"""Offline checks for which advisories and versions the cache builder keeps."""

import importlib.util
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).parents[1]
SPEC = importlib.util.spec_from_file_location(
    "build_symbols_cache",
    ROOT / "scripts" / "build_symbols_cache.py",
)
assert SPEC is not None and SPEC.loader is not None
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)

SINCE = datetime(2018, 1, 1, tzinfo=timezone.utc)


def test_indexed_version_is_the_highest_below_the_fix() -> None:
    record = {
        "affected": [
            {
                "package": {"ecosystem": "PyPI", "name": "Requests"},
                "versions": ["2.19.1", "2.20.0", "2.32.0"],
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.32.0"}]}],
            }
        ]
    }
    assert builder.indexed_version(record, "requests") == "2.20.0"


def test_indexed_version_without_a_fix_uses_the_highest() -> None:
    record = {
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "versions": ["9.0.0", "10.0.0"],
            }
        ]
    }
    assert builder.indexed_version(record, "pillow") == "10.0.0"


def test_empty_versions_are_not_indexed() -> None:
    record = {
        "affected": [
            {
                "package": {"name": "pillow", "ecosystem": "PyPI"},
                "ranges": [{"events": [{"fixed": "1"}]}],
            }
        ]
    }
    assert builder.indexed_version(record, "pillow") is None


def test_select_keeps_twelve_with_fix_refs_first() -> None:
    records: list[dict[str, object]] = []
    for number in range(15):
        record: dict[str, object] = {
            "id": f"GHSA-{number:04d}",
            "published": f"2020-01-{(number % 28) + 1:02d}T00:00:00Z",
            "summary": "example",
        }
        if number % 2 == 0:
            record["references"] = [
                {
                    "type": "FIX",
                    "url": f"https://github.com/org/repo/commit/{number:040d}",
                }
            ]
        records.append(record)
    records.append(
        {
            "id": "PYSEC-1",
            "aliases": ["GHSA-0000"],
            "published": "2021-06-01T00:00:00Z",
            "summary": "alias of GHSA-0000",
        }
    )
    records.append(
        {
            "id": "GHSA-old",
            "published": "2017-12-31T00:00:00Z",
            "summary": "too old",
            "references": [
                {"type": "FIX", "url": "https://github.com/org/repo/commit/" + "ab" * 20}
            ],
        }
    )
    records.append(
        {
            "id": "GHSA-gone",
            "published": "2022-01-01T00:00:00Z",
            "withdrawn": "2022-02-01T00:00:00Z",
            "summary": "withdrawn",
        }
    )
    chosen = builder.select_advisories(records, "requests", limit=12, since=SINCE)
    ids = [advisory.id for advisory, _record in chosen]
    assert len(ids) == 12
    assert ids.count("GHSA-0000") == 1
    assert "PYSEC-1" not in ids
    assert "GHSA-old" not in ids
    assert "GHSA-gone" not in ids
    assert all(int(item.split("-")[1]) % 2 == 0 for item in ids[:8])
    assert all(int(item.split("-")[1]) % 2 == 1 for item in ids[8:])
