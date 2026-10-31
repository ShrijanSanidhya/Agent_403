"""Shared data types for a scan."""

from dataclasses import dataclass
from enum import Enum


class Verdict(str, Enum):
    REACHABLE = "reachable"
    NOT_AFFECTED = "not_affected"
    UNCERTAIN = "uncertain"


@dataclass
class Dependency:
    name: str
    version: str
    pinned: bool
    source_file: str


@dataclass
class Advisory:
    id: str
    aliases: list[str]
    summary: str
    details: str
    package: str
    version: str
    fixed_versions: list[str]
    fix_refs: list[str]


@dataclass
class PathHop:
    symbol: str
    file: str | None
    line: int | None

    def to_dict(self) -> dict[str, str | int | None]:
        return {"symbol": self.symbol, "file": self.file, "line": self.line}


@dataclass
class Evidence:
    paths: list[list[PathHop]]
    dynamic_sites: list[dict[str, object]]
    reasons: list[str]

    def to_dict(self) -> dict[str, object]:
        return {
            "paths": [[hop.to_dict() for hop in path] for path in self.paths],
            "dynamic_sites": list(self.dynamic_sites),
            "reasons": list(self.reasons),
        }


@dataclass
class VulnSymbols:
    symbols: list[str]
    safe_symbols: list[str]
    source: str
    confidence: str
    provenance: dict[str, object]
    rejected: list[str]


@dataclass
class Finding:
    advisory: Advisory
    verdict: Verdict
    vulnerable_symbols: list[dict[str, str]]
    evidence: Evidence
    vex_status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "vuln_id": self.advisory.id,
            "aliases": list(self.advisory.aliases),
            "package": self.advisory.package,
            "version": self.advisory.version,
            "fixed_in": list(self.advisory.fixed_versions),
            "summary": self.advisory.summary,
            "verdict": self.verdict.value,
            "vulnerable_symbols": list(self.vulnerable_symbols),
            "evidence": self.evidence.to_dict(),
            "vex_status": self.vex_status,
        }
