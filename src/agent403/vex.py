"""Write an OpenVEX 0.2.0 document for a scan."""

import hashlib
import json
from typing import TextIO

from agent403.analyzer import ScanResult
from agent403.models import Finding


def to_vex(result: ScanResult) -> dict[str, object]:
    """Return an OpenVEX document for every finding in the scan."""
    raw = f"{result.project}{result.generated_at}".encode()
    digest = hashlib.sha256(raw).hexdigest()
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://openvex.dev/docs/agent403/{digest}",
        "author": "agent403",
        "timestamp": result.generated_at,
        "version": 1,
        "statements": [_statement(result, finding) for finding in result.findings],
    }


def dump_vex(result: ScanResult, handle: TextIO) -> None:
    """Write the OpenVEX document."""
    json.dump(to_vex(result), handle, indent=2)
    handle.write("\n")


def _statement(result: ScanResult, finding: Finding) -> dict[str, object]:
    statement: dict[str, object] = {
        "vulnerability": {
            "name": finding.advisory.id,
            "aliases": list(finding.advisory.aliases),
        },
        "products": [
            {
                "@id": f"pkg:pypi/{result.project.name}",
                "subcomponents": [
                    {"@id": f"pkg:pypi/{finding.advisory.package}@{finding.advisory.version}"}
                ],
            }
        ],
        "status": finding.vex_status,
    }
    reason = finding.evidence.reasons[0] if finding.evidence.reasons else ""
    if finding.vex_status == "affected":
        fixed = "a fixed version"
        if finding.advisory.fixed_versions:
            fixed = finding.advisory.fixed_versions[0]
        package = finding.advisory.package
        statement["action_statement"] = f"Upgrade {package} to {fixed} or later"
    elif finding.vex_status == "not_affected":
        statement["justification"] = "vulnerable_code_not_in_execute_path"
        statement["impact_statement"] = reason
    else:
        statement["status_notes"] = "; ".join(finding.evidence.reasons)
    return statement
