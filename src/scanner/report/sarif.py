import json
from typing import Any
from urllib.parse import quote

from scanner import __version__
from scanner.core.result import ScanReport
from scanner.normalize.finding import Finding, Severity
from scanner.plugins.base import Status

SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
# GitHub ranks code-scanning alerts by this CVSS-like number.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def _rule_id(finding: Finding) -> str:
    return f"{finding.tool}/{finding.rule_id}"


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": _rule_id(finding),
        "ruleIndex": rule_index,
        "level": _LEVEL[finding.severity],
        "message": {"text": finding.message or finding.title},
        "partialFingerprints": {"codeScanner/v1": finding.fingerprint},
        "properties": {
            "category": finding.category.value,
            "sources": finding.sources,
            "severity": finding.severity.value,
        },
    }
    if finding.is_new is not None:
        result["properties"]["isNew"] = finding.is_new
    if finding.commit:  # history scans: the location is in this commit, not the current tree
        result["properties"]["commit"] = finding.commit
    if finding.file:
        physical: dict[str, Any] = {
            "artifactLocation": {"uri": quote(finding.file), "uriBaseId": "%SRCROOT%"}
        }
        if finding.line_start:
            region = {"startLine": finding.line_start}
            if finding.line_end and finding.line_end >= finding.line_start:
                region["endLine"] = finding.line_end
            physical["region"] = region
        result["locations"] = [{"physicalLocation": physical}]
    return result


def render(report: ScanReport) -> str:
    """SARIF 2.1.0 with the findings that matter for the change: only new ones in diff mode."""
    rules: list[dict[str, Any]] = []
    index: dict[str, int] = {}
    results = []
    for finding in report.new_findings():
        rule_id = _rule_id(finding)
        if rule_id not in index:
            index[rule_id] = len(rules)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": finding.title},
                    "properties": {
                        "tags": [finding.category.value],
                        "security-severity": _SECURITY_SEVERITY[finding.severity],
                    },
                }
            )
        results.append(_result(finding, index[rule_id]))
    problems = [t for t in report.tools if t.status in (Status.FAILED, Status.TIMEOUT)]
    document = {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {"name": "code-scanner", "version": __version__, "rules": rules}
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not problems,
                        "toolExecutionNotifications": [
                            {
                                "level": "error",
                                "message": {"text": f"{t.tool}: {t.message or t.status.value}"},
                            }
                            for t in problems
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
