from typing import Any

from scanner.normalize import severity
from scanner.normalize.finding import Category, Finding
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    ScanContext,
    ScannerPlugin,
    load_json,
    rel_path,
)


def _fixed_version(vuln: dict[str, Any], package: str | None) -> str | None:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name") != package:
            continue
        for rng in affected.get("ranges", []):
            if rng.get("type") == "GIT":  # a commit hash, not a version users can install
                continue
            for event in rng.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return None


class OsvPlugin(ScannerPlugin):
    name = "osv"
    binary = "osv-scanner"
    # 1 = vulnerabilities found, 128 = no package sources found.
    ok_exit_codes = frozenset({0, 1, 128})

    def build_command(self, ctx: ScanContext) -> list[str]:
        offline = ["--offline"] if ctx.config.offline else []
        return ["osv-scanner", "scan", "source", *offline, "-r", "--format", "json", "."]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        data = load_json(proc.stdout, {})
        findings: list[Finding] = []
        for result in data.get("results") or []:
            source = rel_path(result.get("source", {}).get("path", ""), ctx.workdir)
            for entry in result.get("packages") or []:
                package = entry.get("package", {})
                name, version = package.get("name"), package.get("version")
                scores = {
                    vuln_id: group.get("max_severity")
                    for group in entry.get("groups") or []
                    for vuln_id in group.get("ids", [])
                }
                for vuln in entry.get("vulnerabilities") or []:
                    vuln_id = str(vuln["id"])
                    cve = next((a for a in vuln.get("aliases", []) if a.startswith("CVE-")), None)
                    rule_id = vuln_id if vuln_id.startswith("CVE-") else (cve or vuln_id)
                    label = vuln.get("database_specific", {}).get("severity")
                    summary = vuln.get("summary") or vuln.get("details", "")[:200] or rule_id
                    fixed = _fixed_version(vuln, name)
                    message = f"{name} {version} is affected by {rule_id}"
                    if fixed:
                        message += f"; fixed in {fixed}"
                    findings.append(
                        Finding(
                            tool=self.name,
                            category=Category.DEPENDENCY,
                            rule_id=rule_id,
                            severity=severity.osv(scores.get(vuln_id), label),
                            title=summary,
                            message=message,
                            file=source or None,
                            package=name,
                            version=version,
                            fixed_version=fixed,
                        )
                    )
        return Parsed(findings)
