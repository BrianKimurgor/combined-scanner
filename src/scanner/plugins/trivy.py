from typing import Any

from scanner.normalize import severity
from scanner.normalize.finding import SECRET_MASK, Category, Finding
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    ScanContext,
    ScannerPlugin,
    load_json,
    rel_path,
    to_line,
)


class TrivyPlugin(ScannerPlugin):
    name = "trivy"
    binary = "trivy"
    env = {"TRIVY_DISABLE_TELEMETRY": "true"}

    def build_command(self, ctx: ScanContext) -> list[str]:
        # Memory cache: the mirrored database may be mounted read-only.
        offline = (
            [
                "--skip-db-update",
                "--skip-java-db-update",
                "--skip-check-update",
                "--offline-scan",
                "--cache-backend",
                "memory",
            ]
            if ctx.config.offline
            else []
        )
        return [
            "trivy",
            "fs",
            *offline,
            # Trivy stops itself after 5 minutes by default. Give it more than our own limit,
            # so the scanner's per-tool timeout decides and the result reads "timeout".
            "--timeout",
            f"{ctx.timeout + 60}s",
            "--scanners",
            # Licence scanning is left out: it is the slowest part and pushed Trivy past its limit.
            # Add ",license" back to get licence findings again; parse() still handles them.
            "vuln,secret,misconfig",
            "--format",
            "json",
            "--quiet",
            ".",
        ]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        data = load_json(proc.stdout, {})
        findings: list[Finding] = []
        for result in data.get("Results") or []:
            target = rel_path(str(result.get("Target", "")), ctx.workdir)
            for vuln in result.get("Vulnerabilities") or []:
                findings.append(self._vulnerability(vuln, target))
            for misconfig in result.get("Misconfigurations") or []:
                if misconfig.get("Status", "FAIL") == "FAIL":
                    findings.append(self._misconfig(misconfig, target))
            # Match holds the offending line, so it is never copied.
            for secret in result.get("Secrets") or []:
                findings.append(self._secret(secret, target))
            for lic in result.get("Licenses") or []:
                # Permissive licences (MIT, Apache, BSD) need no action and would bury the rest.
                if str(lic.get("Severity", "")).upper() != "LOW":
                    findings.append(self._license(lic, target, ctx))
        return Parsed(findings)

    def _vulnerability(self, vuln: dict[str, Any], target: str) -> Finding:
        rule_id = str(vuln["VulnerabilityID"])
        name, version, fixed = (
            vuln.get("PkgName"),
            vuln.get("InstalledVersion"),
            vuln.get("FixedVersion"),
        )
        message = f"{name} {version} is affected by {rule_id}"
        if fixed:
            message += f"; fixed in {fixed}"
        return Finding(
            tool=self.name,
            category=Category.DEPENDENCY,
            rule_id=rule_id,
            severity=severity.lookup(severity.TRIVY, vuln.get("Severity")),
            title=str(vuln.get("Title") or rule_id),
            message=message,
            file=target or None,
            package=name,
            version=version,
            fixed_version=fixed or None,
        )

    def _misconfig(self, item: dict[str, Any], target: str) -> Finding:
        cause = item.get("CauseMetadata", {})
        rule_id = str(item.get("ID") or item.get("AVDID"))
        return Finding(
            tool=self.name,
            category=Category.IAC,
            rule_id=rule_id,
            severity=severity.lookup(severity.TRIVY, item.get("Severity")),
            title=str(item.get("Title") or rule_id),
            message=str(item.get("Message") or item.get("Description") or ""),
            file=target or None,
            line_start=to_line(cause.get("StartLine")),
            line_end=to_line(cause.get("EndLine")),
        )

    def _secret(self, item: dict[str, Any], target: str) -> Finding:
        rule_id = str(item["RuleID"])
        return Finding(
            tool=self.name,
            category=Category.SECRET,
            rule_id=rule_id,
            severity=severity.lookup(severity.TRIVY, item.get("Severity")),
            title=str(item.get("Title") or rule_id),
            message=f"Possible secret detected by rule {rule_id}",
            file=target or None,
            line_start=to_line(item.get("StartLine")),
            line_end=to_line(item.get("EndLine")),
            secret_masked=SECRET_MASK,
        )

    def _license(self, item: dict[str, Any], target: str, ctx: ScanContext) -> Finding:
        name = str(item.get("Name", "unknown"))
        return Finding(
            tool=self.name,
            category=Category.LICENSE,
            rule_id=name,
            severity=severity.lookup(severity.TRIVY, item.get("Severity")),
            title=f"License {name} ({item.get('Category', 'unknown')})",
            message=f"{item.get('PkgName', 'package')} uses license {name}",
            file=rel_path(str(item.get("FilePath") or target), ctx.workdir) or None,
            package=item.get("PkgName"),
        )
