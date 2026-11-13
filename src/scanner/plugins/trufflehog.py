import json
from typing import Any

from scanner.normalize.finding import SECRET_MASK, Category, Finding, Severity
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    ScanContext,
    ScannerPlugin,
    rel_path,
    to_line,
)


class TrufflehogPlugin(ScannerPlugin):
    name = "trufflehog"
    binary = "trufflehog"

    def build_command(self, ctx: ScanContext) -> list[str]:
        # Verification sends each secret found to its provider's API, so it is opt-in,
        # and never happens offline.
        verify = ctx.config.scanners.trufflehog_verify and not ctx.config.offline
        return [
            "trufflehog",
            "filesystem",
            ".",
            "--json",
            "--no-update",
            "--no-color",
            *([] if verify else ["--no-verification"]),
        ]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        # One JSON object per line. Raw, RawV2, Redacted and ExtraData can hold the secret,
        # so only the detector name, location and verification result are read.
        findings: list[Finding] = []
        for line in proc.stdout.splitlines():
            if not line.strip():
                continue
            item: dict[str, Any] = json.loads(line)
            data = (item.get("SourceMetadata") or {}).get("Data") or {}
            location = data.get("Filesystem") or {}
            if not location.get("file"):
                continue
            findings.append(self._finding(ctx, item, location))
        return Parsed(findings)

    def _finding(self, ctx: ScanContext, item: dict[str, Any], location: dict[str, Any]) -> Finding:
        detector = str(item.get("DetectorName") or "unknown")
        verified = bool(item.get("Verified"))
        message = (
            f"Live {detector} secret: the provider accepted it, so rotate it now"
            if verified
            else f"Possible {detector} secret detected"
        )
        return Finding(
            tool=self.name,
            category=Category.SECRET,
            rule_id=detector.lower(),
            # A secret the provider accepted is in use right now.
            severity=Severity.CRITICAL if verified else Severity.HIGH,
            title=f"{detector} secret",
            message=message,
            file=rel_path(str(location["file"]), ctx.workdir),
            line_start=to_line(location.get("line")),
            secret_masked=SECRET_MASK,
        )
