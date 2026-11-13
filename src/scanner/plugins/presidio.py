import json
import sys
from importlib.util import find_spec

from scanner.normalize import severity
from scanner.normalize.finding import SECRET_MASK, Category, Finding
from scanner.plugins.base import CommandResult, Parsed, ScanContext, ScannerPlugin, load_json

_LABELS = {
    "EMAIL_ADDRESS": "email address",
    "CREDIT_CARD": "credit card number",
    "US_SSN": "US social security number",
    "IBAN_CODE": "IBAN",
    "PHONE_NUMBER": "phone number",
    "CRYPTO": "crypto wallet address",
    "IP_ADDRESS": "IP address",
}


class PresidioPlugin(ScannerPlugin):
    name = "presidio"
    binary = sys.executable  # Presidio is a library, so a small runner module drives it

    def unavailable_reason(self) -> str | None:
        if find_spec("presidio_analyzer") is None:
            return "presidio-analyzer is not installed (pip install 'code-scanner[pii]')"
        return super().unavailable_reason()

    def build_command(self, ctx: ScanContext) -> list[str]:
        plugin_dir = ctx.plugin_dir(self.name)
        config = plugin_dir / "config.json"
        config.write_text(
            json.dumps(
                {
                    "root": str(ctx.workdir),
                    "ignore": ctx.config.ignore,
                    "entities": ctx.config.scanners.pii_entities,
                    "min_score": ctx.config.scanners.pii_min_score,
                }
            ),
            encoding="utf-8",
        )
        # -I keeps the scanned directory (the cwd) off sys.path so uploaded code is never imported.
        return [
            sys.executable,
            "-I",
            "-m",
            "scanner.plugins.pii_runner",
            str(config),
            str(plugin_dir / "result.json"),
        ]

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        result = ctx.plugin_dir(self.name) / "result.json"
        data = load_json(result.read_text(encoding="utf-8"), {})
        # One finding per file and entity type: a data file with 50 addresses is one problem.
        grouped: dict[tuple[str, str], list[tuple[int, int]]] = {}
        for item in data.get("findings") or []:
            key = (str(item["file"]), str(item["entity"]))
            grouped.setdefault(key, []).append((int(item["line"]), int(item.get("count", 1))))
        findings: list[Finding] = []
        for (file, entity), hits in grouped.items():
            label = _LABELS.get(entity, entity.lower())
            first = min(line for line, _ in hits)
            values = sum(count for _, count in hits)
            where = f"first at line {first}" if len(hits) > 1 else f"line {first}"
            findings.append(
                Finding(
                    tool=self.name,
                    category=Category.PII,
                    rule_id=entity,
                    severity=severity.lookup(severity.PII, entity),
                    title=f"Possible {label} in source",
                    message=(
                        f"{values} possible {label} value(s) on {len(hits)} line(s) "
                        f"({where}); none are stored"
                    ),
                    file=file,
                    line_start=first,
                    secret_masked=SECRET_MASK,
                )
            )
        return Parsed(findings)
