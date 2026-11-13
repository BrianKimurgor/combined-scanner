import json
from collections.abc import Callable
from typing import Any

from scanner.normalize.dedupe import dedupe
from scanner.normalize.finding import SECRET_MASK, Category, Severity
from scanner.plugins.base import CommandResult, ScanContext
from scanner.plugins.checkov import CheckovPlugin
from scanner.plugins.gitleaks import GitleaksPlugin
from scanner.plugins.jscpd import JscpdPlugin
from scanner.plugins.lizard import LizardPlugin
from scanner.plugins.osv import OsvPlugin
from scanner.plugins.semgrep import SemgrepPlugin
from scanner.plugins.trivy import TrivyPlugin
from scanner.plugins.trufflehog import TrufflehogPlugin

Fixture = Callable[[str], str]


def _out(text: str) -> CommandResult:
    return CommandResult(0, text, "")


def test_osv(ctx: ScanContext, fixture_text: Fixture) -> None:
    (finding,) = OsvPlugin().parse(ctx, _out(fixture_text("osv.json"))).findings
    assert finding.category is Category.DEPENDENCY
    assert finding.rule_id == "CVE-2020-8203"  # CVE alias preferred over the GHSA id
    assert finding.severity is Severity.HIGH  # CVSS 7.4
    assert (finding.package, finding.version, finding.fixed_version) == (
        "lodash",
        "4.17.15",
        "4.17.19",
    )
    assert finding.file == "package-lock.json"


def test_osv_no_packages_is_empty(ctx: ScanContext) -> None:
    assert OsvPlugin().parse(ctx, CommandResult(128, "", "no packages")).findings == []


def test_osv_ignores_git_commit_ranges_when_reporting_the_fix(ctx: ScanContext) -> None:
    vuln = {
        "id": "CVE-2023-30861",
        "summary": "s",
        "affected": [
            {
                "package": {"name": "flask"},
                "ranges": [
                    {"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "70f906c51ce4"}]},
                    {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.2.5"}]},
                ],
            }
        ],
    }
    data = {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {"package": {"name": "flask", "version": "1.0"}, "vulnerabilities": [vuln]}
                ],
            }
        ]
    }
    (finding,) = OsvPlugin().parse(ctx, _out(json.dumps(data))).findings
    assert finding.fixed_version == "2.2.5"


def test_semgrep(ctx: ScanContext, fixture_text: Fixture) -> None:
    sql, opened = SemgrepPlugin().parse(ctx, _out(fixture_text("semgrep.json"))).findings
    assert sql.category is Category.CODE
    assert sql.severity is Severity.HIGH
    assert (sql.file, sql.line_start, sql.line_end) == ("app/db.py", 12, 14)
    assert sql.title == "sql-injection-using-raw"
    assert opened.severity is Severity.MEDIUM


def test_gitleaks_masks_secret(ctx: ScanContext, fixture_text: Fixture) -> None:
    plugin = GitleaksPlugin()
    plugin.build_command(ctx)
    (ctx.plugin_dir("gitleaks") / "report.json").write_text(fixture_text("gitleaks.json"))
    (finding,) = plugin.parse(ctx, _out("")).findings
    assert finding.category is Category.SECRET
    assert finding.secret_masked == SECRET_MASK
    assert (finding.file, finding.line_start) == ("config/settings.py", 7)
    assert "AKIAFAKE" not in finding.model_dump_json()


def test_gitleaks_without_report_is_empty(ctx: ScanContext) -> None:
    assert GitleaksPlugin().parse(ctx, _out("")).findings == []


def test_trufflehog_masks_secret_and_rates_live_ones_critical(
    ctx: ScanContext, fixture_text: Fixture
) -> None:
    live, possible = TrufflehogPlugin().parse(ctx, _out(fixture_text("trufflehog.jsonl"))).findings
    assert live.category is Category.SECRET
    assert live.severity is Severity.CRITICAL  # the provider accepted it
    assert (live.rule_id, live.file, live.line_start) == ("aws", "config/settings.py", 7)
    assert possible.severity is Severity.HIGH
    assert (possible.file, possible.line_start) == ("deploy/.env", 3)
    dumped = live.model_dump_json() + possible.model_dump_json()
    for leaked in ("AKIAFAKE", "ghp_FAKE", "123456789012", "wJalr"):
        assert leaked not in dumped
    assert live.secret_masked == possible.secret_masked == SECRET_MASK


def test_trufflehog_skips_results_without_a_file(ctx: ScanContext) -> None:
    line = json.dumps(
        {"SourceMetadata": {"Data": {"Git": {"commit": "abc"}}}, "DetectorName": "AWS"}
    )
    assert TrufflehogPlugin().parse(ctx, _out(line)).findings == []
    assert TrufflehogPlugin().parse(ctx, _out("")).findings == []


def test_trufflehog_and_gitleaks_merge_on_the_same_line(
    ctx: ScanContext, fixture_text: Fixture
) -> None:
    gitleaks = GitleaksPlugin()
    gitleaks.build_command(ctx)
    (ctx.plugin_dir("gitleaks") / "report.json").write_text(fixture_text("gitleaks.json"))
    found = [
        *gitleaks.parse(ctx, _out("")).findings,
        *TrufflehogPlugin().parse(ctx, _out(fixture_text("trufflehog.jsonl"))).findings,
    ]
    merged = {f.file: f for f in dedupe(found)}
    assert merged["config/settings.py"].sources == ["gitleaks", "trufflehog"]
    assert merged["config/settings.py"].severity is Severity.CRITICAL


def test_trivy_covers_all_categories(ctx: ScanContext, fixture_text: Fixture) -> None:
    findings = TrivyPlugin().parse(ctx, _out(fixture_text("trivy.json"))).findings
    by_category = {f.category: f for f in findings}
    assert set(by_category) == {
        Category.DEPENDENCY,
        Category.IAC,
        Category.SECRET,
        Category.LICENSE,
    }
    assert (
        len(findings) == 4
    )  # the PASS misconfiguration and the permissive MIT licence are skipped
    assert by_category[Category.DEPENDENCY].rule_id == "CVE-2020-8203"
    assert by_category[Category.IAC].rule_id == "DS002"
    assert by_category[Category.IAC].line_start is None
    assert by_category[Category.SECRET].severity is Severity.CRITICAL
    assert "AKIAFAKE" not in by_category[Category.SECRET].model_dump_json()
    assert by_category[Category.LICENSE].file == "package-lock.json"
    assert by_category[Category.LICENSE].rule_id == "GPL-3.0-only"


def test_jscpd(ctx: ScanContext, fixture_text: Fixture) -> None:
    plugin = JscpdPlugin()
    plugin.build_command(ctx)
    (ctx.plugin_dir("jscpd") / "jscpd-report.json").write_text(fixture_text("jscpd-report.json"))
    parsed = plugin.parse(ctx, _out(""))
    (finding,) = parsed.findings
    assert finding.category is Category.DUPLICATION
    assert (finding.file, finding.line_start, finding.line_end) == ("app/a.py", 10, 25)
    assert "app/b.py:40" in finding.message
    assert parsed.metrics == {"duplication_percent": 15.0}


def test_jscpd_only_looks_at_programming_languages(ctx: ScanContext) -> None:
    command = JscpdPlugin().build_command(ctx)
    formats = command[command.index("--format") + 1].split(",")
    assert {"typescript", "python", "go"} <= set(formats)
    assert not {"json", "markdown", "sql", "yaml"} & set(formats)
    ignored = command[command.index("--ignore") + 1].split(",")
    assert "**/__tests__/**" in ignored and "**/node_modules/**" in ignored


def test_jscpd_reports_one_finding_per_file(ctx: ScanContext) -> None:
    def clone(first: str, start: int, lines: int, second: str) -> dict[str, Any]:
        return {
            "lines": lines,
            "firstFile": {"name": first, "start": start, "end": start + lines},
            "secondFile": {"name": second, "start": 1, "end": lines},
        }

    plugin = JscpdPlugin()
    plugin.build_command(ctx)
    report = {
        "statistics": {"total": {"percentage": 9}},
        "duplicates": [
            clone("a.py", 10, 5, "b.py"),
            clone("a.py", 40, 30, "c.py"),
            clone("a.py", 90, 7, "b.py"),
            clone("b.py", 1, 5, "a.py"),
        ],
    }
    (ctx.plugin_dir("jscpd") / "jscpd-report.json").write_text(json.dumps(report))
    by_file = {f.file: f for f in plugin.parse(ctx, _out("")).findings}
    assert set(by_file) == {"a.py", "b.py"}
    many = by_file["a.py"]
    assert many.title == "3 duplicated blocks (42 lines)"
    assert (many.line_start, many.line_end) == (40, 70)  # the largest block
    assert "c.py:1" in many.message


def test_lizard_reports_only_functions_over_limits(ctx: ScanContext, fixture_text: Fixture) -> None:
    big, huge = LizardPlugin().parse(ctx, _out(fixture_text("lizard.csv"))).findings
    assert big.title == "big exceeds complexity limits"
    assert big.severity is Severity.MEDIUM
    assert "complexity 20 > 15" in big.message
    assert big.file == "app/long.py"
    assert huge.severity is Severity.HIGH
    assert "parameters 7 > 6" in huge.message


def test_checkov(ctx: ScanContext, fixture_text: Fixture) -> None:
    user, health = CheckovPlugin().parse(ctx, _out(fixture_text("checkov.json"))).findings
    assert user.category is Category.IAC
    assert user.file == "Dockerfile"
    assert user.severity is Severity.MEDIUM  # null severity falls back to medium
    assert (user.line_start, user.line_end) == (1, 5)
    assert health.severity is Severity.LOW


def test_checkov_multiple_framework_reports(ctx: ScanContext, fixture_text: Fixture) -> None:
    text = f"[{fixture_text('checkov.json')}, {fixture_text('checkov.json')}]"
    assert len(CheckovPlugin().parse(ctx, _out(text)).findings) == 4
