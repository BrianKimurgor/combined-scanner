from pathlib import Path

from fakes import (
    CrashingPlugin,
    FailingPlugin,
    GarbagePlugin,
    GoodPlugin,
    LowPlugin,
    MissingPlugin,
    SlowPlugin,
)
from scanner.core.config import Config
from scanner.core.orchestrator import _ignored, run_scan
from scanner.core.result import ScanReport, exit_code
from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins.base import ScannerPlugin, Status


def _scan(tmp_path: Path, plugins: list[ScannerPlugin], config: Config | None = None) -> ScanReport:
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    return run_scan(target, config or Config(), plugins, tmp_path / "out")


def test_successful_scan(tmp_path: Path) -> None:
    report = _scan(tmp_path, [GoodPlugin()])
    assert [(t.tool, t.status) for t in report.tools] == [("good", Status.OK)]
    assert [f.rule_id for f in report.findings] == ["R1"]
    assert not report.gate.passed
    assert exit_code(report) == 1


def test_findings_get_source_snippets(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (target / "a.py").write_text("first\nsecond\n", encoding="utf-8")
    report = _scan(tmp_path, [GoodPlugin()])
    snippet = report.findings[0].snippet
    assert snippet is not None
    assert snippet.lines == ["first", "second"]
    assert snippet.highlight_start == 1


def test_one_failing_tool_does_not_abort_the_scan(tmp_path: Path) -> None:
    report = _scan(tmp_path, [FailingPlugin(), GoodPlugin()])
    statuses = {t.tool: t for t in report.tools}
    assert statuses["failing"].status is Status.FAILED
    assert "boom" in statuses["failing"].message
    assert statuses["good"].status is Status.OK
    assert len(report.findings) == 1


def test_timeout_is_reported(tmp_path: Path) -> None:
    config = Config.model_validate({"scanners": {"timeout_seconds": 1}})
    report = _scan(tmp_path, [SlowPlugin()], config)
    assert report.tools[0].status is Status.TIMEOUT
    assert exit_code(report) == 2


def test_malformed_output_is_reported(tmp_path: Path) -> None:
    report = _scan(tmp_path, [GarbagePlugin()])
    assert report.tools[0].status is Status.FAILED
    assert "could not parse output" in report.tools[0].message


def test_missing_tool_is_skipped(tmp_path: Path) -> None:
    report = _scan(tmp_path, [MissingPlugin(), LowPlugin()])
    assert {t.tool: t.status for t in report.tools} == {
        "missing": Status.SKIPPED,
        "low": Status.OK,
    }
    assert exit_code(report) == 0


def test_scan_where_no_scanner_ran_is_an_error(tmp_path: Path) -> None:
    report = _scan(tmp_path, [MissingPlugin()])
    assert report.tools[0].status is Status.SKIPPED
    assert report.gate.passed
    assert exit_code(report) == 2
    assert exit_code(_scan(tmp_path, [])) == 2


def test_crashing_plugin_is_contained(tmp_path: Path) -> None:
    report = _scan(tmp_path, [CrashingPlugin(), GoodPlugin()])
    assert {t.tool: t.status for t in report.tools} == {
        "crashing": Status.FAILED,
        "good": Status.OK,
    }


def test_ignored_paths_are_dropped(tmp_path: Path) -> None:
    config = Config.model_validate({"ignore": ["a.py"]})
    report = _scan(tmp_path, [GoodPlugin()], config)
    assert report.findings == []
    assert report.gate.passed


def test_test_files_skip_quality_checks_but_not_security_checks() -> None:
    def finding(category: Category) -> Finding:
        return Finding(
            tool="t", category=category, rule_id="r", severity=Severity.HIGH,
            title="t", message="m", file="src/__tests__/a.test.ts",
        )  # fmt: skip

    config = Config()
    assert _ignored(finding(Category.COMPLEXITY), config)
    assert _ignored(finding(Category.DUPLICATION), config)
    assert not _ignored(finding(Category.SECRET), config)
    assert not _ignored(finding(Category.DEPENDENCY), config)


def test_licence_findings_for_ignored_packages_are_dropped() -> None:
    def finding(category: Category, package: str) -> Finding:
        return Finding(
            tool="t", category=category, rule_id="LGPL-3.0", severity=Severity.HIGH,
            title="t", message="m", file="package-lock.json", package=package,
        )  # fmt: skip

    config = Config()
    assert _ignored(finding(Category.LICENSE, "@img/sharp-libvips-linux-x64"), config)
    assert _ignored(finding(Category.LICENSE, "@img/sharp-win32-arm64"), config)
    assert not _ignored(finding(Category.LICENSE, "country-state-city"), config)
    assert not _ignored(finding(Category.DEPENDENCY, "@img/sharp-win32-arm64"), config)


def test_findings_from_two_tools_are_deduplicated(tmp_path: Path) -> None:
    class Twin(GoodPlugin):
        name = "twin"

    report = _scan(tmp_path, [GoodPlugin(), Twin()])
    # Same category/rule/file/line but different tools stay separate for code findings.
    assert len(report.findings) == 2
