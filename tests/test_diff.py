from pathlib import Path

import pytest

from fakes import DuplicationPlugin, FlakyPlugin, VulnGrepPlugin
from scanner.core import diff as diff_module
from scanner.core.config import Config
from scanner.core.diff import changed_files, finding_keys, tag_new
from scanner.core.diff_scan import Revision, run_diff_scan
from scanner.core.result import ScanReport, exit_code
from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins.base import ScannerPlugin, Status


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _diff(
    tmp_path: Path,
    base: dict[str, str],
    head: dict[str, str],
    plugins: list[ScannerPlugin] | None = None,
    config: Config | None = None,
) -> ScanReport:
    return run_diff_scan(
        Revision(_tree(tmp_path / "base", base), "main"),
        Revision(_tree(tmp_path / "head", head), "feature"),
        config or Config(),
        plugins or [VulnGrepPlugin()],
        tmp_path / "out",
    )


def _finding(**overrides: object) -> Finding:
    fields: dict[str, object] = {
        "tool": "t",
        "category": Category.CODE,
        "rule_id": "R",
        "severity": Severity.HIGH,
        "title": "title",
        "file": "a.py",
        "line_start": 1,
    }
    return Finding(**{**fields, **overrides})  # type: ignore[arg-type]


def test_changed_files_lists_added_modified_and_deleted(tmp_path: Path) -> None:
    base = _tree(
        tmp_path / "b", {"same.txt": "1", "mod.txt": "old", "gone.txt": "x", "d/deep.txt": "1"}
    )
    head = _tree(
        tmp_path / "h", {"same.txt": "1", "mod.txt": "new!", "new.txt": "y", "d/deep.txt": "2"}
    )
    changes = {(c.path, c.status) for c in changed_files(base, head, [])}
    assert changes == {
        ("mod.txt", "modified"),
        ("gone.txt", "deleted"),
        ("new.txt", "added"),
        ("d/deep.txt", "modified"),
    }


def test_changed_files_detects_same_size_edits_and_honours_ignores(tmp_path: Path) -> None:
    base = _tree(tmp_path / "b", {"a.txt": "abc", "node_modules/x/y.js": "1"})
    head = _tree(
        tmp_path / "h", {"a.txt": "abd", "node_modules/x/y.js": "2", ".git/config": "ignored"}
    )
    changes = changed_files(base, head, ["**/node_modules/**"])
    assert [(c.path, c.status) for c in changes] == [("a.txt", "modified")]


def test_moving_a_finding_down_the_file_does_not_make_it_new(tmp_path: Path) -> None:
    report = _diff(
        tmp_path,
        {"a.py": "ok\nVULN old\n"},
        {"a.py": "added line\nanother\nok\nVULN old\n"},
    )
    assert report.diff is not None
    assert (report.diff.new_count, report.diff.existing_count, report.diff.fixed_count) == (0, 1, 0)
    assert report.findings[0].line_start == 4 and report.findings[0].is_new is False


def test_a_new_finding_is_flagged_and_the_old_one_is_not(tmp_path: Path) -> None:
    report = _diff(tmp_path, {"a.py": "VULN old\n"}, {"a.py": "VULN old\nVULN fresh\n"})
    assert report.diff is not None and report.diff.new_count == 1
    new = report.new_findings()
    assert [(f.file, f.line_start) for f in new] == [("a.py", 2)]


def test_identical_lines_are_counted_not_collapsed(tmp_path: Path) -> None:
    report = _diff(tmp_path, {"a.py": "VULN x\nVULN x\n"}, {"a.py": "VULN x\nVULN x\nVULN x\n"})
    assert report.diff is not None
    assert (report.diff.new_count, report.diff.existing_count) == (1, 2)


def test_fixed_findings_are_counted(tmp_path: Path) -> None:
    report = _diff(tmp_path, {"a.py": "VULN a\nVULN b\n"}, {"a.py": "VULN a\n"})
    assert report.diff is not None
    assert (report.diff.new_count, report.diff.fixed_count) == (0, 1)


def test_findings_in_new_files_are_new(tmp_path: Path) -> None:
    report = _diff(tmp_path, {"a.py": "ok\n"}, {"a.py": "ok\n", "b/c.py": "VULN\n"})
    assert [f.file for f in report.new_findings()] == ["b/c.py"]
    assert [(c.path, c.status) for c in report.diff.changed_files] == [("b/c.py", "added")]  # type: ignore[union-attr]


def test_gate_and_exit_code_judge_only_new_findings(tmp_path: Path) -> None:
    unchanged = _diff(tmp_path / "one", {"a.py": "VULN a\n"}, {"a.py": "VULN a\n# comment\n"})
    assert unchanged.gate.passed and exit_code(unchanged) == 0  # the old high finding does not fail

    worse = _diff(tmp_path / "two", {"a.py": "VULN a\n"}, {"a.py": "VULN a\nVULN b\n"})
    assert not worse.gate.passed and exit_code(worse) == 1


def test_health_score_still_counts_existing_findings(tmp_path: Path) -> None:
    report = _diff(tmp_path, {"a.py": "VULN a\n"}, {"a.py": "VULN a\n# touched\n"})
    assert report.gate.passed
    assert report.score.percent == 95.0  # one high finding remains in the code


def test_a_tool_that_failed_on_the_base_cannot_be_compared(tmp_path: Path) -> None:
    report = _diff(
        tmp_path,
        {"FAIL_ME": "", "a.py": "VULN a\n"},
        {"a.py": "VULN a\nVULN b\n"},
        plugins=[FlakyPlugin()],
    )
    (tool,) = report.tools
    assert tool.status is Status.FAILED and "not compared" in tool.message
    assert all(f.is_new is False for f in report.findings)  # nothing is blamed on the change
    assert exit_code(report) == 2  # but the problem is not silent


def test_tools_that_are_skipped_on_both_sides_are_fine(tmp_path: Path) -> None:
    from fakes import MissingPlugin

    report = _diff(tmp_path, {"a": "1"}, {"a": "2"}, plugins=[MissingPlugin(), VulnGrepPlugin()])
    statuses = {t.tool: t.status for t in report.tools}
    assert statuses == {"missing": Status.SKIPPED, "grep": Status.OK}
    assert exit_code(report) == 0


@pytest.mark.parametrize(
    ("base", "head", "passes"),
    [
        ("10", "10", True),
        ("10", "8", True),
        ("10", "12", False),
        ("0", "6", False),
        ("0", "4", True),
    ],
)
def test_duplication_gate_only_fails_when_the_change_makes_it_worse(
    tmp_path: Path, base: str, head: str, passes: bool
) -> None:
    report = _diff(tmp_path, {"PERCENT": base}, {"PERCENT": head}, plugins=[DuplicationPlugin()])
    assert report.gate.passed is passes


def test_keys_ignore_line_numbers_but_not_content(tmp_path: Path) -> None:
    root = _tree(tmp_path, {"a.py": "x\nfoo()\nbar()\n"})
    first = finding_keys([_finding(line_start=2)], root)
    moved = finding_keys([_finding(line_start=3)], root)
    assert first != moved  # different line content...
    again = _tree(tmp_path / "other", {"a.py": "pad\npad\nx\nfoo()\n"})
    shifted = finding_keys([_finding(line_start=4)], again)
    assert first == shifted  # ...but the same line elsewhere in the file matches


def test_whitespace_only_changes_do_not_create_new_findings(tmp_path: Path) -> None:
    base = _tree(tmp_path / "b", {"a.py": "foo(  1)\n"})
    head = _tree(tmp_path / "h", {"a.py": "    foo( 1)\n"})
    assert finding_keys([_finding()], base) == finding_keys([_finding()], head)


def test_dependency_keys_ignore_files_and_case() -> None:
    def dep(file: str, rule: str) -> Finding:
        return _finding(
            category=Category.DEPENDENCY, file=file, line_start=None, package="lodash",
            version="4.17.15", rule_id=rule,
        )  # fmt: skip

    root = Path(".")
    assert finding_keys([dep("a/package-lock.json", "cve-2020-8203")], root) == finding_keys(
        [dep("package-lock.json", "CVE-2020-8203")], root
    )


def test_secret_and_pii_findings_never_have_their_lines_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object) -> None:
        raise AssertionError("source lines near secrets must not be read")

    monkeypatch.setattr(diff_module, "read_lines", forbidden)
    findings = [
        _finding(category=Category.SECRET, rule_id="aws"),
        _finding(category=Category.PII, rule_id="US_SSN", line_start=9),
    ]
    assert len(finding_keys(findings, Path("."))) == 2


def test_secrets_are_matched_by_rule_and_file_not_by_line(tmp_path: Path) -> None:
    base = [_finding(category=Category.SECRET, rule_id="aws", line_start=3)]
    head = [_finding(category=Category.SECRET, rule_id="aws", line_start=40)]
    tag_new(base, tmp_path, head, tmp_path, {"t"})
    assert head[0].is_new is False
    extra = [*head, _finding(category=Category.SECRET, rule_id="aws", line_start=50)]
    tag_new(base, tmp_path, extra, tmp_path, {"t"})
    assert [f.is_new for f in extra].count(True) == 1


def test_complexity_is_tracked_by_function_name(tmp_path: Path) -> None:
    def fn(line: int) -> Finding:
        return _finding(category=Category.COMPLEXITY, title="big exceeds limits", line_start=line)

    base, head = [fn(10)], [fn(80)]
    tag_new(base, tmp_path, head, tmp_path, {"t"})
    assert head[0].is_new is False
