import json
import re
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from scanner.core.config import Config, GateConfig
from scanner.core.gate import evaluate
from scanner.core.snippets import attach_snippets
from scanner.normalize.finding import SECRET_MASK, Category, Finding, Severity
from scanner.plugins import pii_runner
from scanner.plugins.base import CommandResult, ScanContext, Status
from scanner.plugins.presidio import PresidioPlugin

EMAIL = re.compile(r"[\w.]+@[\w.]+")


class FakeEmailRecognizer:
    """Stands in for presidio_analyzer's EmailRecognizer, which is not installed in the tests."""

    supported_entities = ["EMAIL_ADDRESS"]

    def analyze(self, text: str, entities: list[str], nlp_artifacts: Any = None) -> list[Any]:
        return [
            SimpleNamespace(entity_type="EMAIL_ADDRESS", start=m.start(), end=m.end(), score=0.9)
            for m in EMAIL.finditer(text)
        ]


class LowScoreRecognizer(FakeEmailRecognizer):
    def analyze(self, text: str, entities: list[str], nlp_artifacts: Any = None) -> list[Any]:
        return [
            SimpleNamespace(entity_type="EMAIL_ADDRESS", start=m.start(), end=m.end(), score=0.1)
            for m in EMAIL.finditer(text)
        ]


def _scan(root: Path, ignore: list[str] | None = None, recognizer: Any = None) -> dict[str, Any]:
    return pii_runner.scan(root, ignore or [], 0.5, [recognizer or FakeEmailRecognizer()])


def test_scan_reports_line_numbers_and_counts(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("hello\ncontact: bob@acme.io, amy@acme.io\nbye\n")
    result = _scan(tmp_path)
    assert result["files_scanned"] == 1
    assert result["findings"] == [
        {"file": "a.txt", "line": 2, "entity": "EMAIL_ADDRESS", "count": 2}
    ]


def test_scan_never_outputs_the_matched_value(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("bob@acme.io\n")
    assert "bob@acme.io" not in json.dumps(_scan(tmp_path))


def test_low_scores_are_dropped(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("bob@acme.io\n")
    assert _scan(tmp_path, recognizer=LowScoreRecognizer())["findings"] == []


class FakeCardRecognizer:
    """Accepts any 13 to 19 digit run, as Presidio does when the Luhn check happens to pass."""

    supported_entities = ["CREDIT_CARD"]

    def analyze(self, text: str, entities: list[str], nlp_artifacts: Any = None) -> list[Any]:
        return [
            SimpleNamespace(entity_type="CREDIT_CARD", start=m.start(), end=m.end(), score=1.0)
            for m in re.finditer(r"\d{13,19}", text)
        ]


def test_placeholder_email_domains_are_not_personal_data(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("a@example.com b@Example.ORG c@host.test d@x.localhost\n")
    assert _scan(tmp_path)["findings"] == []
    (tmp_path / "b.txt").write_text("real@acme.io\n")
    assert [f["file"] for f in _scan(tmp_path)["findings"]] == ["b.txt"]


def test_only_numbers_shaped_like_real_cards_are_reported(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text(
        "ts 1761800000000\nvisa 4111111111111111\namex 378282246310005\n"
    )
    findings = _scan(tmp_path, recognizer=FakeCardRecognizer())["findings"]
    assert [f["line"] for f in findings] == [2, 3]  # the millisecond timestamp is not a card


def test_generated_files_are_not_scanned_for_personal_data(tmp_path: Path) -> None:
    for name in ("diagram.excalidraw", "logo.svg", "app.js.map", "package-lock.json", "x.min.js"):
        (tmp_path / name).write_text("bob@acme.io\n")
    result = _scan(tmp_path)
    assert result["files_scanned"] == 0 and result["findings"] == []


def test_ignored_dirs_git_binary_and_large_files_are_skipped(tmp_path: Path) -> None:
    for folder in ("node_modules", ".git", "src"):
        (tmp_path / folder).mkdir()
        (tmp_path / folder / "x.txt").write_text("bob@acme.io\n")
    (tmp_path / "bin.dat").write_bytes(b"bob@acme.io\0\n")
    (tmp_path / "big.txt").write_text("bob@acme.io\n" + "x" * pii_runner.MAX_FILE_BYTES)
    result = _scan(tmp_path, ignore=["**/node_modules/**"])
    assert [f["file"] for f in result["findings"]] == ["src/x.txt"]


def test_symlinks_are_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("bob@acme.io\n")
    try:
        (root / "link.txt").symlink_to(tmp_path / "outside.txt")
    except OSError:
        pytest.skip("symlinks not permitted on this system")
    assert _scan(root)["findings"] == []


def test_main_writes_the_result_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "a.txt").write_text("bob@acme.io\n")
    config = tmp_path / "config.json"
    out = tmp_path / "out.json"
    config.write_text(
        json.dumps(
            {"root": str(tmp_path), "ignore": [], "entities": ["EMAIL_ADDRESS"], "min_score": 0.5}
        )
    )
    monkeypatch.setattr(pii_runner, "load_recognizers", lambda entities: [FakeEmailRecognizer()])
    assert pii_runner.main([str(config), str(out)]) == 0
    assert json.loads(out.read_text())["findings"][0]["entity"] == "EMAIL_ADDRESS"


def test_plugin_parses_runner_output(ctx: ScanContext) -> None:
    plugin = PresidioPlugin()
    plugin.build_command(ctx)
    result = {
        "files_scanned": 3,
        "findings": [
            {"file": "data/users.csv", "line": 4, "entity": "US_SSN", "count": 1},
            {"file": "README.md", "line": 9, "entity": "EMAIL_ADDRESS", "count": 2},
        ],
    }
    (ctx.plugin_dir("presidio") / "result.json").write_text(json.dumps(result))
    ssn, email = plugin.parse(ctx, CommandResult(0, "", "")).findings
    assert ssn.category is Category.PII
    assert ssn.severity is Severity.HIGH
    assert ssn.secret_masked == SECRET_MASK
    assert (ssn.file, ssn.line_start) == ("data/users.csv", 4)
    assert email.severity is Severity.LOW
    assert "2 possible email address" in email.message


def test_many_lines_in_one_file_become_one_finding(ctx: ScanContext) -> None:
    plugin = PresidioPlugin()
    plugin.build_command(ctx)
    rows = [{"file": "d.csv", "line": n, "entity": "EMAIL_ADDRESS", "count": 1} for n in (7, 3, 9)]
    rows.append({"file": "d.csv", "line": 5, "entity": "US_SSN", "count": 1})
    (ctx.plugin_dir("presidio") / "result.json").write_text(json.dumps({"findings": rows}))
    email, ssn = plugin.parse(ctx, CommandResult(0, "", "")).findings
    assert (email.line_start, email.rule_id) == (3, "EMAIL_ADDRESS")
    assert "3 possible email address value(s) on 3 line(s) (first at line 3)" in email.message
    assert ssn.rule_id == "US_SSN"


def test_command_runs_in_isolated_mode_with_a_config_file(ctx: ScanContext) -> None:
    command = PresidioPlugin().build_command(ctx)
    assert "-I" in command  # keeps the scanned directory off sys.path
    config = json.loads((ctx.plugin_dir("presidio") / "config.json").read_text())
    assert config["root"] == str(ctx.workdir)
    assert config["entities"] == ["EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", "IBAN_CODE"]


def test_plugin_is_skipped_when_presidio_is_not_installed(
    ctx: ScanContext, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("scanner.plugins.presidio.find_spec", lambda name: None)
    result = PresidioPlugin().run(ctx)
    assert result.status is Status.SKIPPED
    assert "code-scanner[pii]" in result.message


def _pii(severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        tool="presidio",
        category=Category.PII,
        rule_id="US_SSN",
        severity=severity,
        title="t",
        file="a.txt",
        line_start=3,
    )


def test_pii_is_report_only_by_default_and_gateable() -> None:
    assert evaluate([_pii()], {}, GateConfig()).passed
    strict = Config.model_validate({"gate": {"fail_on": {"pii": "high"}}}).gate
    result = evaluate([_pii()], {}, strict)
    assert not result.passed
    assert "pii" in result.reasons[0]


def test_no_source_lines_are_copied_near_pii(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_text("\n".join(f"line {n}" for n in range(1, 11)))
    pii = _pii()
    nearby = Finding(
        tool="t",
        category=Category.CODE,
        rule_id="R",
        severity=Severity.LOW,
        title="t",
        file="a.txt",
        line_start=5,
    )
    attach_snippets([pii, nearby], tmp_path)
    assert pii.snippet is None
    assert nearby.snippet is None
