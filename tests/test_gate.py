from pathlib import Path

import pytest
from pydantic import ValidationError

from scanner.core.config import Config, GateConfig, load_config
from scanner.core.gate import evaluate
from scanner.normalize.finding import Category, Finding, Severity


def _finding(category: Category, sev: Severity) -> Finding:
    return Finding(
        tool="t", category=category, rule_id="R", severity=sev, title="t", file="a", line_start=1
    )


def test_defaults_pass_on_empty() -> None:
    assert evaluate([], {}, GateConfig()).passed


def test_vulnerability_threshold() -> None:
    gate = GateConfig()
    assert evaluate([_finding(Category.DEPENDENCY, Severity.MEDIUM)], {}, gate).passed
    result = evaluate([_finding(Category.DEPENDENCY, Severity.HIGH)], {}, gate)
    assert not result.passed
    assert "vulnerability" in result.reasons[0]


def test_any_secret_fails() -> None:
    assert not evaluate([_finding(Category.SECRET, Severity.INFO)], {}, GateConfig()).passed


def test_none_disables_a_category() -> None:
    gate = Config.model_validate({"gate": {"fail_on": {"secret": "none"}}}).gate
    assert evaluate([_finding(Category.SECRET, Severity.CRITICAL)], {}, gate).passed


def test_complexity_and_duplication_fail() -> None:
    gate = GateConfig()
    assert not evaluate([_finding(Category.COMPLEXITY, Severity.MEDIUM)], {}, gate).passed
    assert evaluate([], {"duplication_percent": 5.0}, gate).passed
    result = evaluate([], {"duplication_percent": 5.1}, gate)
    assert not result.passed
    assert "duplication" in result.reasons[0]


def test_license_and_duplication_findings_do_not_fail() -> None:
    findings = [
        _finding(Category.LICENSE, Severity.HIGH),
        _finding(Category.DUPLICATION, Severity.LOW),
    ]
    assert evaluate(findings, {}, GateConfig()).passed


def test_load_config_from_file(tmp_path: Path) -> None:
    path = tmp_path / "scanner.yml"
    path.write_text(
        "gate:\n  fail_on: {code: medium}\nscanners:\n  enabled: [osv]\n  timeout_seconds: 5\n",
        encoding="utf-8",
    )
    config = load_config(path)
    assert config.gate.fail_on.code == "medium"
    assert config.scanners.enabled == ["osv"]
    assert config.scanners.timeout_seconds == 5


def test_load_config_defaults_without_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    assert load_config(None) == Config()


def test_invalid_config_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "scanner.yml"
    path.write_text("gate:\n  fail_on: {code: severe}\n", encoding="utf-8")
    with pytest.raises(ValidationError):
        load_config(path)
