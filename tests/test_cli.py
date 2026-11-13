import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fakes import FailingPlugin, GoodPlugin, LowPlugin, MissingPlugin
from scanner import __version__
from scanner.cli import app, stage
from scanner.plugins.base import ScannerPlugin

runner = CliRunner()


def _use(monkeypatch: pytest.MonkeyPatch, *plugins: ScannerPlugin) -> None:
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: list(plugins))


def test_version_command() -> None:
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert result.stdout.strip() == __version__


def test_scan_gate_failure_exits_1_with_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, GoodPlugin())
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    data = json.loads(result.stdout)
    assert data["gate"]["passed"] is False
    assert data["findings"][0]["rule_id"] == "R1"


def test_fail_on_override_passes_the_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, GoodPlugin())
    result = runner.invoke(app, ["scan", str(tmp_path), "--fail-on", "critical"])
    assert result.exit_code == 0


def test_staged_scan_copies_the_source_but_reports_the_original_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src, stage_dir = tmp_path / "src", tmp_path / "stage"
    src.mkdir()
    (src / "a.py").write_text("x = 1\n")
    stage_dir.mkdir()
    _use(monkeypatch, GoodPlugin())
    result = runner.invoke(app, ["scan", str(src), "--stage-dir", str(stage_dir)])
    assert json.loads(result.stdout)["target"] == str(src.resolve())
    assert (stage_dir / "head" / "a.py").read_text() == "x = 1\n"


def test_stage_falls_back_to_the_original_when_the_copy_fails(tmp_path: Path) -> None:
    src = tmp_path / "src"
    src.mkdir()
    blocked = tmp_path / "file"
    blocked.write_text("not a directory")
    assert stage(src, blocked / "head") == src


def test_scanner_failure_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, FailingPlugin())
    assert runner.invoke(app, ["scan", str(tmp_path)]).exit_code == 2


def test_skipped_tool_alongside_a_working_one_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _use(monkeypatch, MissingPlugin(), LowPlugin())
    result = runner.invoke(app, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert [t["status"] for t in json.loads(result.stdout)["tools"]] == ["skipped", "ok"]


def test_no_scanner_ran_exits_2(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, MissingPlugin())
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "md"])
    assert result.exit_code == 2
    assert "no scanner ran successfully" in result.stdout


def test_markdown_output_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, GoodPlugin())
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "md", "-o", str(out)])
    assert result.exit_code == 1
    assert out.read_text(encoding="utf-8").startswith("# Code Scan Report")


def test_html_output_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _use(monkeypatch, GoodPlugin())
    out = tmp_path / "report.html"
    result = runner.invoke(app, ["scan", str(tmp_path), "-f", "html", "-o", str(out)])
    assert result.exit_code == 1
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")


def test_invalid_config_exits_2(tmp_path: Path) -> None:
    config = tmp_path / "scanner.yml"
    config.write_text("gate:\n  fail_on: {code: severe}\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--config", str(config)])
    assert result.exit_code == 2
    assert "Configuration error" in result.output


def test_unknown_scanner_in_config_exits_2(tmp_path: Path) -> None:
    config = tmp_path / "scanner.yml"
    config.write_text("scanners:\n  enabled: [nope]\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--config", str(config)])
    assert result.exit_code == 2
    assert "unknown scanner" in result.output


def test_scan_requires_existing_directory(tmp_path: Path) -> None:
    assert runner.invoke(app, ["scan", str(tmp_path / "missing")]).exit_code != 0
