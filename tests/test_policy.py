import json
from datetime import date, timedelta
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError
from typer.testing import CliRunner

from fakes import DuplicationPlugin, MissingPlugin, VulnGrepPlugin
from scanner.cli import app
from scanner.core import baseline as baseline_module
from scanner.core.config import Config, Suppression, load_config
from scanner.core.diff_scan import Revision, run_diff_scan
from scanner.core.orchestrator import ScanOptions, run_scan
from scanner.core.policy import apply_policy
from scanner.core.result import ScanReport, exit_code

runner = CliRunner()
TOMORROW = date.today() + timedelta(days=1)


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _scan(
    tmp_path: Path, files: dict[str, str], config: Config | None = None, **kwargs: object
) -> ScanReport:
    root = _tree(tmp_path / "src", files)
    options = ScanOptions(**kwargs)  # type: ignore[arg-type]
    return run_scan(root, config or Config(), [VulnGrepPlugin()], tmp_path / "out", options)


def _suppression(fingerprint: str, **overrides: object) -> Suppression:
    fields: dict[str, object] = {
        "fingerprint": fingerprint,
        "reason": "accepted risk",
        "expires": TOMORROW,
    }
    return Suppression(**{**fields, **overrides})  # type: ignore[arg-type]


def test_fingerprints_survive_unrelated_edits(tmp_path: Path) -> None:
    before = _scan(tmp_path / "a", {"x.py": "ok\nVULN here\n"})
    after = _scan(tmp_path / "b", {"x.py": "new\nlines\nadded\nok\nVULN here\n"})
    assert before.findings[0].fingerprint == after.findings[0].fingerprint
    assert len(before.findings[0].fingerprint) == 16


def test_fingerprints_differ_for_different_findings(tmp_path: Path) -> None:
    report = _scan(
        tmp_path, {"a.py": "VULN one\n", "b.py": "VULN one\n", "c.py": "VULN two\nVULN two\n"}
    )
    assert len({f.fingerprint for f in report.findings}) == 4


def test_a_suppressed_finding_stays_visible_but_no_longer_counts(tmp_path: Path) -> None:
    report = _scan(tmp_path / "a", {"x.py": "VULN here\n"})
    fingerprint = report.findings[0].fingerprint
    config = Config(suppressions=[_suppression(fingerprint, reason="tracked in TICKET-1")])
    judged = _scan(tmp_path / "b", {"x.py": "VULN here\n"}, config)
    (finding,) = judged.findings
    assert finding.suppressed is not None and finding.suppressed.reason == "tracked in TICKET-1"
    assert judged.new_findings() == [] and judged.suppressed_count() == 1
    assert judged.gate.passed and exit_code(judged) == 0
    assert judged.score.percent == 100.0  # suppressed findings cost nothing


def test_expired_suppressions_stop_working_and_say_so(tmp_path: Path) -> None:
    fingerprint = _scan(tmp_path / "a", {"x.py": "VULN here\n"}).findings[0].fingerprint
    config = Config(
        suppressions=[_suppression(fingerprint, expires=date.today() - timedelta(days=1))]
    )
    report = _scan(tmp_path / "b", {"x.py": "VULN here\n"}, config)
    assert report.findings[0].suppressed is None
    assert not report.gate.passed
    assert any("expired" in notice for notice in report.notices)


def test_unused_suppressions_are_reported(tmp_path: Path) -> None:
    config = Config(suppressions=[_suppression("0" * 16)])
    report = _scan(tmp_path, {"x.py": "fine\n"}, config)
    assert any("matched no finding" in notice for notice in report.notices)


def test_suppressions_must_be_complete_and_short_lived() -> None:
    with pytest.raises(ValidationError):
        Suppression(fingerprint="nothex", reason="x", expires=TOMORROW)
    with pytest.raises(ValidationError):
        _suppression("a" * 16, reason="   ")
    with pytest.raises(ValidationError, match="more than a year"):
        _suppression("a" * 16, expires=date.today() + timedelta(days=400))
    with pytest.raises(ValidationError):
        Suppression.model_validate({"fingerprint": "a" * 16, "reason": "x"})  # no expiry


def test_suppressions_load_from_scanner_yml(tmp_path: Path) -> None:
    path = tmp_path / "scanner.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "suppressions": [
                    {"fingerprint": "ab" * 8, "reason": "ok", "expires": TOMORROW.isoformat()}
                ]
            }
        )
    )
    assert load_config(path).suppressions[0].fingerprint == "ab" * 8


def test_apply_policy_can_be_rerun_and_undone(tmp_path: Path) -> None:
    report = _scan(tmp_path, {"x.py": "VULN here\n"})
    suppressed = apply_policy(
        report, Config(), suppressions=[_suppression(report.findings[0].fingerprint)]
    )
    assert suppressed.gate.passed
    restored = apply_policy(suppressed, Config())
    assert restored.findings[0].suppressed is None and not restored.gate.passed
    assert report.findings[0].suppressed is None  # the input is never modified


def test_a_baseline_accepts_existing_findings_and_gates_new_ones(tmp_path: Path) -> None:
    first = _scan(tmp_path / "one", {"a.py": "VULN old\n"})
    baseline = baseline_module.from_report(first)

    same = _scan(tmp_path / "two", {"a.py": "pad\nVULN old\n"}, baseline=baseline)
    assert same.gate.passed and same.new_findings() == []
    assert same.baseline is not None
    assert (same.baseline.size, same.baseline.new_count, same.baseline.existing_count) == (1, 0, 1)

    worse = _scan(tmp_path / "three", {"a.py": "VULN old\nVULN new\n"}, baseline=baseline)
    assert not worse.gate.passed
    assert [f.is_new for f in worse.findings] == [False, True]
    assert worse.baseline is not None and worse.baseline.new_count == 1


def test_baseline_files_hold_fingerprints_only(tmp_path: Path) -> None:
    report = _scan(tmp_path / "one", {"a.py": "VULN secret-looking text\n"})
    path = tmp_path / "baseline.json"
    baseline_module.save(baseline_module.from_report(report), path)
    text = path.read_text()
    assert "secret-looking" not in text and "a.py" not in text
    assert json.loads(text)["fingerprints"] == [report.findings[0].fingerprint]
    assert baseline_module.load(path).fingerprints == [report.findings[0].fingerprint]


def test_suppressed_findings_are_left_out_of_a_baseline(tmp_path: Path) -> None:
    probe = _scan(tmp_path / "p", {"a.py": "VULN a\nVULN b\n"})
    config = Config(suppressions=[_suppression(probe.findings[0].fingerprint)])
    report = _scan(tmp_path / "q", {"a.py": "VULN a\nVULN b\n"}, config)
    assert baseline_module.from_report(report).fingerprints == [report.findings[1].fingerprint]


def test_a_baseline_also_applies_in_diff_mode(tmp_path: Path) -> None:
    base = _tree(tmp_path / "base", {"a.py": "ok\n"})
    head = _tree(tmp_path / "head", {"a.py": "VULN legacy\n"})
    revisions = (Revision(base, "b"), Revision(head, "h"))
    plain = run_diff_scan(*revisions, Config(), [VulnGrepPlugin()], tmp_path / "o1")
    assert not plain.gate.passed
    accepted = baseline_module.from_report(plain)
    rerun = run_diff_scan(
        *revisions, Config(), [VulnGrepPlugin()], tmp_path / "o2", ScanOptions(baseline=accepted)
    )
    assert rerun.gate.passed and rerun.diff is not None and rerun.diff.new_count == 0


def test_duplication_is_judged_against_the_baseline(tmp_path: Path) -> None:
    def scan(percent: str, **kwargs: object) -> ScanReport:
        root = _tree(tmp_path / f"r{percent}", {"PERCENT": percent})
        options = ScanOptions(**kwargs)  # type: ignore[arg-type]
        return run_scan(root, Config(), [DuplicationPlugin()], tmp_path / f"o{percent}", options)

    baseline = baseline_module.from_report(scan("12"))
    assert not scan("12").gate.passed  # over the 5% limit
    assert scan("12", baseline=baseline).gate.passed  # not worse than the baseline
    assert not scan("15", baseline=baseline).gate.passed


@pytest.fixture
def cli_plugins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: [VulnGrepPlugin()])


@pytest.mark.usefixtures("cli_plugins")
def test_cli_baseline_workflow(tmp_path: Path) -> None:
    legacy = _tree(tmp_path / "proj", {"a.py": "VULN legacy\n"})
    baseline_file = tmp_path / "baseline.json"
    made = runner.invoke(app, ["baseline", str(legacy), "-o", str(baseline_file)])
    assert made.exit_code == 0 and "1 finding(s)" in made.stdout

    assert runner.invoke(app, ["scan", str(legacy)]).exit_code == 1
    assert (
        runner.invoke(app, ["scan", str(legacy), "--baseline", str(baseline_file)]).exit_code == 0
    )

    (legacy / "b.py").write_text("VULN fresh\n")
    again = runner.invoke(app, ["scan", str(legacy), "--baseline", str(baseline_file)])
    assert again.exit_code == 1
    assert json.loads(again.stdout)["baseline"]["new_count"] == 1


@pytest.mark.usefixtures("cli_plugins")
def test_cli_refuses_an_incomplete_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: [MissingPlugin()])
    result = runner.invoke(app, ["baseline", str(tmp_path), "-o", str(tmp_path / "b.json")])
    assert result.exit_code == 2 and "incomplete" in result.output
    assert not (tmp_path / "b.json").exists()


@pytest.mark.usefixtures("cli_plugins")
def test_cli_rejects_a_bad_baseline_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text('{"nope": 1}')
    result = runner.invoke(app, ["scan", str(tmp_path), "--baseline", str(bad)])
    assert result.exit_code == 2 and "Configuration error" in result.output


@pytest.mark.usefixtures("cli_plugins")
def test_cli_applies_suppressions_from_a_config_file(tmp_path: Path) -> None:
    project = _tree(tmp_path / "proj", {"a.py": "VULN here\n"})
    first = json.loads(runner.invoke(app, ["scan", str(project)]).stdout)
    fingerprint = first["findings"][0]["fingerprint"]
    config = tmp_path / "scanner.yml"
    config.write_text(
        yaml.safe_dump(
            {
                "suppressions": [
                    {"fingerprint": fingerprint, "reason": "known", "expires": TOMORROW.isoformat()}
                ]
            }
        )
    )
    result = runner.invoke(app, ["scan", str(project), "--config", str(config)])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["findings"][0]["suppressed"]["reason"] == "known"
