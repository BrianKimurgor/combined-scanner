import json
import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

from fakes import VulnGrepPlugin
from gitrepo import Repo
from scanner.cli import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def grep_plugin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: [VulnGrepPlugin()])


def _tree(root: Path, files: dict[str, str]) -> Path:
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _scan(*args: str) -> tuple[int, dict]:  # type: ignore[type-arg]
    result = runner.invoke(app, ["scan", *args])
    return result.exit_code, (json.loads(result.stdout) if result.stdout.strip() else {})


def test_diff_against_a_directory_fails_on_new_findings(tmp_path: Path) -> None:
    base = _tree(tmp_path / "base", {"a.py": "VULN old\n"})
    head = _tree(tmp_path / "head", {"a.py": "VULN old\nVULN new\n"})
    code, report = _scan(str(head), "--base-path", str(base))
    assert code == 1
    assert report["diff"]["new_count"] == 1 and report["diff"]["existing_count"] == 1
    assert [f["is_new"] for f in report["findings"]] == [False, True]


def test_diff_with_only_old_findings_passes(tmp_path: Path) -> None:
    base = _tree(tmp_path / "base", {"a.py": "VULN old\n"})
    head = _tree(tmp_path / "head", {"a.py": "VULN old\n# edit\n"})
    code, report = _scan(str(head), "--base-path", str(base))
    assert code == 0 and report["gate"]["passed"] is True


def test_base_and_base_path_are_mutually_exclusive(tmp_path: Path) -> None:
    result = runner.invoke(
        app, ["scan", str(tmp_path), "--base", "main", "--base-path", str(tmp_path)]
    )
    assert result.exit_code == 2 and "either --base or --base-path" in result.output


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
class TestGitDiff:
    def test_compares_two_commits(self, tmp_path: Path) -> None:
        repo = Repo(tmp_path / "repo")
        repo.commit({"a.py": "VULN old\n"})
        repo.commit({"a.py": "VULN old\nVULN new\n"})
        code, report = _scan(str(repo.path), "--base", "HEAD~1")
        assert code == 1
        assert report["diff"]["new_count"] == 1
        assert report["diff"]["base"].startswith("HEAD~1 (") and report["diff"]["head"].startswith(
            "HEAD ("
        )
        assert report["target"].startswith("HEAD (")  # no server path in the report

    def test_same_commit_has_nothing_new(self, tmp_path: Path) -> None:
        repo = Repo(tmp_path / "repo")
        repo.commit({"a.py": "VULN old\n"})
        code, report = _scan(str(repo.path), "--base", "HEAD")
        assert (
            code == 0 and report["diff"]["new_count"] == 0 and report["diff"]["changed_total"] == 0
        )

    def test_explicit_head_ref_and_uncommitted_changes_are_ignored(self, tmp_path: Path) -> None:
        repo = Repo(tmp_path / "repo")
        first = repo.commit({"a.py": "ok\n"})
        second = repo.commit({"a.py": "VULN x\n"})
        (repo.path / "a.py").write_text("VULN x\nVULN uncommitted\n")
        code, report = _scan(str(repo.path), "--base", first, "--head", second)
        assert code == 1 and report["diff"]["new_count"] == 1

    def test_scanning_a_subdirectory_compares_just_that_folder(self, tmp_path: Path) -> None:
        repo = Repo(tmp_path / "repo")
        repo.commit({"sub/a.py": "ok\n", "other/b.py": "ok\n"})
        repo.commit({"sub/a.py": "VULN\n", "other/b.py": "VULN\n"})
        code, report = _scan(str(repo.path / "sub"), "--base", "HEAD~1")
        assert code == 1 and [f["file"] for f in report["findings"]] == ["a.py"]

    def test_a_folder_that_did_not_exist_before_is_all_new(self, tmp_path: Path) -> None:
        repo = Repo(tmp_path / "repo")
        repo.commit({"a.py": "ok\n"})
        repo.commit({"newdir/b.py": "VULN\n"})
        code, report = _scan(str(repo.path / "newdir"), "--base", "HEAD~1")
        assert code == 1 and report["diff"]["new_count"] == 1

    def test_unknown_ref_and_non_repositories_are_reported(self, tmp_path: Path) -> None:
        repo = Repo(tmp_path / "repo")
        repo.commit({"a.py": "ok\n"})
        unknown = runner.invoke(app, ["scan", str(repo.path), "--base", "no-such-ref"])
        assert unknown.exit_code == 2 and "unknown git ref" in unknown.output
        plain = _tree(tmp_path / "plain", {"a.py": "ok\n"})
        outside = runner.invoke(app, ["scan", str(plain), "--base", "HEAD"])
        assert outside.exit_code == 2 and "not inside a git repository" in outside.output


def test_scan_can_write_sarif_and_comment_formats(tmp_path: Path) -> None:
    base = _tree(tmp_path / "base", {"a.py": "ok\n"})
    head = _tree(tmp_path / "head", {"a.py": "VULN\n"})
    sarif = runner.invoke(app, ["scan", str(head), "--base-path", str(base), "-f", "sarif"])
    assert json.loads(sarif.stdout)["version"] == "2.1.0"
    comment = runner.invoke(app, ["scan", str(head), "--base-path", str(base), "-f", "comment"])
    assert comment.stdout.startswith("<!-- code-scanner:pr-comment -->")
    assert comment.exit_code == 1


def test_render_converts_a_saved_report(tmp_path: Path) -> None:
    base = _tree(tmp_path / "base", {"a.py": "ok\n"})
    head = _tree(tmp_path / "head", {"a.py": "VULN\n"})
    saved = tmp_path / "report.json"
    runner.invoke(app, ["scan", str(head), "--base-path", str(base), "-o", str(saved)])
    for fmt, marker in (
        ("sarif", '"version": "2.1.0"'),
        ("md", "# Code Scan Report"),
        ("html", "<!doctype html>"),
    ):
        out = tmp_path / f"report.{fmt}"
        result = runner.invoke(app, ["render", str(saved), "--format", fmt, "-o", str(out)])
        assert result.exit_code == 0 and marker in out.read_text(encoding="utf-8")


def test_render_rejects_files_that_are_not_reports(tmp_path: Path) -> None:
    bogus = tmp_path / "bogus.json"
    bogus.write_text('{"hello": "world"}')
    result = runner.invoke(app, ["render", str(bogus), "--format", "md"])
    assert result.exit_code == 2 and "Not a scan report" in result.output
