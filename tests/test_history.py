"""History scans: the secret scanners read every commit of a git repository."""

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from gitrepo import Repo
from scanner.cli import app
from scanner.core.config import Config
from scanner.core.diff import assign_fingerprints
from scanner.core.result import GateResult, ScanReport
from scanner.core.score import compute_score
from scanner.ingest.errors import UnsafeSourceError
from scanner.ingest.git_checkout import FetchOptions, fetch_ref, git_checkout
from scanner.normalize.dedupe import dedupe
from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins.base import (
    CommandResult,
    Parsed,
    PluginResult,
    ScanContext,
    ScannerPlugin,
    Status,
)
from scanner.plugins.gitleaks import GitleaksPlugin
from scanner.plugins.trufflehog import TrufflehogPlugin
from scanner.report import markdown, sarif
from scanner.settings import Settings
from scanner.worker import runner as worker_runner
from scanner.worker.sandbox import SandboxDirs, docker_command
from test_api import Env, build_env

COMMIT = "82d5d0f5f85e5dc99dd9352280a1b48f313e93d5"
OTHER_COMMIT = "1f2e3d4c5b6a79881f2e3d4c5b6a79881f2e3d4c"
runner = CliRunner()
needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


def _ctx(tmp_path: Path, history: str | None) -> ScanContext:
    workdir = tmp_path / "project"
    workdir.mkdir(exist_ok=True)
    return ScanContext(workdir, tmp_path / "out", Config(history=history), 10)


def _secret(commit: str | None) -> Finding:
    return Finding(
        tool="gitleaks",
        category=Category.SECRET,
        rule_id="github-pat",
        severity=Severity.HIGH,
        title="t",
        file="config.py",
        line_start=1,
        commit=commit,
    )


# ---------------------------------------------------------------- scanner commands


def test_secret_scanners_read_every_commit_in_history_mode(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, "/history")
    gitleaks = GitleaksPlugin().build_command(ctx)
    assert gitleaks[:3] == ["gitleaks", "git", "/history"]
    assert "--redact" in gitleaks and "--no-git" not in gitleaks
    trufflehog = TrufflehogPlugin().build_command(ctx)
    assert trufflehog[1] == "git" and trufflehog[2].startswith("file:///")
    assert trufflehog[2].endswith("/history") and "--no-verification" in trufflehog


def test_trufflehog_is_told_when_the_history_is_a_bare_repository(tmp_path: Path) -> None:
    bare = tmp_path / "history"
    (bare / "objects").mkdir(parents=True)
    (bare / "HEAD").write_text("ref: refs/heads/scan\n")
    assert "--bare" in TrufflehogPlugin().build_command(_ctx(tmp_path, str(bare)))
    working_copy = tmp_path / "repo"
    (working_copy / ".git").mkdir(parents=True)
    assert "--bare" not in TrufflehogPlugin().build_command(_ctx(tmp_path, str(working_copy)))


def test_current_files_are_scanned_without_history(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, None)
    assert GitleaksPlugin().build_command(ctx)[1:3] == ["detect", "--no-git"]
    assert TrufflehogPlugin().build_command(ctx)[1:3] == ["filesystem", "."]
    assert GitleaksPlugin().command_env(ctx) == TrufflehogPlugin().command_env(ctx) == {}


def test_history_mode_trusts_only_the_history_repository(tmp_path: Path) -> None:
    # Git refuses repositories owned by another user, and the sandbox runs as its own user.
    env = TrufflehogPlugin().command_env(_ctx(tmp_path, "/history"))
    config = Path(env["GIT_CONFIG_GLOBAL"]).read_text(encoding="utf-8")
    assert config == "[safe]\n\tdirectory = /history\n"


# ---------------------------------------------------------------- parsing


def test_gitleaks_keeps_the_commit_and_drops_the_author(tmp_path: Path) -> None:
    ctx = _ctx(tmp_path, "/history")
    plugin = GitleaksPlugin()
    plugin.build_command(ctx)
    leak = {
        "RuleID": "github-pat",
        "Description": "GitHub token",
        "StartLine": 3,
        "EndLine": 3,
        "File": "config.py",
        "Secret": "REDACTED",
        "Match": "REDACTED",
        "Commit": COMMIT,
        "Author": "Jane Doe",
        "Email": "jane@example.com",
        "Message": "add the deploy settings",
        "Date": "2026-11-13T14:58:49Z",
    }
    (ctx.plugin_dir("gitleaks") / "report.json").write_text(json.dumps([leak]))
    (finding,) = plugin.parse(ctx, CommandResult(0, "", "")).findings
    assert (finding.commit, finding.file, finding.line_start) == (COMMIT, "config.py", 3)
    assert finding.message.endswith("(found in commit 82d5d0f5)")
    dumped = finding.model_dump_json()
    for personal in ("Jane", "jane@", "deploy settings", "14:58"):
        assert personal not in dumped


def test_trufflehog_keeps_the_commit_and_drops_the_author(tmp_path: Path) -> None:
    location = {
        "commit": COMMIT,
        "file": "config.py",
        "email": "Jane Doe <jane@example.com>",
        "repository": "file:///history",
        "timestamp": "2026-11-13 14:58:49 +0000",
        "line": 1,
    }
    line = json.dumps(
        {
            "SourceMetadata": {"Data": {"Git": location}},
            "DetectorName": "Github",
            "Verified": False,
            "Raw": "not-a-real-token",
            "Redacted": "",
        }
    )
    ctx = _ctx(tmp_path, "/history")
    (finding,) = TrufflehogPlugin().parse(ctx, CommandResult(0, line, "")).findings
    assert (finding.commit, finding.file, finding.line_start) == (COMMIT, "config.py", 1)
    dumped = finding.model_dump_json()
    for personal in ("Jane", "jane@", "not-a-real-token", "14:58"):
        assert personal not in dumped


def test_the_same_secret_in_two_commits_stays_two_findings(tmp_path: Path) -> None:
    findings = [_secret(COMMIT), _secret(OTHER_COMMIT)]
    assert len(dedupe(findings)) == 2
    assign_fingerprints(findings, tmp_path)
    assert findings[0].fingerprint != findings[1].fingerprint
    assert findings[0].id != findings[1].id


def test_findings_without_a_commit_are_identified_as_before() -> None:
    # Fingerprints of current-file findings must not change, or suppressions would stop matching.
    current = _secret(None)
    assert current.commit is None
    assert current.fingerprint == Finding.model_validate(current.model_dump()).fingerprint
    assert "commit" not in current.message


# ---------------------------------------------------------------- reports


def test_reports_name_the_commit(tmp_path: Path) -> None:
    finding = _secret(COMMIT)
    report = ScanReport(
        target="t",
        started_at="2026-11-13T00:00:00Z",
        duration_seconds=1.0,
        tools=[],
        findings=[finding],
        gate=GateResult(passed=False),
        score=compute_score([finding], []),
    )
    assert "config.py:1 (commit 82d5d0f5)" in markdown.render(report)
    result = json.loads(sarif.render(report))["runs"][0]["results"][0]
    assert result["properties"]["commit"] == COMMIT


# ---------------------------------------------------------------- fetching history


def _git(git_dir: Path, *args: str) -> str:
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    done = subprocess.run(  # noqa: S603
        ["git", "--git-dir", str(git_dir), *args],  # noqa: S607
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout.strip()


@pytest.fixture
def thirty_commits(tmp_path: Path) -> Repo:
    repo = Repo(tmp_path / "source")
    for number in range(30):
        repo.commit({"notes.txt": f"line {number}\n"}, f"commit {number}")
    return repo


@needs_git
def test_history_fetch_keeps_every_commit_as_a_bare_repository(
    thirty_commits: Repo, tmp_path: Path
) -> None:
    dest, keep = tmp_path / "dest", tmp_path / "history"
    options = FetchOptions(protocol="file", depth=1000, history_dest=keep)
    fetch_ref(thirty_commits.path.as_uri(), "main", dest, options)
    assert (dest / "notes.txt").read_text() == "line 29\n"
    assert not (dest / ".git").exists()  # the scanned tree still has no git data in it
    assert _git(keep, "rev-parse", "--is-bare-repository") == "true"
    assert _git(keep, "rev-parse", "refs/heads/scan") == thirty_commits.git("rev-parse", "HEAD")
    assert _git(keep, "rev-list", "--count", "scan") == "30"


@needs_git
def test_history_depth_limits_the_commits_fetched(thirty_commits: Repo, tmp_path: Path) -> None:
    keep = tmp_path / "history"
    options = FetchOptions(protocol="file", depth=10, history_dest=keep)
    fetch_ref(thirty_commits.path.as_uri(), "main", tmp_path / "dest", options)
    assert _git(keep, "rev-list", "--count", "scan") == "10"


@needs_git
def test_a_normal_fetch_still_takes_one_commit_and_keeps_no_git_data(
    thirty_commits: Repo, tmp_path: Path
) -> None:
    dest = tmp_path / "dest"
    fetch_ref(thirty_commits.path.as_uri(), "main", dest, FetchOptions(protocol="file"))
    assert (dest / "notes.txt").read_text() == "line 29\n"
    assert not (dest / ".git").exists() and not (tmp_path / "history").exists()


def test_server_checkouts_stay_https_only(tmp_path: Path) -> None:
    with pytest.raises(UnsafeSourceError, match="https"):
        git_checkout("https://github.com/a/b", "main", tmp_path, FetchOptions(protocol="file"))


# ---------------------------------------------------------------- sandbox


def test_history_is_mounted_read_only_and_passed_to_the_scan(tmp_path: Path) -> None:
    src, out, history = tmp_path / "src", tmp_path / "out", tmp_path / "history"
    for directory in (src, out, history):
        directory.mkdir()
    settings = Settings(data_dir=tmp_path)
    command = docker_command(settings, "abc", SandboxDirs(src, out, history=history))
    assert f"type=bind,source={history.resolve()},target=/history,readonly" in command
    assert command[command.index("SCANNER_HISTORY_REPO=/history") - 1] == "-e"
    assert command[-1] == "--history"
    without = docker_command(settings, "abc", SandboxDirs(src, out))
    assert "--history" not in without and "SCANNER_HISTORY_REPO=/history" not in without
    assert not any(part.endswith("target=/history,readonly") for part in without)


# ---------------------------------------------------------------- command line


class _Spy(ScannerPlugin):
    """Records which repository the scanners were pointed at, without running anything."""

    name = "spy"
    binary = "spy"
    seen: list[str | None] = []

    def build_command(self, ctx: ScanContext) -> list[str]:
        return ["spy"]

    def run(self, ctx: ScanContext) -> PluginResult:
        _Spy.seen.append(ctx.config.history)
        return PluginResult(tool=self.name, status=Status.OK)

    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        return Parsed([])


def test_history_cannot_be_combined_with_a_diff(tmp_path: Path) -> None:
    result = runner.invoke(app, ["scan", str(tmp_path), "--history", "--base", "main"])
    assert result.exit_code == 2 and "--history cannot be combined" in result.output


def test_history_needs_a_git_repository(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SCANNER_HISTORY_REPO", raising=False)
    result = runner.invoke(app, ["scan", str(tmp_path), "--history"])
    assert result.exit_code == 2 and "not inside a git repository" in result.output


@needs_git
def test_history_points_the_scanners_at_the_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = Repo(tmp_path / "repo")
    repo.commit({"src/app.py": "x = 1\n"})
    monkeypatch.delenv("SCANNER_HISTORY_REPO", raising=False)
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: [_Spy()])
    _Spy.seen.clear()
    runner.invoke(app, ["scan", str(repo.path / "src"), "--history"])
    assert len(_Spy.seen) == 1 and Path(_Spy.seen[0] or "") == repo.path.resolve()


def test_the_worker_names_the_history_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SCANNER_HISTORY_REPO", "/history")
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: [_Spy()])
    _Spy.seen.clear()
    runner.invoke(app, ["scan", str(tmp_path), "--history"])
    assert _Spy.seen == ["/history"]


# ---------------------------------------------------------------- API


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Env:
    monkeypatch.setattr("scanner.ingest.git_checkout._resolve", lambda host: ["93.184.216.34"])
    return build_env(tmp_path, monkeypatch)


def test_history_scans_are_queued_with_the_flag(env: Env) -> None:
    body = {"git_url": "https://github.com/a/b", "ref": "main", "history": True}
    created = env.client.post("/scans", json=body, headers=env.headers)
    assert created.status_code == 202
    status = env.client.get(f"/scans/{created.json()['scan_id']}", headers=env.headers).json()
    assert status["history"] is True


def test_history_scans_cannot_be_diff_scans(env: Env) -> None:
    body = {"git_url": "https://github.com/a/b", "base": "main", "history": True}
    response = env.client.post("/scans", json=body, headers=env.headers)
    assert response.status_code == 400 and "history" in response.json()["detail"]


# ---------------------------------------------------------------- worker


def _fake_checkout(calls: list[FetchOptions | None]) -> Any:
    def checkout(url: str, ref: str, dest: Path, options: FetchOptions | None = None) -> None:
        calls.append(options)
        dest.mkdir(parents=True)
        (dest / "app.py").write_text("x = 1\n")
        if options is not None and options.history_dest is not None:
            options.history_dest.mkdir()

    return checkout


@pytest.mark.parametrize("history", [True, False])
def test_the_worker_fetches_history_only_for_history_scans(
    env: Env, monkeypatch: pytest.MonkeyPatch, history: bool
) -> None:
    calls: list[FetchOptions | None] = []
    monkeypatch.setattr(worker_runner, "git_checkout", _fake_checkout(calls))
    sandboxed: list[SandboxDirs] = []
    real_sandbox = worker_runner.run_in_sandbox

    def spy(settings: Settings, scan_id: str, dirs: SandboxDirs, watch: Any = None) -> Any:
        sandboxed.append(dirs)
        return real_sandbox(settings, scan_id, dirs, watch)

    monkeypatch.setattr(worker_runner, "run_in_sandbox", spy)
    body = {"git_url": "https://github.com/a/b", "ref": "main", "history": history}
    scan_id = env.client.post("/scans", json=body, headers=env.headers).json()["scan_id"]
    worker_runner.process_next(env.settings, env.factory)

    status = env.client.get(f"/scans/{scan_id}", headers=env.headers).json()
    assert status["status"] == "done"
    (options,) = calls
    assert options is not None
    if history:
        assert options.depth == env.settings.history_max_commits
        assert options.history_dest is not None
        assert sandboxed[0].history == options.history_dest
    else:
        assert options.depth == 1 and options.history_dest is None
        assert sandboxed[0].history is None
