import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scanner.ingest.errors import UnsafeSourceError
from scanner.ingest.git_checkout import fetch_ref, validate_git_url, validate_ref
from scanner.ingest.safe_extract import ExtractLimits

PUBLIC = ["93.184.216.34"]


def _public(host: str) -> list[str]:
    return PUBLIC


def test_public_https_url_is_accepted() -> None:
    url = "https://github.com/octocat/Hello-World.git"
    assert validate_git_url(url, _public) == url


@pytest.mark.parametrize(
    "url",
    [
        "http://github.com/a/b",
        "ssh://git@github.com/a/b",
        "git://github.com/a/b",
        "file:///etc/passwd",
        "/srv/git/repo",
        "ext::sh -c touch% /tmp/pwned",
        "https://user:pass@github.com/a/b",
        "https://github.com:22/a/b",
        "https://github.com:8443/a/b",
        "https:///a/b",
        "https://github.com/a/b\nsecond-line",
        "https://github.com/" + "a" * 2100,
    ],
)
def test_unsafe_urls_are_rejected(url: str) -> None:
    with pytest.raises(UnsafeSourceError):
        validate_git_url(url, _public)


@pytest.mark.parametrize(
    "address",
    [
        "10.0.0.5",
        "192.168.1.10",
        "172.16.0.1",
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",  # noqa: S104
        "::1",
        "fd00::1",
        "fe80::1%eth0",
    ],  # noqa: S104
)
def test_hosts_resolving_to_non_public_addresses_are_rejected(address: str) -> None:
    with pytest.raises(UnsafeSourceError, match="public"):
        validate_git_url("https://git.example.com/a/b", lambda host: [address])


def test_one_private_address_among_public_ones_is_enough_to_reject() -> None:
    with pytest.raises(UnsafeSourceError):
        validate_git_url("https://git.example.com/a/b", lambda host: [*PUBLIC, "10.0.0.5"])


def test_unresolvable_hosts_are_rejected() -> None:
    with pytest.raises(UnsafeSourceError, match="resolved"):
        validate_git_url("https://git.example.com/a/b", lambda host: [])


@pytest.mark.parametrize(
    "url", ["https://127.0.0.1/a/b", "https://[::1]/a/b", "https://169.254.169.254/latest"]
)
def test_ip_literals_are_checked_without_dns(url: str) -> None:
    with pytest.raises(UnsafeSourceError):
        validate_git_url(url)


@pytest.mark.parametrize("ref", ["main", "v1.2.3", "feature/new-thing", "a" * 40, "release_1.0"])
def test_valid_refs(ref: str) -> None:
    assert validate_ref(ref) == ref


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "-x",
        "--upload-pack=evil",
        "a..b",
        "a b",
        "x;rm -rf",
        "ref/",
        "branch.lock",
        "a" * 201,
        "$(id)",
        "a\nb",
        "main\n",
    ],
)
def test_invalid_refs(ref: str) -> None:
    with pytest.raises(UnsafeSourceError):
        validate_ref(ref)


class Recorder:
    def __init__(self, fail_on: str | None = None, big_file: Path | None = None) -> None:
        self.calls: list[tuple[list[str], dict[str, str]]] = []
        self.fail_on = fail_on
        self.big_file = big_file

    def __call__(
        self, args: list[str], env: dict[str, str], timeout: int
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((args, env))
        code = 1 if self.fail_on and self.fail_on in args else 0
        if self.big_file and "checkout" in args:
            self.big_file.write_bytes(b"x" * 500)
        return subprocess.CompletedProcess(args, code, "", "")


def test_git_is_locked_down(tmp_path: Path) -> None:
    recorder = Recorder()
    fetch_ref("https://github.com/a/b", "main", tmp_path / "dest", runner=recorder)
    fetch = next(args for args, _ in recorder.calls if "fetch" in args)
    assert fetch[-3:] == ["--", "https://github.com/a/b", "main"]
    for args, env in recorder.calls:
        assert "protocol.allow=never" in args
        assert "protocol.https.allow=always" in args
        assert "http.followRedirects=false" in args
        assert "core.symlinks=false" in args  # repository symlinks become plain files
        assert f"core.hooksPath={os.devnull}" in args
        assert env["GIT_ALLOW_PROTOCOL"] == "https"
        assert env["GIT_TERMINAL_PROMPT"] == "0"
        assert env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert env["HOME"] != os.environ.get("HOME")
    assert any("--template=" in args for args, _ in recorder.calls)


def test_failed_fetch_leaves_nothing_behind(tmp_path: Path) -> None:
    with pytest.raises(UnsafeSourceError, match="could not fetch"):
        fetch_ref(
            "https://github.com/a/b", "main", tmp_path / "dest", runner=Recorder(fail_on="fetch")
        )
    assert not (tmp_path / "dest").exists()


def test_timeout_is_reported(tmp_path: Path) -> None:
    def slow(
        args: list[str], env: dict[str, str], timeout: int
    ) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(args, timeout)

    with pytest.raises(UnsafeSourceError, match="timed out"):
        fetch_ref("https://github.com/a/b", "main", tmp_path / "dest", runner=slow)
    assert not (tmp_path / "dest").exists()


def test_oversized_repository_is_rejected(tmp_path: Path) -> None:
    dest = tmp_path / "dest"
    recorder = Recorder(big_file=dest / "big.bin")
    with pytest.raises(UnsafeSourceError, match="larger"):
        fetch_ref(
            "https://github.com/a/b",
            "main",
            dest,
            limits=ExtractLimits(max_total_bytes=100),
            runner=recorder,
        )
    assert not dest.exists()


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")
class TestAgainstRealGit:
    @pytest.fixture
    def repo(self, tmp_path: Path) -> tuple[Path, str]:
        source = tmp_path / "source"
        source.mkdir()
        env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}

        def git(*args: str) -> str:
            identity = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
            done = subprocess.run(  # noqa: S603
                ["git", *identity, "-C", str(source), *args],  # noqa: S607
                env=env,
                capture_output=True,
                text=True,
                check=True,
            )
            return done.stdout.strip()

        git("init", "--quiet", "-b", "main")
        (source / "app.py").write_text("print('one')\n")
        git("add", ".")
        git("commit", "--quiet", "-m", "one")
        git("tag", "v1")
        return source, git("rev-parse", "HEAD")

    def test_branch_tag_and_commit_refs(self, repo: tuple[Path, str], tmp_path: Path) -> None:
        source, sha = repo
        for index, ref in enumerate(["main", "v1", sha]):
            dest = tmp_path / f"dest{index}"
            fetch_ref(source.as_posix(), ref, dest, protocol="file")
            assert (dest / "app.py").read_text() == "print('one')\n"
            assert not (dest / ".git").exists()

    def test_missing_ref_is_reported_cleanly(self, repo: tuple[Path, str], tmp_path: Path) -> None:
        source, _ = repo
        with pytest.raises(UnsafeSourceError, match="could not fetch"):
            fetch_ref(source.as_posix(), "no-such-branch", tmp_path / "dest", protocol="file")
        assert not (tmp_path / "dest").exists()

    def test_https_only_policy_blocks_other_protocols(
        self, repo: tuple[Path, str], tmp_path: Path
    ) -> None:
        source, _ = repo
        with pytest.raises(UnsafeSourceError):
            fetch_ref(source.as_posix(), "main", tmp_path / "dest")  # default protocol is https
