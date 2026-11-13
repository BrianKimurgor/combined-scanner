import shutil
import tarfile
from pathlib import Path

import pytest

from gitrepo import Repo
from scanner.ingest.errors import UnsafeSourceError
from scanner.ingest.git_export import export_commit, git_toplevel, resolve_commit
from scanner.ingest.safe_extract import ExtractLimits

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")


@pytest.fixture
def repo(tmp_path: Path) -> Repo:
    return Repo(tmp_path / "repo")


def test_resolves_branches_tags_and_relative_refs(repo: Repo) -> None:
    first = repo.commit({"a.txt": "1"})
    repo.git("tag", "v1")
    second = repo.commit({"a.txt": "2"})
    assert resolve_commit(repo.path, "HEAD") == second
    assert resolve_commit(repo.path, "main") == second
    assert resolve_commit(repo.path, "v1") == first
    assert resolve_commit(repo.path, "HEAD~1") == first
    assert resolve_commit(repo.path, first[:10]) == first


@pytest.mark.parametrize("ref", ["no-such-ref", "", "-x", "--upload-pack=evil", "HEAD; rm -rf /"])
def test_unknown_or_option_like_refs_are_rejected(repo: Repo, ref: str) -> None:
    repo.commit({"a.txt": "1"})
    with pytest.raises(UnsafeSourceError):
        resolve_commit(repo.path, ref)


def test_export_writes_exactly_the_commit(repo: Repo, tmp_path: Path) -> None:
    first = repo.commit({"a.txt": "one", "dir/b.txt": "bee"})
    repo.commit({"a.txt": "two", "c.txt": "see"})
    dest = tmp_path / "out"
    export_commit(repo.path, first, dest)
    assert (dest / "a.txt").read_text() == "one"
    assert (dest / "dir/b.txt").read_text() == "bee"
    assert not (dest / "c.txt").exists()
    assert not (dest / ".git").exists()


def test_export_does_not_touch_the_working_tree_or_index(repo: Repo, tmp_path: Path) -> None:
    sha = repo.commit({"a.txt": "committed"})
    (repo.path / "a.txt").write_text("uncommitted edit")
    export_commit(repo.path, sha, tmp_path / "out")
    assert (repo.path / "a.txt").read_text() == "uncommitted edit"
    assert repo.git("status", "--porcelain") == "M a.txt"
    assert (tmp_path / "out/a.txt").read_text() == "committed"


def test_export_ignore_cannot_hide_files_from_the_scan(repo: Repo, tmp_path: Path) -> None:
    files = {".gitattributes": "hidden/** export-ignore\n", "hidden/evil.py": "VULN", "ok.py": "1"}
    sha = repo.commit(files)
    archive = tmp_path / "archive.tar"
    repo.git("archive", "--format=tar", f"--output={archive}", "HEAD")
    with tarfile.open(archive) as tar:
        assert "hidden/evil.py" not in tar.getnames()  # why git archive is not used
    dest = tmp_path / "out"
    export_commit(repo.path, sha, dest)
    assert (dest / "hidden/evil.py").read_text() == "VULN"


def test_export_rejects_partial_ids_and_failures(repo: Repo, tmp_path: Path) -> None:
    sha = repo.commit({"a.txt": "1"})
    with pytest.raises(UnsafeSourceError, match="full commit id"):
        export_commit(repo.path, sha[:8], tmp_path / "out")
    with pytest.raises(UnsafeSourceError, match="failed"):
        export_commit(repo.path, "0" * 40, tmp_path / "out2")
    assert not (tmp_path / "out2").exists()


def test_export_enforces_size_limits(repo: Repo, tmp_path: Path) -> None:
    sha = repo.commit({"big.txt": "x" * 500})
    with pytest.raises(UnsafeSourceError, match="larger"):
        export_commit(repo.path, sha, tmp_path / "out", ExtractLimits(max_total_bytes=100))
    assert not (tmp_path / "out").exists()


def test_toplevel_of_a_subdirectory(repo: Repo) -> None:
    repo.commit({"sub/a.txt": "1"})
    assert git_toplevel(repo.path / "sub") == repo.path.resolve()


def test_toplevel_outside_a_repository(tmp_path: Path) -> None:
    plain = tmp_path / "plain"
    plain.mkdir()
    with pytest.raises(UnsafeSourceError, match="not inside a git repository"):
        git_toplevel(plain)
