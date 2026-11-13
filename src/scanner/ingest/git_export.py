import os
import re
import subprocess
import tempfile
from collections.abc import Callable
from pathlib import Path

from scanner.ingest.errors import UnsafeSourceError
from scanner.ingest.git_checkout import check_tree_size, remove_tree
from scanner.ingest.safe_extract import ExtractLimits

Runner = Callable[[list[str], dict[str, str]], subprocess.CompletedProcess[str]]
_COMMIT = re.compile(r"^[0-9a-f]{40}([0-9a-f]{24})?$")
_CONFIG = ["-c", "core.symlinks=false", "-c", "core.autocrlf=false", "-c", "core.fsmonitor=false"]


def _run(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        args, env=env, capture_output=True, text=True, timeout=300, check=False
    )


def git_toplevel(path: Path, runner: Runner = _run) -> Path:
    done = runner(["git", "-C", str(path), "rev-parse", "--show-toplevel"], dict(os.environ))
    if done.returncode != 0 or not done.stdout.strip():
        raise UnsafeSourceError(f"{path} is not inside a git repository")
    return Path(done.stdout.strip()).resolve()


def resolve_commit(repo: Path, ref: str, runner: Runner = _run) -> str:
    if ref.startswith("-") or not ref:
        raise UnsafeSourceError("invalid git ref")
    command = ["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", "--end-of-options"]
    done = runner([*command, f"{ref}^{{commit}}"], dict(os.environ))
    sha = done.stdout.strip()
    if done.returncode != 0 or not _COMMIT.match(sha):
        raise UnsafeSourceError(f"unknown git ref: {ref}")
    return sha


def export_commit(
    repo: Path,
    sha: str,
    dest: Path,
    limits: ExtractLimits | None = None,
    runner: Runner = _run,
) -> None:
    """Write the files of one commit into dest without touching the repository's working tree.

    Uses a temporary index and checkout-index rather than `git archive`, because archive
    honours export-ignore, which would let a repository hide files from the scan.
    """
    limits = limits or ExtractLimits()
    if not _COMMIT.match(sha):
        raise UnsafeSourceError("expected a full commit id")
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="scanner-index-") as scratch:
        env = {
            **os.environ,
            "GIT_INDEX_FILE": str(Path(scratch, "index")),
            "GIT_TERMINAL_PROMPT": "0",
        }
        git = ["git", *_CONFIG, "-C", str(repo)]
        for step in (
            [*git, "read-tree", sha],
            [*git, "checkout-index", "--all", "--force", f"--prefix={dest.as_posix()}/"],
        ):
            done = runner(step, env)
            if done.returncode != 0:
                remove_tree(dest, ignore_errors=True)
                raise UnsafeSourceError(f"git {step[len(git)]} failed while exporting {sha[:12]}")
    try:
        check_tree_size(dest, limits)
    except UnsafeSourceError:
        remove_tree(dest, ignore_errors=True)
        raise
