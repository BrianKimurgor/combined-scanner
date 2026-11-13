import ipaddress
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from scanner.ingest.errors import UnsafeSourceError
from scanner.ingest.safe_extract import ExtractLimits

Resolver = Callable[[str], Sequence[str]]
Runner = Callable[[list[str], dict[str, str], int], subprocess.CompletedProcess[str]]

_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/\-]{0,199}$")
_ALLOWED_PORTS = {None, 443}


def _resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError as exc:
        raise UnsafeSourceError("repository host could not be resolved") from exc
    return [str(info[4][0]) for info in infos]


def validate_git_url(url: str, resolver: Resolver | None = None) -> str:
    """Accept only public https repository URLs, to keep the server from being used for SSRF."""
    _require_public_host(_https_hostname(url), resolver or _resolve)
    return url


def _https_hostname(url: str) -> str:
    """Check the URL's shape (https, no credentials, default port) and return its host."""
    if len(url) > 2048 or any(c.isspace() or ord(c) < 32 for c in url):
        raise UnsafeSourceError("invalid repository URL")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError as exc:
        raise UnsafeSourceError("invalid repository URL") from exc
    if parts.scheme != "https":
        raise UnsafeSourceError("only https repository URLs are allowed")
    if parts.username or parts.password:
        raise UnsafeSourceError("credentials in the repository URL are not allowed")
    if not parts.hostname or port not in _ALLOWED_PORTS:
        raise UnsafeSourceError("repository URL must use a hostname and the default https port")
    return parts.hostname


def _require_public_host(hostname: str, resolver: Resolver) -> None:
    """Every address the host resolves to must be public, or the fetch could reach internal ones."""
    addresses = resolver(hostname)
    if not addresses:
        raise UnsafeSourceError("repository host could not be resolved")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%")[0])
        except ValueError as exc:
            raise UnsafeSourceError("repository host resolved to an invalid address") from exc
        if not parsed.is_global:
            raise UnsafeSourceError("repository host is not a public address")


def validate_ref(ref: str) -> str:
    if not _REF.fullmatch(ref) or ".." in ref or ref.endswith(("/", ".lock")):
        raise UnsafeSourceError("invalid git ref")
    return ref


def _run(args: list[str], env: dict[str, str], timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        args, env=env, capture_output=True, text=True, timeout=timeout, check=False
    )


def _make_writable_and_retry(
    func: Callable[[str], object], target: str, exc: BaseException
) -> None:
    if isinstance(exc, FileNotFoundError):  # already gone
        return
    os.chmod(target, stat.S_IWRITE)
    func(target)


def remove_tree(path: Path, *, ignore_errors: bool) -> None:
    """rmtree that also deletes read-only files, which git creates under .git on Windows."""
    try:
        shutil.rmtree(path, onexc=_make_writable_and_retry)
    except OSError:
        if not ignore_errors:
            raise


def check_tree_size(root: Path, limits: ExtractLimits) -> None:
    files = total = 0
    for current, _dirs, names in os.walk(root):
        for name in names:
            files += 1
            total += Path(current, name).lstat().st_size
            if files > limits.max_files or total > limits.max_total_bytes:
                raise UnsafeSourceError("repository is larger than the allowed size")


@dataclass(frozen=True)
class FetchOptions:
    """How fetch_ref runs git."""

    protocol: str = "https"  # the only one allowed; tests fetch local repositories with "file"
    timeout: int = 300
    limits: ExtractLimits = field(default_factory=ExtractLimits)
    runner: Runner = _run  # replaced in tests to record or fake the git calls
    depth: int = 1  # how many commits to fetch, counting back from the ref
    # Keep the git data here, as a bare repository, instead of deleting it (history scans).
    history_dest: Path | None = None


def _git_env(home: str, protocol: str) -> dict[str, str]:
    """A minimal environment: no user or system config, no prompts, one protocol."""
    return {
        "PATH": os.environ.get("PATH", ""),
        "HOME": home,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_ALLOW_PROTOCOL": protocol,
        "LC_ALL": "C",
    }


def _git_steps(
    dest: Path, protocol: str, url: str, ref: str, depth: int
) -> tuple[int, list[list[str]]]:
    """The git commands that fetch one ref, and how many leading arguments they share."""
    git = [
        "git",
        "-c", "protocol.allow=never",
        "-c", f"protocol.{protocol}.allow=always",
        "-c", "http.followRedirects=false",
        "-c", f"core.hooksPath={os.devnull}",
        "-c", "core.symlinks=false",  # repository symlinks become plain files
        "-c", "core.fsmonitor=false",
        "-C", str(dest),
    ]  # fmt: skip
    fetch = ["fetch", "--quiet", "--depth", str(depth), "--no-tags", "--no-recurse-submodules"]
    return len(git), [
        git + ["init", "--quiet", "--template="],
        git + [*fetch, "--", url, ref],
        git + ["checkout", "--quiet", "--detach", "FETCH_HEAD"],
    ]


def _keep_history(dest: Path, keep: Path, env: dict[str, str], opts: FetchOptions) -> None:
    """Move the fetched git data out of the tree and make it a bare repository.

    The scanned commit becomes branch `scan`: tools that clone the repository copy branches,
    not a detached HEAD.
    """
    os.replace(dest / ".git", keep)
    git = ["git", "-c", f"core.hooksPath={os.devnull}", "--git-dir", str(keep)]
    for step in (
        [*git, "config", "core.bare", "true"],
        [*git, "update-ref", "refs/heads/scan", "HEAD"],
        [*git, "symbolic-ref", "HEAD", "refs/heads/scan"],
    ):
        if opts.runner(step, env, opts.timeout).returncode != 0:
            raise UnsafeSourceError("could not prepare the repository history")


def _discard(*paths: Path | None) -> None:
    for path in paths:
        if path is not None:
            remove_tree(path, ignore_errors=True)


def fetch_ref(url: str, ref: str, dest: Path, options: FetchOptions | None = None) -> None:
    """Fetch a ref into dest, without .git; url and ref must already be validated.

    With options.history_dest, the fetched commits are kept there as a bare repository.
    """
    opts = options or FetchOptions()
    keep = opts.history_dest
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError(f"destination is not empty: {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="git-home-") as home:
        env = _git_env(home, opts.protocol)
        shared, steps = _git_steps(dest, opts.protocol, url, ref, opts.depth)
        try:
            for step in steps:
                done = opts.runner(step, env, opts.timeout)
                if done.returncode != 0:
                    raise UnsafeSourceError(
                        f"git {step[shared]} failed: could not fetch the repository or ref"
                    )
            if keep is not None:
                _keep_history(dest, keep, env, opts)
        except subprocess.TimeoutExpired as exc:
            _discard(dest, keep)
            raise UnsafeSourceError("fetching the repository timed out") from exc
        except BaseException:
            _discard(dest, keep)
            raise
    if keep is None:
        try:
            remove_tree(dest / ".git", ignore_errors=False)
        except OSError as exc:
            _discard(dest)
            raise UnsafeSourceError("could not clean up the fetched repository") from exc
    try:
        check_tree_size(dest, opts.limits)
        if keep is not None:
            check_tree_size(keep, opts.limits)
    except UnsafeSourceError:
        _discard(dest, keep)
        raise


def git_checkout(url: str, ref: str, dest: Path, options: FetchOptions | None = None) -> None:
    """Validate the URL and ref, then fetch; options.protocol is always https here."""
    opts = options or FetchOptions()
    if opts.protocol != "https":
        raise UnsafeSourceError("only https repository URLs are allowed")
    fetch_ref(validate_git_url(url), validate_ref(ref), dest, opts)
