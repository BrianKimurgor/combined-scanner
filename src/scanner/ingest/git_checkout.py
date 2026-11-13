import ipaddress
import os
import re
import shutil
import socket
import stat
import subprocess
import tempfile
from collections.abc import Callable, Sequence
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
    addresses = (resolver or _resolve)(parts.hostname)
    if not addresses:
        raise UnsafeSourceError("repository host could not be resolved")
    for address in addresses:
        try:
            parsed = ipaddress.ip_address(address.split("%")[0])
        except ValueError as exc:
            raise UnsafeSourceError("repository host resolved to an invalid address") from exc
        if not parsed.is_global:
            raise UnsafeSourceError("repository host is not a public address")
    return url


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


def fetch_ref(
    url: str,
    ref: str,
    dest: Path,
    *,
    protocol: str = "https",
    timeout: int = 300,
    limits: ExtractLimits | None = None,
    runner: Runner = _run,
) -> None:
    """Fetch one ref shallowly into dest and drop .git; url and ref must already be validated."""
    limits = limits or ExtractLimits()
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError(f"destination is not empty: {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="git-home-") as home:
        env = {
            "PATH": os.environ.get("PATH", ""),
            "HOME": home,
            "GIT_TERMINAL_PROMPT": "0",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ALLOW_PROTOCOL": protocol,
            "LC_ALL": "C",
        }
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
        steps = [
            git + ["init", "--quiet", "--template="],
            git
            + [
                "fetch",
                "--quiet",
                "--depth",
                "1",
                "--no-tags",
                "--no-recurse-submodules",
                "--",
                url,
                ref,
            ],
            git + ["checkout", "--quiet", "--detach", "FETCH_HEAD"],
        ]
        try:
            for step in steps:
                done = runner(step, env, timeout)
                if done.returncode != 0:
                    raise UnsafeSourceError(
                        f"git {step[len(git)]} failed: could not fetch the repository or ref"
                    )
        except subprocess.TimeoutExpired as exc:
            remove_tree(dest, ignore_errors=True)
            raise UnsafeSourceError("fetching the repository timed out") from exc
        except BaseException:
            remove_tree(dest, ignore_errors=True)
            raise
    try:
        remove_tree(dest / ".git", ignore_errors=False)
    except OSError as exc:
        remove_tree(dest, ignore_errors=True)
        raise UnsafeSourceError("could not clean up the fetched repository") from exc
    try:
        check_tree_size(dest, limits)
    except UnsafeSourceError:
        remove_tree(dest, ignore_errors=True)
        raise


def git_checkout(
    url: str, ref: str, dest: Path, *, timeout: int = 300, limits: ExtractLimits | None = None
) -> None:
    fetch_ref(validate_git_url(url), validate_ref(ref), dest, timeout=timeout, limits=limits)
