import os
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from scanner.core.config import Config
from scanner.core.diff_scan import Revision, run_diff_scan
from scanner.core.orchestrator import ScanOptions, run_scan
from scanner.core.progress import ProgressTracker, ScanProgress, read_progress
from scanner.core.result import exit_code
from scanner.mirror import OSV_DIR
from scanner.plugins import build_plugins
from scanner.settings import Settings

SANDBOX_UID = 10001
PROGRESS_FILE = "progress.json"
POLL_SECONDS = 1.0

ProgressCallback = Callable[[ScanProgress], None]


class SandboxError(RuntimeError):
    """A scan could not be run; the message is safe to show the user."""


@dataclass(frozen=True)
class SandboxResult:
    exit_code: int | None
    timed_out: bool
    stderr: str


def docker_command(
    settings: Settings,
    scan_id: str,
    source_dir: Path,
    out_dir: Path,
    base_dir: Path | None = None,
) -> list[str]:
    """One throwaway, locked-down container per scan; the source is mounted read-only."""
    source, out = str(source_dir.resolve()), str(out_dir.resolve())
    base = str(base_dir.resolve()) if base_dir else None
    mirror = str(settings.mirror_dir.resolve()) if settings.offline else None
    if any("," in path for path in (source, out, base or "", mirror or "")):
        raise SandboxError("scan paths must not contain commas")
    if mirror and not settings.mirror_dir.is_dir():
        raise SandboxError("offline mode needs a database mirror (scanner admin mirror-update)")
    command = _locked_down_run(settings, scan_id, offline=mirror is not None)
    if mirror:
        command += _mirror_mounts(settings, mirror)
    command += _cache_mount(settings)
    command += [
        "--mount", f"type=bind,source={source},target=/scan,readonly",
        "--mount", f"type=bind,source={out},target=/out",
    ]  # fmt: skip
    if base:
        command += ["--mount", f"type=bind,source={base},target=/base,readonly"]
    return command + [
        settings.sandbox_image,
        *_scan_arguments(base is not None, mirror is not None),
    ]


def _locked_down_run(settings: Settings, scan_id: str, *, offline: bool) -> list[str]:
    """docker run with no privileges, a read-only root, resource limits and private tmpfs."""
    memory = settings.sandbox_memory
    # Offline scans get no network at all, whatever SCANNER_SANDBOX_NETWORK says.
    network = "none" if offline else settings.sandbox_network
    return [
        "docker", "run", "--rm", "--name", f"scanner-{scan_id}",
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,size=1g",  # noqa: S108 - tmpfs inside the container
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--user", f"{SANDBOX_UID}:{SANDBOX_UID}",
        "--memory", memory, "--memory-swap", memory,
        "--cpus", settings.sandbox_cpus,
        "--pids-limit", str(settings.sandbox_pids),
        "--network", network,
        "--ulimit", "nofile=4096:4096",
        "-e", "HOME=/tmp",  # noqa: S108
        "-e", "XDG_CACHE_HOME=/cache",
        "-e", f"TRIVY_CACHE_DIR={'/mirror/trivy' if offline else '/cache/trivy'}",
        # The source is copied here first: bind mounts (Docker Desktop) read files very slowly.
        "--tmpfs", f"/work:rw,nosuid,size=2g,uid={SANDBOX_UID},gid={SANDBOX_UID}",
        "-e", "SCANNER_STAGE_DIR=/work",
    ]  # fmt: skip


def _mirror_mounts(settings: Settings, mirror: str) -> list[str]:
    """Offline scans read their vulnerability databases from a read-only mirror."""
    # OSV-Scanner writes beside its database, so the read-only archives overlay a tmpfs.
    args = ["-e", "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv"]
    args += ["--tmpfs", f"/osv:rw,nosuid,size=256m,uid={SANDBOX_UID},gid={SANDBOX_UID}"]
    args += ["--mount", f"type=bind,source={mirror},target=/mirror,readonly"]
    if (settings.mirror_dir / "osv" / OSV_DIR).is_dir():
        archives = f"{mirror}/osv/{OSV_DIR}"
        args += ["--mount", f"type=bind,source={archives},target=/osv/{OSV_DIR},readonly"]
    return args


def _cache_mount(settings: Settings) -> list[str]:
    """Scanner caches go in a shared volume, or in a tmpfs when no volume is configured."""
    if settings.sandbox_cache_volume:
        return ["--mount", f"type=volume,source={settings.sandbox_cache_volume},target=/cache"]
    return ["--tmpfs", f"/cache:rw,nosuid,size=2g,uid={SANDBOX_UID},gid={SANDBOX_UID}"]


def _scan_arguments(diff: bool, offline: bool) -> list[str]:
    """The `scanner scan` command line run inside the container."""
    args = [
        "scan", "/scan",
        "--format", "json",
        "--output", "/out/report.json",
        "--progress", f"/out/{PROGRESS_FILE}",
    ]  # fmt: skip
    if diff:
        args += ["--base-path", "/base"]
    if offline:
        args += ["--offline", "--semgrep-rules", "/mirror/semgrep-rules"]
    return args


def _run_local(
    source_dir: Path, out_dir: Path, base_dir: Path | None, on_progress: ProgressCallback | None
) -> SandboxResult:
    """Unsandboxed, for development and tests only."""
    config = Config()
    plugins = build_plugins(config.scanners.enabled)
    progress = (
        ProgressTracker([p.name for p in plugins], on_progress, passes=1 if base_dir is None else 2)
        if on_progress is not None
        else None
    )
    options = ScanOptions(progress=progress)
    if base_dir is None:
        report = run_scan(source_dir, config, plugins, out_dir / "tool-output", options)
    else:
        report = run_diff_scan(
            Revision(base_dir, str(base_dir)), Revision(source_dir, str(source_dir)),
            config, plugins, out_dir / "tool-output", options,
        )  # fmt: skip
    (out_dir / "report.json").write_text(report.model_dump_json(), encoding="utf-8")
    return SandboxResult(exit_code(report), False, "")


@dataclass(frozen=True)
class ProgressWatch:
    """Who to tell when per-scanner progress changes, and which scanners to expect."""

    expected_tools: list[str]
    on_progress: ProgressCallback


def run_in_sandbox(
    settings: Settings,
    scan_id: str,
    source_dir: Path,
    out_dir: Path,
    base_dir: Path | None = None,
    watch: ProgressWatch | None = None,
) -> SandboxResult:
    if settings.sandbox_mode == "local":
        return _run_local(source_dir, out_dir, base_dir, watch.on_progress if watch else None)
    command = docker_command(settings, scan_id, source_dir, out_dir, base_dir)
    progress_path = out_dir / PROGRESS_FILE
    last_seen: ScanProgress | None = None

    def report_progress() -> None:
        nonlocal last_seen
        if watch is None:
            return
        progress = read_progress(progress_path, watch.expected_tools)
        if progress is not None and progress != last_seen:
            last_seen = progress
            watch.on_progress(progress)

    # stderr goes to a file, not a pipe: nobody reads a pipe while polling, so it could fill up.
    stderr_path = out_dir.parent / "sandbox-stderr.txt"
    deadline = time.monotonic() + settings.scan_timeout_seconds
    try:
        with stderr_path.open("w+", encoding="utf-8", errors="replace") as stderr:
            proc = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
                command, stdout=subprocess.DEVNULL, stderr=stderr
            )
            while True:
                try:
                    returncode = proc.wait(timeout=POLL_SECONDS)
                    break
                except subprocess.TimeoutExpired:
                    report_progress()
                    if time.monotonic() >= deadline:
                        subprocess.run(  # noqa: S603
                            ["docker", "kill", f"scanner-{scan_id}"],  # noqa: S607
                            capture_output=True,
                            check=False,
                        )
                        proc.kill()
                        proc.wait()
                        return SandboxResult(None, True, "")
            report_progress()
            stderr.seek(0)
            tail = stderr.read().strip()[-500:]
    except OSError as exc:
        raise SandboxError("the sandbox could not be started (is Docker available?)") from exc
    return SandboxResult(returncode, False, tail)


def prepare_out_dir(out_dir: Path) -> None:
    """The container runs as an unprivileged uid, so it must be able to write the report here."""
    out_dir.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        # A per-scan temporary directory, deleted afterwards; the container's uid differs from ours.
        os.chmod(out_dir, 0o777)  # noqa: S103  # nosemgrep
