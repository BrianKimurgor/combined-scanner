import json
import os
import re
import shutil
import subprocess
import urllib.request
import zipfile
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

OSV_BASE = "https://osv-vulnerabilities.storage.googleapis.com"
OSV_DIR = "osv-scalibr"  # what OSV-Scanner 2.x reads; its docs still say osv-scanner
DEFAULT_ECOSYSTEMS = (
    "Go",
    "npm",
    "PyPI",
    "Maven",
    "crates.io",
    "RubyGems",
    "Packagist",
    "NuGet",
    "Pub",
    "Hex",
)
MAX_DOWNLOAD_BYTES = 4 * 1024**3
CHUNK = 1024 * 1024
_ECOSYSTEM = re.compile(r"^[A-Za-z0-9._+:-]{1,40}$")  # becomes a folder name


class MirrorError(RuntimeError):
    pass


@dataclass(frozen=True)
class MirrorEntry:
    name: str
    present: bool
    updated: datetime | None
    detail: str = ""


Fetch = Callable[[str, Path], None]
RunTool = Callable[[list[str]], int]


def _download(url: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise MirrorError("databases are only fetched over https")
    partial = dest.with_name(dest.name + ".part")
    size = 0
    try:
        with urllib.request.urlopen(url, timeout=120) as response, partial.open("wb") as out:  # noqa: S310 - https only
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > MAX_DOWNLOAD_BYTES:
                    raise MirrorError(f"{url} is larger than the allowed size")
                out.write(chunk)
        if not zipfile.is_zipfile(partial):
            raise MirrorError(f"{url} did not return a zip archive")
        os.replace(partial, dest)
    finally:
        partial.unlink(missing_ok=True)


def _run_tool(args: list[str]) -> int:
    return subprocess.run(args, check=False).returncode  # noqa: S603 - fixed argv, no shell


def update_osv(mirror: Path, ecosystems: list[str], fetch: Fetch = _download) -> list[str]:
    """Download each ecosystem's vulnerability archive into OSV-Scanner's offline layout."""
    for name in ecosystems:
        if not _ECOSYSTEM.fullmatch(name):
            raise MirrorError(f"invalid ecosystem name: {name!r}")
    done = []
    for name in ecosystems:
        target = mirror / "osv" / OSV_DIR / name
        target.mkdir(parents=True, exist_ok=True)
        fetch(f"{OSV_BASE}/{name}/all.zip", target / "all.zip")
        done.append(name)
    return done


def update_trivy(mirror: Path, run: RunTool = _run_tool) -> None:
    """Fetch Trivy's vulnerability and Java databases with the trivy on this machine."""
    if run is _run_tool and shutil.which("trivy") is None:
        raise MirrorError("trivy is not installed on this machine")
    cache = mirror / "trivy"
    cache.mkdir(parents=True, exist_ok=True)
    for flag in ("--download-db-only", "--download-java-db-only"):
        if run(["trivy", "image", flag, "--cache-dir", str(cache), "--quiet"]) != 0:
            raise MirrorError(f"trivy {flag} failed")


def _mtime(path: Path) -> datetime:
    return datetime.fromtimestamp(path.stat().st_mtime, UTC)


def status(mirror: Path) -> list[MirrorEntry]:
    entries: list[MirrorEntry] = []
    osv = mirror / "osv" / OSV_DIR
    archives = sorted(osv.glob("*/all.zip")) if osv.is_dir() else []
    if archives:
        entries.extend(
            MirrorEntry(f"osv/{a.parent.name}", True, _mtime(a), f"{a.stat().st_size // 1024} KiB")
            for a in archives
        )
    else:
        entries.append(MirrorEntry("osv", False, None, "no ecosystems downloaded"))
    metadata = mirror / "trivy" / "db" / "metadata.json"
    if metadata.is_file():
        try:
            detail = f"next update {json.loads(metadata.read_text(encoding='utf-8'))['NextUpdate']}"
        except (ValueError, KeyError, OSError):
            detail = ""
        entries.append(MirrorEntry("trivy-db", True, _mtime(metadata), detail))
    else:
        entries.append(MirrorEntry("trivy-db", False, None, "not downloaded"))
    java = mirror / "trivy" / "java-db"
    entries.append(
        MirrorEntry("trivy-java-db", java.is_dir(), _mtime(java) if java.is_dir() else None)
    )
    rules = mirror / "semgrep-rules"
    count = sum(1 for _ in rules.rglob("*.y*ml")) if rules.is_dir() else 0
    entries.append(
        MirrorEntry(
            "semgrep-rules",
            count > 0,
            _mtime(rules) if count else None,
            f"{count} rule file(s); provide these yourself" if count else "provide these yourself",
        )
    )
    return entries
