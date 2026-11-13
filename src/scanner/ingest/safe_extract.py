import os
import re
import shutil
import stat
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from scanner.ingest.errors import UnsafeArchiveError

MIB = 1024 * 1024
CHUNK = 64 * 1024
_DRIVE = re.compile(r"^[A-Za-z]:")
_ENCRYPTED = 0x1


@dataclass(frozen=True)
class ExtractLimits:
    max_compressed_bytes: int = 100 * MIB
    max_total_bytes: int = 1024 * MIB
    max_file_bytes: int = 200 * MIB
    max_files: int = 20_000
    max_depth: int = 20
    max_ratio: float = 100.0
    ratio_floor_bytes: int = 4 * MIB  # compression ratios on small data are meaningless


@dataclass(frozen=True)
class ExtractResult:
    files: int
    total_bytes: int


@dataclass
class _Budget:
    archive_bytes: int
    total: int = 0


def _show(raw: str) -> str:
    return repr(raw[:100])


def _parts(raw: str, limits: ExtractLimits) -> tuple[str, ...]:
    if "\0" in raw:
        raise UnsafeArchiveError(f"invalid entry name {_show(raw)}")
    name = raw.replace("\\", "/")
    if name.startswith("/") or _DRIVE.match(name):
        raise UnsafeArchiveError(f"absolute path in archive: {_show(raw)}")
    parts = tuple(p for p in name.split("/") if p not in ("", "."))
    if ".." in parts:
        raise UnsafeArchiveError(f"path traversal in archive: {_show(raw)}")
    if any(":" in p for p in parts):
        raise UnsafeArchiveError(f"unsupported character in entry name: {_show(raw)}")
    if len(parts) > limits.max_depth:
        raise UnsafeArchiveError(f"path nested deeper than {limits.max_depth} levels")
    return parts


def _check_ratio(written: int, compressed: int, limits: ExtractLimits) -> None:
    if written <= limits.ratio_floor_bytes:
        return
    if compressed <= 0 or written / compressed > limits.max_ratio:
        raise UnsafeArchiveError("compression ratio too high (possible zip bomb)")


def _plan(
    infos: list[zipfile.ZipInfo], limits: ExtractLimits
) -> list[tuple[zipfile.ZipInfo, tuple[str, ...], bool]]:
    plan = []
    seen: set[str] = set()
    declared_total = 0
    for info in infos:
        parts = _parts(info.filename, limits)
        mode = stat.S_IFMT(info.external_attr >> 16)
        if mode == stat.S_IFLNK:
            raise UnsafeArchiveError(f"symbolic link in archive: {_show(info.filename)}")
        if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise UnsafeArchiveError(f"special file in archive: {_show(info.filename)}")
        if info.flag_bits & _ENCRYPTED:
            raise UnsafeArchiveError("encrypted entries are not supported")
        is_dir = info.is_dir() or mode == stat.S_IFDIR
        if not parts:
            if is_dir:
                continue
            raise UnsafeArchiveError(f"invalid entry name {_show(info.filename)}")
        key = "/".join(parts).lower()  # lower-case so case-insensitive filesystems cannot collide
        if key in seen:
            raise UnsafeArchiveError(f"duplicate entry: {_show(info.filename)}")
        seen.add(key)
        if not is_dir:
            if info.file_size > limits.max_file_bytes:
                raise UnsafeArchiveError(f"file too large: {_show(info.filename)}")
            declared_total += info.file_size
            _check_ratio(info.file_size, info.compress_size, limits)
        plan.append((info, parts, is_dir))
    if declared_total > limits.max_total_bytes:
        raise UnsafeArchiveError("archive expands to more than the allowed total size")
    return plan


def _copy(
    src: IO[bytes],
    target: Path,
    info: zipfile.ZipInfo,
    limits: ExtractLimits,
    budget: _Budget,
) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_BINARY", 0)
    )
    fd = os.open(target, flags, 0o644)
    written = 0
    with os.fdopen(fd, "wb") as out:
        # Real byte counts are enforced because declared sizes in the headers can be forged.
        while chunk := src.read(CHUNK):
            written += len(chunk)
            budget.total += len(chunk)
            if written > limits.max_file_bytes:
                raise UnsafeArchiveError(f"file too large: {_show(info.filename)}")
            if budget.total > limits.max_total_bytes:
                raise UnsafeArchiveError("archive expands to more than the allowed total size")
            _check_ratio(written, info.compress_size, limits)
            _check_ratio(budget.total, budget.archive_bytes, limits)
            out.write(chunk)


def _normalise_permissions(root: Path) -> None:
    for current, _dirs, files in os.walk(root):
        # Directories must stay traversable for the unprivileged sandbox user; files stay 0o644.
        os.chmod(current, 0o755)  # noqa: S103  # nosemgrep
        for name in files:
            os.chmod(Path(current, name), 0o644)


def _extract(
    zf: zipfile.ZipFile, root: Path, limits: ExtractLimits, archive_bytes: int
) -> ExtractResult:
    infos = zf.infolist()
    if len(infos) > limits.max_files:
        raise UnsafeArchiveError(f"archive has more than {limits.max_files} entries")
    budget = _Budget(archive_bytes)
    files = 0
    for info, parts, is_dir in _plan(infos, limits):
        target = root.joinpath(*parts)
        try:
            if is_dir:
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if root not in target.parent.resolve().parents and target.parent.resolve() != root:
                raise UnsafeArchiveError(
                    f"path escapes the extraction directory: {_show(info.filename)}"
                )
            with zf.open(info) as src:
                _copy(src, target, info, limits, budget)
        except (FileExistsError, NotADirectoryError, IsADirectoryError) as exc:
            raise UnsafeArchiveError(
                f"conflicting paths in archive: {_show(info.filename)}"
            ) from exc
        files += 1
    if os.name == "posix":
        _normalise_permissions(root)
    return ExtractResult(files=files, total_bytes=budget.total)


def safe_extract(zip_path: Path, dest: Path, limits: ExtractLimits | None = None) -> ExtractResult:
    """Extract an untrusted zip into dest, or raise UnsafeArchiveError and leave nothing behind."""
    limits = limits or ExtractLimits()
    archive_bytes = zip_path.stat().st_size
    if archive_bytes > limits.max_compressed_bytes:
        raise UnsafeArchiveError("archive is larger than the allowed upload size")
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError(f"destination is not empty: {dest}")
    dest.mkdir(parents=True, exist_ok=True)
    try:
        try:
            zf = zipfile.ZipFile(zip_path)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError) as exc:
            raise UnsafeArchiveError("not a valid zip archive") from exc
        with zf:
            return _extract(zf, dest.resolve(), limits, archive_bytes)
    except zipfile.BadZipFile as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise UnsafeArchiveError("corrupt zip archive") from exc
    except (NotImplementedError, RuntimeError) as exc:
        shutil.rmtree(dest, ignore_errors=True)
        raise UnsafeArchiveError(
            "unsupported zip features (compression method or encryption)"
        ) from exc
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise


def effective_root(extracted: Path) -> Path:
    """Descend into the single top-level folder most zips (for example GitHub's) contain."""
    entries = list(extracted.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return extracted
