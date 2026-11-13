import io
import os
import stat
import warnings
import zipfile
from pathlib import Path

import pytest

from scanner.ingest.errors import UnsafeArchiveError
from scanner.ingest.safe_extract import (
    ExtractLimits,
    _Budget,
    _copy,
    effective_root,
    safe_extract,
)

Entry = tuple[str, bytes, int | None]  # name, data, unix mode (None = default)


def _zip(path: Path, *entries: Entry, compression: int = zipfile.ZIP_DEFLATED) -> Path:
    with zipfile.ZipFile(path, "w", compression) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = compression
            if mode is not None:
                info.external_attr = mode << 16
            zf.writestr(info, data)
    return path


def _extract(tmp_path: Path, *entries: Entry, limits: ExtractLimits | None = None):  # type: ignore[no-untyped-def]
    archive = _zip(tmp_path / "in.zip", *entries)
    return safe_extract(archive, tmp_path / "out", limits)


def _rejected(tmp_path: Path, *entries: Entry, limits: ExtractLimits | None = None) -> str:
    with pytest.raises(UnsafeArchiveError) as excinfo:
        _extract(tmp_path, *entries, limits=limits)
    assert not (tmp_path / "out").exists(), "partial output must be removed"
    return str(excinfo.value)


def test_extracts_files_and_directories(tmp_path: Path) -> None:
    result = _extract(
        tmp_path,
        ("src/", b"", None),
        ("src/app.py", b"print(1)\n", None),
        ("README.md", b"hi", None),
    )
    assert result.files == 2
    assert result.total_bytes == len(b"print(1)\n") + 2
    assert (tmp_path / "out/src/app.py").read_bytes() == b"print(1)\n"


def test_empty_archive_is_fine(tmp_path: Path) -> None:
    assert _extract(tmp_path).files == 0


def test_backslash_separators_are_normalised(tmp_path: Path) -> None:
    _extract(tmp_path, ("dir\\file.txt", b"x", None))
    assert (tmp_path / "out/dir/file.txt").read_bytes() == b"x"


@pytest.mark.parametrize(
    "name",
    ["../evil.txt", "a/../../evil.txt", "..\\evil.txt", "a\\..\\..\\evil.txt", "a/b/../../../evil"],
)
def test_path_traversal_is_rejected(tmp_path: Path, name: str) -> None:
    assert "traversal" in _rejected(tmp_path, ("ok.txt", b"1", None), (name, b"pwned", None))
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path.parent / "evil.txt").exists()


@pytest.mark.parametrize("name", ["/etc/passwd", "\\windows\\system32\\x", "C:/x.txt", "c:\\x.txt"])
def test_absolute_paths_are_rejected(tmp_path: Path, name: str) -> None:
    assert "absolute" in _rejected(tmp_path, (name, b"x", None))


def test_alternate_data_stream_names_are_rejected(tmp_path: Path) -> None:
    assert "character" in _rejected(tmp_path, ("file.txt:stream", b"x", None))


def test_symlinks_are_rejected(tmp_path: Path) -> None:
    link = stat.S_IFLNK | 0o777
    assert "symbolic link" in _rejected(tmp_path, ("link", b"/etc/passwd", link))


@pytest.mark.parametrize("kind", [stat.S_IFCHR, stat.S_IFBLK, stat.S_IFIFO, stat.S_IFSOCK])
def test_special_files_are_rejected(tmp_path: Path, kind: int) -> None:
    assert "special file" in _rejected(tmp_path, ("dev", b"", kind | 0o666))


def test_encrypted_entries_are_rejected(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "in.zip", ("a.txt", b"secret", None))
    data = bytearray(archive.read_bytes())
    for signature, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        position = data.find(signature) + offset
        data[position] |= 0x1
    archive.write_bytes(data)
    with pytest.raises(UnsafeArchiveError, match="encrypted"):
        safe_extract(archive, tmp_path / "out")


@pytest.mark.parametrize("second", ["a.txt", "A.TXT"])
def test_duplicate_names_are_rejected_case_insensitively(tmp_path: Path, second: str) -> None:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        message = _rejected(tmp_path, ("a.txt", b"1", None), (second, b"2", None))
    assert "duplicate" in message


def test_file_and_directory_conflict_is_rejected(tmp_path: Path) -> None:
    assert "conflict" in _rejected(tmp_path, ("a", b"1", None), ("a/b", b"2", None))


def test_too_many_entries(tmp_path: Path) -> None:
    entries = [(f"f{n}.txt", b"x", None) for n in range(5)]
    assert "more than 3" in _rejected(tmp_path, *entries, limits=ExtractLimits(max_files=3))


def test_too_deep(tmp_path: Path) -> None:
    assert "deeper" in _rejected(
        tmp_path, ("a/b/c/d/e.txt", b"x", None), limits=ExtractLimits(max_depth=3)
    )


def test_zip_bomb_is_rejected_by_compression_ratio(tmp_path: Path) -> None:
    bomb = ("zeros.bin", b"\0" * (20 * 1024 * 1024), None)
    assert "zip bomb" in _rejected(tmp_path, bomb)


def test_total_size_limit(tmp_path: Path) -> None:
    entries = [(f"f{n}", os.urandom(800), None) for n in range(3)]
    assert "total size" in _rejected(tmp_path, *entries, limits=ExtractLimits(max_total_bytes=2000))


def test_single_file_size_limit(tmp_path: Path) -> None:
    assert "too large" in _rejected(
        tmp_path, ("big", os.urandom(2000), None), limits=ExtractLimits(max_file_bytes=1000)
    )


def test_actual_bytes_are_counted_even_if_the_header_lies(tmp_path: Path) -> None:
    info = zipfile.ZipInfo("liar.bin")
    info.file_size = 10  # forged declared size
    info.compress_size = 10
    stream = io.BytesIO(b"x" * 5000)
    with pytest.raises(UnsafeArchiveError, match="too large"):
        _copy(stream, tmp_path / "liar.bin", info, ExtractLimits(max_file_bytes=1000), _Budget(100))  # type: ignore[arg-type]


def test_oversized_archive_is_rejected_before_reading(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "in.zip", ("a.txt", b"x" * 100, None))
    with pytest.raises(UnsafeArchiveError, match="upload size"):
        safe_extract(archive, tmp_path / "out", ExtractLimits(max_compressed_bytes=10))


def test_not_a_zip(tmp_path: Path) -> None:
    bogus = tmp_path / "in.zip"
    bogus.write_text("definitely not a zip")
    with pytest.raises(UnsafeArchiveError, match="not a valid zip"):
        safe_extract(bogus, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_corrupt_data_is_rejected(tmp_path: Path) -> None:
    archive = _zip(
        tmp_path / "in.zip", ("a.txt", b"hello world", None), compression=zipfile.ZIP_STORED
    )
    archive.write_bytes(archive.read_bytes().replace(b"hello world", b"hellp world"))
    with pytest.raises(UnsafeArchiveError, match="corrupt"):
        safe_extract(archive, tmp_path / "out")
    assert not (tmp_path / "out").exists()


def test_destination_must_be_empty(tmp_path: Path) -> None:
    archive = _zip(tmp_path / "in.zip", ("a.txt", b"x", None))
    (tmp_path / "out").mkdir()
    (tmp_path / "out/existing").write_text("keep me")
    with pytest.raises(FileExistsError):
        safe_extract(archive, tmp_path / "out")
    assert (tmp_path / "out/existing").read_text() == "keep me"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_permissions_are_normalised_and_setuid_dropped(tmp_path: Path) -> None:
    _extract(tmp_path, ("tool.sh", b"#!/bin/sh\n", stat.S_IFREG | 0o4755), ("d/x", b"1", None))
    assert stat.S_IMODE((tmp_path / "out/tool.sh").stat().st_mode) == 0o644
    assert stat.S_IMODE((tmp_path / "out/d").stat().st_mode) == 0o755


def test_effective_root_descends_into_a_single_top_level_folder(tmp_path: Path) -> None:
    _extract(tmp_path, ("repo-main/a.py", b"1", None), ("repo-main/b/c.py", b"2", None))
    assert effective_root(tmp_path / "out") == tmp_path / "out/repo-main"


def test_effective_root_stays_when_there_are_several_entries(tmp_path: Path) -> None:
    _extract(tmp_path, ("a.py", b"1", None), ("b.py", b"2", None))
    assert effective_root(tmp_path / "out") == tmp_path / "out"
