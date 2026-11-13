from pathlib import Path

import pytest

from scanner.core.snippets import MAX_HIGHLIGHT_LINES, MAX_LINE_CHARS, attach_snippets
from scanner.normalize.finding import Category, Finding, Severity


def _finding(
    file: str | None,
    start: int | None,
    end: int | None = None,
    category: Category = Category.CODE,
) -> Finding:
    return Finding(
        tool="t",
        category=category,
        rule_id="R",
        severity=Severity.HIGH,
        title="t",
        file=file,
        line_start=start,
        line_end=end,
    )


def _write(root: Path, name: str, lines: list[str]) -> None:
    (root / name).write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_snippet_has_context_and_highlight(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", [f"line {n}" for n in range(1, 21)])
    finding = _finding("a.py", 10, 11)
    attach_snippets([finding], tmp_path)
    snippet = finding.snippet
    assert snippet is not None
    assert (snippet.start_line, snippet.highlight_start, snippet.highlight_end) == (7, 10, 11)
    assert snippet.lines == [f"line {n}" for n in range(7, 15)]


def test_snippet_is_clamped_at_file_edges(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", ["one", "two", "three"])
    finding = _finding("a.py", 1)
    attach_snippets([finding], tmp_path)
    assert finding.snippet is not None
    assert finding.snippet.start_line == 1
    assert finding.snippet.lines == ["one", "two", "three"]


def test_long_ranges_and_lines_are_capped(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", ["x" * (MAX_LINE_CHARS + 50)] * 100)
    finding = _finding("a.py", 1, 100)
    attach_snippets([finding], tmp_path)
    snippet = finding.snippet
    assert snippet is not None
    assert snippet.highlight_end == MAX_HIGHLIGHT_LINES
    assert len(snippet.lines[0]) == MAX_LINE_CHARS + 1


def test_secret_findings_never_get_a_snippet(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", ["key = 'AKIAFAKE'"])
    secret = _finding("a.py", 1, category=Category.SECRET)
    attach_snippets([secret], tmp_path)
    assert secret.snippet is None


def test_snippets_overlapping_a_secret_are_dropped(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", [f"line {n}" for n in range(1, 31)])
    secret = _finding("a.py", 5, category=Category.SECRET)
    near = _finding("a.py", 7)  # context window reaches line 5
    far = _finding("a.py", 25)
    attach_snippets([secret, near, far], tmp_path)
    assert near.snippet is None
    assert far.snippet is not None


def test_unlocated_secret_hides_every_snippet_in_the_file(tmp_path: Path) -> None:
    _write(tmp_path, "a.py", ["a", "b", "c"])
    secret = _finding("a.py", None, category=Category.SECRET)
    code = _finding("a.py", 2)
    attach_snippets([secret, code], tmp_path)
    assert code.snippet is None


def test_paths_outside_the_root_are_never_read(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret data\n", encoding="utf-8")
    findings = [_finding("../outside.txt", 1), _finding(str(tmp_path / "outside.txt"), 1)]
    attach_snippets(findings, root)
    assert all(f.snippet is None for f in findings)


def test_symlink_escaping_the_root_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (tmp_path / "outside.txt").write_text("secret data\n", encoding="utf-8")
    try:
        (root / "link.txt").symlink_to(tmp_path / "outside.txt")
    except OSError:
        pytest.skip("symlinks not permitted on this system")
    finding = _finding("link.txt", 1)
    attach_snippets([finding], root)
    assert finding.snippet is None


def test_missing_binary_and_out_of_range_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "bin.dat").write_bytes(b"abc\0def\n")
    _write(tmp_path, "a.py", ["one"])
    findings = [
        _finding("bin.dat", 1),
        _finding("missing.py", 1),
        _finding("a.py", 5),
        _finding("a.py", None),
        _finding(None, 1),
    ]
    attach_snippets(findings, tmp_path)
    assert all(f.snippet is None for f in findings)


def test_crlf_files_use_the_same_line_numbers(tmp_path: Path) -> None:
    (tmp_path / "a.py").write_bytes(b"one\r\ntwo\r\nthree\r\n")
    finding = _finding("a.py", 2)
    attach_snippets([finding], tmp_path)
    assert finding.snippet is not None
    assert finding.snippet.lines == ["one", "two", "three"]
