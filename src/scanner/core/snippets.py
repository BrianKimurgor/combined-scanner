from collections import defaultdict
from collections.abc import Iterable
from pathlib import Path

from scanner.normalize.finding import Category, Finding, Snippet

CONTEXT_LINES = 3
MAX_HIGHLIGHT_LINES = 20
MAX_LINE_CHARS = 300
MAX_FILE_BYTES = 1_000_000
PROTECTED = (Category.SECRET, Category.PII)


def read_lines(root: Path, relative: str, cache: dict[str, list[str] | None]) -> list[str] | None:
    """Lines of a text file under root, or None if it is missing, binary, large or outside root."""
    if relative in cache:
        return cache[relative]
    cache[relative] = None
    try:
        path = (root / relative).resolve()
        path.relative_to(root)  # rejects ../ and symlinks pointing outside the scan root
        if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except (OSError, ValueError):
        return None
    if b"\0" in data:
        return None
    lines = data.decode("utf-8", errors="replace").replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    cache[relative] = lines
    return lines


def _clip(line: str) -> str:
    return line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS] + "\u2026"


def _window(lines: list[str], start: int, end: int, secret_lines: set[int]) -> Snippet | None:
    if start > len(lines):
        return None
    end = min(max(end, start), start + MAX_HIGHLIGHT_LINES - 1, len(lines))
    first = max(1, start - CONTEXT_LINES)
    last = min(len(lines), end + CONTEXT_LINES)
    if any(first <= n <= last for n in secret_lines):
        return None
    return Snippet(
        start_line=first,
        lines=[_clip(line) for line in lines[first - 1 : last]],
        highlight_start=start,
        highlight_end=end,
    )


def attach_snippets(findings: Iterable[Finding], root: Path) -> None:
    """Add source context to findings. Nothing near a detected secret or PII is ever copied."""
    root = root.resolve()
    findings = list(findings)
    secret_lines: dict[str, set[int]] = defaultdict(set)
    files_with_unlocated_secret: set[str] = set()
    for finding in findings:
        if finding.category not in PROTECTED or not finding.file:
            continue
        if finding.line_start is None:
            files_with_unlocated_secret.add(finding.file)
        else:
            end = finding.line_end or finding.line_start
            secret_lines[finding.file].update(range(finding.line_start, end + 1))

    cache: dict[str, list[str] | None] = {}
    for finding in findings:
        if finding.category in PROTECTED or not finding.file or not finding.line_start:
            continue
        if finding.file in files_with_unlocated_secret:
            continue
        lines = read_lines(root, finding.file, cache)
        if lines is None:
            continue
        finding.snippet = _window(
            lines,
            finding.line_start,
            finding.line_end or finding.line_start,
            secret_lines.get(finding.file, set()),
        )
