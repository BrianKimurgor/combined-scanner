import hashlib
import os
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from scanner.core.ignore import is_ignored
from scanner.core.result import ChangedFile
from scanner.core.snippets import PROTECTED, read_lines
from scanner.normalize.finding import Category, Finding, normalize_package, normalize_version

MAX_LISTED_CHANGES = 2000


def _files(root: Path, ignore: Sequence[str]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for current, dirs, names in os.walk(root):
        prefix = Path(current).relative_to(root).as_posix()
        prefix = "" if prefix == "." else prefix + "/"
        dirs[:] = [d for d in dirs if d != ".git" and not is_ignored(f"{prefix}{d}/", ignore)]
        for name in names:
            path = Path(current, name)
            relative = f"{prefix}{name}"
            if not path.is_symlink() and not is_ignored(relative, ignore):
                found[relative] = path
    return found


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            sha.update(chunk)
    return sha.hexdigest()


def _same(a: Path, b: Path) -> bool:
    return a.stat().st_size == b.stat().st_size and _digest(a) == _digest(b)


def changed_files(base_root: Path, head_root: Path, ignore: Sequence[str]) -> list[ChangedFile]:
    base, head = _files(base_root, ignore), _files(head_root, ignore)
    changes = [ChangedFile(path=p, status="added") for p in head.keys() - base.keys()]
    changes += [ChangedFile(path=p, status="deleted") for p in base.keys() - head.keys()]
    changes += [
        ChangedFile(path=p, status="modified")
        for p in head.keys() & base.keys()
        if not _same(base[p], head[p])
    ]
    return sorted(changes, key=lambda c: c.path)


def _normalise(line: str) -> str:
    return " ".join(line.split())


def _stable_key(
    finding: Finding, root: Path, cache: dict[str, list[str] | None]
) -> tuple[str, ...]:
    """An identity that survives edits elsewhere in the file, so line shifts do not look new."""
    category = finding.category
    if category is Category.DEPENDENCY:
        return (
            "dep",
            normalize_package(finding.package),
            normalize_version(finding.version),
            finding.rule_id.upper(),
        )
    if category is Category.LICENSE:
        return ("license", finding.package or "", finding.rule_id)
    if (
        category in PROTECTED
    ):  # never read the offending line; position among same-rule hits is enough
        return (category.value, finding.rule_id, finding.file or "")
    if category is Category.COMPLEXITY:
        return ("complexity", finding.file or "", finding.title)
    text = ""
    if finding.file and finding.line_start:
        lines = read_lines(root, finding.file, cache)
        if lines and finding.line_start <= len(lines):
            text = _normalise(lines[finding.line_start - 1])
    return (
        category.value,
        finding.tool,
        finding.rule_id,
        finding.file or "",
        text or finding.title,
    )


def finding_keys(findings: Sequence[Finding], root: Path) -> list[tuple[str, ...]]:
    """One key per finding; identical findings are told apart by their order in the file."""
    root = root.resolve()
    cache: dict[str, list[str] | None] = {}
    order = sorted(
        range(len(findings)),
        key=lambda i: (
            findings[i].file or "",
            findings[i].line_start or 0,
            findings[i].rule_id,
            findings[i].tool,
        ),
    )
    seen: Counter[tuple[str, ...]] = Counter()
    keys: list[tuple[str, ...]] = [()] * len(findings)
    for index in order:
        stable = _stable_key(findings[index], root, cache)
        keys[index] = (*stable, str(seen[stable]))
        seen[stable] += 1
    return keys


def stable_fingerprint(key: tuple[str, ...]) -> str:
    return hashlib.sha256("\x1f".join(key).encode()).hexdigest()[:16]


def assign_fingerprints(findings: Sequence[Finding], root: Path) -> None:
    """Replace each finding's fingerprint with one that survives unrelated edits to its file."""
    for finding, key in zip(findings, finding_keys(findings, root), strict=True):
        finding.fingerprint = stable_fingerprint(key)


def tag_new(
    base: Sequence[Finding],
    base_root: Path,
    head: Sequence[Finding],
    head_root: Path,
    comparable_tools: set[str],
) -> int:
    """Set is_new on every head finding and return how many base findings are gone."""

    def comparable(finding: Finding) -> bool:
        return any(source in comparable_tools for source in finding.sources)

    remaining = Counter(
        key
        for finding, key in zip(base, finding_keys(base, base_root), strict=True)
        if comparable(finding)
    )
    for finding, key in zip(head, finding_keys(head, head_root), strict=True):
        if not comparable(finding):
            finding.is_new = False  # cannot be compared, so it is not blamed on this change
        elif remaining[key] > 0:
            remaining[key] -= 1
            finding.is_new = False
        else:
            finding.is_new = True
    return sum(remaining.values())
