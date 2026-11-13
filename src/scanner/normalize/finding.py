import hashlib
import re
from datetime import date
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, Field, model_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return _RANK[self]


_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Category(StrEnum):
    DEPENDENCY = "dependency"
    CODE = "code"
    SECRET = "secret"  # noqa: S105 - category name, not a credential
    PII = "pii"
    IAC = "iac"
    DUPLICATION = "duplication"
    COMPLEXITY = "complexity"
    LICENSE = "license"


SECRET_MASK = "[REDACTED]"  # noqa: S105 - placeholder, not a credential


def _digest(parts: tuple[object, ...]) -> str:
    return hashlib.sha256("\x1f".join(map(str, parts)).encode()).hexdigest()[:16]


def normalize_package(name: str | None) -> str:
    """Tools spell the same package differently (PyYAML, pyyaml, py_yaml)."""
    return re.sub(r"[-_.]+", "-", name or "").lower()


def normalize_version(version: str | None) -> str:
    """OSV reports 3.13.0 where Trivy reports 3.13; treat trailing zero parts as absent."""
    parts = (version or "").strip().removeprefix("v").split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts.pop()
    return ".".join(parts)


def dedupe_key(finding: "Finding") -> tuple[str, ...]:
    """Key identifying the same issue; dependency and secret findings merge across tools."""
    if finding.category is Category.DEPENDENCY:
        return (
            "dependency",
            normalize_package(finding.package),
            normalize_version(finding.version),
            finding.rule_id.upper(),
        )
    if finding.category is Category.SECRET:
        key = ("secret", finding.file or "", str(finding.line_start or 0))
        return (*key, finding.commit) if finding.commit else key
    if finding.category is Category.LICENSE:
        return ("license", normalize_package(finding.package), finding.rule_id, finding.file or "")
    return (
        finding.category.value,
        finding.tool,
        finding.rule_id,
        finding.file or "",
        str(finding.line_start or 0),
        str(finding.line_end or 0),
    )


class Snippet(BaseModel):
    """Source lines around a finding; lines are 1-based, highlight_* is the reported range."""

    start_line: int
    lines: list[str]
    highlight_start: int
    highlight_end: int


class Suppressed(BaseModel):
    """A finding a human accepted for now; it stays visible but no longer counts."""

    reason: str
    expires: date


class Finding(BaseModel):
    id: str = ""
    tool: str
    category: Category
    rule_id: str
    severity: Severity
    title: str
    message: str = ""
    file: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    package: str | None = None
    version: str | None = None
    fixed_version: str | None = None
    fingerprint: str = ""
    secret_masked: str | None = None  # the raw secret is never stored
    commit: str | None = None  # history scans: the commit the finding was found in
    sources: list[str] = Field(default_factory=list)
    snippet: Snippet | None = None
    is_new: bool | None = None  # set in diff or baseline mode: absent from the reference
    suppressed: Suppressed | None = None

    @model_validator(mode="after")
    def _fill_derived(self) -> Self:
        if not self.sources:
            self.sources = [self.tool]
        if not self.fingerprint:
            self.fingerprint = _digest(dedupe_key(self))
        if not self.id:
            where = (self.file, self.line_start, self.package, self.version)
            parts = (self.tool, self.rule_id, *where)
            self.id = _digest((*parts, self.commit) if self.commit else parts)
        return self
