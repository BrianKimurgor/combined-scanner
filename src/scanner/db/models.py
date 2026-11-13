from datetime import UTC, date, datetime

from sqlalchemy import (
    Boolean,
    Date,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True)
    key_hash: Mapped[str] = mapped_column(
        String(64), unique=True
    )  # sha256; the key is never stored
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)


class Scan(Base):
    __tablename__ = "scans"
    __table_args__ = (Index("ix_scans_status_created", "status", "created_at"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"), index=True)
    status: Mapped[str] = mapped_column(String(16))  # queued | running | done | failed
    source_type: Mapped[str] = mapped_column(String(8))  # zip | git
    source_ref: Mapped[str | None] = mapped_column(String(2200), nullable=True)
    git_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    base_ref: Mapped[str | None] = mapped_column(String(200), nullable=True)  # set for diff scans
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    gate_passed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    score_percent: Mapped[float | None] = mapped_column(Float, nullable=True)
    summary_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # tools, counts, gate
    baseline_id: Mapped[int | None] = mapped_column(Integer, nullable=True)  # baselines.id
    progress_json: Mapped[str | None] = mapped_column(Text, nullable=True)  # per-scanner state
    history: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # every commit too


class UiSession(Base):
    """A browser login; only the hash of the cookie token is stored."""

    __tablename__ = "ui_sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))


class SuppressionRow(Base):
    __tablename__ = "suppressions"
    __table_args__ = (UniqueConstraint("owner_id", "scope", "fingerprint"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"), index=True)
    scope: Mapped[str] = mapped_column(String(2200))  # the scan source it applies to
    fingerprint: Mapped[str] = mapped_column(String(16))
    reason: Mapped[str] = mapped_column(String(500))
    expires: Mapped[date] = mapped_column(Date)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class BaselineRow(Base):
    __tablename__ = "baselines"
    __table_args__ = (UniqueConstraint("owner_id", "name"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("api_keys.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    source: Mapped[str] = mapped_column(String(2200))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    size: Mapped[int] = mapped_column(Integer)
    data: Mapped[str] = mapped_column(Text)  # the Baseline as JSON: fingerprints and metrics only


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_scan_severity", "scan_id", "severity"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[str] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    position: Mapped[int] = mapped_column(Integer)  # keeps the report's severity ordering
    severity: Mapped[str] = mapped_column(String(16))
    category: Mapped[str] = mapped_column(String(16))
    is_new: Mapped[bool | None] = mapped_column(Boolean, nullable=True)  # diff or baseline scans
    suppressed: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    fingerprint: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    sources: Mapped[str] = mapped_column(String(200))  # ",osv,trivy," so LIKE can match one tool
    data: Mapped[str] = mapped_column(Text)  # the full Finding as JSON
