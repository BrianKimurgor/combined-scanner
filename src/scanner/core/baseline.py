from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from scanner.core.result import ScanReport


class Baseline(BaseModel):
    """The findings accepted as the starting point; later scans only fail on new ones.

    Holds fingerprints only: no code, messages or secrets.
    """

    version: Literal[1] = 1
    created_at: datetime
    source: str
    fingerprints: list[str]
    metrics: dict[str, float] = Field(default_factory=dict)


def from_report(report: ScanReport) -> Baseline:
    active = {f.fingerprint for f in report.findings if f.suppressed is None}
    return Baseline(
        created_at=report.started_at,
        source=report.target,
        fingerprints=sorted(active),
        metrics=report.metrics,
    )


def load(path: Path) -> Baseline:
    return Baseline.model_validate_json(path.read_bytes())


def save(baseline: Baseline, path: Path) -> None:
    path.write_text(baseline.model_dump_json(indent=2) + "\n", encoding="utf-8")
