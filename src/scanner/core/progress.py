"""Live per-scanner progress, recorded while a scan runs so the web UI can show it."""

import os
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, ValidationError

from scanner.plugins.base import PluginResult, Status

ToolState = Literal["waiting", "running", "ok", "failed", "timeout", "skipped"]

# The file is written inside the sandbox, so the worker reads it as untrusted input.
MAX_PROGRESS_BYTES = 64 * 1024


class ToolProgress(BaseModel):
    tool: str = Field(max_length=40)
    state: ToolState = "waiting"
    # Diff scans run every scanner twice: once on the base, once on the head.
    passes: int = Field(default=1, ge=1, le=2)
    passes_done: int = Field(default=0, ge=0, le=2)
    started_at: datetime | None = None
    duration_seconds: float | None = Field(default=None, ge=0)
    finding_count: int | None = Field(default=None, ge=0)
    message: str = Field(default="", max_length=500)


class ScanProgress(BaseModel):
    tools: list[ToolProgress] = Field(default_factory=list, max_length=32)


def waiting(tools: Sequence[str], passes: int = 1) -> ScanProgress:
    return ScanProgress(tools=[ToolProgress(tool=name, passes=passes) for name in tools])


class ProgressTracker:
    """Collects start and finish events; scanners run in parallel, each in its own thread."""

    def __init__(
        self,
        tools: Sequence[str],
        on_change: Callable[[ScanProgress], None],
        *,
        passes: int = 1,
    ) -> None:
        self._progress = waiting(tools, passes)
        self._by_name = {t.tool: t for t in self._progress.tools}
        self._on_change = on_change
        self._lock = threading.Lock()
        self._publish()

    def _publish(self) -> None:
        self._on_change(self._progress.model_copy(deep=True))

    def started(self, tool: str) -> None:
        with self._lock:
            entry = self._by_name.get(tool)
            if entry is None:
                return
            if entry.state == "waiting":
                entry.state = "running"
                entry.started_at = datetime.now(UTC)
            self._publish()

    def finished(self, result: PluginResult) -> None:
        with self._lock:
            entry = self._by_name.get(result.tool)
            if entry is None:
                return
            entry.passes_done = min(entry.passes, entry.passes_done + 1)
            entry.duration_seconds = round(
                (entry.duration_seconds or 0) + result.duration_seconds, 3
            )
            # The head pass runs last, so its count is the one the report shows.
            entry.finding_count = len(result.findings)
            if result.status is not Status.OK:
                entry.message = result.message[:500]
            failed_before = bool(entry.message) and result.status is Status.OK
            if entry.passes_done >= entry.passes:
                entry.state = "failed" if failed_before else result.status.value
            self._publish()


def write_progress(path: Path, progress: ScanProgress) -> None:
    """Replace the file in one step, so a reader never sees half of it."""
    partial = path.with_name(path.name + ".tmp")
    partial.write_text(progress.model_dump_json(), encoding="utf-8")
    os.replace(partial, path)


def read_progress(path: Path, expected: Sequence[str]) -> ScanProgress | None:
    """Read a progress file written in the sandbox; anything odd is ignored, not trusted."""
    try:
        if not path.is_file() or path.stat().st_size > MAX_PROGRESS_BYTES:
            return None
        progress = ScanProgress.model_validate_json(path.read_bytes())
    except (OSError, ValidationError, ValueError):
        return None
    allowed = set(expected)
    return ScanProgress(tools=[t for t in progress.tools if t.tool in allowed])
