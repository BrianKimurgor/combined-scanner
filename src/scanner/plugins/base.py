import json
import os
import shutil
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, Field

from scanner.core.config import Config
from scanner.normalize.finding import Finding


class Status(StrEnum):
    OK = "ok"
    FAILED = "failed"
    TIMEOUT = "timeout"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ScanContext:
    workdir: Path
    output_dir: Path
    config: Config
    timeout: int

    def plugin_dir(self, name: str) -> Path:
        path = self.output_dir / name
        path.mkdir(parents=True, exist_ok=True)
        return path


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass
class Parsed:
    findings: list[Finding]
    metrics: dict[str, float] = field(default_factory=dict)


class PluginResult(BaseModel):
    tool: str
    status: Status
    findings: list[Finding] = Field(default_factory=list)
    message: str = ""
    duration_seconds: float = 0.0
    metrics: dict[str, float] = Field(default_factory=dict)


def load_json(text: str, default: Any) -> Any:
    return json.loads(text) if text.strip() else default


def to_line(value: Any) -> int | None:
    """Tools use 0 or missing for 'no line'."""
    number = int(value or 0)
    return number or None


def rel_path(path: str, root: Path) -> str:
    """Normalise a tool-reported path to a posix path relative to the scan root."""
    candidate = Path(path)
    if candidate.is_absolute():
        try:
            return candidate.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            pass
    return path.replace("\\", "/").removeprefix("./").lstrip("/")


def _tail(text: str, limit: int = 500) -> str:
    return text.strip()[-limit:]


class ScannerPlugin(ABC):
    name: ClassVar[str]
    binary: ClassVar[str]
    ok_exit_codes: ClassVar[frozenset[int]] = frozenset({0})
    env: ClassVar[dict[str, str]] = {}

    def unavailable_reason(self) -> str | None:
        if shutil.which(self.binary) is None:
            return f"{self.binary} not found on PATH"
        return None

    def available(self) -> bool:
        return self.unavailable_reason() is None

    def command_env(self, ctx: ScanContext) -> dict[str, str]:
        """Environment added for this run, on top of the class-level env."""
        return {}

    def skip_reason(self, ctx: ScanContext) -> str | None:
        """Why this tool cannot run with this configuration, if it cannot."""
        return None

    @abstractmethod
    def build_command(self, ctx: ScanContext) -> list[str]:
        """Full-scan command line; the first element is the binary name."""

    @abstractmethod
    def parse(self, ctx: ScanContext, proc: CommandResult) -> Parsed:
        """Turn the tool output into normalised findings."""

    def run(self, ctx: ScanContext) -> PluginResult:
        start = time.monotonic()

        def result(status: Status, message: str = "", parsed: Parsed | None = None) -> PluginResult:
            return PluginResult(
                tool=self.name,
                status=status,
                message=message,
                findings=parsed.findings if parsed else [],
                metrics=parsed.metrics if parsed else {},
                duration_seconds=round(time.monotonic() - start, 3),
            )

        reason = self.unavailable_reason()
        exe = shutil.which(self.binary)
        if reason is not None or exe is None:
            return result(Status.SKIPPED, reason or f"{self.binary} not found on PATH")
        if (skip := self.skip_reason(ctx)) is not None:
            return result(Status.SKIPPED, skip)
        args = [exe, *self.build_command(ctx)[1:]]
        try:
            completed = subprocess.run(  # noqa: S603 - fixed argv, no shell
                args,
                cwd=ctx.workdir,
                env={**os.environ, **self.env, **self.command_env(ctx)},
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=ctx.timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return result(Status.TIMEOUT, f"timed out after {ctx.timeout}s")
        except OSError as exc:
            return result(Status.FAILED, f"could not start {self.binary}: {exc}")
        proc = CommandResult(completed.returncode, completed.stdout, completed.stderr)
        if proc.returncode not in self.ok_exit_codes:
            return result(Status.FAILED, f"exit code {proc.returncode}: {_tail(proc.stderr)}")
        try:
            parsed = self.parse(ctx, proc)
        except Exception as exc:
            return result(Status.FAILED, f"could not parse output: {exc!r}")
        return result(Status.OK, parsed=parsed)
