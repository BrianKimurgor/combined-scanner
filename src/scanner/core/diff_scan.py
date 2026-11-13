import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from scanner.core.config import Config
from scanner.core.diff import MAX_LISTED_CHANGES, changed_files, tag_new
from scanner.core.orchestrator import ScanOptions, collect
from scanner.core.policy import apply_policy
from scanner.core.result import DiffInfo, GateResult, ScanReport, ToolStatus
from scanner.core.score import compute_score
from scanner.plugins.base import ScannerPlugin, Status


def _compare_tools(
    base: list[ToolStatus], head: list[ToolStatus]
) -> tuple[list[ToolStatus], set[str]]:
    """A tool that worked on the head but not the base cannot be diffed; say so and fail it."""
    base_status = {t.tool: t for t in base}
    comparable: set[str] = set()
    tools: list[ToolStatus] = []
    for tool in head:
        before = base_status.get(tool.tool)
        if tool.status is Status.OK and before is not None and before.status is Status.OK:
            comparable.add(tool.tool)
        elif tool.status is Status.OK:
            reason = before.status.value if before else "missing"
            tool = tool.model_copy(
                update={
                    "status": Status.FAILED,
                    "message": f"not compared: the base scan was {reason}",
                }
            )
        tools.append(tool)
    return tools, comparable


@dataclass(frozen=True)
class Revision:
    """One side of a comparison: a source tree and how to name it in the report."""

    root: Path
    label: str


def run_diff_scan(
    base_rev: Revision,
    head_rev: Revision,
    config: Config,
    plugins: Sequence[ScannerPlugin],
    output_dir: Path,
    options: ScanOptions | None = None,
) -> ScanReport:
    """Scan both trees; the gate then judges only findings that are new in the head."""
    opts = options or ScanOptions()
    started_at = datetime.now(UTC)
    clock = time.monotonic()
    base = collect(
        base_rev.root, config, plugins, output_dir / "base", snippets=False, progress=opts.progress
    )
    head = collect(head_rev.root, config, plugins, output_dir / "head", progress=opts.progress)

    tools, comparable = _compare_tools(base.tools, head.tools)
    fixed = tag_new(base.findings, base.root, head.findings, head.root, comparable)
    new = [f for f in head.findings if f.is_new]

    changes = changed_files(base.root, head.root, config.ignore)
    report = ScanReport(
        target=head_rev.label,
        started_at=started_at,
        duration_seconds=round(time.monotonic() - clock, 3),
        tools=tools,
        findings=head.findings,
        metrics=head.metrics,
        gate=GateResult(passed=True),  # replaced by apply_policy
        score=compute_score(head.findings, tools),
        diff=DiffInfo(
            base=base_rev.label,
            head=head_rev.label,
            changed_files=changes[:MAX_LISTED_CHANGES],
            changed_total=len(changes),
            new_count=len(new),
            existing_count=len(head.findings) - len(new),
            fixed_count=fixed,
            base_metrics=base.metrics,
        ),
    )
    return apply_policy(report, config, suppressions=config.suppressions, baseline=opts.baseline)
