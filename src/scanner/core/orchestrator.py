import time
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path

from scanner.core.baseline import Baseline
from scanner.core.config import Config
from scanner.core.diff import assign_fingerprints
from scanner.core.ignore import is_ignored
from scanner.core.policy import apply_policy
from scanner.core.progress import ProgressTracker
from scanner.core.result import GateResult, ScanReport, ToolStatus
from scanner.core.score import compute_score
from scanner.core.snippets import attach_snippets
from scanner.normalize.dedupe import dedupe
from scanner.normalize.finding import Category, Finding
from scanner.plugins.base import PluginResult, ScanContext, ScannerPlugin, Status


def _safe_run(plugin: ScannerPlugin, ctx: ScanContext) -> PluginResult:
    try:
        return plugin.run(ctx)
    except Exception as exc:  # one broken plugin must not abort the scan
        return PluginResult(tool=plugin.name, status=Status.FAILED, message=f"crashed: {exc!r}")


def _ignored(finding: Finding, config: Config) -> bool:
    if is_ignored(finding.file, config.ignore):
        return True
    if finding.category is Category.LICENSE and finding.package:
        return any(fnmatchcase(finding.package, p) for p in config.license_ignore)
    quality = finding.category in (Category.COMPLEXITY, Category.DUPLICATION)
    return quality and is_ignored(finding.file, config.quality_ignore)


@dataclass
class Collected:
    """Everything one scan produces before it is turned into a report."""

    findings: list[Finding]
    metrics: dict[str, float]
    tools: list[ToolStatus]
    started_at: datetime
    duration_seconds: float
    root: Path


def collect(
    target: Path,
    config: Config,
    plugins: Sequence[ScannerPlugin],
    output_dir: Path,
    *,
    snippets: bool = True,
    progress: ProgressTracker | None = None,
) -> Collected:
    ctx = ScanContext(
        workdir=target.resolve(),
        output_dir=output_dir,
        config=config,
        timeout=config.scanners.timeout_seconds,
    )
    started_at = datetime.now(UTC)
    clock = time.monotonic()

    def run_one(plugin: ScannerPlugin) -> PluginResult:
        if progress is not None:
            progress.started(plugin.name)
        result = _safe_run(plugin, ctx)
        if progress is not None:
            progress.finished(result)
        return result

    with ThreadPoolExecutor(max_workers=max(1, len(plugins))) as pool:
        results = list(pool.map(run_one, plugins))

    findings = dedupe(f for result in results for f in result.findings if not _ignored(f, config))
    findings.sort(key=lambda f: (-f.severity.rank, f.file or "", f.line_start or 0, f.rule_id))
    assign_fingerprints(findings, ctx.workdir)
    if snippets:
        attach_snippets(findings, ctx.workdir)
    tools = [
        ToolStatus(
            tool=result.tool,
            status=result.status,
            message=result.message,
            duration_seconds=result.duration_seconds,
            finding_count=len(result.findings),
        )
        for result in results
    ]
    return Collected(
        findings=findings,
        metrics={key: value for result in results for key, value in result.metrics.items()},
        tools=tools,
        started_at=started_at,
        duration_seconds=round(time.monotonic() - clock, 3),
        root=ctx.workdir,
    )


def run_scan(
    target: Path,
    config: Config,
    plugins: Sequence[ScannerPlugin],
    output_dir: Path,
    *,
    baseline: Baseline | None = None,
    progress: ProgressTracker | None = None,
) -> ScanReport:
    scan = collect(target, config, plugins, output_dir, progress=progress)
    report = ScanReport(
        target=str(scan.root),
        started_at=scan.started_at,
        duration_seconds=scan.duration_seconds,
        tools=scan.tools,
        findings=scan.findings,
        metrics=scan.metrics,
        gate=GateResult(passed=True),  # replaced by apply_policy
        score=compute_score(scan.findings, scan.tools),
    )
    return apply_policy(report, config, suppressions=config.suppressions, baseline=baseline)
