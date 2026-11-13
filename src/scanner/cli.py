import os
import shutil
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Annotated, cast

import typer
import yaml
from pydantic import ValidationError

from scanner import __version__, server_cli
from scanner.core.baseline import from_report as baseline_from_report
from scanner.core.baseline import load as load_baseline
from scanner.core.baseline import save as save_baseline
from scanner.core.config import Config, FailLevel, load_config
from scanner.core.diff_scan import Revision, run_diff_scan
from scanner.core.orchestrator import ScanOptions, run_scan
from scanner.core.progress import ProgressTracker, write_progress
from scanner.core.result import ScanReport, exit_code
from scanner.ingest.errors import UnsafeSourceError
from scanner.ingest.git_export import export_commit, git_toplevel, resolve_commit
from scanner.normalize.finding import Severity
from scanner.plugins import build_plugins
from scanner.plugins.base import ScannerPlugin, Status
from scanner.report import comment as comment_report
from scanner.report import html as html_report
from scanner.report import json as json_report
from scanner.report import markdown as markdown_report
from scanner.report import sarif as sarif_report

app = typer.Typer(help="Scan a codebase with open-source scanners and merge the results.")
app.add_typer(server_cli.app)
app.add_typer(server_cli.admin, name="admin")

CONFIG_ERROR = 2


class ReportFormat(StrEnum):
    JSON = "json"
    MD = "md"
    HTML = "html"
    SARIF = "sarif"
    COMMENT = "comment"


_RENDERERS = {
    ReportFormat.JSON: json_report.render,
    ReportFormat.MD: markdown_report.render,
    ReportFormat.HTML: html_report.render,
    ReportFormat.SARIF: sarif_report.render,
    ReportFormat.COMMENT: comment_report.render,
}


def stage(source: Path, dest: Path) -> Path:
    """Copy a tree onto local disk; reading thousands of files from a bind mount can be glacial."""
    try:
        shutil.copytree(source, dest, symlinks=True)
    except OSError:
        shutil.rmtree(dest, ignore_errors=True)
        return source  # e.g. the staging area is too small; scanning in place still works
    return dest


@dataclass(frozen=True)
class Target:
    """What to scan: one directory, or a comparison of two revisions."""

    path: Path
    base: str | None = None  # git ref to compare against
    head: str = "HEAD"
    base_path: Path | None = None  # directory to compare against

    @property
    def is_diff(self) -> bool:
        return self.base is not None or self.base_path is not None


def _progress(
    plugins: list[ScannerPlugin], target: Target, file: Path | None
) -> ProgressTracker | None:
    if file is None:
        return None
    names = [p.name for p in plugins]
    return ProgressTracker(
        names, lambda state: write_progress(file, state), passes=2 if target.is_diff else 1
    )


def _run(
    target: Target, cfg: Config, plugins: list[ScannerPlugin], options: ScanOptions
) -> ScanReport:
    with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
        work = Path(tmp)
        if target.base_path is not None:
            base_rev = Revision(target.base_path, str(target.base_path))
            head_rev = Revision(target.path, str(target.path))
            return run_diff_scan(base_rev, head_rev, cfg, plugins, work / "out", options)
        if target.base is None:
            return run_scan(target.path, cfg, plugins, work / "out", options)
        base_rev, head_rev = _export_revisions(target, target.base, work)
        return run_diff_scan(base_rev, head_rev, cfg, plugins, work / "out", options)


def _export_revisions(target: Target, base: str, work: Path) -> tuple[Revision, Revision]:
    """Check out both git revisions of the target's folder side by side."""
    top = git_toplevel(target.path)
    relative = target.path.relative_to(top)
    base_sha, head_sha = resolve_commit(top, base), resolve_commit(top, target.head)
    export_commit(top, base_sha, work / "base")
    export_commit(top, head_sha, work / "head")
    roots = (work / "base" / relative, work / "head" / relative)
    for root in roots:
        root.mkdir(parents=True, exist_ok=True)  # the folder may not exist on one side
    return (
        Revision(roots[0], f"{base} ({base_sha[:8]})"),
        Revision(roots[1], f"{target.head} ({head_sha[:8]})"),
    )


def _scan_config(
    config: Path | None, fail_on: Severity | None, offline: bool, semgrep_rules: list[str] | None
) -> Config:
    cfg = load_config(config)
    if fail_on is not None:
        level = cast(FailLevel, fail_on.value)
        cfg.gate.fail_on.vulnerability = level
        cfg.gate.fail_on.code = level
        cfg.gate.fail_on.iac = level
    if offline:
        cfg.offline = True
    if semgrep_rules:
        cfg.scanners.semgrep_rules = semgrep_rules
    return cfg


def _relabel(report: ScanReport, target: Target) -> ScanReport:
    """Name the original folders in the report, not the staging copies that were scanned."""
    update: dict[str, object] = {"target": str(target.path)}
    if report.diff is not None:
        base = str(target.base_path) if target.base_path else report.diff.base
        update["diff"] = report.diff.model_copy(update={"head": str(target.path), "base": base})
    return report.model_copy(update=update)


@app.callback()
def main() -> None:
    """Code scanner CLI."""


@app.command()
def version() -> None:
    """Print the scanner version."""
    typer.echo(__version__)


@app.command()
def render(
    report_file: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, help="A JSON report from `scan`.")
    ],
    fmt: Annotated[ReportFormat, typer.Option("--format", "-f", help="Report format.")],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report here, not to stdout.")
    ] = None,
) -> None:
    """Convert a JSON report to another format without scanning again."""
    try:
        report = ScanReport.model_validate_json(report_file.read_bytes())
    except (OSError, ValidationError) as exc:
        typer.echo(f"Not a scan report: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR) from exc
    rendered = _RENDERERS[fmt](report)
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        output.write_text(rendered, encoding="utf-8")


@app.command("baseline")
def create_baseline(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, resolve_path=True, help="Directory to scan."),
    ],
    output: Annotated[Path, typer.Option("--output", "-o", help="Where to write the baseline.")],
    config: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, help="Path to scanner.yml.")
    ] = None,
) -> None:
    """Record today's findings so later scans only fail on new ones."""
    try:
        cfg = load_config(config)
        plugins = build_plugins(cfg.scanners.enabled)
    except (OSError, ValueError, yaml.YAMLError, ValidationError) as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR) from exc
    with tempfile.TemporaryDirectory(prefix="scanner-") as tmp:
        report = run_scan(path, cfg, plugins, Path(tmp))
    if not report.any_scanner_ran() or any(
        t.status in (Status.FAILED, Status.TIMEOUT) for t in report.tools
    ):
        typer.echo(
            "Not writing a baseline: some scanners did not run, so it would be incomplete.",
            err=True,
        )
        raise typer.Exit(CONFIG_ERROR)
    baseline = baseline_from_report(report)
    save_baseline(baseline, output)
    typer.echo(f"Baseline of {len(baseline.fingerprints)} finding(s) written to {output}")


@app.command()
def scan(
    path: Annotated[
        Path,
        typer.Argument(exists=True, file_okay=False, resolve_path=True, help="Directory to scan."),
    ],
    fmt: Annotated[ReportFormat, typer.Option("--format", "-f", help="Report format.")] = (
        ReportFormat.JSON
    ),
    fail_on: Annotated[
        Severity | None,
        typer.Option(help="Minimum severity failing the gate for vulnerability, code and IaC."),
    ] = None,
    config: Annotated[
        Path | None, typer.Option(exists=True, dir_okay=False, help="Path to scanner.yml.")
    ] = None,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report here, not to stdout.")
    ] = None,
    base: Annotated[
        str | None,
        typer.Option(help="Diff mode: compare this git ref with --head; only new findings gate."),
    ] = None,
    head: Annotated[str, typer.Option(help="Git ref compared against --base.")] = "HEAD",
    base_path: Annotated[
        Path | None,
        typer.Option(
            exists=True, file_okay=False, resolve_path=True, help="Diff against a directory."
        ),
    ] = None,
    baseline_file: Annotated[
        Path | None,
        typer.Option(
            "--baseline",
            exists=True,
            dir_okay=False,
            help="Only findings missing from this baseline gate.",
        ),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option(
            help="Make no network calls; vulnerability databases must already be on disk."
        ),
    ] = False,
    semgrep_rules: Annotated[
        list[str] | None,
        typer.Option(
            "--semgrep-rules", help="Semgrep rules to use instead of the configured ones."
        ),
    ] = None,
    history: Annotated[
        bool,
        typer.Option(
            help="Read secrets from every commit of the git repository, not only the current files."
        ),
    ] = False,
    progress_file: Annotated[
        Path | None,
        typer.Option(
            "--progress",
            hidden=True,
            dir_okay=False,
            help="Keep per-scanner progress in this JSON file (used by the worker).",
        ),
    ] = None,
    stage_dir: Annotated[
        Path | None,
        typer.Option(
            envvar="SCANNER_STAGE_DIR",
            hidden=True,
            file_okay=False,
            help="Copy the source here first (used inside the sandbox).",
        ),
    ] = None,
) -> None:
    """Scan a directory and print a merged, deduplicated report.

    With --base REF (a git repository) or --base-path DIR, scan both revisions and report
    only the findings the change introduced. With --baseline FILE (see `scanner baseline`),
    findings already recorded there are treated as accepted. With --history, the secret
    scanners read every commit of the git repository instead of the current files. Exit codes:
    0 pass, 1 quality gate failed, 2 scanner or configuration error.
    """
    # Every Typer option is a parameter; the logic itself lives in the helpers below.
    # lizard forgives(parameter_count)
    target = Target(path, base, head, base_path)
    _check_options(target, history)
    try:
        cfg = _scan_config(config, fail_on, offline, semgrep_rules)
        cfg.history = _history_repo(path) if history else None
        baseline = load_baseline(baseline_file) if baseline_file else None
        plugins = build_plugins(cfg.scanners.enabled)
    except (OSError, ValueError, yaml.YAMLError, ValidationError, UnsafeSourceError) as exc:
        typer.echo(f"Configuration error: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR) from exc
    options = ScanOptions(baseline, _progress(plugins, target, progress_file))
    report = _scan_target(target, stage_dir, cfg, plugins, options)
    _emit(_RENDERERS[fmt](report), output)
    raise typer.Exit(exit_code(report))


def _check_options(target: Target, history: bool) -> None:
    if target.base is not None and target.base_path is not None:
        typer.echo("Use either --base or --base-path, not both.", err=True)
        raise typer.Exit(CONFIG_ERROR)
    if history and target.is_diff:
        typer.echo("--history cannot be combined with --base or --base-path.", err=True)
        raise typer.Exit(CONFIG_ERROR)


def _history_repo(path: Path) -> str:
    """The worker mounts the fetched history separately; otherwise it is PATH's repository."""
    return os.environ.get("SCANNER_HISTORY_REPO") or str(git_toplevel(path))


def _scan_target(
    target: Target, stage_dir: Path | None, cfg: Config, plugins: list[ScannerPlugin],
    options: ScanOptions,
) -> ScanReport:  # fmt: skip
    scanned = _staged(target, stage_dir) if stage_dir is not None else target
    try:
        report = _run(scanned, cfg, plugins, options)
    except UnsafeSourceError as exc:
        typer.echo(f"Cannot compare revisions: {exc}", err=True)
        raise typer.Exit(CONFIG_ERROR) from exc
    # Name the folders the user gave, not the staging copies that were scanned.
    return _relabel(report, target) if scanned.path != target.path else report


def _staged(target: Target, stage_dir: Path) -> Target:
    """The same target, copied onto local disk first (see `stage`)."""
    base_path = target.base_path
    staged_base = stage(base_path, stage_dir / "base") if base_path is not None else None
    return Target(stage(target.path, stage_dir / "head"), target.base, target.head, staged_base)


def _emit(rendered: str, output: Path | None) -> None:
    if output is None:
        typer.echo(rendered, nl=False)
    else:
        output.write_text(rendered, encoding="utf-8")
