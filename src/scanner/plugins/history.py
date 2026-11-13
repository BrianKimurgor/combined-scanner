"""Shared by the secret scanners when they read every commit of a repository."""

from pathlib import Path

from scanner.plugins.base import ScanContext


def history_repo(ctx: ScanContext) -> str | None:
    """The git repository whose commits to scan, or None to scan the current files."""
    return ctx.config.history


def history_env(ctx: ScanContext, tool: str) -> dict[str, str]:
    """Git refuses a repository owned by another user, and the sandbox runs as its own user.

    A private global config trusts exactly the history repository; the user's own git config is
    not read at all.
    """
    repo = history_repo(ctx)
    if repo is None:
        return {}
    config = ctx.plugin_dir(tool) / "gitconfig"
    config.write_text(f"[safe]\n\tdirectory = {Path(repo).as_posix()}\n", encoding="utf-8")
    return {"GIT_CONFIG_GLOBAL": str(config)}


def in_commit(message: str, commit: str | None) -> str:
    return f"{message} (found in commit {commit[:8]})" if commit else message
