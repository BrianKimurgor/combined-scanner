import re
from pathlib import Path

import pytest
from typer.testing import CliRunner

from scanner.cli import app

runner = CliRunner()


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {"SCANNER_DATA_DIR": str(tmp_path / "data"), "SCANNER_SANDBOX": "local"}


def test_create_key_prints_a_usable_key_once(env: dict[str, str]) -> None:
    result = runner.invoke(app, ["admin", "create-key", "alice"], env=env)
    assert result.exit_code == 0
    assert result.stdout.strip().startswith("cs_")
    assert "cannot be shown again" in result.output


def test_duplicate_key_names_are_refused(env: dict[str, str]) -> None:
    assert runner.invoke(app, ["admin", "create-key", "alice"], env=env).exit_code == 0
    again = runner.invoke(app, ["admin", "create-key", "alice"], env=env)
    assert again.exit_code == 2 and "already exists" in again.output


def test_worker_with_an_empty_queue_exits_cleanly(env: dict[str, str]) -> None:
    result = runner.invoke(app, ["worker", "--once"], env=env)
    assert result.exit_code == 0
    assert "processed 0 scan(s)" in result.output
    assert "without a sandbox" in result.output  # local mode is flagged loudly


def test_bad_server_settings_are_reported(env: dict[str, str]) -> None:
    result = runner.invoke(app, ["worker", "--once"], env={**env, "SCANNER_SANDBOX": "vm"})
    assert result.exit_code == 2 and "SCANNER_SANDBOX" in result.output


def test_serve_help_lists_the_options() -> None:
    # CI runners ask for colour, and colour codes would split "--host" in the raw output.
    result = runner.invoke(app, ["serve", "--help"], env={"NO_COLOR": "1", "FORCE_COLOR": ""})
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    assert result.exit_code == 0 and "--host" in plain and "--port" in plain
