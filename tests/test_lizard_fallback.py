import subprocess
from pathlib import Path
from typing import Any

import pytest

from scanner.core.config import Config
from scanner.plugins import lizard as lizard_module
from scanner.plugins.base import ScanContext, Status
from scanner.plugins.lizard import LizardPlugin


def _csv(path: str) -> str:
    return f'12,20,100,2,40,"big@1-40@./{path}","./{path}","big","big( a )",1,40\n'


class FakeLizard:
    """Exits 1 for any run that includes a file named bad*, like lizard's parser crashes."""

    def __init__(self) -> None:
        self.runs: list[list[str]] = []

    def __call__(self, args: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        self.runs.append(args)
        files = [a for a in args[2:] if a != "."]
        if args[-1] == ".":
            files = ["bad.ts", "ok1.py", "ok2.py"]  # the recursive run walks the whole tree
        if any(Path(f).name.startswith("bad") for f in files):
            return subprocess.CompletedProcess(args, 1, "", "IndexError: list index out of range")
        return subprocess.CompletedProcess(args, 0, "".join(_csv(f) for f in files), "")


def _context(tmp_path: Path) -> ScanContext:
    for name in ("ok1.py", "bad.ts", "ok2.py"):
        (tmp_path / name).write_text("x = 1\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "dep.js").write_text("x\n")
    return ScanContext(tmp_path, tmp_path / "out", Config(), 30)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeLizard:
    runner = FakeLizard()
    monkeypatch.setattr(subprocess, "run", runner)
    monkeypatch.setattr(lizard_module.shutil, "which", lambda name: "/usr/bin/lizard")
    return runner


def test_a_file_that_crashes_lizard_is_skipped_not_fatal(tmp_path: Path, fake: FakeLizard) -> None:
    result = LizardPlugin().run(_context(tmp_path))
    assert result.status is Status.OK
    assert "1 file(s) skipped" in result.message
    assert sorted(f.file for f in result.findings if f.file) == ["ok1.py", "ok2.py"]
    assert all("node_modules" not in " ".join(run) for run in fake.runs[1:])  # ignores apply


def test_a_clean_run_is_untouched(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ok = subprocess.CompletedProcess([], 0, _csv("a.py"), "")
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: ok)
    monkeypatch.setattr(lizard_module.shutil, "which", lambda name: "/usr/bin/lizard")
    result = LizardPlugin().run(_context(tmp_path))
    assert result.status is Status.OK and result.message == ""
    assert [f.file for f in result.findings] == ["a.py"]


def test_test_folders_are_excluded_from_the_lizard_run(tmp_path: Path) -> None:
    command = LizardPlugin().build_command(_context(tmp_path))
    excluded = [command[i + 1] for i, arg in enumerate(command) if arg == "-x"]
    assert "*/__tests__/*" in excluded and "*/*.test.*" in excluded
    assert command[:2] == ["lizard", "--csv"] and command[-1] == "."


def test_a_very_long_field_does_not_crash_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    row = f'12,20,100,2,40,"big@1-40@./a.js","./a.js","{"x" * 200_000}","big( a )",1,40\n'
    ok = subprocess.CompletedProcess([], 0, row, "")
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: ok)
    monkeypatch.setattr(lizard_module.shutil, "which", lambda name: "/usr/bin/lizard")
    result = LizardPlugin().run(_context(tmp_path))
    assert result.status is Status.OK
    assert [f.file for f in result.findings] == ["a.js"]


def test_failure_stays_a_failure_when_every_file_crashes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    broken = subprocess.CompletedProcess([], 1, "", "IndexError")
    monkeypatch.setattr(subprocess, "run", lambda args, **kwargs: broken)
    monkeypatch.setattr(lizard_module.shutil, "which", lambda name: "/usr/bin/lizard")
    result = LizardPlugin().run(_context(tmp_path))
    assert result.status is Status.FAILED
