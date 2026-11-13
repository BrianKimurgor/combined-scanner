from collections.abc import Callable
from pathlib import Path

import pytest

from scanner.core.config import Config
from scanner.plugins.base import ScanContext

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def ctx(tmp_path: Path) -> ScanContext:
    workdir = tmp_path / "project"
    workdir.mkdir()
    return ScanContext(workdir=workdir, output_dir=tmp_path / "out", config=Config(), timeout=10)


@pytest.fixture
def fixture_text() -> Callable[[str], str]:
    def read(name: str) -> str:
        return (FIXTURES / name).read_text(encoding="utf-8")

    return read
