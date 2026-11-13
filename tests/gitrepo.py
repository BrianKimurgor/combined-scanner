import os
import subprocess
from pathlib import Path


class Repo:
    """A throwaway git repository for tests; isolated from the user's git configuration."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir(parents=True, exist_ok=True)
        self.env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
        self.git("init", "--quiet", "-b", "main")

    def git(self, *args: str) -> str:
        identity = ["-c", "user.name=t", "-c", "user.email=t@example.com"]
        done = subprocess.run(  # noqa: S603
            ["git", *identity, "-C", str(self.path), *args],  # noqa: S607
            env=self.env,
            capture_output=True,
            text=True,
            check=True,
        )
        return done.stdout.strip()

    def commit(self, files: dict[str, str], message: str = "c") -> str:
        for name, text in files.items():
            target = self.path / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        self.git("add", "-A")
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")
