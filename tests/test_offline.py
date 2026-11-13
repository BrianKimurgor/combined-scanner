import io
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from fakes import GoodPlugin
from scanner import mirror
from scanner.cli import app
from scanner.core.config import Config
from scanner.plugins.base import ScanContext
from scanner.plugins.osv import OsvPlugin
from scanner.plugins.semgrep import SemgrepPlugin
from scanner.plugins.trivy import TrivyPlugin
from scanner.plugins.trufflehog import TrufflehogPlugin
from scanner.settings import Settings
from scanner.worker.sandbox import SandboxError, docker_command

runner = CliRunner()


def ctx(tmp_path: Path, *, offline: bool, rules: list[str] | None = None) -> ScanContext:
    config = Config(offline=offline)
    if rules is not None:
        config.scanners.semgrep_rules = rules
    return ScanContext(tmp_path, tmp_path / "out", config, 10)


def zip_bytes() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("a.json", "{}")
    return buffer.getvalue()


# ----------------------------------------------------------------- scanner flags


def test_online_commands_are_unchanged(tmp_path: Path) -> None:
    assert "--offline" not in OsvPlugin().build_command(ctx(tmp_path, offline=False))
    assert "--offline-scan" not in TrivyPlugin().build_command(ctx(tmp_path, offline=False))


def test_trivy_timeout_outlasts_the_per_tool_limit(tmp_path: Path) -> None:
    command = TrivyPlugin().build_command(ctx(tmp_path, offline=False))
    assert command[command.index("--timeout") + 1] == "70s"


def test_trivy_skips_licence_scanning(tmp_path: Path) -> None:
    command = TrivyPlugin().build_command(ctx(tmp_path, offline=False))
    assert command[command.index("--scanners") + 1] == "vuln,secret,misconfig"


def test_offline_osv_uses_its_local_database(tmp_path: Path) -> None:
    command = OsvPlugin().build_command(ctx(tmp_path, offline=True))
    assert command.index("--offline") < command.index("-r")


def test_trufflehog_does_not_verify_secrets_by_default(tmp_path: Path) -> None:
    command = TrufflehogPlugin().build_command(ctx(tmp_path, offline=False))
    assert "--no-verification" in command
    assert "--no-update" in command


def test_trufflehog_verifies_only_when_enabled_and_online(tmp_path: Path) -> None:
    online = ctx(tmp_path, offline=False)
    online.config.scanners.trufflehog_verify = True
    assert "--no-verification" not in TrufflehogPlugin().build_command(online)
    offline = ctx(tmp_path, offline=True)
    offline.config.scanners.trufflehog_verify = True
    assert "--no-verification" in TrufflehogPlugin().build_command(offline)


def test_offline_trivy_skips_every_download_and_avoids_cache_writes(tmp_path: Path) -> None:
    command = TrivyPlugin().build_command(ctx(tmp_path, offline=True))
    for flag in (
        "--skip-db-update",
        "--skip-java-db-update",
        "--skip-check-update",
        "--offline-scan",
    ):
        assert flag in command
    assert command[command.index("--cache-backend") + 1] == "memory"


def test_offline_semgrep_needs_rules_on_disk(tmp_path: Path) -> None:
    plugin = SemgrepPlugin()
    registry = ctx(tmp_path, offline=True)  # default rules are the downloaded p/default pack
    assert "local semgrep rules" in (plugin.skip_reason(registry) or "")
    local = ctx(tmp_path, offline=True, rules=[str(tmp_path)])
    assert plugin.skip_reason(local) is None
    assert plugin.skip_reason(ctx(tmp_path, offline=False)) is None


class Recorder(GoodPlugin):
    seen: list[tuple[bool, list[str]]] = []  # noqa: RUF012

    def build_command(self, ctx: ScanContext) -> list[str]:
        self.seen.append((ctx.config.offline, ctx.config.scanners.semgrep_rules))
        return super().build_command(ctx)


def test_scan_command_passes_offline_and_rules_to_the_scanners(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    Recorder.seen = []
    monkeypatch.setattr("scanner.cli.build_plugins", lambda names: [Recorder()])
    target = tmp_path / "proj"
    target.mkdir()
    result = runner.invoke(
        app, ["scan", str(target), "--offline", "--semgrep-rules", "/mirror/semgrep-rules"]
    )
    assert result.exit_code in {0, 1}
    assert Recorder.seen == [(True, ["/mirror/semgrep-rules"])]


# ----------------------------------------------------------------- sandbox


def sandbox_settings(tmp_path: Path, **overrides: Any) -> Settings:
    return Settings(data_dir=tmp_path / "data", **overrides)


def command(settings: Settings, tmp_path: Path) -> list[str]:
    src, out = tmp_path / "src", tmp_path / "out"
    src.mkdir(exist_ok=True)
    out.mkdir(exist_ok=True)
    return docker_command(settings, "a" * 32, src, out)


def test_offline_containers_have_no_network_and_a_read_only_mirror(tmp_path: Path) -> None:
    mirror_dir = tmp_path / "mirror"
    (mirror_dir / "osv" / "osv-scalibr").mkdir(parents=True)
    settings = sandbox_settings(
        tmp_path, offline=True, mirror_path=str(mirror_dir), sandbox_network="bridge"
    )
    args = command(settings, tmp_path)
    assert args[args.index("--network") + 1] == "none"
    mount = next(a for a in args if a.endswith("target=/mirror,readonly"))
    assert mount.startswith("type=bind,source=")
    # OSV must be able to write beside its database, so only the archives are mounted read-only.
    assert "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv" in args
    assert any(a.startswith("/osv:rw") for a in args)
    assert any(a.endswith("target=/osv/osv-scalibr,readonly") for a in args)
    assert "TRIVY_CACHE_DIR=/mirror/trivy" in args
    assert args[-3:] == ["--offline", "--semgrep-rules", "/mirror/semgrep-rules"]


def test_offline_mode_refuses_to_run_without_a_mirror(tmp_path: Path) -> None:
    settings = sandbox_settings(tmp_path, offline=True, mirror_path=str(tmp_path / "missing"))
    with pytest.raises(SandboxError, match="mirror"):
        command(settings, tmp_path)


def test_online_containers_are_unaffected(tmp_path: Path) -> None:
    args = command(sandbox_settings(tmp_path), tmp_path)
    assert "--offline" not in args and not any("/mirror" in a for a in args)
    assert "TRIVY_CACHE_DIR=/cache/trivy" in args


def test_offline_settings_come_from_the_environment(tmp_path: Path) -> None:
    settings = Settings.from_env({"SCANNER_OFFLINE": "1", "SCANNER_MIRROR_DIR": str(tmp_path)})
    assert settings.offline and settings.mirror_dir == tmp_path
    assert not Settings.from_env({}).offline
    assert Settings.from_env({"SCANNER_DATA_DIR": str(tmp_path)}).mirror_dir == tmp_path / "mirror"


# ----------------------------------------------------------------- mirror


def test_osv_archives_land_where_osv_scanner_looks(tmp_path: Path) -> None:
    fetched: list[tuple[str, Path]] = []
    done = mirror.update_osv(
        tmp_path, ["PyPI", "npm"], lambda url, dest: fetched.append((url, dest))
    )
    assert done == ["PyPI", "npm"]
    assert fetched[0] == (
        f"{mirror.OSV_BASE}/PyPI/all.zip",
        tmp_path / "osv" / "osv-scalibr" / "PyPI" / "all.zip",
    )


@pytest.mark.parametrize("name", ["../etc", "a/b", "", "x" * 50, "a b", "..\\x"])
def test_ecosystem_names_cannot_escape_the_mirror(tmp_path: Path, name: str) -> None:
    with pytest.raises(mirror.MirrorError, match="invalid ecosystem"):
        mirror.update_osv(tmp_path, [name], lambda url, dest: None)
    assert not any(tmp_path.iterdir())


def test_trivy_update_fetches_both_databases_into_the_mirror(tmp_path: Path) -> None:
    calls: list[list[str]] = []
    mirror.update_trivy(tmp_path, lambda args: calls.append(args) or 0)
    assert [c[2] for c in calls] == ["--download-db-only", "--download-java-db-only"]
    assert all(c[c.index("--cache-dir") + 1] == str(tmp_path / "trivy") for c in calls)
    with pytest.raises(mirror.MirrorError, match="failed"):
        mirror.update_trivy(tmp_path, lambda args: 1)


class FakeResponse(io.BytesIO):
    def __enter__(self) -> "FakeResponse":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def test_downloads_are_verified_and_replace_the_old_file_atomically(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dest = tmp_path / "all.zip"
    dest.write_bytes(b"old")
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: FakeResponse(b"not a zip"))
    with pytest.raises(mirror.MirrorError, match="zip"):
        mirror._download("https://example.com/all.zip", dest)
    assert dest.read_bytes() == b"old" and not list(tmp_path.glob("*.part"))

    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout: FakeResponse(zip_bytes()))
    mirror._download("https://example.com/all.zip", dest)
    assert zipfile.is_zipfile(dest) and not list(tmp_path.glob("*.part"))


def test_only_https_sources_are_fetched(tmp_path: Path) -> None:
    with pytest.raises(mirror.MirrorError, match="https"):
        mirror._download("http://example.com/all.zip", tmp_path / "all.zip")
    with pytest.raises(mirror.MirrorError, match="https"):
        mirror._download("file:///etc/passwd", tmp_path / "all.zip")


def test_status_reports_what_is_present(tmp_path: Path) -> None:
    empty = {e.name: e.present for e in mirror.status(tmp_path)}
    assert not any(empty.values())

    archive = tmp_path / "osv" / "osv-scalibr" / "PyPI"
    archive.mkdir(parents=True)
    (archive / "all.zip").write_bytes(zip_bytes())
    db = tmp_path / "trivy" / "db"
    db.mkdir(parents=True)
    (db / "metadata.json").write_text('{"NextUpdate": "2026-11-01"}', encoding="utf-8")
    rules = tmp_path / "semgrep-rules"
    rules.mkdir()
    (rules / "r.yaml").write_text("rules: []", encoding="utf-8")

    found = {e.name: e for e in mirror.status(tmp_path)}
    assert found["osv/PyPI"].present and found["trivy-db"].detail == "next update 2026-11-01"
    assert found["semgrep-rules"].present and "1 rule file" in found["semgrep-rules"].detail


def test_mirror_commands_report_status_and_failures(tmp_path: Path) -> None:
    env = {"SCANNER_DATA_DIR": str(tmp_path / "data"), "SCANNER_SANDBOX": "local"}
    status = runner.invoke(app, ["admin", "mirror-status"], env=env)
    assert status.exit_code == 0 and "osv\tmissing" in status.output
    bad = runner.invoke(
        app, ["admin", "mirror-update", "--skip-trivy", "--ecosystems", "../x"], env=env
    )
    assert bad.exit_code == 2 and "invalid ecosystem" in bad.output
