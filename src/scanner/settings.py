import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from scanner.ingest.safe_extract import ExtractLimits

SandboxMode = Literal["docker", "local"]
MIB = 1024 * 1024


def _positive_int(env: Mapping[str, str], key: str, default: int) -> int:
    raw = env.get(key)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        raise ValueError(f"{key} must be a positive integer")
    return value


@dataclass(frozen=True)
class Settings:
    data_dir: Path = Path("scanner-data")
    database_url: str = ""
    max_upload_bytes: int = 100 * MIB
    max_scans_per_hour: int = 30
    max_queued_scans: int = 200
    scan_timeout_seconds: int = 1800
    sandbox_mode: SandboxMode = "docker"
    sandbox_image: str = "code-scanner-worker"
    sandbox_network: str = "bridge"
    sandbox_memory: str = "4g"
    sandbox_cpus: str = "2"
    sandbox_pids: int = 512
    # Shared across scans so Trivy's database is downloaded once; empty means a throwaway tmpfs.
    sandbox_cache_volume: str = "scanner-cache"
    poll_seconds: float = 2.0
    session_hours: int = 12
    retention_days: int = 90
    prune_interval_seconds: int = 3600
    # Empty disables /metrics; otherwise it must be sent as a bearer token.
    metrics_token: str = ""
    log_format: Literal["text", "json"] = "text"
    # Scans run with no network, reading vulnerability databases from the mirror directory.
    offline: bool = False
    mirror_path: str = ""
    # Send the login cookie only over https (localhost counts as secure in modern browsers).
    cookie_secure: bool = True

    @property
    def mirror_dir(self) -> Path:
        return Path(self.mirror_path) if self.mirror_path else self.data_dir / "mirror"

    @property
    def uploads_dir(self) -> Path:
        return self.data_dir / "uploads"

    @property
    def work_dir(self) -> Path:
        return self.data_dir / "work"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"

    @property
    def db_url(self) -> str:
        return (
            self.database_url or f"sqlite:///{(self.data_dir / 'scanner.db').resolve().as_posix()}"
        )

    @property
    def extract_limits(self) -> ExtractLimits:
        return ExtractLimits(max_compressed_bytes=self.max_upload_bytes)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Settings":
        env = os.environ if env is None else env
        raw_mode = env.get("SCANNER_SANDBOX", "docker")
        if raw_mode == "docker":
            mode: SandboxMode = "docker"
        elif raw_mode == "local":
            mode = "local"
        else:
            raise ValueError("SCANNER_SANDBOX must be 'docker' or 'local'")
        raw_format = env.get("SCANNER_LOG_FORMAT", "text")
        if raw_format == "json":
            log_format: Literal["text", "json"] = "json"
        elif raw_format == "text":
            log_format = "text"
        else:
            raise ValueError("SCANNER_LOG_FORMAT must be 'text' or 'json'")
        return cls(
            data_dir=Path(env.get("SCANNER_DATA_DIR", "scanner-data")),
            database_url=env.get("SCANNER_DATABASE_URL", ""),
            max_upload_bytes=_positive_int(env, "SCANNER_MAX_UPLOAD_MB", 100) * MIB,
            max_scans_per_hour=_positive_int(env, "SCANNER_MAX_SCANS_PER_HOUR", 30),
            max_queued_scans=_positive_int(env, "SCANNER_MAX_QUEUED_SCANS", 200),
            scan_timeout_seconds=_positive_int(env, "SCANNER_SCAN_TIMEOUT_SECONDS", 1800),
            sandbox_mode=mode,
            sandbox_image=env.get("SCANNER_SANDBOX_IMAGE", "code-scanner-worker"),
            sandbox_network=env.get("SCANNER_SANDBOX_NETWORK", "bridge"),
            sandbox_memory=env.get("SCANNER_SANDBOX_MEMORY", "4g"),
            sandbox_cpus=env.get("SCANNER_SANDBOX_CPUS", "2"),
            sandbox_pids=_positive_int(env, "SCANNER_SANDBOX_PIDS", 512),
            sandbox_cache_volume=env.get("SCANNER_SANDBOX_CACHE_VOLUME", "scanner-cache"),
            session_hours=_positive_int(env, "SCANNER_SESSION_HOURS", 12),
            retention_days=_positive_int(env, "SCANNER_RETENTION_DAYS", 90),
            metrics_token=env.get("SCANNER_METRICS_TOKEN", ""),
            log_format=log_format,
            offline=env.get("SCANNER_OFFLINE", "0") in {"1", "true", "yes"},
            mirror_path=env.get("SCANNER_MIRROR_DIR", ""),
            cookie_secure=env.get("SCANNER_COOKIE_SECURE", "1") not in {"0", "false", "no"},
        )
