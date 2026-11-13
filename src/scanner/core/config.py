from datetime import date, timedelta
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, PositiveInt, field_validator

ALL_SCANNERS = [
    "osv",
    "semgrep",
    "gitleaks",
    "trivy",
    "jscpd",
    "lizard",
    "checkov",
    "presidio",
    "trufflehog",
]

FailLevel = Literal["any", "critical", "high", "medium", "low", "none"]
PiiEntity = Literal[
    "EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", "IBAN_CODE", "PHONE_NUMBER", "CRYPTO", "IP_ADDRESS"
]
DEFAULT_PII_ENTITIES: list[PiiEntity] = ["EMAIL_ADDRESS", "CREDIT_CARD", "US_SSN", "IBAN_CODE"]


class FailOn(BaseModel):
    vulnerability: FailLevel = "high"
    secret: FailLevel = "any"  # noqa: S105 - a gate level, not a credential
    code: FailLevel = "high"
    iac: FailLevel = "high"
    pii: FailLevel = "none"  # report-only: test data and docs often contain sample PII


class ComplexityConfig(BaseModel):
    ccn: PositiveInt = 15
    length: PositiveInt = 100
    args: PositiveInt = 6


class DuplicationConfig(BaseModel):
    max_percent: float = Field(default=5.0, ge=0)


class GateConfig(BaseModel):
    fail_on: FailOn = Field(default_factory=FailOn)
    complexity: ComplexityConfig = Field(default_factory=ComplexityConfig)
    duplication: DuplicationConfig = Field(default_factory=DuplicationConfig)


class ScannersConfig(BaseModel):
    enabled: list[str] = Field(default_factory=lambda: list(ALL_SCANNERS))
    timeout_seconds: PositiveInt = 600
    # Registry rules fall under the Semgrep Rules License; use your own packs if hosting.
    semgrep_rules: list[str] = Field(default_factory=lambda: ["p/default"])
    # Semgrep starts one process per CPU it sees, not per CPU it may use, which stalls a container.
    semgrep_jobs: PositiveInt = 2
    # Phone numbers and IP addresses are off by default because they are very noisy in code.
    pii_entities: list[PiiEntity] = Field(default_factory=lambda: list(DEFAULT_PII_ENTITIES))
    pii_min_score: float = Field(default=0.5, ge=0, le=1)
    # Off by default: verifying sends each secret found to its provider (AWS, GitHub, ...)
    # to check whether it still works. Never happens in offline mode.
    trufflehog_verify: bool = False


MAX_SUPPRESSION_DAYS = 366


class Suppression(BaseModel):
    """Accept one finding, identified by its fingerprint, until a review date."""

    fingerprint: str = Field(pattern=r"^[0-9a-f]{16}$")
    reason: str = Field(min_length=1, max_length=500)
    expires: date

    @field_validator("reason")
    @classmethod
    def _reason_is_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("a suppression needs a reason")
        return value.strip()

    @field_validator("expires")
    @classmethod
    def _expiry_is_not_too_far_away(cls, value: date) -> date:
        if value > date.today() + timedelta(days=MAX_SUPPRESSION_DAYS):
            raise ValueError("suppressions may not last more than a year; they must be reviewed")
        return value


class Config(BaseModel):
    gate: GateConfig = Field(default_factory=GateConfig)
    scanners: ScannersConfig = Field(default_factory=ScannersConfig)
    ignore: list[str] = Field(
        default_factory=lambda: ["**/node_modules/**", "**/vendor/**", "**/*.min.js"]
    )
    # Only complexity and duplication skip these: tests are still scanned for secrets and CVEs.
    quality_ignore: list[str] = Field(
        default_factory=lambda: [
            "**/__tests__/**", "**/tests/**", "**/test/**", "**/e2e/**", "**/cypress/**",
            "**/*.test.*", "**/*.spec.*", "**/*.cy.*", "**/fixtures/**", "**/migrations/**",
        ]
    )  # fmt: skip
    suppressions: list[Suppression] = Field(default_factory=list)
    # Licence findings for matching package names are dropped; CVEs for them are still reported.
    license_ignore: list[str] = Field(default_factory=lambda: ["@img/sharp-*"])
    # Set by the operator (CLI flag), not meant for scanned projects: no network, local databases.
    offline: bool = False


def load_config(path: Path | None) -> Config:
    """Load scanner.yml from a given path or the cwd, never from the scan target."""
    if path is None:
        default = Path("scanner.yml")
        path = default if default.is_file() else None
    if path is None:
        return Config()
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return Config.model_validate(data)
