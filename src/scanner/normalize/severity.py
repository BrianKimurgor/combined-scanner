from collections.abc import Mapping

from scanner.core.config import ComplexityConfig
from scanner.normalize.finding import Severity

SEMGREP: Mapping[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

TRIVY: Mapping[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}

CHECKOV: Mapping[str, Severity] = TRIVY

OSV_LABELS: Mapping[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

DUPLICATION = Severity.LOW

PII: Mapping[str, Severity] = {
    "US_SSN": Severity.HIGH,
    "CREDIT_CARD": Severity.HIGH,
    "IBAN_CODE": Severity.HIGH,
    "CRYPTO": Severity.MEDIUM,
    "PHONE_NUMBER": Severity.MEDIUM,
    "EMAIL_ADDRESS": Severity.LOW,
    "IP_ADDRESS": Severity.LOW,
}


def lookup(
    table: Mapping[str, Severity], label: str | None, default: Severity = Severity.MEDIUM
) -> Severity:
    return table.get((label or "").upper(), default)


def from_cvss(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def osv(score: str | None, label: str | None) -> Severity:
    """Prefer the CVSS score OSV computes for the vulnerability group, then the advisory label."""
    if score:
        try:
            return from_cvss(float(score))
        except ValueError:
            pass
    return lookup(OSV_LABELS, label)


def complexity(ccn: int, length: int, args: int, limits: ComplexityConfig) -> Severity:
    worst = max(ccn / limits.ccn, length / limits.length, args / limits.args)
    return Severity.HIGH if worst >= 2 else Severity.MEDIUM
