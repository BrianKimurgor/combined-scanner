from collections.abc import Iterable

from scanner.normalize.finding import Finding


def dedupe(findings: Iterable[Finding]) -> list[Finding]:
    """Merge findings sharing a fingerprint, keeping the highest severity and all sources."""
    merged: dict[str, Finding] = {}
    for finding in findings:
        existing = merged.get(finding.fingerprint)
        if existing is None:
            merged[finding.fingerprint] = finding.model_copy(deep=True)
            continue
        for source in finding.sources:
            if source not in existing.sources:
                existing.sources.append(source)
        if finding.severity.rank > existing.severity.rank:
            existing.severity = finding.severity
        existing.fixed_version = existing.fixed_version or finding.fixed_version
    return list(merged.values())
