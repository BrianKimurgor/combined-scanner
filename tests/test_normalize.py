from scanner.core.config import ALL_SCANNERS, ComplexityConfig
from scanner.core.ignore import is_ignored
from scanner.normalize import severity
from scanner.normalize.dedupe import dedupe
from scanner.normalize.finding import Category, Finding, Severity
from scanner.plugins import REGISTRY, build_plugins


def _dep(
    tool: str,
    sev: Severity = Severity.HIGH,
    fixed: str | None = None,
    package: str = "lodash",
    version: str = "4.17.15",
) -> Finding:
    return Finding(
        tool=tool,
        category=Category.DEPENDENCY,
        rule_id="CVE-2020-8203",
        severity=sev,
        title="t",
        file="package-lock.json",
        package=package,
        version=version,
        fixed_version=fixed,
    )


def _secret(tool: str, rule: str) -> Finding:
    return Finding(
        tool=tool,
        category=Category.SECRET,
        rule_id=rule,
        severity=Severity.HIGH,
        title="t",
        file="a.py",
        line_start=7,
    )


def test_dependency_findings_merge_across_tools() -> None:
    (merged,) = dedupe([_dep("osv", Severity.MEDIUM), _dep("trivy", Severity.CRITICAL, "4.17.19")])
    assert merged.sources == ["osv", "trivy"]
    assert merged.severity is Severity.CRITICAL
    assert merged.fixed_version == "4.17.19"


def test_dependency_findings_merge_despite_spelling_differences() -> None:
    (merged,) = dedupe(
        [
            _dep("osv", package="PyYAML", version="3.13.0"),
            _dep("trivy", package="pyyaml", version="3.13"),
        ]
    )
    assert merged.sources == ["osv", "trivy"]


def test_different_versions_stay_separate() -> None:
    assert len(dedupe([_dep("osv", version="1.2"), _dep("trivy", version="1.20")])) == 2


def test_licence_findings_for_different_packages_stay_separate() -> None:
    def licence(package: str) -> Finding:
        return Finding(
            tool="trivy",
            category=Category.LICENSE,
            rule_id="GPL-3.0-only",
            severity=Severity.HIGH,
            title="t",
            file="package-lock.json",
            package=package,
        )

    assert len(dedupe([licence("a"), licence("b"), licence("A")])) == 2


def test_secret_findings_merge_by_location() -> None:
    (merged,) = dedupe(
        [_secret("gitleaks", "aws-access-token"), _secret("trivy", "aws-access-key-id")]
    )
    assert merged.sources == ["gitleaks", "trivy"]


def test_code_findings_from_different_tools_stay_separate() -> None:
    def code(tool: str) -> Finding:
        return Finding(
            tool=tool,
            category=Category.IAC,
            rule_id="R",
            severity=Severity.LOW,
            title="t",
            file="Dockerfile",
            line_start=1,
        )

    assert len(dedupe([code("trivy"), code("checkov")])) == 2


def test_dedupe_does_not_mutate_inputs() -> None:
    first = _dep("osv")
    dedupe([first, _dep("trivy")])
    assert first.sources == ["osv"]


def test_ids_are_stable() -> None:
    assert _dep("osv").id == _dep("osv").id
    assert _dep("osv").id != _dep("trivy").id
    assert _dep("osv").fingerprint == _dep("trivy").fingerprint


def test_cvss_mapping() -> None:
    assert severity.from_cvss(9.8) is Severity.CRITICAL
    assert severity.from_cvss(7.0) is Severity.HIGH
    assert severity.from_cvss(5.0) is Severity.MEDIUM
    assert severity.from_cvss(0.1) is Severity.LOW
    assert severity.osv(None, "MODERATE") is Severity.MEDIUM
    assert severity.osv("bad", None) is Severity.MEDIUM


def test_tool_label_mapping() -> None:
    assert severity.lookup(severity.SEMGREP, "ERROR") is Severity.HIGH
    assert severity.lookup(severity.TRIVY, "UNKNOWN") is Severity.INFO
    assert severity.lookup(severity.CHECKOV, None) is Severity.MEDIUM


def test_complexity_severity_scales_with_limits() -> None:
    limits = ComplexityConfig()
    assert severity.complexity(16, 10, 1, limits) is Severity.MEDIUM
    assert severity.complexity(30, 10, 1, limits) is Severity.HIGH


def test_ignore_globs() -> None:
    patterns = ["**/node_modules/**", "**/*.min.js", "build/*"]
    assert is_ignored("node_modules/x/index.js", patterns)
    assert is_ignored("web/node_modules/x/index.js", patterns)
    assert is_ignored("static/app.min.js", patterns)
    assert is_ignored("build/out.txt", patterns)
    assert not is_ignored("build/sub/out.txt", patterns)
    assert not is_ignored("src/app.js", patterns)
    assert not is_ignored(None, patterns)


def test_registry_matches_default_scanners() -> None:
    assert sorted(REGISTRY) == sorted(ALL_SCANNERS)
    assert [p.name for p in build_plugins(ALL_SCANNERS)] == ALL_SCANNERS
