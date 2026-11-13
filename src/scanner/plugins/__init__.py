from scanner.core.config import ALL_SCANNERS
from scanner.plugins.base import ScannerPlugin
from scanner.plugins.checkov import CheckovPlugin
from scanner.plugins.gitleaks import GitleaksPlugin
from scanner.plugins.jscpd import JscpdPlugin
from scanner.plugins.lizard import LizardPlugin
from scanner.plugins.osv import OsvPlugin
from scanner.plugins.presidio import PresidioPlugin
from scanner.plugins.semgrep import SemgrepPlugin
from scanner.plugins.trivy import TrivyPlugin
from scanner.plugins.trufflehog import TrufflehogPlugin

REGISTRY: dict[str, type[ScannerPlugin]] = {
    plugin.name: plugin
    for plugin in (
        OsvPlugin,
        SemgrepPlugin,
        GitleaksPlugin,
        TrivyPlugin,
        JscpdPlugin,
        LizardPlugin,
        CheckovPlugin,
        PresidioPlugin,
        TrufflehogPlugin,
    )
}

assert sorted(REGISTRY) == sorted(ALL_SCANNERS)  # noqa: S101 - keeps config defaults in sync


def build_plugins(names: list[str]) -> list[ScannerPlugin]:
    unknown = [name for name in names if name not in REGISTRY]
    if unknown:
        raise ValueError(f"unknown scanner(s): {', '.join(unknown)}")
    return [REGISTRY[name]() for name in names]
