from scanner.core.result import ScanReport


def render(report: ScanReport) -> str:
    return report.model_dump_json(indent=2) + "\n"
