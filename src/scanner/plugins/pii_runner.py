"""Find personal data in text files with Presidio's pattern recognizers.

Runs in its own process (see PresidioPlugin) so a crash or hang cannot affect the scan.
Matched values are never written out, only entity type, file, line and a count.
"""

import bisect
import importlib
import json
import os
import re
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from scanner.core.ignore import is_ignored

MAX_FILE_BYTES = 1_000_000
MAX_FILES = 20_000

# Generated or machine-written files are full of long numbers and ids, never real personal data.
SKIPPED_SUFFIXES = (".excalidraw", ".svg", ".map", ".lock", ".min.js", ".min.css")
SKIPPED_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "composer.lock"}
# RFC 2606 names and common placeholders: addresses here cannot belong to a real person.
PLACEHOLDER_DOMAINS = {"example.com", "example.org", "example.net", "localhost", "test.com"}
PLACEHOLDER_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local")
# Issuer prefix and length of the main card networks. Luhn alone also accepts about one in ten
# random digit strings, such as millisecond timestamps (1761800000000).
_CARD = re.compile(
    r"4\d{12}(\d{3}(\d{3})?)?"  # Visa
    r"|5[1-5]\d{14}|2(22[1-9]|2[3-9]\d|[3-6]\d\d|7[01]\d|720)\d{12}"  # Mastercard
    r"|3[47]\d{13}"  # American Express
    r"|6011\d{12}|65\d{14}"  # Discover
    r"|3(0[0-5]|[68]\d)\d{11}"  # Diners Club
    r"|35(2[89]|[3-8]\d)\d{12}"  # JCB
)


def _is_placeholder_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].lower().rstrip(".")
    return domain in PLACEHOLDER_DOMAINS or domain.endswith(PLACEHOLDER_SUFFIXES)


def _is_plausible_card(value: str) -> bool:
    return _CARD.fullmatch(re.sub(r"\D", "", value)) is not None


def _is_false_positive(entity: str, value: str) -> bool:
    if entity == "EMAIL_ADDRESS":
        return _is_placeholder_email(value)
    if entity == "CREDIT_CARD":
        return not _is_plausible_card(value)
    return False


# Pattern-based recognizers only: they need no NLP model and are far less noisy on code than NER.
RECOGNIZER_CLASSES = {
    "EMAIL_ADDRESS": "EmailRecognizer",
    "CREDIT_CARD": "CreditCardRecognizer",
    "US_SSN": "UsSsnRecognizer",
    "IBAN_CODE": "IbanRecognizer",
    "PHONE_NUMBER": "PhoneRecognizer",
    "CRYPTO": "CryptoRecognizer",
    "IP_ADDRESS": "IpRecognizer",
}


def load_recognizers(entities: Sequence[str]) -> list[Any]:
    module = importlib.import_module("presidio_analyzer.predefined_recognizers")
    return [getattr(module, RECOGNIZER_CLASSES[entity])() for entity in entities]


def iter_files(root: Path, ignore: Sequence[str]) -> Iterator[Path]:
    """Walk the tree without following symlinks, skipping .git and ignored paths."""
    for dirpath, dirnames, filenames in os.walk(root):
        relative_dir = Path(dirpath).relative_to(root).as_posix()
        prefix = "" if relative_dir == "." else relative_dir + "/"
        dirnames[:] = sorted(
            d for d in dirnames if d != ".git" and not is_ignored(f"{prefix}{d}/", ignore)
        )
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or is_ignored(f"{prefix}{name}", ignore):
                continue
            if name in SKIPPED_NAMES or name.lower().endswith(SKIPPED_SUFFIXES):
                continue
            yield path


def _read_text(path: Path) -> str | None:
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data:
        return None
    return data.decode("utf-8", errors="replace")


def scan(
    root: Path, ignore: Sequence[str], min_score: float, recognizers: Sequence[Any]
) -> dict[str, Any]:
    counts: Counter[tuple[str, int, str]] = Counter()
    files_scanned = 0
    for path in iter_files(root, ignore):
        if files_scanned >= MAX_FILES:
            break
        text = _read_text(path)
        if text is None:
            continue
        files_scanned += 1
        relative = path.relative_to(root).as_posix()
        newlines = [m.start() for m in re.finditer("\n", text)]
        for recognizer in recognizers:
            entities = list(recognizer.supported_entities)
            for match in recognizer.analyze(text=text, entities=entities, nlp_artifacts=None):
                if match.score < min_score:
                    continue
                if _is_false_positive(match.entity_type, text[match.start : match.end]):
                    continue
                line = bisect.bisect_right(newlines, match.start) + 1
                counts[(relative, line, match.entity_type)] += 1
    findings = [
        {"file": file, "line": line, "entity": entity, "count": count}
        for (file, line, entity), count in sorted(counts.items())
    ]
    return {"files_scanned": files_scanned, "findings": findings}


def main(argv: Sequence[str]) -> int:
    config_path, output_path = Path(argv[0]), Path(argv[1])
    config = json.loads(config_path.read_text(encoding="utf-8"))
    result = scan(
        Path(config["root"]),
        config["ignore"],
        float(config["min_score"]),
        load_recognizers(config["entities"]),
    )
    output_path.write_text(json.dumps(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
