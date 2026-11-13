import json
import logging
import sys
from datetime import UTC, datetime

from scanner.settings import Settings

# Fields passed with `extra=` that are worth keeping in structured logs.
EXTRA_FIELDS = ("scan_id", "outcome", "seconds", "findings", "method", "path", "status", "ms")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        entry.update({k: getattr(record, k) for k in EXTRA_FIELDS if hasattr(record, k)})
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry, default=str)


def configure_logging(settings: Settings) -> None:
    handler = logging.StreamHandler(sys.stderr)
    if settings.log_format == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
