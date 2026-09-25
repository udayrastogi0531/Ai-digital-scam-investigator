"""Structured logging configuration.

Every investigation gets a dedicated logger context carrying the
investigation id and processing stage.  Sensitive user content is never
logged: the raw message body is excluded from log records.
"""
import json
import logging
import sys
from typing import Any

from .config import get_settings

_configured = False


class JsonFormatter(logging.Formatter):
    """Compact JSON log formatter (single line per record)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if extra:
            payload.update(extra)
        return json.dumps(payload, default=str)


def setup_logging() -> None:
    global _configured
    if _configured:
        return
    settings = get_settings()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if settings.debug else logging.INFO)
    # Never let third-party HTTP clients log request URLs.  A URL can carry a
    # credential (an API key in a query parameter) and always carries the
    # user-submitted link; both must stay out of the log stream.  Their
    # warnings/errors still surface.
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    _configured = True


def investigation_logger(investigation_id: str | None = None) -> logging.Logger:
    """Return a logger bound to an investigation context."""
    logger = logging.getLogger("scaminvestigator")
    if investigation_id:
        logger = logging.LoggerAdapter(logger, {"extra_fields": {"investigation_id": investigation_id}})
    return logger