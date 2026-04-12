"""
Structured JSON logger used by every module in the research pipeline.

Usage:
    from research.utils.logger import get_logger
    logger = get_logger(__name__)
    logger.info("Processing vulnerability", extra={"vuln_id": "CVE-2023-1234"})
"""

import json
import logging
from datetime import datetime, timezone

# Standard LogRecord attributes to exclude from the `extra` dict
_STANDARD_LOG_ATTRS = frozenset({
    "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
    "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
    "created", "msecs", "relativeCreated", "thread", "threadName",
    "processName", "process", "message", "taskName", "asctime",
})


class JsonFormatter(logging.Formatter):
    """Formats log records as single-line JSON strings."""

    def format(self, record: logging.LogRecord) -> str:
        # Ensure message is populated
        record.message = record.getMessage()

        # Collect any extra fields passed via logger.info("msg", extra={...})
        # Extra keys are merged directly into record.__dict__ by Python's logging.
        extra = {
            k: v
            for k, v in record.__dict__.items()
            if k not in _STANDARD_LOG_ATTRS and not k.startswith("_")
        }

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "name": record.name,
            "message": record.message,
            "extra": extra,
        }

        if record.exc_info:
            log_entry["exc_info"] = self.formatException(record.exc_info)

        return json.dumps(log_entry, default=str)


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    """
    Return a named logger configured with JSON output.

    Args:
        name:  Logger name — use __name__ from the calling module.
        level: Logging level (default INFO). Can be overridden per-logger.

    Returns:
        Configured logging.Logger instance.
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if called multiple times
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)

    logger.setLevel(level)
    # Prevent propagation to root logger to avoid duplicate output
    logger.propagate = False

    return logger
