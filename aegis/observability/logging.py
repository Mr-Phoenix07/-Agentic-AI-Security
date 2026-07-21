"""Structured logging.

Emits JSON lines by default (machine-parseable, ships cleanly to ELK/Loki) with
an optional human-readable console format. Zero dependencies; every log record
can carry an assessment id so events are correlatable across agents.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any, Optional


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        base: dict[str, Any] = {
            "ts": round(record.created, 3),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key in ("assessment_id", "agent", "target_id", "event", "extra"):
            val = getattr(record, key, None)
            if val is not None:
                base[key] = val
        if record.exc_info:
            base["exc"] = self.formatException(record.exc_info)
        return json.dumps(base, default=str, ensure_ascii=False)


def get_logger(name: str = "aegis", level: str = "INFO",
               json_format: bool = True) -> logging.Logger:
    logger = logging.getLogger(name)
    if getattr(logger, "_aegis_configured", False):
        return logger
    logger.setLevel(level)
    handler = logging.StreamHandler(sys.stderr)
    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)s | %(message)s"))
    logger.addHandler(handler)
    logger._aegis_configured = True  # type: ignore[attr-defined]
    return logger


class BoundLogger:
    """A logger with bound context (assessment id, agent) for correlation."""

    def __init__(self, logger: logging.Logger, **ctx) -> None:
        self._logger = logger
        self._ctx = ctx

    def bind(self, **ctx) -> "BoundLogger":
        return BoundLogger(self._logger, **{**self._ctx, **ctx})

    def _log(self, level: int, event: str, msg: str = "", **extra) -> None:
        self._logger.log(level, msg or event,
                         extra={**self._ctx, "event": event,
                                "extra": extra or None})

    def info(self, event: str, msg: str = "", **extra) -> None:
        self._log(logging.INFO, event, msg, **extra)

    def warning(self, event: str, msg: str = "", **extra) -> None:
        self._log(logging.WARNING, event, msg, **extra)

    def error(self, event: str, msg: str = "", **extra) -> None:
        self._log(logging.ERROR, event, msg, **extra)

    def debug(self, event: str, msg: str = "", **extra) -> None:
        self._log(logging.DEBUG, event, msg, **extra)
