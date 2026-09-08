"""Centralized logging configuration for ARIA platform."""
import logging
import re
import sys
from typing import Optional


class SensitiveFilter(logging.Filter):
    """Filter to redact sensitive information such as passwords from logs."""

    PASSWORD_PATTERN = re.compile(r'(password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE)

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = self.PASSWORD_PATTERN.sub(r'\1***REDACTED***\3', record.msg)
        return True


def setup_logging(log_level: Optional[str] = None) -> None:
    """Configure root logger with formatting and sensitive data redacting."""
    from backend.app.core.config import get_settings

    level_name = log_level or get_settings().log_level
    numeric_level = getattr(logging, level_name.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicate output
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    console_handler.addFilter(SensitiveFilter())

    root_logger.addHandler(console_handler)


def get_logger(name: str) -> logging.Logger:
    """Get a logger instance for the given module name."""
    logger = logging.getLogger(name)
    logger.addFilter(SensitiveFilter())
    return logger
