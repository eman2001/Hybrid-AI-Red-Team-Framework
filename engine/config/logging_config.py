"""
config/logging_config.py
------------------------
Centralised logging setup for the entire framework.
Call setup_logging() once at startup (main.py).
After that, every module gets a logger with:

    import logging
    log = logging.getLogger(__name__)
"""

import logging
import logging.config
import os
from pathlib import Path
from engine.config.settings import BASE_DIR

# ─────────────────────────────────────────────
# Log file location
# ─────────────────────────────────────────────
LOG_DIR  = BASE_DIR / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = str(LOG_DIR / "redteam.log")

# ─────────────────────────────────────────────
# Logging configuration dict
# ─────────────────────────────────────────────
LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,

    # ── Formatters ──────────────────────────
    "formatters": {
        "detailed": {
            "format": "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
            "datefmt": "%Y-%m-%d %H:%M:%S",
        },
        "simple": {
            "format": "%(levelname)-8s | %(message)s",
        },
    },

    # ── Handlers ────────────────────────────
    "handlers": {
        "console": {
            "class":     "logging.StreamHandler",
            "formatter": "simple",
            "level":     "INFO",
            "stream":    "ext://sys.stdout",
        },
        "file": {
            "class":        "logging.handlers.RotatingFileHandler",
            "formatter":    "detailed",
            "level":        "DEBUG",
            "filename":     LOG_FILE,
            "maxBytes":     10 * 1024 * 1024,   # 10 MB
            "backupCount":  5,
            "encoding":     "utf-8",
        },
    },

    # ── Root logger ─────────────────────────
    "root": {
        "level":    "DEBUG",
        "handlers": ["console", "file"],
    },

    # ── Per-module overrides ─────────────────
    "loggers": {
        # Silence noisy third-party libraries
        "urllib3":    {"level": "WARNING", "propagate": True},
        "requests":   {"level": "WARNING", "propagate": True},
        "sqlalchemy": {"level": "WARNING", "propagate": True},
        "nmap":       {"level": "WARNING", "propagate": True},
        # Framework modules — DEBUG level, output to both handlers
        "modules":    {"level": "DEBUG",   "propagate": True},
        "config":     {"level": "DEBUG",   "propagate": True},
    },
}


def setup_logging(level: str | None = None) -> None:
    """
    Apply the logging configuration.
    Optionally override the root level at runtime:

        setup_logging("DEBUG")   # verbose
        setup_logging("WARNING") # quiet
    """
    logging.config.dictConfig(LOGGING_CONFIG)

    if level:
        logging.getLogger().setLevel(level.upper())

    logging.getLogger(__name__).info(
        "Logging initialised — file: %s", LOG_FILE
    )


def get_logger(name: str) -> logging.Logger:
    """
    Convenience wrapper so modules can do:

        from engine.config.logging_config import get_logger
        log = get_logger(__name__)
    """
    return logging.getLogger(name)
