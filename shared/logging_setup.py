"""
shared/logging_setup.py
=======================
Central logging setup for Monitor Suite.

WHAT THIS SOLVES
----------------
Before Phase 1.6, each module configured its own logger — sometimes
with `logging.basicConfig` (which silently fails if another module
already called it), sometimes with custom handlers pointing at paths
that break under PyInstaller. Result: some logs went to the wrong
file in the .exe, some duplicated, some vanished entirely.

This module is the ONE place logging is configured. Every module just
does `logger = logging.getLogger(__name__)` and lets this file decide
where the output goes.

WHERE LOGS GO
-------------
    Dev:    <project>/data/logs/monitor_suite.log
    .exe:   %APPDATA%\\MonitorSuite\\logs\\monitor_suite.log
    Cloud:  /tmp/monitor-suite/logs/monitor_suite.log (or env override)

Rotation: log file rotates at 5 MB, keeps 3 backups (15 MB max total).

USAGE
-----
Called ONCE at app startup, before any other imports do logging:

    from shared.logging_setup import setup_logging
    setup_logging()

After that, anywhere in the codebase:

    import logging
    logger = logging.getLogger(__name__)
    logger.info("something happened")
"""

from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path

from shared.paths import get_logs_dir


LOG_FILENAME = "monitor_suite.log"
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Rotation settings — 5MB per file, keep 3 old ones. Total disk usage
# capped at ~20MB, which is generous for a monitoring tool's own logs
# but bounded so we never fill up a user's disk.
MAX_BYTES_PER_LOG = 5 * 1024 * 1024   # 5 MB
BACKUP_COUNT = 3

_configured = False


def get_log_file_path() -> Path:
    """Where the log file actually lives on disk right now."""
    return get_logs_dir() / LOG_FILENAME


def setup_logging(level: int = logging.INFO,
                  console: bool = True,
                  quiet_libraries: bool = True) -> None:
    """
    Configure the root logger. Idempotent — safe to call multiple
    times, only the first call takes effect.

    Args:
        level: minimum level captured (DEBUG, INFO, WARNING, ERROR).
        console: also print to stderr (True in dev; keep True in
            .exe too so users can see errors if they launch from
            terminal for troubleshooting).
        quiet_libraries: turn down noisy third-party loggers
            (werkzeug, urllib3) to WARNING, so INFO from your own
            code isn't buried in HTTP access logs.
    """
    global _configured
    if _configured:
        return

    root_logger = logging.getLogger()
    root_logger.setLevel(level)

    # Remove any pre-existing handlers (e.g. from a stray
    # basicConfig() elsewhere) so we get a clean single setup.
    for existing in list(root_logger.handlers):
        root_logger.removeHandler(existing)

    formatter = logging.Formatter(LOG_FORMAT, datefmt=LOG_DATE_FORMAT)

    # --- File handler (rotating) ---
    log_path = get_log_file_path()
    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=MAX_BYTES_PER_LOG,
            backupCount=BACKUP_COUNT,
            encoding="utf-8",
            delay=True,  # don't open file until first write
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        root_logger.addHandler(file_handler)
    except OSError as e:
        # If we can't write the log file (disk full, permission,
        # AppData not writable), print to stderr and continue with
        # console-only logging. Never crash the app because of logs.
        print(f"[logging] WARNING: could not open log file {log_path}: {e}",
              file=sys.stderr)

    # --- Console handler ---
    if console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        root_logger.addHandler(console_handler)

    # --- Quiet the noisy libraries ---
    if quiet_libraries:
        for noisy in ("werkzeug", "urllib3", "httpx", "httpcore", "asyncio"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    _configured = True

    # First log line confirms setup worked and shows the location.
    logging.getLogger(__name__).info(
        "Logging configured — file=%s level=%s console=%s",
        log_path, logging.getLevelName(level), console,
    )


def describe() -> dict:
    """Debug helper — call this from a diagnostic script."""
    root = logging.getLogger()
    return {
        "configured": _configured,
        "log_file": str(get_log_file_path()),
        "log_file_exists": get_log_file_path().exists(),
        "log_file_size_bytes": (
            get_log_file_path().stat().st_size
            if get_log_file_path().exists() else 0
        ),
        "root_level": logging.getLevelName(root.level),
        "handlers": [
            {
                "type": type(h).__name__,
                "level": logging.getLevelName(h.level),
            }
            for h in root.handlers
        ],
    }


if __name__ == "__main__":
    # Standalone diagnostic:  python -m shared.logging_setup
    import json
    setup_logging()
    logging.getLogger(__name__).info("Test log line from logging_setup")
    print(json.dumps(describe(), indent=2))