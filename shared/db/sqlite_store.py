"""
shared/db/sqlite_store.py
=========================
Thin, safe wrapper around SQLite for the desktop app.

Why a wrapper (and not raw sqlite3 calls everywhere):
  1. ONE place to configure connection settings (WAL mode, foreign
     keys ON, row factory) so all callers behave identically.
  2. ONE place to run schema.sql at first launch — no "database
     already exists" edge cases scattered across modules.
  3. Every function takes a connection and returns plain Python
     dicts/lists — modules never see sqlite3 objects. That means
     Phase 3 can swap SQLite for Postgres and the module code
     doesn't change.
  4. Foreign keys ON — SQLite has them OFF by default (weird
     historical choice). Without this, ON DELETE CASCADE silently
     doesn't work.

USAGE PATTERN:

    from shared.db.sqlite_store import get_conn, init_db

    init_db()                          # once, at app startup
    with get_conn() as conn:           # in a request handler
        row = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        # row is a dict-like Row object

Always use `?` placeholders — NEVER f-string SQL. This prevents
SQL injection and is a hill I will die on.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from shared.paths import db_path, get_resource_dir

logger = logging.getLogger(__name__)

# A single lock for schema initialization. SQLite handles concurrent
# reads/writes fine on its own once WAL is on — we only need the lock
# to ensure init_db() runs exactly once across threads.
_init_lock = threading.Lock()
_initialized = False


def _schema_sql_path() -> Path:
    """Location of schema.sql — inside shared/db/ next to this file."""
    return Path(__file__).resolve().parent / "schema.sql"


def _apply_connection_pragmas(conn: sqlite3.Connection) -> None:
    """
    Settings applied to EVERY new connection.

    - foreign_keys=ON: enforce ON DELETE CASCADE etc.
    - journal_mode=WAL: much better concurrency; readers don't block
      writers. Persistent across restarts (only need to set once
      per database file, but setting on every connection is safe).
    - synchronous=NORMAL: safe with WAL, ~10x faster than FULL.
    """
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")


def _connect() -> sqlite3.Connection:
    """
    Open a new SQLite connection with our standard settings.

    row_factory = sqlite3.Row means you can access columns by name:
        row["email"]   instead of   row[1]
    """
    path = db_path()
    logger.debug("Opening SQLite connection to %s", path)
    conn = sqlite3.connect(
        str(path),
        # Connections opened in one thread can be used in another —
        # required because Flask handles requests on multiple threads.
        check_same_thread=False,
        # Return timestamps as strings; we control our own timezone
        # handling and don't want Python's naive datetime auto-parsing.
        detect_types=0,
    )
    conn.row_factory = sqlite3.Row
    _apply_connection_pragmas(conn)
    return conn


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """
    Context manager for a database connection.

    Commits on clean exit. Rolls back on exception. Always closes.

        with get_conn() as conn:
            conn.execute("INSERT INTO ...", (...))
            # auto-commits if no exception raised
    """
    conn = _connect()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """
    Create tables from schema.sql if they don't exist.

    Idempotent — safe to call every startup. Uses CREATE TABLE IF
    NOT EXISTS, so re-runs are no-ops.

    Call this ONCE at app startup, before any other db calls.
    """
    global _initialized
    with _init_lock:
        if _initialized:
            return

        schema_file = _schema_sql_path()
        if not schema_file.exists():
            raise FileNotFoundError(
                f"Database schema file not found: {schema_file}. "
                "Did you forget to create shared/db/schema.sql?"
            )

        sql = schema_file.read_text(encoding="utf-8")

        logger.info("Initializing database at %s", db_path())
        with get_conn() as conn:
            conn.executescript(sql)

        _initialized = True
        logger.info("Database initialized successfully")


def describe() -> dict:
    """
    Diagnostic helper — reports on the database's current state.
    Call this from a debug endpoint or a verification script.
    """
    info = {
        "db_path": str(db_path()),
        "db_exists": db_path().exists(),
        "db_size_bytes": db_path().stat().st_size if db_path().exists() else 0,
        "tables": [],
        "row_counts": {},
    }

    if not info["db_exists"]:
        return info

    with get_conn() as conn:
        # List all tables
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            " ORDER BY name"
        ).fetchall()
        info["tables"] = [r["name"] for r in rows]

        # Row count per table
        for table in info["tables"]:
            count = conn.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()["c"]
            info["row_counts"][table] = count

    return info


# ------------------------------------------------------------------
# Convenience helpers for the auth migration in Phase 1.3.
# Kept minimal here — richer per-module helpers land in later phases.
# ------------------------------------------------------------------

def fetch_one(sql: str, params: tuple = ()) -> Optional[dict]:
    """Run a SELECT that returns 0 or 1 row. Returns dict or None."""
    with get_conn() as conn:
        row = conn.execute(sql, params).fetchone()
        return dict(row) if row else None


def fetch_all(sql: str, params: tuple = ()) -> list[dict]:
    """Run a SELECT that returns any number of rows. Returns list of dicts."""
    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def execute(sql: str, params: tuple = ()) -> int:
    """
    Run an INSERT/UPDATE/DELETE.

    Returns lastrowid for INSERTs, or number of rows affected otherwise.
    """
    with get_conn() as conn:
        cur = conn.execute(sql, params)
        return cur.lastrowid or cur.rowcount