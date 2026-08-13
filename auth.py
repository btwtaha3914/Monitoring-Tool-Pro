"""
auth.py — Monitor Suite authentication
========================================
Local user store for the sign-in gate. Storage is SQLite
(see shared/db/sqlite_store.py), not users.json.

Public API:
  - ensure_ready()
  - create_user(username, email, password)
  - verify_user(email, password)
  - get_user_by_email(email)
  - get_or_create_guest_user()
  - count_users()
"""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from datetime import datetime, timezone
from typing import Optional

from werkzeug.security import check_password_hash, generate_password_hash

from shared.db.sqlite_store import execute, fetch_one, init_db
from shared.paths import get_data_dir

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

_migration_lock = threading.Lock()
_migration_done = False

GUEST_EMAIL = "guest@monitorsuite.local"


# ----------------------------------------------------------------------
# One-time migration from users.json
# ----------------------------------------------------------------------

def _legacy_users_json_path() -> str:
    return os.path.join(str(get_data_dir()), "users.json")


def _migrate_json_users_if_needed() -> None:
    global _migration_done
    with _migration_lock:
        if _migration_done:
            return

        json_path = _legacy_users_json_path()
        migrated_marker = json_path + ".migrated"

        if os.path.exists(migrated_marker) and not os.path.exists(json_path):
            _migration_done = True
            return

        if not os.path.exists(json_path):
            _migration_done = True
            return

        logger.info("Legacy users.json found at %s — migrating to database", json_path)

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                legacy = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.error("Could not read %s (%s) — skipping migration", json_path, e)
            _migration_done = True
            return

        migrated_count = 0
        skipped_count = 0

        for email, user in (legacy or {}).items():
            existing = fetch_one("SELECT id FROM users WHERE email = ?", (email,))
            if existing:
                skipped_count += 1
                continue

            try:
                execute(
                    """
                    INSERT INTO users
                        (email, username, password_hash, is_guest, created_at)
                    VALUES (?, ?, ?, 0, ?)
                    """,
                    (
                        email,
                        user.get("username", str(email).split("@")[0]),
                        user.get("password_hash", ""),
                        user.get("created_at", datetime.now(timezone.utc).isoformat()),
                    ),
                )
                migrated_count += 1
            except Exception as e:
                logger.error("Failed to migrate user %s: %s", email, e)

        logger.info(
            "Migration complete: %d users migrated, %d already existed",
            migrated_count,
            skipped_count,
        )

        try:
            os.replace(json_path, migrated_marker)
            logger.info("Renamed %s -> %s", json_path, migrated_marker)
        except OSError as e:
            logger.warning("Could not rename %s to %s (%s)", json_path, migrated_marker, e)

        _migration_done = True


def ensure_ready() -> None:
    """Create tables if needed, then migrate users.json if present."""
    init_db()
    _migrate_json_users_if_needed()


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------

def create_user(username: str, email: str, password: str):
    username = (username or "").strip()
    email = (email or "").strip().lower()
    password = password or ""

    if len(username) < 2:
        return None, "Username must be at least 2 characters."
    if not _EMAIL_RE.match(email):
        return None, "Please enter a valid email address."
    if len(password) < 6:
        return None, "Password must be at least 6 characters."

    now = datetime.now(timezone.utc).isoformat()

    existing = fetch_one("SELECT id FROM users WHERE email = ?", (email,))
    if existing:
        return None, "An account with that email already exists."

    try:
        new_id = execute(
            """
            INSERT INTO users
                (email, username, password_hash, is_guest, created_at)
            VALUES (?, ?, ?, 0, ?)
            """,
            (email, username, generate_password_hash(password), now),
        )
    except Exception:
        logger.exception("Failed to create user %s", email)
        return None, "Could not create account. Please try again."

    logger.info("Created user id=%s email=%s", new_id, email)
    return {
        "id": new_id,
        "username": username,
        "email": email,
        "created_at": now,
    }, None


def verify_user(email: str, password: str):
    email = (email or "").strip().lower()

    user = fetch_one(
        "SELECT id, email, username, password_hash, created_at FROM users WHERE email = ?",
        (email,),
    )

    if not user or not check_password_hash(user["password_hash"], password or ""):
        return None, "Incorrect email or password."

    try:
        execute(
            "UPDATE users SET last_login_at = ? WHERE id = ?",
            (datetime.now(timezone.utc).isoformat(), user["id"]),
        )
    except Exception:
        logger.warning("Could not update last_login_at for user %s", email, exc_info=True)

    logger.info("User logged in: id=%s email=%s", user["id"], email)
    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"],
        "created_at": user["created_at"],
    }, None


def get_user_by_email(email: str) -> Optional[dict]:
    email = (email or "").strip().lower()
    return fetch_one(
        "SELECT id, email, username, is_guest, created_at, last_login_at "
        "FROM users WHERE email = ?",
        (email,),
    )


def count_users() -> int:
    row = fetch_one("SELECT COUNT(*) AS c FROM users")
    return int(row["c"]) if row else 0


def get_or_create_guest_user() -> dict:
    """
    All guests share ONE database row (is_guest=1).
    Creates it on first use, then always returns the same row.
    """
    ensure_ready()

    existing = fetch_one(
        "SELECT id, email, username, is_guest, created_at FROM users WHERE email = ?",
        (GUEST_EMAIL,),
    )
    if existing:
        return existing

    now = datetime.now(timezone.utc).isoformat()
    new_id = execute(
        """
        INSERT INTO users
            (email, username, password_hash, is_guest, created_at)
        VALUES (?, ?, ?, 1, ?)
        """,
        (GUEST_EMAIL, "Guest", "!disabled!", now),
    )
    logger.info("Created shared guest user row id=%s", new_id)

    created = fetch_one(
        "SELECT id, email, username, is_guest, created_at FROM users WHERE email = ?",
        (GUEST_EMAIL,),
    )
    if not created:
        raise RuntimeError("Guest user insert succeeded but row could not be read back.")
    return created