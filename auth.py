"""
Minimal local user store for the Monitor Suite sign-in page.

Not meant as an enterprise auth system -- just enough real, working
sign-up / sign-in so the app has a genuine login gate in front of the
three monitoring tools, plus a "Continue as guest" path. Passwords are
hashed (never stored in plain text) and kept in a small JSON file on
disk when the filesystem is writable.

On read-only-filesystem hosts (e.g. Vercel serverless, where only /tmp
is writable and nothing written there survives past the request), this
transparently falls back to an in-memory store for that invocation
instead of crashing sign-up with a 500. Accounts created that way won't
persist between requests on such hosts -- "Continue as guest" is the
reliable option there. On a normal always-on host (Render, your own
machine, etc.) this behaves exactly as a plain JSON file store.
"""

import json
import os
import re
import threading
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

_LOCK = threading.Lock()
if os.environ.get("VERCEL"):
    _DATA_DIR = "/tmp/monitor_suite_data"
else:
    _DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_USERS_FILE = os.path.join(_DATA_DIR, "users.json")

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Set once we detect the real data dir isn't writable (e.g. Vercel's
# read-only filesystem). When True, we keep users in this process-local
# dict instead of touching disk at all.
_FILESYSTEM_WRITABLE = True
_MEMORY_USERS: dict = {}


def _ensure_data_dir():
    global _FILESYSTEM_WRITABLE
    try:
        os.makedirs(_DATA_DIR, exist_ok=True)
        probe = os.path.join(_DATA_DIR, ".write_probe")
        with open(probe, "w") as f:
            f.write("ok")
        os.remove(probe)
    except OSError:
        _FILESYSTEM_WRITABLE = False


_ensure_data_dir()


def _load():
    if not _FILESYSTEM_WRITABLE:
        return dict(_MEMORY_USERS)
    if not os.path.exists(_USERS_FILE):
        return {}
    try:
        with open(_USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(users):
    global _FILESYSTEM_WRITABLE
    if not _FILESYSTEM_WRITABLE:
        _MEMORY_USERS.clear()
        _MEMORY_USERS.update(users)
        return
    try:
        tmp_path = _USERS_FILE + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(users, f, indent=2)
        os.replace(tmp_path, _USERS_FILE)
    except OSError:
        # Disk turned out not to be writable after all (e.g. detected
        # mid-request on a host with unusual permissions) -- fall back
        # to memory for the rest of this process rather than 500ing.
        _FILESYSTEM_WRITABLE = False
        _MEMORY_USERS.clear()
        _MEMORY_USERS.update(users)


def create_user(username, email, password):
    username = (username or "").strip()
    email = (email or "").strip().lower()
    password = password or ""

    if len(username) < 2:
        return None, "Username must be at least 2 characters."
    if not _EMAIL_RE.match(email):
        return None, "Please enter a valid email address."
    if len(password) < 6:
        return None, "Password must be at least 6 characters."

    with _LOCK:
        users = _load()
        if email in users:
            return None, "An account with that email already exists."

        users[email] = {
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        _save(users)

    return users[email], None


def verify_user(email, password):
    email = (email or "").strip().lower()
    with _LOCK:
        users = _load()

    user = users.get(email)
    if not user or not check_password_hash(user["password_hash"], password or ""):
        return None, "Incorrect email or password."

    return user, None
