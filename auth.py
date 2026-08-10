"""
Minimal local user store for the Monitor Suite sign-in page.

Not meant as an enterprise auth system -- just enough real, working
sign-up / sign-in so the app has a genuine login gate in front of the
three monitoring tools, plus a "Continue as guest" path. Passwords are
hashed (never stored in plain text) and kept in a small JSON file on
disk.
"""

import json
import os
import re
import threading
from datetime import datetime, timezone

from werkzeug.security import generate_password_hash, check_password_hash

_LOCK = threading.Lock()
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
_USERS_FILE = os.path.join(_DATA_DIR, "users.json")

os.makedirs(_DATA_DIR, exist_ok=True)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _load():
    if not os.path.exists(_USERS_FILE):
        return {}
    try:
        with open(_USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def _save(users):
    tmp_path = _USERS_FILE + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)
    os.replace(tmp_path, _USERS_FILE)


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
