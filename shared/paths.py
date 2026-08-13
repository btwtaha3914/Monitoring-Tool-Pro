"""
shared/paths.py
===============
Single source of truth for every filesystem path in Monitor Suite.

WHY THIS FILE EXISTS
--------------------
In normal Python:

    Path(__file__).parent     # folder that contains this .py file

is reliable. After PyInstaller freezes the app into an .exe, it is NOT.

PyInstaller extracts bundled files into a temp folder like:

    C:\\Users\\<you>\\AppData\\Local\\Temp\\_MEI12345\\

and Windows DELETES that folder when the app exits.

If we write users.json / SQLite / logs next to __file__, they vanish
every time the user closes the .exe. That is bugs B1 and C2.

RULES
-----
1. Anything the user must KEEP  -> get_data_dir()
   (database, settings, logs, exports, offline sync queue)

2. Anything shipped INSIDE the app (read-only) -> get_resource_dir()
   (HTML templates, CSS, JS, icons)

3. Never compute a writable path from __file__ again.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path


APP_NAME = "MonitorSuite"


def is_frozen() -> bool:
    """True when running as a PyInstaller .exe, False in normal Python."""
    return bool(getattr(sys, "frozen", False))


def is_cloud() -> bool:
    """
    True when running on a cloud host.

    Render / Railway / Fly all set PORT. We also accept an explicit
    MONITOR_SUITE_MODE=cloud so we can force the mode in tests.
    """
    mode = os.environ.get("MONITOR_SUITE_MODE", "").strip().lower()
    if mode == "cloud":
        return True
    if mode == "desktop":
        return False
    return bool(os.environ.get("PORT")) and not is_frozen()


def project_root() -> Path:
    """
    The folder that contains app.py during development.

    Layout assumed:

        project_root/
            app.py
            shared/paths.py   <-- this file
    """
    return Path(__file__).resolve().parent.parent


def get_resource_dir() -> Path:
    """
    Read-only files bundled with the app (templates/, static/).

    Dev:    project root
    .exe:   the temp extract folder (sys._MEIPASS)
    Cloud:  project root (same as dev; the host checks out the repo)
    """
    if is_frozen():
        # PyInstaller sets this to the extract directory.
        return Path(sys._MEIPASS)
    return project_root()


def get_data_dir() -> Path:
    """
    Writable directory that SURVIVES app restarts.

    Priority:
      1. MONITOR_SUITE_DATA_DIR env var (explicit override)
      2. Frozen .exe  -> %APPDATA%\\MonitorSuite
      3. Cloud        -> /tmp/monitor-suite  (or the env override)
      4. Dev          -> <project>/data
    """
    override = os.environ.get("MONITOR_SUITE_DATA_DIR", "").strip()
    if override:
        path = Path(override)
    elif is_frozen():
        # Roaming AppData is the correct Windows location for user data.
        appdata = os.environ.get("APPDATA")
        if appdata:
            path = Path(appdata) / APP_NAME
        else:
            path = Path.home() / "AppData" / "Roaming" / APP_NAME
    elif is_cloud():
        path = Path("/tmp") / "monitor-suite"
    else:
        path = project_root() / "data"

    path.mkdir(parents=True, exist_ok=True)
    return path


def get_logs_dir() -> Path:
    path = get_data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_exports_dir() -> Path:
    path = get_data_dir() / "exports"
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    """The single SQLite file used by the desktop app."""
    return get_data_dir() / "monitor_suite.db"


def settings_path() -> Path:
    """Desktop settings (API key, scan interval, last window size, etc.)."""
    return get_data_dir() / "settings.json"


def templates_dir() -> Path:
    return get_resource_dir() / "templates"


def static_dir() -> Path:
    return get_resource_dir() / "static"


def describe() -> dict:
    """Debug helper — print this if a path looks wrong."""
    return {
        "frozen": is_frozen(),
        "cloud": is_cloud(),
        "project_root": str(project_root()),
        "resource_dir": str(get_resource_dir()),
        "data_dir": str(get_data_dir()),
        "logs_dir": str(get_logs_dir()),
        "exports_dir": str(get_exports_dir()),
        "db_path": str(db_path()),
        "templates_dir": str(templates_dir()),
        "static_dir": str(static_dir()),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(describe(), indent=2))