"""
VPN Monitor
-----------
Orchestrates a real OpenVPN connection so the platform can reach a
private IP range for "Private Server Monitoring", the same way an
engineer would: upload the .ovpn profile, supply the VPN username/
password if the profile needs them, connect, then run the normal
probes (ping, port scan, SNMP) against the now-reachable private IP.

WHAT THIS DOES NOT DO: it does not implement a VPN client itself.
Standing up an encrypted tunnel (key exchange, routing, a tun/tap
device) is exactly what OpenVPN already does correctly -- reimplementing
that would be a security liability, not an improvement. This module is
an orchestration layer around the real `openvpn` binary.

OPERATIONAL REQUIREMENTS (this will not work in every environment):
  - the `openvpn` binary must be installed on the host running Flask
  - creating a tun/tap network device normally requires root/admin
    privileges (or, on Linux, the CAP_NET_ADMIN capability) -- running
    this inside an unprivileged container will fail cleanly with a
    clear error rather than a silent hang
  - only one VPN connection is tracked per session in this in-memory
    implementation; a production deployment should isolate tunnels
    per user/namespace

SECURITY NOTES:
  - the uploaded .ovpn profile and any username/password are written
    to a private temp directory (mode 0700) only for the lifetime of
    the connection attempt
  - the auth file (username+password) is deleted immediately after
    OpenVPN reads it, whether or not the connection succeeded
  - nothing here logs the password; only the username and profile
    filename are logged
"""

import logging
import os
import re
import shutil
import signal
import stat
import subprocess
import tempfile
import time
import uuid

logger = logging.getLogger("monitor.vpn_monitor")

VPN_RUN_DIR = os.path.join(tempfile.gettempdir(), "sentinelops_vpn")
CONNECT_TIMEOUT_SEC = 25
SUCCESS_MARKER = "Initialization Sequence Completed"
FAILURE_MARKERS = (
    "AUTH_FAILED",
    "TLS Error",
    "connection refused",
    "Cannot resolve host address",
    "process restarting",
)

# server_id -> {"pid": int, "log_path": str, "run_dir": str, "started_at": float}
_ACTIVE_CONNECTIONS: dict[str, dict] = {}


def openvpn_available() -> bool:
    return shutil.which("openvpn") is not None


def _make_run_dir(connection_id: str) -> str:
    run_dir = os.path.join(VPN_RUN_DIR, connection_id)
    os.makedirs(run_dir, mode=0o700, exist_ok=True)
    return run_dir


def _write_private_file(path: str, content: bytes) -> None:
    with open(path, "wb") as fh:
        fh.write(content)
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600, owner only


# =====================================================================
# Profile upload handling -- plain .ovpn, or a .zip/.rar bundle
# =====================================================================
# A VPN profile often isn't a single file: the .ovpn config references
# separate certificate/key files (ca.crt, client.crt, client.key,
# ta.key) via relative `ca`/`cert`/`key`/`tls-auth` directives. When
# that's the case, people naturally zip or rar the whole folder before
# uploading it. This layer detects that, extracts every file from the
# archive into the same run directory as the profile (so those relative
# references resolve), and points OpenVPN at whichever extracted file
# is the actual .ovpn/.conf profile.
def _looks_like_zip(data: bytes) -> bool:
    return data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")


def _looks_like_rar(data: bytes) -> bool:
    return data[:7] == b"Rar!\x1a\x07\x00" or data[:8] == b"Rar!\x1a\x07\x01\x00"


def _find_profile_file(run_dir: str):
    candidates = [f for f in os.listdir(run_dir) if f.lower().endswith((".ovpn", ".conf"))]
    if not candidates:
        return None, (
            "No .ovpn or .conf file was found inside the uploaded archive. "
            "Make sure the archive contains your OpenVPN profile file "
            "alongside any certificate/key files it references (ca.crt, "
            "client.crt, client.key, ta.key, etc.)."
        )
    # Prefer a real .ovpn extension over a bare .conf if both are present.
    candidates.sort(key=lambda f: (0 if f.lower().endswith(".ovpn") else 1, f))
    return os.path.join(run_dir, candidates[0]), None


def _extract_zip(run_dir: str, data: bytes):
    import io
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = [n for n in zf.namelist() if not n.endswith("/")]
            if not names:
                return None, "The uploaded .zip file is empty."
            for name in names:
                target = os.path.join(run_dir, os.path.basename(name))
                if not target:
                    continue
                with zf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    except zipfile.BadZipFile:
        return None, "The uploaded .zip file is corrupt or not a valid zip archive."
    return _find_profile_file(run_dir)


def _extract_rar(run_dir: str, data: bytes):
    try:
        import rarfile
    except ImportError:
        return None, (
            "Reading .rar archives needs the `rarfile` Python package "
            "(pip install rarfile) plus a system `unrar`, `unar`, or `bsdtar` "
            "binary on PATH. Install one of those, or re-zip your VPN profile "
            "as a .zip and upload that instead."
        )

    archive_path = os.path.join(run_dir, "_upload.rar")
    _write_private_file(archive_path, data)
    try:
        with rarfile.RarFile(archive_path) as rf:
            names = [n for n in rf.namelist() if not n.endswith("/")]
            if not names:
                return None, "The uploaded .rar file is empty."
            for name in names:
                target = os.path.join(run_dir, os.path.basename(name))
                with rf.open(name) as src, open(target, "wb") as dst:
                    dst.write(src.read())
                os.chmod(target, stat.S_IRUSR | stat.S_IWUSR)
    except rarfile.RarCannotExec:
        return None, (
            "The `unrar` (or `unar`/`bsdtar`) command-line tool isn't installed, "
            "so the .rar archive can't be extracted. Install it "
            "(e.g. `apt install unrar` / `brew install unar`), or re-zip your "
            "VPN profile as a .zip and upload that instead."
        )
    except rarfile.Error as e:
        return None, f"Could not read the .rar archive: {e}"
    finally:
        try:
            os.remove(archive_path)
        except OSError:
            pass
    return _find_profile_file(run_dir)


def _prepare_profile(run_dir: str, filename: str, data: bytes):
    """Writes the uploaded VPN profile (plain .ovpn, .zip, or .rar) into
    run_dir and returns (profile_path, error)."""
    lower_name = (filename or "").lower()

    if _looks_like_zip(data) or lower_name.endswith(".zip"):
        return _extract_zip(run_dir, data)

    if _looks_like_rar(data) or lower_name.endswith(".rar"):
        return _extract_rar(run_dir, data)

    # Not a recognized archive -- treat as a raw .ovpn/.conf profile.
    config_path = os.path.join(run_dir, "profile.ovpn")
    _write_private_file(config_path, data)
    return config_path, None


def connect(config_bytes: bytes, filename: str = None, username: str = None, password: str = None,
            timeout: float = CONNECT_TIMEOUT_SEC) -> dict:
    """
    Starts `openvpn` with the given profile and (optional) credentials,
    waits up to `timeout` seconds for it to report a completed tunnel,
    then returns a status dict. On any failure, cleans up after itself
    (kills the process, deletes temp files) rather than leaving a
    half-connected tunnel or an orphaned process behind.

    `config_bytes` may be a plain .ovpn/.conf file, or a .zip/.rar
    archive containing the profile plus any certificate/key files it
    references -- see `_prepare_profile` above.
    """
    if not openvpn_available():
        return {
            "connected": False,
            "error": (
                "The `openvpn` binary is not installed on this host. Install it "
                "(e.g. `apt install openvpn` / `brew install openvpn`) and ensure "
                "this app runs with permission to create a tun/tap device."
            ),
        }

    connection_id = uuid.uuid4().hex[:12]
    run_dir = _make_run_dir(connection_id)
    log_path = os.path.join(run_dir, "openvpn.log")
    auth_path = os.path.join(run_dir, "auth.txt")

    config_path, err = _prepare_profile(run_dir, filename, config_bytes)
    if err:
        _cleanup_run_dir(run_dir)
        return {"connected": False, "error": err}

    cmd = ["openvpn", "--config", config_path, "--log", log_path]
    if username is not None and password is not None:
        _write_private_file(auth_path, f"{username}\n{password}\n".encode())
        cmd += ["--auth-user-pass", auth_path]

    logger.info("Starting OpenVPN (connection_id=%s, user=%s)", connection_id, username or "n/a")

    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except PermissionError:
        _cleanup_run_dir(run_dir)
        return {"connected": False, "error": "Permission denied launching openvpn — this process needs root/CAP_NET_ADMIN to create a VPN tunnel."}
    except Exception as e:
        _cleanup_run_dir(run_dir)
        return {"connected": False, "error": f"Could not start openvpn: {e}"}

    result = _wait_for_connection(proc, log_path, timeout)

    # The auth file only needs to exist long enough for OpenVPN to read
    # it at startup — remove the plaintext credentials immediately.
    if os.path.exists(auth_path):
        os.remove(auth_path)

    if not result["connected"]:
        _terminate(proc)
        _cleanup_run_dir(run_dir)
        return result

    _ACTIVE_CONNECTIONS[connection_id] = {
        "pid": proc.pid,
        "log_path": log_path,
        "run_dir": run_dir,
        "started_at": time.time(),
    }
    result["connection_id"] = connection_id
    return result


def _wait_for_connection(proc: subprocess.Popen, log_path: str, timeout: float) -> dict:
    deadline = time.time() + timeout
    tun_ip = None

    while time.time() < deadline:
        if proc.poll() is not None:
            return {
                "connected": False,
                "error": f"openvpn exited early (code {proc.returncode}) — check the profile/credentials.",
                "log_tail": _tail_log(log_path),
            }

        text = _read_log(log_path)
        if any(marker in text for marker in FAILURE_MARKERS):
            return {"connected": False, "error": "OpenVPN reported an authentication/connection failure.", "log_tail": _tail_log(log_path)}

        if SUCCESS_MARKER in text:
            match = re.search(r"ifconfig\s+(\d+\.\d+\.\d+\.\d+)", text) or re.search(r"TUN/TAP.*?(\d+\.\d+\.\d+\.\d+)", text)
            tun_ip = match.group(1) if match else None
            return {"connected": True, "tunnel_ip": tun_ip, "log_tail": _tail_log(log_path)}

        time.sleep(0.5)

    return {"connected": False, "error": f"Timed out after {timeout}s waiting for the tunnel to establish.", "log_tail": _tail_log(log_path)}


def _read_log(log_path: str) -> str:
    try:
        with open(log_path, "r", errors="ignore") as fh:
            return fh.read()
    except FileNotFoundError:
        return ""


def _tail_log(log_path: str, lines: int = 15) -> list:
    text = _read_log(log_path)
    return text.strip().splitlines()[-lines:]


def disconnect(connection_id: str) -> dict:
    conn = _ACTIVE_CONNECTIONS.pop(connection_id, None)
    if not conn:
        return {"disconnected": False, "error": "No active VPN connection with that ID."}

    try:
        os.kill(conn["pid"], signal.SIGTERM)
    except ProcessLookupError:
        pass
    except Exception as e:
        logger.warning("Error terminating openvpn pid %s: %s", conn["pid"], e)

    _cleanup_run_dir(conn["run_dir"])
    logger.info("VPN connection %s torn down", connection_id)
    return {"disconnected": True}


def status(connection_id: str) -> dict:
    conn = _ACTIVE_CONNECTIONS.get(connection_id)
    if not conn:
        return {"connected": False, "error": "No active VPN connection with that ID."}
    alive = _process_alive(conn["pid"])
    return {
        "connected": alive,
        "uptime_seconds": round(time.time() - conn["started_at"]) if alive else None,
    }


def _process_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _terminate(proc: subprocess.Popen) -> None:
    try:
        proc.terminate()
        proc.wait(timeout=3)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _cleanup_run_dir(run_dir: str) -> None:
    shutil.rmtree(run_dir, ignore_errors=True)