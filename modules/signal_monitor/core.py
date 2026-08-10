#!/usr/bin/env python3
"""
app.py — SignalWatch Pro v2
------------------------------------------------------------------
Wi-Fi & Local Network Device/Server Monitor

Scope note (unchanged from v1, worth repeating): this tool monitors
Wi-Fi conditions around you and the devices/servers on YOUR OWN
active local network — the one this machine is currently connected
to. It discovers devices, identifies likely servers by open ports,
and tracks who's on the network over time.

------------------------------------------------------------------
WHAT THIS v2 FIXES (the "sometimes it works, sometimes it doesn't"
reliability bug you ran into)
------------------------------------------------------------------
The old `get_all_connected_devices()` scanned every device on the
subnet **sequentially**: for each of up to ~254 possible hosts, it
ran a latency check (up to 5 ports x 0.3s) and then a full port scan
(11 ports x 0.15s) one device at a time, entirely synchronously. On
a busy /24 network that's a worst case of minutes of blocking work
per scan — which is exactly the kind of thing that makes a request
"lag" or get cut off partway through, so the device/server list
looks incomplete or inconsistent between runs. On top of that:

  - `arp -n` (used to read the ARP table on Linux/macOS) doesn't
    exist on every distro by default (net-tools is often missing on
    modern Ubuntu/Debian) — when the command isn't found, the old
    code silently caught the exception and returned an *empty*
    device map, so some runs would show every device correctly and
    others would show almost nothing, with no error message telling
    you why.
  - There was no macOS branch for Wi-Fi scanning or ARP parsing at
    all, so on a Mac the tool degraded silently.
  - Devices that block ICMP ping (default on Windows Firewall, and
    common on phones) could be missed entirely if they also didn't
    happen to respond on one of the 5 latency-check ports.

Fixes applied below:
  1. Per-device enrichment (latency + port scan) now runs in a
     thread pool, in parallel, the same fix used for the domain
     monitor's async rewrite — this is the single biggest reliability
     and speed improvement.
  2. ARP table reading now tries multiple tools in order (`arp`,
     then `ip neighbor` on Linux, with real error visibility) instead
     of silently returning nothing when one tool is missing.
  3. macOS support added for both Wi-Fi scanning and ARP parsing.
  4. Reachability now tries ICMP ping *and* TCP connect, so a device
     that blocks one but not the other is still found.
  5. Hostname resolution now tries reverse DNS, then NetBIOS
     (Windows), then mDNS/Avahi (Linux), before falling back to
     "Unknown Device" — so real device names show up far more often.
  6. A background scan loop (used in --web mode) keeps a fresh cached
     snapshot so the dashboard responds instantly instead of forcing
     a full blocking rescan on every page load.

------------------------------------------------------------------
WHAT THIS TOOL DELIBERATELY DOES NOT DO
------------------------------------------------------------------
Two things were requested that this tool does not implement, and
it's worth being upfront about why rather than silently skipping
them:

  - "What things a device is browsing" — surfacing another device's
    browsing activity requires intercepting its traffic content
    (packet capture, DNS logging of its queries, or ARP-spoofing a
    man-in-the-middle position). That's surveillance of other
    people's activity, not monitoring of your own infrastructure —
    it stays invasive and often illegal even on a network you
    personally administer, if the people using those devices haven't
    consented to being watched. This tool sticks to what a device
    IS (open ports / likely service type), never what it's doing.
  - "How much internet each *other* device used in the last 24h" —
    accurate per-device bandwidth requires either traffic
    interception (same problem as above) or reading it from the
    router/gateway, which already aggregates this legitimately for
    its own routing job. See `RouterBandwidthIntegration` near the
    bottom for a stub you can wire up to your own router's API/SNMP
    if it exposes one — that's the legitimate path. What this tool
    *does* provide is 24h bandwidth for the machine it's running on
    (via `get_self_bandwidth_last_24h`), since that's your own traffic.
------------------------------------------------------------------

Usage:
  python app.py                 # CLI
  python app.py --web            # Web dashboard on :8000
  python app.py --web --port 9000 --interval 5
"""

import os
import re
import sys
import csv
import json
import time
import shutil
import socket
import logging
import sqlite3
import platform
import argparse
import threading
import subprocess
from datetime import datetime, date
from concurrent.futures import ThreadPoolExecutor, as_completed
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import unquote as _url_unquote

try:
    import ctypes
    from ctypes import wintypes
    _CTYPES_AVAILABLE = True
except Exception:                                   # pragma: no cover
    _CTYPES_AVAILABLE = False

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:                                  # pragma: no cover
    _PSUTIL_AVAILABLE = False


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("signalwatch")


# ============================================================
# CONFIG
# ============================================================

APP_DIR = os.path.dirname(os.path.abspath(__file__))
if os.environ.get("VERCEL"):
    DATA_DIR = "/tmp/monitor_suite_data"
else:
    DATA_DIR = os.path.abspath(os.path.join(APP_DIR, "..", "..", "data"))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "signalwatch_history.db")
EXPORT_PATH = os.path.join(DATA_DIR, "latest_devices_export.csv")

OS_TYPE = platform.system()               # "Windows" | "Linux" | "Darwin"

# Per-device probing (the part that used to be sequential).
DEVICE_SCAN_WORKERS = 40                  # devices enriched concurrently
PORT_SCAN_TIMEOUT = 0.35                  # seconds per port attempt
PORT_SCAN_WORKERS = 11                    # one thread per port, per device
PING_SWEEP_WORKERS = 100                  # concurrent ping subprocesses
PING_TIMEOUT_SECONDS = 1.2
TCP_LATENCY_TIMEOUT = 0.6

SUBNET_HOST_RANGE = range(1, 255)         # assumes a /24 — see note in sweep_subnet()

# Devices are considered "gone" (offline) once a scan completes and
# they weren't seen — this drives the active-time/session tracking.
ACTIVE_TIME_MAX_GAP_SECONDS = 900         # don't credit >15 min of "active" time
                                           # between two consecutive sightings

MAC_VENDORS = {
    "3C:78:95": "TP-Link / Router",
    "00:15:5D": "Microsoft Hyper-V / Virtual Server",
    "7C:2A:31": "Intel Corporate",
    "DC:21:5C": "Intel Mobile / PC",
    "D2:01:9C": "Randomized / Android Mobile",
    "40:A3:CC": "Apple Inc.",
    "AA:77:4E": "Private / Virtual MAC",
    "F4:D4:88": "Samsung Electronics",
    "00:50:56": "VMware Virtual Server",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Trading",
    "00:1A:11": "Google LLC",
    "00:04:20": "Cisco Systems",
    "00:1B:63": "Apple Inc.",
    "3C:5A:B4": "Google LLC",
    "F0:27:2D": "Amazon Technologies",
    "68:37:E9": "Amazon Technologies",
    "00:1D:D8": "Microsoft Corporation",
    "00:0C:29": "VMware Virtual Server",
    "08:00:27": "VirtualBox Virtual NIC",
    "FC:FC:48": "Espressif (IoT / Smart Home)",
    "B4:E6:2D": "Espressif (IoT / Smart Home)",
    "A4:CF:12": "Espressif (IoT / Smart Home)",
    "00:17:88": "Philips Hue / Signify",
    "18:B4:30": "Nest / Google Home",
}
# This is a small curated set for readability. For production use,
# swap it for the full IEEE OUI database (a prefix -> vendor CSV
# loaded at startup) — see `load_full_oui_database()` below.

COMMON_SERVER_PORTS = {
    80: "HTTP Web Server",
    443: "HTTPS Web Server",
    22: "SSH Remote Shell",
    445: "SMB File Share",
    3389: "RDP Remote Desktop",
    8080: "Alt Web App Server",
    3000: "Node / React App",
    5432: "PostgreSQL Database",
    3306: "MySQL Database",
    21: "FTP Server",
    53: "DNS Server",
    32400: "Plex Media Server",
    8096: "Jellyfin Media Server",
    9100: "Network Printer",
    631: "IPP Printer / CUPS",
    554: "RTSP / IP Camera",
}


def load_full_oui_database(csv_path=None):
    """
    Optional: point this at a full IEEE OUI CSV (prefix,vendor) to
    replace the small built-in MAC_VENDORS table with comprehensive
    coverage. No-op if the file isn't provided/found.
    """
    if not csv_path or not os.path.exists(csv_path):
        return
    try:
        with open(csv_path, newline="", encoding="utf-8") as f:
            for row in csv.reader(f):
                if len(row) >= 2:
                    MAC_VENDORS[row[0].strip().upper()] = row[1].strip()
        logger.info("Loaded extended OUI database from %s", csv_path)
    except Exception:
        logger.exception("Failed to load OUI database from %s", csv_path)


# ============================================================
# SUBPROCESS HELPER
# ============================================================

def run_command(args, timeout=5):
    """
    Runs a command and returns (success, stdout_text). Never raises —
    callers get a clean False on missing binaries, timeouts, or
    non-zero exit codes, with the reason logged instead of silently
    swallowed (the old code's `except Exception: pass` pattern is
    exactly what made ARP-table failures invisible).
    """
    if shutil.which(args[0]) is None:
        logger.warning("Command not found: %s (is it installed / on PATH?)", args[0])
        return False, ""

    try:
        output = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        text = output.stdout.decode("utf-8", errors="ignore")

        if output.returncode != 0 and not text.strip():
            stderr = output.stderr.decode("utf-8", errors="ignore").strip()
            logger.warning("Command %s exited %s: %s", args[0], output.returncode, stderr[:200])
            return False, ""

        return True, text

    except subprocess.TimeoutExpired:
        logger.warning("Command timed out: %s", " ".join(args))
        return False, ""
    except Exception:
        logger.exception("Command failed: %s", " ".join(args))
        return False, ""


# ============================================================
# Native Windows WlanScan API Integration
# ============================================================

def trigger_native_wlan_scan():
    """Forces the Windows WLAN driver to trigger a hardware scan for nearby APs."""
    if OS_TYPE != "Windows" or not _CTYPES_AVAILABLE:
        return False

    try:
        wlan = ctypes.windll.wlanapi
        dw_client_version = 2
        dw_negotiated_version = wintypes.DWORD()
        p_client_handle = wintypes.HANDLE()

        res = wlan.WlanOpenHandle(
            dw_client_version, None, ctypes.byref(dw_negotiated_version), ctypes.byref(p_client_handle)
        )
        if res != 0:
            return False

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD),
                ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD),
                ("Data4", wintypes.BYTE * 8),
            ]

        class WLAN_INTERFACE_INFO(ctypes.Structure):
            _fields_ = [
                ("InterfaceGuid", GUID),
                ("strInterfaceDescription", wintypes.WCHAR * 256),
                ("isState", ctypes.c_uint),
            ]

        class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
            _fields_ = [
                ("dwNumberOfItems", wintypes.DWORD),
                ("dwIndex", wintypes.DWORD),
                ("InterfaceInfo", WLAN_INTERFACE_INFO * 1),
            ]

        p_list = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
        res2 = wlan.WlanEnumInterfaces(p_client_handle, None, ctypes.byref(p_list))
        if res2 == 0:
            items = p_list.contents.dwNumberOfItems
            for i in range(items):
                guid = p_list.contents.InterfaceInfo[i].InterfaceGuid
                wlan.WlanScan(p_client_handle, ctypes.byref(guid), None, None, None)

        wlan.WlanCloseHandle(p_client_handle, None)
        return True
    except Exception:
        logger.debug("Native WLAN scan trigger failed (non-fatal)", exc_info=True)
        return False


# ============================================================
# Wi-Fi Scanner (Windows / Linux / macOS)
# ============================================================

def _estimate_distance_meters(signal_percent):
    """
    Very rough distance ESTIMATE from Wi-Fi signal strength, using a
    standard log-distance path-loss approximation. This is NOT a
    precise measurement — real distance depends heavily on walls,
    interference, and the specific radio hardware. Treat it as a
    ballpark ("near" vs "far"), not a tape measure.
    """
    if signal_percent is None or signal_percent <= 0:
        return None

    # Convert signal % (as reported by Windows/nmcli) to an approximate
    # RSSI in dBm, then apply a log-distance model against a typical
    # -40dBm-at-1m reference and a mid-range path-loss exponent.
    rssi_dbm = (signal_percent / 2) - 100
    reference_rssi = -40
    path_loss_exponent = 2.7

    try:
        distance = 10 ** ((reference_rssi - rssi_dbm) / (10 * path_loss_exponent))
        return round(max(distance, 0.5), 1)
    except Exception:
        return None


class AdvancedWifiScanner:
    """Scans and lists nearby Wi-Fi networks in range (SSID/signal/security only)."""

    @staticmethod
    def scan_all_nearby_wifis():
        trigger_native_wlan_scan()
        time.sleep(0.8)  # let beacon frames accumulate

        if OS_TYPE == "Windows":
            networks = AdvancedWifiScanner._scan_windows()
        elif OS_TYPE == "Linux":
            networks = AdvancedWifiScanner._scan_linux()
        elif OS_TYPE == "Darwin":
            networks = AdvancedWifiScanner._scan_macos()
        else:
            logger.warning("Wi-Fi scanning isn't supported on OS: %s", OS_TYPE)
            networks = []

        for net in networks:
            net["est_distance_m"] = _estimate_distance_meters(net.get("signal"))

        return sorted(networks, key=lambda x: x.get("signal", 0), reverse=True)

    @staticmethod
    def _scan_windows():
        ok, output = run_command(
            ["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=10
        )
        if not ok:
            return []

        networks = []
        current_net = {}

        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SSID "):
                if current_net and "ssid" in current_net:
                    networks.append(current_net)
                parts = line.split(":", 1)
                ssid_name = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "Hidden Network"
                current_net = {
                    "ssid": ssid_name, "bssid": "Unknown", "signal": 0,
                    "auth": "Unknown", "band": "Unknown", "channel": "Unknown",
                }
            elif line.startswith("Authentication"):
                parts = line.split(":", 1)
                if current_net and len(parts) > 1:
                    current_net["auth"] = parts[1].strip()
            elif line.startswith("Signal"):
                parts = line.split(":", 1)
                if current_net and len(parts) > 1:
                    try:
                        current_net["signal"] = int(parts[1].strip().replace("%", ""))
                    except ValueError:
                        pass
            elif line.startswith("BSSID "):
                parts = line.split(":", 1)
                if current_net and len(parts) > 1:
                    current_net["bssid"] = parts[1].strip()
            elif line.startswith("Band"):
                parts = line.split(":", 1)
                if current_net and len(parts) > 1:
                    current_net["band"] = parts[1].strip()
            elif line.startswith("Channel"):
                parts = line.split(":", 1)
                if current_net and len(parts) > 1:
                    current_net["channel"] = parts[1].strip()

        if current_net and "ssid" in current_net:
            networks.append(current_net)

        return networks

    @staticmethod
    def _scan_linux():
        ok, output = run_command(
            ["nmcli", "-t", "-f", "SSID,BSSID,SIGNAL,SECURITY,CHAN",
             "device", "wifi", "list", "--rescan", "yes"],
            timeout=15,
        )
        if not ok:
            logger.warning(
                "nmcli unavailable or failed — Wi-Fi scan skipped. "
                "Install NetworkManager (`sudo apt install network-manager`) to enable this."
            )
            return []

        networks = []
        for line in output.splitlines():
            if not line.strip():
                continue
            fields = re.split(r"(?<!\\):", line)
            fields = [f.replace("\\:", ":") for f in fields]
            if len(fields) < 5:
                continue
            ssid, bssid, signal, security, chan = fields[:5]
            networks.append({
                "ssid": ssid if ssid else "Hidden Network",
                "bssid": bssid if bssid else "Unknown",
                "signal": int(signal) if signal.isdigit() else 0,
                "auth": security if security else "Open",
                "band": "2.4/5GHz",
                "channel": chan if chan else "N/A",
            })
        return networks

    @staticmethod
    def _scan_macos():
        # Apple has progressively locked down Wi-Fi scan APIs. The
        # legacy `airport` utility still works on many systems that
        # haven't disabled it; `system_profiler` is the documented
        # fallback but only reports the *currently joined* network,
        # not full nearby-network scan results.
        airport_path = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport"
        )

        if os.path.exists(airport_path):
            ok, output = run_command([airport_path, "-s"], timeout=10)
            if ok:
                networks = []
                lines = [l for l in output.splitlines() if l.strip()]
                for line in lines[1:]:  # skip header row
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    ssid = parts[0]
                    try:
                        signal_dbm = int(parts[2])
                        signal_pct = max(0, min(100, 2 * (signal_dbm + 100)))
                    except (ValueError, IndexError):
                        signal_pct = 0
                    networks.append({
                        "ssid": ssid, "bssid": parts[1] if len(parts) > 1 else "Unknown",
                        "signal": signal_pct, "auth": parts[-1] if parts else "Unknown",
                        "band": "2.4/5GHz", "channel": parts[3] if len(parts) > 3 else "N/A",
                    })
                if networks:
                    return networks

        logger.warning(
            "Full Wi-Fi network scanning is restricted on this macOS version. "
            "Showing the currently-joined network only, via system_profiler."
        )
        ok, output = run_command(
            ["system_profiler", "SPAirPortDataType"], timeout=10
        )
        if not ok:
            return []

        match = re.search(r"Current Network Information:\s*\n\s*(.+):", output)
        if not match:
            return []

        ssid = match.group(1).strip()
        signal_match = re.search(r"Signal / Noise:\s*(-?\d+)\s*dBm", output)
        signal_pct = 0
        if signal_match:
            signal_pct = max(0, min(100, 2 * (int(signal_match.group(1)) + 100)))

        return [{
            "ssid": ssid, "bssid": "Unknown", "signal": signal_pct,
            "auth": "Unknown", "band": "2.4/5GHz", "channel": "N/A",
        }]


# ============================================================
# Currently-Connected SSID (for tagging local network devices)
# ============================================================
# scan_all_nearby_wifis() above lists every network IN RANGE. This is
# different: it's the ONE network this machine is actually a member
# of right now, used to label every discovered local device with the
# SSID it was found on (the "SSID column" the local-device table needs).

def get_current_connected_ssid():
    try:
        if OS_TYPE == "Windows":
            ok, output = run_command(["netsh", "wlan", "show", "interfaces"], timeout=5)
            if ok:
                match = re.search(r"^\s*SSID\s*:\s*(.+)$", output, re.MULTILINE)
                if match:
                    ssid = match.group(1).strip()
                    if ssid and "BSSID" not in ssid:
                        return ssid
            return "Not connected to Wi-Fi (wired/other)"

        elif OS_TYPE == "Linux":
            ok, output = run_command(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"], timeout=5
            )
            if ok:
                for line in output.splitlines():
                    if line.startswith("yes:"):
                        return line.split(":", 1)[1].strip()
            return "Not connected to Wi-Fi (wired/other)"

        elif OS_TYPE == "Darwin":
            ok, output = run_command(
                ["networksetup", "-getairportnetwork", "en0"], timeout=5
            )
            if ok and ":" in output:
                return output.split(":", 1)[1].strip()
            return "Not connected to Wi-Fi (wired/other)"

    except Exception:
        logger.debug("Failed to detect current SSID (non-fatal)", exc_info=True)

    return "Unknown"


# ============================================================
# Wi-Fi Switching (connect this machine to a different network)
# ============================================================
# Uses each OS's own connection manager (netsh / nmcli / networksetup)
# — the same mechanism a person would use by hand from the system
# Wi-Fi menu — rather than touching the radio driver directly. This
# can only join networks that are actually in range and reachable
# with the credentials supplied; it can't "hack into" anything.

class WifiConnectionManager:
    @staticmethod
    def connect(ssid, password=""):
        if not ssid:
            return {"success": False, "error": "ssid is required"}
        if OS_TYPE == "Windows":
            return WifiConnectionManager._connect_windows(ssid, password)
        elif OS_TYPE == "Linux":
            return WifiConnectionManager._connect_linux(ssid, password)
        elif OS_TYPE == "Darwin":
            return WifiConnectionManager._connect_macos(ssid, password)
        return {"success": False, "error": f"Wi-Fi switching isn't supported on OS: {OS_TYPE}"}

    # -------------------- Linux (NetworkManager) --------------------
    @staticmethod
    def _connect_linux(ssid, password):
        if shutil.which("nmcli") is None:
            return {"success": False, "error": "nmcli (NetworkManager) was not found on this system."}

        args = ["nmcli", "device", "wifi", "connect", ssid]
        if password:
            args += ["password", password]
        ok, output = run_command(args, timeout=25)
        lowered = output.lower()
        if ok and ("successfully activated" in lowered or "device" in lowered and "error" not in lowered):
            return {"success": True, "message": f"Connected to '{ssid}'.", "raw": output.strip()}
        return {
            "success": False,
            "error": output.strip() or "nmcli could not connect — check the SSID/password and try again.",
            "raw": output.strip(),
        }

    # -------------------- Windows (netsh) --------------------
    @staticmethod
    def _connect_windows(ssid, password):
        if shutil.which("netsh") is None:
            return {"success": False, "error": "netsh was not found on this system."}

        # Try an existing saved profile first (no password needed if
        # this network has been joined before).
        ok, output = run_command(["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"], timeout=15)
        if ok and "completed successfully" in output.lower():
            return {"success": True, "message": f"Connected to '{ssid}' using a saved profile.", "raw": output.strip()}

        if not password:
            return {
                "success": False,
                "error": f"No saved profile for '{ssid}' yet, and no password was provided.",
                "raw": output.strip(),
            }

        # No saved profile — create a temporary WPA2-PSK profile, add
        # it, then connect. The temp file is removed immediately after.
        profile_xml = (
            '<?xml version="1.0"?>\n'
            '<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">\n'
            f"    <name>{ssid}</name>\n"
            f"    <SSIDConfig><SSID><name>{ssid}</name></SSID></SSIDConfig>\n"
            "    <connectionType>ESS</connectionType>\n"
            "    <connectionMode>manual</connectionMode>\n"
            "    <MSM><security>\n"
            "        <authEncryption><authentication>WPA2PSK</authentication>"
            "<encryption>AES</encryption><useOneX>false</useOneX></authEncryption>\n"
            f"        <sharedKey><keyType>passPhrase</keyType><protected>false</protected>"
            f"<keyMaterial>{password}</keyMaterial></sharedKey>\n"
            "    </security></MSM>\n"
            "</WLANProfile>"
        )
        tmp_path = os.path.join(APP_DIR, f"_tmp_wifi_profile_{int(time.time())}.xml")
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(profile_xml)
            ok2, out2 = run_command(["netsh", "wlan", "add", "profile", f"filename={tmp_path}"], timeout=10)
            if not ok2:
                return {"success": False, "error": out2.strip() or "Failed to add the Wi-Fi profile."}
            ok3, out3 = run_command(["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"], timeout=15)
            if ok3 and "completed successfully" in out3.lower():
                return {"success": True, "message": f"Connected to '{ssid}'.", "raw": out3.strip()}
            return {"success": False, "error": out3.strip() or "Failed to connect after adding the profile."}
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass

    # -------------------- macOS (networksetup) --------------------
    @staticmethod
    def _connect_macos(ssid, password):
        if shutil.which("networksetup") is None:
            return {"success": False, "error": "networksetup was not found on this system."}

        iface = WifiConnectionManager._macos_wifi_interface() or "en0"
        args = ["networksetup", "-setairportnetwork", iface, ssid]
        if password:
            args.append(password)
        ok, output = run_command(args, timeout=15)
        lowered = output.lower()
        if ok and "not associated" not in lowered and "error" not in lowered and "failed" not in lowered:
            return {"success": True, "message": f"Connected to '{ssid}'.", "raw": output.strip()}
        return {
            "success": False,
            "error": output.strip() or "Failed to join the network — check the password.",
            "raw": output.strip(),
        }

    @staticmethod
    def _macos_wifi_interface():
        ok, output = run_command(["networksetup", "-listallhardwareports"], timeout=5)
        if not ok:
            return None
        lines = output.splitlines()
        for i, line in enumerate(lines):
            if "Wi-Fi" in line or "AirPort" in line:
                for follow in lines[i:i + 3]:
                    if follow.strip().startswith("Device:"):
                        return follow.split(":", 1)[1].strip()
        return None


# ============================================================
# Local Network Device Scanner
# ============================================================

def list_active_networks():
    """
    Returns one entry per network this machine is CURRENTLY A MEMBER
    OF at the same time — e.g. Wi-Fi + wired Ethernet + a VPN adapter
    all connected at once — instead of only the single "default
    route" network that `get_local_ip_and_subnet()` uses elsewhere.

    This is what powers "show devices near me on different networks":
    it can only see networks your machine actually has an interface
    on (that's still the honest boundary — it can't see into a
    neighbor's Wi-Fi you're not connected to), but if you're on a
    laptop with Wi-Fi *and* a docked Ethernet connection, or a phone
    hotspot bridged alongside your home Wi-Fi, this will scan each
    one instead of picking just one.

    Requires `psutil`. Without it, falls back to the single active
    network (same as before).
    """
    if not _PSUTIL_AVAILABLE:
        ip, subnet = DeepNetworkScanner.get_local_ip_and_subnet()
        return [{"interface": "default", "ip": ip, "subnet_base": subnet, "netmask": None}]

    networks = []
    try:
        interface_stats = psutil.net_if_stats()
        interface_addrs = psutil.net_if_addrs()
    except Exception:
        logger.exception("Failed to enumerate network interfaces via psutil")
        ip, subnet = DeepNetworkScanner.get_local_ip_and_subnet()
        return [{"interface": "default", "ip": ip, "subnet_base": subnet, "netmask": None}]

    for iface_name, addrs in interface_addrs.items():
        stats = interface_stats.get(iface_name)
        if stats is not None and not stats.isup:
            continue

        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            if ip.startswith("127.") or ip.startswith("169.254."):
                continue  # loopback / link-local-only, not a real reachable network

            subnet_base = ".".join(ip.split(".")[:-1])
            networks.append({
                "interface": iface_name,
                "ip": ip,
                "netmask": addr.netmask,
                "subnet_base": subnet_base,
            })

    # Two virtual adapters can legitimately land on the same subnet —
    # only scan each distinct subnet once.
    seen_subnets = set()
    unique_networks = []
    for net in networks:
        if net["subnet_base"] in seen_subnets:
            continue
        seen_subnets.add(net["subnet_base"])
        unique_networks.append(net)

    if not unique_networks:
        ip, subnet = DeepNetworkScanner.get_local_ip_and_subnet()
        unique_networks = [{"interface": "default", "ip": ip, "subnet_base": subnet, "netmask": None}]

    return unique_networks


class DeepNetworkScanner:
    """Multi-protocol scanner for devices/servers on YOUR OWN active local subnet."""

    # -------------------- subnet / interface --------------------

    @staticmethod
    def get_local_ip_and_subnet():
        """
        Identifies the IP/subnet of whichever network interface is
        actually carrying outbound traffic right now (the "active"
        network), rather than guessing from a list of interfaces —
        this keeps working correctly even with VPNs or multiple
        adapters enabled.
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            s.close()

        subnet_base = ".".join(ip.split(".")[:-1])
        return ip, subnet_base

    # -------------------- discovery sweep --------------------

    @staticmethod
    def probe_single_ip(ip):
        """Active touch (ping + light UDP nudge) to surface devices in the ARP table."""
        if OS_TYPE == "Windows":
            args = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT_SECONDS * 1000)), ip]
        else:
            args = ["ping", "-c", "1", "-W", str(max(1, int(PING_TIMEOUT_SECONDS))), ip]

        run_command(args, timeout=PING_TIMEOUT_SECONDS + 1)

        for port in (137, 5353):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.1)
                sock.sendto(b"\x00", (ip, port))
                sock.close()
            except Exception:
                pass

    @classmethod
    def sweep_subnet(cls, subnet_base):
        # NOTE: assumes a /24 (254 usable hosts), which covers the
        # overwhelming majority of home/small-office networks. If
        # your network uses a different mask, pass a narrower/wider
        # `host_range` here.
        ips = [f"{subnet_base}.{i}" for i in SUBNET_HOST_RANGE]
        with ThreadPoolExecutor(max_workers=PING_SWEEP_WORKERS) as executor:
            list(executor.map(cls.probe_single_ip, ips))

    # -------------------- ARP table --------------------

    @staticmethod
    def parse_arp_table():
        device_map = {}

        if OS_TYPE == "Windows":
            ok, output = run_command(["arp", "-a"], timeout=5)
            if ok:
                for line in output.splitlines():
                    line = line.strip()
                    match = re.search(
                        r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}"
                        r"[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})\s+(\w+)",
                        line,
                    )
                    if match:
                        ip, mac, _alloc_type = match.groups()
                        mac_clean = mac.replace("-", ":").upper()
                        if not ip.startswith(("224.", "239.")) and ip != "255.255.255.255":
                            device_map[ip] = mac_clean

        elif OS_TYPE == "Darwin":
            ok, output = run_command(["arp", "-a"], timeout=5)
            if ok:
                # macOS format: "hostname (192.168.1.5) at aa:bb:cc:dd:ee:ff on en0 ..."
                for line in output.splitlines():
                    match = re.search(
                        r"\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+"
                        r"([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})",
                        line,
                    )
                    if match:
                        ip, mac = match.groups()
                        # macOS drops leading zeros in octets (e.g. "8:0:27"); normalise.
                        mac_clean = ":".join(p.zfill(2) for p in mac.split(":")).upper()
                        device_map[ip] = mac_clean

        else:  # Linux and other POSIX
            ok, output = run_command(["arp", "-n"], timeout=5)
            if ok:
                for line in output.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and ":" in parts[2]:
                        device_map[parts[0]] = parts[2].upper()
            else:
                # `arp` (net-tools) is frequently missing on modern
                # distros — `ip neighbor` (iproute2) is the maintained
                # replacement and is present almost everywhere instead.
                ok2, output2 = run_command(["ip", "neighbor", "show"], timeout=5)
                if ok2:
                    for line in output2.splitlines():
                        parts = line.split()
                        if len(parts) >= 5 and parts[0].count(".") == 3:
                            try:
                                mac_index = parts.index("lladdr") + 1
                                device_map[parts[0]] = parts[mac_index].upper()
                            except (ValueError, IndexError):
                                continue
                else:
                    logger.error(
                        "Neither `arp` nor `ip neighbor` is available — cannot read the "
                        "ARP table. Install iproute2 (`sudo apt install iproute2`) or "
                        "net-tools (`sudo apt install net-tools`)."
                    )

        return device_map

    # -------------------- hostname / vendor --------------------

    @staticmethod
    def _resolve_via_dns(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    @staticmethod
    def _resolve_via_netbios(ip):
        if OS_TYPE != "Windows":
            return None
        ok, output = run_command(["nbtstat", "-A", ip], timeout=2)
        if not ok:
            return None
        match = re.search(r"^\s*(\S+)\s+<00>\s+UNIQUE", output, re.MULTILINE)
        return match.group(1).strip() if match else None

    @staticmethod
    def _resolve_via_mdns(ip):
        if OS_TYPE != "Linux" or shutil.which("avahi-resolve") is None:
            return None
        ok, output = run_command(["avahi-resolve", "-a", ip], timeout=2)
        if not ok:
            return None
        parts = output.strip().split()
        return parts[1] if len(parts) >= 2 else None

    @classmethod
    def resolve_hostname_and_vendor(cls, ip, mac):
        hostname = cls._resolve_via_dns(ip)
        source = "dns"

        if not hostname:
            hostname = cls._resolve_via_netbios(ip)
            source = "netbios"

        if not hostname:
            hostname = cls._resolve_via_mdns(ip)
            source = "mdns"

        vendor = "Generic Network Device"
        if mac and mac != "SELF-MAC":
            prefix = mac[:8]
            vendor = MAC_VENDORS.get(prefix, "Network Adapter / Hardware")

        if not hostname:
            # No DNS/NetBIOS/mDNS name available (very common for phones,
            # IoT, and locked-down devices on a home router). Rather than
            # showing a bare "Unknown Device" with no information at all,
            # fall back to a vendor + MAC-suffix label — e.g.
            # "Apple Inc. Device (E6:2D)" — so there's always something
            # identifying to look at, honestly derived from what we
            # actually know (the MAC's OUI), not guessed.
            mac_suffix = mac[-5:] if mac and mac != "SELF-MAC" and len(mac) >= 5 else "????"
            vendor_short = vendor.split("/")[0].strip()
            hostname = f"{vendor_short} Device ({mac_suffix})"
            source = "vendor_fallback"

        return hostname, source, vendor

    # -------------------- reachability / latency --------------------

    @staticmethod
    def check_alive_and_latency(ip):
        """
        Reachability check via ICMP ping first (works even for devices
        with every TCP port closed), falling back to a TCP connect
        probe (works for devices that block ICMP, e.g. Windows
        Firewall defaults) — using only one misses real devices, which
        was part of the old inconsistency.
        """
        ping_ok, ping_ms = DeepNetworkScanner._ping_latency(ip)
        if ping_ok:
            return True, ping_ms, "icmp"

        for port in (80, 443, 22, 445, 139):
            start = time.time()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(TCP_LATENCY_TIMEOUT)
                result = s.connect_ex((ip, port))
                s.close()
                if result == 0:
                    return True, round((time.time() - start) * 1000, 1), f"tcp:{port}"
            except Exception:
                pass

        return False, None, None

    @staticmethod
    def _ping_latency(ip):
        if OS_TYPE == "Windows":
            args = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT_SECONDS * 1000)), ip]
        else:
            args = ["ping", "-c", "1", "-W", str(max(1, int(PING_TIMEOUT_SECONDS))), ip]

        ok, output = run_command(args, timeout=PING_TIMEOUT_SECONDS + 1)
        if not ok:
            return False, None

        match = re.search(r"time[=<]([\d.]+)\s*ms", output)
        if match:
            return True, round(float(match.group(1)), 1)

        # Some ping variants report success without a parseable "time="
        # (e.g. localhost on some platforms) — still counts as reachable.
        if OS_TYPE == "Windows" and "Reply from" in output:
            return True, None
        if OS_TYPE != "Windows" and " 0% packet loss" in output:
            return True, None

        return False, None

    # -------------------- port scan --------------------

    @staticmethod
    def scan_ports(ip):
        open_ports = []

        def _try_port(port_and_name):
            port, name = port_and_name
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(PORT_SCAN_TIMEOUT)
                if s.connect_ex((ip, port)) == 0:
                    return {"port": port, "service": name}
            except Exception:
                pass
            finally:
                try:
                    s.close()
                except Exception:
                    pass
            return None

        with ThreadPoolExecutor(max_workers=PORT_SCAN_WORKERS) as pool:
            for result in pool.map(_try_port, COMMON_SERVER_PORTS.items()):
                if result:
                    open_ports.append(result)

        return sorted(open_ports, key=lambda p: p["port"])

    # -------------------- per-device enrichment --------------------

    @classmethod
    def _enrich_device(cls, ip, mac, local_ip, network_label, ssid):
        is_self = (ip == local_ip)
        hostname, hostname_source, vendor = cls.resolve_hostname_and_vendor(
            ip, mac if mac != "SELF-MAC" else ""
        )

        if is_self:
            is_up, latency_ms, latency_method = True, 0.0, "self"
        else:
            is_up, latency_ms, latency_method = cls.check_alive_and_latency(ip)

        open_ports = cls.scan_ports(ip) if is_up or is_self else []

        device_type = cls.classify_device_type(ip, mac, vendor, hostname, open_ports)

        return {
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "hostname_source": hostname_source,
            "vendor": vendor,
            "type": device_type,
            "ssid": ssid,
            "latency_ms": latency_ms if latency_ms is not None else "-",
            "latency_method": latency_method,
            "reachable": is_up,
            "open_ports": open_ports,
            "is_self": is_self,
            "network_interface": network_label,
        }

    @staticmethod
    def classify_device_type(ip, mac, vendor, hostname, open_ports):
        """
        Best-effort device type / model hint from vendor + open services
        + hostname — the closest honest substitute for "what device/model
        is this" without router-level DHCP option-12 hostnames or active
        fingerprinting (which this tool intentionally avoids, see module
        docstring on scope).
        """
        vendor_l = (vendor or "").lower()
        host_l = (hostname or "").lower()
        port_numbers = {p["port"] for p in open_ports}
        port_names = {p["service"] for p in open_ports}

        if ip.endswith(".1") or "router" in host_l or "gateway" in host_l:
            return "Router / Gateway"
        if 9100 in port_numbers or 631 in port_numbers or "printer" in host_l:
            return "Network Printer"
        if 554 in port_numbers or "camera" in host_l or "cam" in host_l:
            return "IP Camera"
        if 32400 in port_numbers or 8096 in port_numbers:
            return "Media Server (Plex/Jellyfin)"
        if "raspberry pi" in vendor_l:
            return "Raspberry Pi"
        if "apple" in vendor_l:
            if "iphone" in host_l:
                return "Apple iPhone"
            if "ipad" in host_l:
                return "Apple iPad"
            if "macbook" in host_l or "imac" in host_l or "mac-" in host_l:
                return "Apple Mac"
            return "Apple Device"
        if "espressif" in vendor_l or "philips hue" in vendor_l or "nest" in vendor_l:
            return "Smart Home / IoT Device"
        if "amazon" in vendor_l:
            return "Amazon Device (Echo/Fire/Kindle)"
        if "samsung" in vendor_l or "randomized" in vendor_l or "android" in host_l:
            return "Mobile Device (Android)"
        if 3389 in port_numbers or 445 in port_numbers or "microsoft" in vendor_l:
            return "Windows PC"
        if port_names:
            return "Server / Service Node"
        return "Client Device"

    # -------------------- full scan --------------------

    @classmethod
    def get_all_connected_devices(cls, local_ip=None, subnet_base=None, network_label=None):
        """
        Scans one subnet. By default that's whichever network is
        currently carrying your outbound (default-route) traffic —
        pass `local_ip`/`subnet_base` explicitly (see
        `get_all_connected_devices_multi_network` below) to scan a
        *different* network your machine also happens to be
        connected to, e.g. a second Wi-Fi/Ethernet adapter or a VPN.
        """
        started = time.perf_counter()

        if local_ip is None or subnet_base is None:
            local_ip, subnet_base = cls.get_local_ip_and_subnet()

        network_label = network_label or subnet_base
        current_ssid = get_current_connected_ssid()

        cls.sweep_subnet(subnet_base)
        arp_map = cls.parse_arp_table()

        if local_ip not in arp_map:
            arp_map[local_ip] = "SELF-MAC"

        devices = []

        # This is the core reliability/performance fix: enrichment for
        # every discovered device (hostname lookup + reachability +
        # 11-port scan) now happens concurrently instead of one device
        # at a time, so a scan of a full /24 finishes in a few seconds
        # instead of potentially minutes.
        with ThreadPoolExecutor(max_workers=DEVICE_SCAN_WORKERS) as pool:
            futures = {
                pool.submit(cls._enrich_device, ip, mac, local_ip, network_label, current_ssid): ip
                for ip, mac in arp_map.items()
            }

            for future in as_completed(futures):
                ip = futures[future]
                try:
                    devices.append(future.result())
                except Exception:
                    logger.exception("Failed to enrich device %s", ip)

        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        logger.info(
            "[%s] Scanned %d candidate hosts, found %d devices in %sms",
            network_label, len(arp_map), len(devices), duration_ms,
        )

        return sorted(devices, key=lambda x: [int(part) for part in x["ip"].split(".")])

    # -------------------- scan across every connected network --------------------

    @classmethod
    def get_all_connected_devices_multi_network(cls):
        """
        Scans EVERY network this machine currently has an active
        interface on — e.g. Wi-Fi + docked Ethernet + a VPN all at
        once — instead of only the single default-route network.
        Each returned device is tagged with `network_interface` and
        `network_subnet` so the UI can group "devices near me" by
        which network they're actually on.

        Note on scope: this still only sees networks your machine is
        a member of. It cannot (and intentionally does not attempt
        to) reach into a neighboring Wi-Fi network you're merely in
        range of but not connected to — that would mean accessing a
        network without authorization.
        """
        started = time.perf_counter()
        networks = list_active_networks()

        all_devices = []
        seen = set()

        for net in networks:
            devices = cls.get_all_connected_devices(
                local_ip=net["ip"],
                subnet_base=net["subnet_base"],
                network_label=net["interface"],
            )
            for d in devices:
                d["network_subnet"] = f"{net['subnet_base']}.0/24"
                key = (d["mac"], d["ip"])
                if key in seen:
                    continue
                seen.add(key)
                all_devices.append(d)

        duration_ms = round((time.perf_counter() - started) * 1000, 1)
        logger.info(
            "Multi-network scan covered %d network(s) (%s), found %d total devices in %sms",
            len(networks), [n["interface"] for n in networks], len(all_devices), duration_ms,
        )

        return all_devices, networks

    # -------------------- on-demand "network distance" --------------------

    @staticmethod
    def traceroute_hops(ip, max_hops=20):
        """
        On-demand only (not run during a bulk scan — it's slow).
        Returns an approximate "network distance" as hop count, which
        is a meaningful, honest stand-in for physical distance: this
        tool cannot measure how many meters away a device is (that
        needs specialized RF hardware), but it *can* tell you how many
        network hops separate you.
        """
        if OS_TYPE == "Windows":
            args = ["tracert", "-d", "-h", str(max_hops), "-w", "800", ip]
        else:
            args = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", ip]

        ok, output = run_command(args, timeout=15)
        if not ok:
            return {"hops": None, "raw": None, "error": "traceroute unavailable"}

        hop_lines = [
            line for line in output.splitlines()
            if re.match(r"^\s*\d+\s", line)
        ]

        return {"hops": len(hop_lines) or None, "raw": output.strip()}


# ============================================================
# Self-machine bandwidth (THIS device only — not other devices)
# ============================================================

class SelfBandwidthTracker:
    """
    Tracks how much data *this machine* has sent/received, by taking
    periodic snapshots of the OS network counters and storing deltas.
    This only ever reflects the traffic of the device the script runs
    on — see the module docstring for why per-*other*-device bandwidth
    isn't implemented here.
    """

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bandwidth_samples (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    bytes_sent INTEGER,
                    bytes_recv INTEGER
                )
            """)

    def record_snapshot(self):
        if not _PSUTIL_AVAILABLE:
            return False

        counters = psutil.net_io_counters()
        now = datetime.now().isoformat(timespec="seconds")

        with self._connect() as conn:
            conn.execute(
                "INSERT INTO bandwidth_samples (timestamp, bytes_sent, bytes_recv) VALUES (?, ?, ?)",
                (now, counters.bytes_sent, counters.bytes_recv),
            )
        return True

    def get_last_24h_usage(self):
        if not _PSUTIL_AVAILABLE:
            return {
                "available": False,
                "reason": "psutil is not installed (pip install psutil) — "
                          "self-bandwidth tracking is disabled without it.",
            }

        cutoff = time.time() - 24 * 3600
        cutoff_iso = datetime.fromtimestamp(cutoff).isoformat(timespec="seconds")

        with self._connect() as conn:
            rows = conn.execute(
                "SELECT timestamp, bytes_sent, bytes_recv FROM bandwidth_samples "
                "WHERE timestamp >= ? ORDER BY timestamp ASC",
                (cutoff_iso,),
            ).fetchall()

        if len(rows) < 2:
            return {
                "available": True,
                "sent_mb": 0.0, "recv_mb": 0.0, "total_mb": 0.0,
                "samples": len(rows),
                "note": "Not enough samples yet — call record_snapshot() periodically "
                        "(e.g. every few minutes) to build up a 24h picture.",
            }

        # Counters reset on reboot; guard against negative deltas by
        # only summing forward-moving windows.
        sent_delta = recv_delta = 0
        for i in range(1, len(rows)):
            prev, cur = rows[i - 1], rows[i]
            d_sent, d_recv = cur[1] - prev[1], cur[2] - prev[2]
            if d_sent >= 0:
                sent_delta += d_sent
            if d_recv >= 0:
                recv_delta += d_recv

        return {
            "available": True,
            "sent_mb": round(sent_delta / (1024 * 1024), 2),
            "recv_mb": round(recv_delta / (1024 * 1024), 2),
            "total_mb": round((sent_delta + recv_delta) / (1024 * 1024), 2),
            "samples": len(rows),
        }


# ============================================================
# Router Bandwidth Integration (STUB — legitimate path for
# per-device bandwidth, opt-in, requires YOUR router's own API)
# ============================================================

class RouterBandwidthIntegration:
    """
    Per-*other*-device bandwidth is only reliably and legitimately
    available from the router/gateway itself, since that's the
    device that already necessarily sees every client's traffic
    volume as part of its normal routing job — no interception
    needed. Many routers (OpenWrt, pfSense/OPNsense, UniFi, some
    ASUS/Netgear firmware) expose this via SNMP or a local API.

    This class is an integration point, not a working implementation:
    wire up `fetch_client_usage()` to your specific router's API/SNMP
    interface with credentials the user explicitly provides, and it
    slots into the same device dicts as `client_bandwidth_mb_24h`.
    Left unimplemented by default so nothing here silently tries to
    reach into a router it hasn't been configured for.
    """

    def __init__(self, router_type=None, host=None, credentials=None):
        self.router_type = router_type
        self.host = host
        self.credentials = credentials

    def is_configured(self):
        return bool(self.router_type and self.host)

    def fetch_client_usage(self):
        if not self.is_configured():
            return {}
        raise NotImplementedError(
            f"Router integration for '{self.router_type}' isn't implemented yet. "
            "Add an SNMP/API client for your specific router model here."
        )


# ============================================================
# Device History, Session/Uptime Tracking & Alerts (SQLite)
# ============================================================

class DeviceHistory:
    """Tracks devices seen on your own network over time: new-device /
    offline alerts, plus how long each device has been continuously
    "active" (online) today."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    ssid TEXT,
                    first_seen TEXT,
                    last_seen TEXT,
                    seen_count INTEGER DEFAULT 1,
                    online INTEGER DEFAULT 1,
                    state_changed_at TEXT,
                    active_seconds_today INTEGER DEFAULT 0,
                    active_day TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT,
                    ip TEXT,
                    hostname TEXT,
                    event_type TEXT,
                    timestamp TEXT
                )
            """)
            self._migrate_devices_table(conn)
            conn.commit()

    @staticmethod
    def _migrate_devices_table(conn):
        """
        `CREATE TABLE IF NOT EXISTS` does nothing if the table already
        exists with an older schema — which is exactly what happens
        when a `signalwatch_history.db` created by an earlier version
        of this script (before online/active-time tracking existed)
        is reused. That mismatch is what produced:
            sqlite3.OperationalError: no such column: online
        This adds any columns a pre-existing devices table is missing,
        so upgrading in place just works instead of crashing — nothing
        needs to be deleted or reset.
        """
        existing_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(devices)").fetchall()
        }

        required_columns = {
            "online": "INTEGER DEFAULT 1",
            "state_changed_at": "TEXT",
            "active_seconds_today": "INTEGER DEFAULT 0",
            "active_day": "TEXT",
            "ssid": "TEXT",
        }

        for column, declaration in required_columns.items():
            if column not in existing_columns:
                conn.execute(f"ALTER TABLE devices ADD COLUMN {column} {declaration}")
                logger.info("Migrated 'devices' table: added missing column '%s'", column)

    def record_scan(self, devices):
        """Updates history with a fresh scan result, tracks active-time
        deltas since the previous sighting, and returns alert events."""
        now_dt = datetime.now()
        now = now_dt.isoformat(timespec="seconds")
        today = date.today().isoformat()
        alerts = []

        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute("SELECT mac FROM devices WHERE online = 1")
            previously_online = {row[0] for row in cur.fetchall() if row[0] and row[0] != "SELF-MAC"}

            seen_this_scan = set()

            for d in devices:
                mac = d.get("mac")
                if not mac or mac == "SELF-MAC":
                    continue
                seen_this_scan.add(mac)

                cur.execute(
                    "SELECT last_seen, active_seconds_today, active_day FROM devices WHERE mac = ?",
                    (mac,),
                )
                existing = cur.fetchone()

                if existing:
                    last_seen_str, active_seconds, active_day = existing
                    active_seconds = active_seconds or 0

                    if active_day != today:
                        active_seconds = 0

                    if last_seen_str:
                        try:
                            gap = (now_dt - datetime.fromisoformat(last_seen_str)).total_seconds()
                            active_seconds += min(max(gap, 0), ACTIVE_TIME_MAX_GAP_SECONDS)
                        except ValueError:
                            pass

                    cur.execute(
                        """UPDATE devices SET ip=?, hostname=?, vendor=?, ssid=?, last_seen=?,
                           seen_count = seen_count + 1, online = 1, active_seconds_today = ?,
                           active_day = ? WHERE mac=?""",
                        (d["ip"], d["hostname"], d["vendor"], d.get("ssid", ""), now,
                         int(active_seconds), today, mac),
                    )
                else:
                    cur.execute(
                        """INSERT INTO devices
                           (mac, ip, hostname, vendor, ssid, first_seen, last_seen, seen_count,
                            online, state_changed_at, active_seconds_today, active_day)
                           VALUES (?, ?, ?, ?, ?, ?, ?, 1, 1, ?, 0, ?)""",
                        (mac, d["ip"], d["hostname"], d["vendor"], d.get("ssid", ""),
                         now, now, now, today),
                    )
                    cur.execute(
                        "INSERT INTO events (mac, ip, hostname, event_type, timestamp) VALUES (?, ?, ?, ?, ?)",
                        (mac, d["ip"], d["hostname"], "new_device", now),
                    )
                    alerts.append({"type": "new_device", "mac": mac, "ip": d["ip"],
                                    "hostname": d["hostname"], "timestamp": now})

            went_offline = previously_online - seen_this_scan
            for mac in went_offline:
                cur.execute("SELECT ip, hostname FROM devices WHERE mac = ?", (mac,))
                row = cur.fetchone()
                ip, hostname = row if row else ("?", "?")

                cur.execute(
                    "UPDATE devices SET online = 0, state_changed_at = ? WHERE mac = ?",
                    (now, mac),
                )
                cur.execute(
                    "INSERT INTO events (mac, ip, hostname, event_type, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (mac, ip, hostname, "device_offline", now),
                )
                alerts.append({"type": "device_offline", "mac": mac, "ip": ip,
                                "hostname": hostname, "timestamp": now})

            conn.commit()

        return alerts

    def annotate_with_uptime(self, devices):
        """Merges active_seconds_today / first_seen / seen_count onto
        each device dict returned by a fresh scan, for display."""
        with self._connect() as conn:
            cur = conn.cursor()
            for d in devices:
                mac = d.get("mac")
                if not mac or mac == "SELF-MAC":
                    d["active_seconds_today"] = None
                    d["first_seen"] = None
                    d["seen_count"] = None
                    continue

                cur.execute(
                    "SELECT first_seen, active_seconds_today, seen_count FROM devices WHERE mac = ?",
                    (mac,),
                )
                row = cur.fetchone()
                if row:
                    d["first_seen"] = row[0]
                    d["active_seconds_today"] = row[1]
                    d["seen_count"] = row[2]
        return devices

    def recent_events(self, limit=25):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT mac, ip, hostname, event_type, timestamp FROM events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        return [{"mac": r[0], "ip": r[1], "hostname": r[2], "event_type": r[3], "timestamp": r[4]} for r in rows]

    def all_known_devices(self):
        with self._connect() as conn:
            cur = conn.cursor()
            cur.execute(
                """SELECT mac, ip, hostname, vendor, first_seen, last_seen, seen_count,
                   online, active_seconds_today, ssid FROM devices"""
            )
            rows = cur.fetchall()
        return [
            {
                "mac": r[0], "ip": r[1], "hostname": r[2], "vendor": r[3],
                "first_seen": r[4], "last_seen": r[5], "seen_count": r[6],
                "online": bool(r[7]), "active_seconds_today": r[8], "ssid": r[9],
            }
            for r in rows
        ]


# ============================================================
# Per-Network Snapshots (device counts/lists remembered per SSID)
# ============================================================
# This is what lets the dashboard show "N devices" for a network you
# are NOT currently connected to: it remembers the result of the last
# time you WERE connected to it and scanned it. It never scans a
# network the machine isn't a member of — that stays out of scope
# (see module docstring) — it only persists honestly-collected past
# scans so switching between networks doesn't lose that context.

class NetworkSnapshotStore:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self._init_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS network_snapshots (
                    ssid TEXT PRIMARY KEY,
                    device_count INTEGER,
                    devices_json TEXT,
                    last_connected_at TEXT
                )
            """)

    def save(self, ssid, devices):
        if not ssid or ssid == "Unknown" or ssid.startswith("Not connected"):
            return
        now = datetime.now().isoformat(timespec="seconds")
        slim_devices = [
            {
                "ip": d.get("ip"), "mac": d.get("mac"), "hostname": d.get("hostname"),
                "vendor": d.get("vendor"), "type": d.get("type"),
                "reachable": d.get("reachable"), "open_ports": d.get("open_ports", []),
                "latency_ms": d.get("latency_ms"), "is_self": d.get("is_self", False),
            }
            for d in devices
        ]
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO network_snapshots (ssid, device_count, devices_json, last_connected_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ssid) DO UPDATE SET
                    device_count = excluded.device_count,
                    devices_json = excluded.devices_json,
                    last_connected_at = excluded.last_connected_at
            """, (ssid, len(devices), json.dumps(slim_devices), now))

    def get(self, ssid):
        if not ssid:
            return None
        with self._connect() as conn:
            row = conn.execute(
                "SELECT device_count, devices_json, last_connected_at FROM network_snapshots WHERE ssid = ?",
                (ssid,),
            ).fetchone()
        if not row:
            return None
        try:
            devices = json.loads(row[1]) if row[1] else []
        except Exception:
            devices = []
        return {"device_count": row[0], "devices": devices, "last_connected_at": row[2]}

    def all(self):
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT ssid, device_count, last_connected_at FROM network_snapshots"
            ).fetchall()
        return {r[0]: {"device_count": r[1], "last_connected_at": r[2]} for r in rows}


# ============================================================
# CSV EXPORT
# ============================================================

def export_devices_csv(devices, path=EXPORT_PATH):
    fieldnames = [
        "ip", "mac", "hostname", "hostname_source", "vendor", "type", "ssid",
        "network_interface", "network_subnet",
        "latency_ms", "latency_method", "reachable", "open_ports",
        "is_self", "active_seconds_today",
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for d in devices:
            row = dict(d)
            row["open_ports"] = "; ".join(f"{p['port']}({p['service']})" for p in d.get("open_ports", []))
            writer.writerow(row)
    return path


# ============================================================
# Terminal Interface
# ============================================================

def format_active_time(seconds):
    if not seconds:
        return "-"
    seconds = int(seconds)
    hours, remainder = divmod(seconds, 3600)
    minutes, _ = divmod(remainder, 60)
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


def print_alerts(alerts):
    if not alerts:
        return
    print("\n [ALERTS]")
    for a in alerts:
        if a["type"] == "new_device":
            print(f"  [+] NEW DEVICE joined your network: {a['hostname']} ({a['ip']} / {a['mac']})")
        else:
            print(f"  [-] Device went offline: {a['hostname']} ({a['ip']} / {a['mac']})")


def run_cli_monitor():
    history = DeviceHistory()
    bandwidth = SelfBandwidthTracker()

    print("=" * 72)
    print("   SIGNALWATCH PRO v2 - WIRELESS & LOCAL NETWORK DEVICE/SERVER MONITOR")
    print("   (scans nearby Wi-Fi signals + devices on YOUR OWN active network)")
    print("=" * 72)

    while True:
        print("\n [SELECT MONITORING MODE]")
        print("  1. Scan & View Nearby Wi-Fi Signals in Range")
        print("  2. Scan Devices & Servers on YOUR Active Network")
        print("  3. Combined Wi-Fi + Local Network Audit")
        print("  4. View Device History / Alerts Log")
        print("  5. Export Latest Device Scan to CSV")
        print("  6. Network Distance (Traceroute) to a Device")
        print("  7. This Machine's Bandwidth Usage (Last 24h)")
        print("  8. Scan Devices Across ALL Connected Networks (Wi-Fi + Ethernet + VPN etc.)")
        print("  9. Exit")

        choice = input("\n Enter choice (1-9): ").strip()

        if choice == "1":
            print("\n Scanning wireless frequencies... Please wait.")
            wifis = AdvancedWifiScanner.scan_all_nearby_wifis()
            print("\n " + "=" * 78)
            print(f" {'SSID NAME':<26} {'SIGNAL %':<9} {'EST. DIST.':<11} {'SECURITY':<16} {'BSSID'}")
            print(" " + "-" * 78)
            for w in wifis:
                sig = w.get("signal", 0)
                dist = f"{w['est_distance_m']}m" if w.get("est_distance_m") else "-"
                ssid = w["ssid"].encode("ascii", "ignore").decode("ascii")
                auth = w["auth"].encode("ascii", "ignore").decode("ascii")
                print(f" {ssid[:25]:<26} {sig:>3}%     {dist:<11} {auth[:15]:<16} {w['bssid']}")
            print(f"\n [OK] Discovered {len(wifis)} Wi-Fi networks in physical range.")
            print(" Note: distance is a rough estimate from signal strength, not a precise measurement.")

        elif choice in ("2", "3"):
            if choice == "3":
                print("\n Running combined signal + local network audit...\n")
                wifis = AdvancedWifiScanner.scan_all_nearby_wifis()
                print(" [SURROUNDING WI-FI SIGNALS]")
                for w in wifis:
                    print(f"  - {w['ssid']:<24} | Signal: {w['signal']}% | Security: {w['auth']} | BSSID: {w['bssid']}")
                print()

            print(" Scanning your local network (parallelized — should take a few seconds)...")
            devices = DeepNetworkScanner.get_all_connected_devices()
            alerts = history.record_scan(devices)
            devices = history.annotate_with_uptime(devices)

            print("\n " + "=" * 116)
            print(f" {'IP ADDRESS':<16} {'DEVICE / HOSTNAME':<22} {'VENDOR':<20} {'SSID':<18} {'ACTIVE TODAY':<13} {'SERVICES'}")
            print(" " + "-" * 116)
            for d in devices:
                svc_str = ", ".join(str(p["port"]) for p in d["open_ports"]) if d["open_ports"] else "Client"
                self_tag = " (This PC)" if d["is_self"] else ""
                active = format_active_time(d.get("active_seconds_today"))
                ssid_str = (d.get("ssid") or "-")[:17]
                print(f" {d['ip']:<16} {(d['hostname'] + self_tag)[:21]:<22} {d['vendor'][:19]:<20} {ssid_str:<18} {active:<13} {svc_str}")
            print(f"\n [OK] Discovered {len(devices)} active devices/servers on your local network.")
            print_alerts(alerts)

        elif choice == "4":
            events = history.recent_events()
            print("\n [RECENT DEVICE EVENTS]")
            if not events:
                print("  No events recorded yet. Run scan option 2 or 3 a few times to build history.")
            for e in events:
                tag = "NEW" if e["event_type"] == "new_device" else "OFFLINE"
                print(f"  [{tag:<7}] {e['timestamp']}  {e['hostname']} ({e['ip']} / {e['mac']})")

        elif choice == "5":
            devices = DeepNetworkScanner.get_all_connected_devices()
            devices = history.annotate_with_uptime(devices)
            path = export_devices_csv(devices)
            print(f"\n [OK] Exported {len(devices)} devices to: {path}")

        elif choice == "6":
            ip = input(" Enter device IP to trace: ").strip()
            print(f"\n Tracing route to {ip} (this can take up to ~15 seconds)...")
            result = DeepNetworkScanner.traceroute_hops(ip)
            if result.get("hops"):
                print(f" [OK] Approx. network distance: {result['hops']} hop(s)")
            else:
                print(f" [!] Could not determine hop count: {result.get('error', 'no route data')}")

        elif choice == "7":
            bandwidth.record_snapshot()
            usage = bandwidth.get_last_24h_usage()
            print("\n [THIS MACHINE'S BANDWIDTH — LAST 24H]")
            if not usage.get("available"):
                print(f"  {usage.get('reason')}")
            elif usage.get("note"):
                print(f"  {usage['note']}")
            else:
                print(f"  Sent:     {usage['sent_mb']} MB")
                print(f"  Received: {usage['recv_mb']} MB")
                print(f"  Total:    {usage['total_mb']} MB  (from {usage['samples']} samples)")

        elif choice == "8":
            if not _PSUTIL_AVAILABLE:
                print("\n [!] This needs `psutil` to enumerate network interfaces: pip install psutil")
                print("     Falling back to your single active network instead.\n")

            print("\n Scanning every network this machine is currently connected to...")
            devices, networks = DeepNetworkScanner.get_all_connected_devices_multi_network()
            alerts = history.record_scan(devices)
            devices = history.annotate_with_uptime(devices)

            print(f"\n [OK] Found {len(networks)} connected network(s):")
            for net in networks:
                print(f"   - {net['interface']:<16} {net['subnet_base']}.0/24  (this machine: {net['ip']})")

            print("\n " + "=" * 105)
            print(f" {'NETWORK':<14} {'IP ADDRESS':<16} {'DEVICE / HOSTNAME':<22} {'VENDOR':<20} {'SERVICES'}")
            print(" " + "-" * 105)
            for d in devices:
                svc_str = ", ".join(str(p["port"]) for p in d["open_ports"]) if d["open_ports"] else "Client"
                self_tag = " (This PC)" if d["is_self"] else ""
                print(f" {d['network_interface'][:13]:<14} {d['ip']:<16} {(d['hostname'] + self_tag)[:21]:<22} {d['vendor'][:19]:<20} {svc_str}")
            print(f"\n [OK] Discovered {len(devices)} total devices across all connected networks.")
            print_alerts(alerts)

        elif choice == "9":
            print(" Exiting SignalWatch Pro.")
            break

        else:
            print(" Invalid choice, try again.")


# ============================================================
# Background Scan Loop (used by --web mode)
# ============================================================
# The old web handler ran a full blocking scan on every single
# request to /api/devices, which is slow and makes the dashboard
# feel unresponsive. This keeps one continuously-refreshed cached
# snapshot instead, so requests return instantly.

class ScanCache:
    def __init__(self):
        self._lock = threading.Lock()
        self._devices = []
        self._alerts = []
        self._local_ip = None
        self._subnet = None
        self._last_scan_at = None

    def update(self, devices, alerts, local_ip, subnet):
        with self._lock:
            self._devices = devices
            self._alerts = alerts
            self._local_ip = local_ip
            self._subnet = subnet
            self._last_scan_at = datetime.now().isoformat(timespec="seconds")

    def snapshot(self):
        with self._lock:
            return {
                "devices": self._devices,
                "alerts": self._alerts,
                "local_ip": self._local_ip,
                "subnet": self._subnet,
                "last_scan_at": self._last_scan_at,
            }


def run_background_scan_loop(cache, history, netstore, stop_event, interval_seconds):
    # Note on the 5s default: this waits `interval_seconds` AFTER each
    # scan finishes, not a fixed 5s clock tick. A full /24 device scan
    # (ping sweep + port scan, parallelized) usually finishes well under
    # a second on a typical home network, so real-world cadence is close
    # to 5s — but on a very large or slow network a single scan pass can
    # itself take longer than 5s, in which case the loop simply runs
    # back-to-back without overlapping instead of pretending to hit an
    # unrealistic fixed interval.
    while not stop_event.is_set():
        try:
            devices = DeepNetworkScanner.get_all_connected_devices()
            alerts = history.record_scan(devices)
            devices = history.annotate_with_uptime(devices)
            local_ip, subnet = DeepNetworkScanner.get_local_ip_and_subnet()
            cache.update(devices, alerts, local_ip, subnet)
            netstore.save(get_current_connected_ssid(), devices)
        except Exception:
            logger.exception("Background scan failed")

        stop_event.wait(interval_seconds)
