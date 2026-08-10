"""
Signal Monitor blueprint
-------------------------
Wraps the SignalWatch Pro v2 scanning engine (modules/signal_monitor/core.py,
ported unmodified apart from its storage paths) in native Flask routes,
replacing the original standalone http.server dashboard so it can live
inside the unified Monitor Suite app.

All API routes are mounted under /signal-monitor/api/... to match the
paths the bundled templates/signal_monitor.html page calls.
"""

import json
import threading
from datetime import datetime

from flask import Blueprint, jsonify, render_template, request, Response

from . import core

signal_monitor_bp = Blueprint(
    "signal_monitor",
    __name__,
    url_prefix="/signal-monitor",
)

# ----------------------------------------------------------------------
# Long-lived singletons (mirrors what WebSignalHandler class attributes
# did in the original standalone server -- one shared instance for the
# whole process, not per-request).
# ----------------------------------------------------------------------
_history = core.DeviceHistory()
_bandwidth = core.SelfBandwidthTracker()
_cache = core.ScanCache()
_netstore = core.NetworkSnapshotStore()

_background_started = False
_background_lock = threading.Lock()

BACKGROUND_SCAN_INTERVAL_SECONDS = 5


def _start_background_threads():
    """Start the background scan + bandwidth sampler loops exactly once,
    the first time this blueprint is actually used."""
    global _background_started
    with _background_lock:
        if _background_started:
            return
        _background_started = True

        scanner_thread = threading.Thread(
            target=core.run_background_scan_loop,
            args=(_cache, _history, _netstore, threading.Event(), BACKGROUND_SCAN_INTERVAL_SECONDS),
            daemon=True,
        )
        scanner_thread.start()

        stop_event = threading.Event()

        def _bandwidth_loop():
            while not stop_event.is_set():
                try:
                    _bandwidth.record_snapshot()
                except Exception:
                    core.logger.exception("Bandwidth sampler failed")
                stop_event.wait(5)

        bandwidth_thread = threading.Thread(target=_bandwidth_loop, daemon=True)
        bandwidth_thread.start()


@signal_monitor_bp.before_app_request
def _ensure_background_started():
    # Cheap flag check; real start only happens once thanks to the lock.
    if not _background_started:
        _start_background_threads()


# ----------------------------------------------------------------------
# Page
# ----------------------------------------------------------------------

@signal_monitor_bp.route("/")
def index():
    return render_template("signal_monitor.html")


# ----------------------------------------------------------------------
# API -- same contract/paths as the original standalone dashboard, just
# reachable under /signal-monitor/api/... now instead of /api/...
# ----------------------------------------------------------------------

@signal_monitor_bp.route("/api/signals")
def api_signals():
    wifis = core.AdvancedWifiScanner.scan_all_nearby_wifis()
    return jsonify({"wifis": wifis, "environment": core.scanning_environment_status()})


@signal_monitor_bp.route("/api/devices")
def api_devices():
    if request.args.get("rescan") == "1":
        devices = core.DeepNetworkScanner.get_all_connected_devices()
        alerts = _history.record_scan(devices)
        devices = _history.annotate_with_uptime(devices)
        local_ip, subnet = core.DeepNetworkScanner.get_local_ip_and_subnet()
        _cache.update(devices, alerts, local_ip, subnet)
        _netstore.save(core.get_current_connected_ssid(), devices)

    return jsonify({**_cache.snapshot(), "environment": core.scanning_environment_status()})


@signal_monitor_bp.route("/api/networks")
def api_networks():
    current_ssid = core.get_current_connected_ssid()
    wifis = core.AdvancedWifiScanner.scan_all_nearby_wifis()
    cache_snapshot = _cache.snapshot()
    live_devices = cache_snapshot["devices"]
    known_snapshots = _netstore.all()

    networks = []
    for w in wifis:
        ssid = w["ssid"]
        is_connected = (
            ssid == current_ssid
            and ssid not in ("Unknown",)
            and not ssid.startswith("Not connected")
        )
        if is_connected:
            device_count = len(live_devices)
            last_scanned = cache_snapshot["last_scan_at"]
        else:
            snap = known_snapshots.get(ssid)
            device_count = snap["device_count"] if snap else None
            last_scanned = snap["last_connected_at"] if snap else None
        networks.append({
            **w,
            "connected": is_connected,
            "device_count": device_count,
            "last_scanned": last_scanned,
        })

    return jsonify({
        "networks": networks,
        "current_ssid": current_ssid,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
        "environment": core.scanning_environment_status(),
    })


@signal_monitor_bp.route("/api/network-devices")
def api_network_devices():
    ssid = request.args.get("ssid", "")
    current_ssid = core.get_current_connected_ssid()

    if ssid and ssid == current_ssid:
        snap = _cache.snapshot()
        return jsonify({
            "ssid": ssid, "connected": True, "live": True,
            "devices": snap["devices"], "scanned_at": snap["last_scan_at"],
        })

    stored = _netstore.get(ssid)
    if stored:
        return jsonify({
            "ssid": ssid, "connected": False, "live": False,
            "devices": stored["devices"], "scanned_at": stored["last_connected_at"],
            "note": "Showing the last scan from when this machine was connected to "
                    "this network. Connect to it to get a live device list.",
        })

    return jsonify({
        "ssid": ssid, "connected": False, "live": False,
        "devices": [], "scanned_at": None,
        "note": "No device data yet for this network — connect to it first. "
                "Devices can only be discovered on a network this machine is "
                "actually a member of.",
    })


@signal_monitor_bp.route("/api/devices/all-networks")
def api_devices_all_networks():
    devices, networks = core.DeepNetworkScanner.get_all_connected_devices_multi_network()
    alerts = _history.record_scan(devices)
    devices = _history.annotate_with_uptime(devices)
    return jsonify({
        "networks": networks,
        "devices": devices,
        "alerts": alerts,
        "scanned_at": datetime.now().isoformat(timespec="seconds"),
    })


@signal_monitor_bp.route("/api/history")
def api_history():
    return jsonify({
        "events": _history.recent_events(50),
        "known_devices": _history.all_known_devices(),
    })


@signal_monitor_bp.route("/api/traceroute")
def api_traceroute():
    ip = request.args.get("ip")
    if not ip:
        return jsonify({"error": "missing ?ip= parameter"}), 400
    return jsonify(core.DeepNetworkScanner.traceroute_hops(ip))


@signal_monitor_bp.route("/api/bandwidth/self")
def api_bandwidth_self():
    _bandwidth.record_snapshot()
    return jsonify(_bandwidth.get_last_24h_usage())


@signal_monitor_bp.route("/api/export")
def api_export():
    devices = core.DeepNetworkScanner.get_all_connected_devices()
    devices = _history.annotate_with_uptime(devices)
    path = core.export_devices_csv(devices)
    with open(path, "rb") as f:
        data = f.read()
    return Response(
        data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=devices_export.csv"},
    )


@signal_monitor_bp.route("/api/health")
def api_health():
    return jsonify({"status": "ok", "last_scan_at": _cache.snapshot()["last_scan_at"]})


@signal_monitor_bp.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    body = request.get_json(silent=True) or {}
    ssid = (body.get("ssid") or "").strip()
    password = body.get("password") or ""

    if not ssid:
        return jsonify({"success": False, "error": "ssid is required"}), 400

    result = core.WifiConnectionManager.connect(ssid, password)

    if result.get("success"):
        import time
        time.sleep(2.5)
        try:
            devices = core.DeepNetworkScanner.get_all_connected_devices()
            alerts = _history.record_scan(devices)
            devices = _history.annotate_with_uptime(devices)
            local_ip, subnet = core.DeepNetworkScanner.get_local_ip_and_subnet()
            _cache.update(devices, alerts, local_ip, subnet)
            new_ssid = core.get_current_connected_ssid()
            _netstore.save(new_ssid, devices)
            result["current_ssid"] = new_ssid
            result["device_count"] = len(devices)
        except Exception:
            core.logger.exception("Post-connect scan failed")

    return jsonify(result), (200 if result.get("success") else 502)
