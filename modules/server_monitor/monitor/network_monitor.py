"""
Network Monitor -- Phase 3
---------------------------
Background continuous-monitoring engine. Once a server is registered
(monitor/registry.py) and monitoring is started for it, this module
runs a per-server check loop on its own thread at the configured
interval, records UP/DOWN + latency into a bounded in-memory history,
and updates the server's live status snapshot in the registry.

Design points, matching the project spec:
    - Never blocks the Flask request/response cycle: checks run on
      background threads, not inside a route handler.
    - One server's failures (timeouts, exceptions, target offline)
      never affect any other server's monitoring loop -- every check
      is wrapped so an exception is recorded as a failed check, not
      raised into the thread runner.
    - Threads stop gracefully via a threading.Event, not by killing
      the thread.
    - History is capped (config.HISTORY_MAX_RECORDS) so memory usage
      doesn't grow unbounded across a long session.
    - A server only counts as DOWN after config.CONSECUTIVE_FAILURES_
      FOR_DOWN consecutive failed checks, to avoid flapping status on
      one dropped packet.

What "UP" means here: at least one authorized port (or, if none were
explicitly authorized, one of the ports discovered open during
registration, falling back to 80/443) accepted a TCP connection
within the timeout. This is connectivity, not a guarantee the
application behind the port is functioning correctly.
"""

import logging
import socket
import threading
import time
from collections import deque
from datetime import datetime, timezone

from config import (
    CONSECUTIVE_FAILURES_FOR_DOWN,
    HISTORY_MAX_RECORDS,
    PORT_CHECK_TIMEOUT,
)
from monitor import registry

logger = logging.getLogger("monitor.network_monitor")

_lock = threading.Lock()
_history: dict = {}          # server_id -> deque of check records
_threads: dict = {}          # server_id -> threading.Thread
_stop_events: dict = {}      # server_id -> threading.Event


def _default_check_ports(server_id: str) -> list:
    """
    If the user hasn't explicitly authorized specific ports to
    monitor, fall back to whatever was found open during registration
    (from the cached intelligence snapshot), or 80/443 as a last
    resort. This keeps "just start monitoring" usable out of the box
    while still preferring an explicit, user-approved list per the
    spec's "no default aggressive scanning" requirement.
    """
    authorized = registry.get_authorized_ports(server_id)
    if authorized:
        return authorized

    detail = registry.get_server(server_id)
    if detail and detail.get("intelligence"):
        discovered = [p["port"] for p in detail["intelligence"].get("open_ports", [])]
        if discovered:
            return discovered

    return [80, 443]


def measure_tcp_latency(ip: str, port: int, timeout: float = PORT_CHECK_TIMEOUT):
    """
    Attempt a TCP connect and time how long it takes. Returns
    (success: bool, latency_ms: float|None).
    """
    start = time.perf_counter()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            elapsed_ms = (time.perf_counter() - start) * 1000
            return (result == 0), round(elapsed_ms, 2)
    except Exception as e:
        logger.debug("Latency check failed for %s:%s -> %s", ip, port, e)
        return False, None


def run_check(server_id: str, ip: str, ports: list) -> dict:
    """
    Run one full check cycle for a server: TCP reachability/latency
    against each candidate port (first successful port contributes to
    the overall best-latency figure). Never raises -- any failure is
    captured in the returned record rather than propagated.
    """
    timestamp = datetime.now(timezone.utc).isoformat()
    port_results = []
    overall_up = False
    best_latency = None

    for port in ports:
        try:
            success, latency_ms = measure_tcp_latency(ip, port)
        except Exception as e:
            logger.warning("Unexpected error checking %s:%s -> %s", ip, port, e)
            success, latency_ms = False, None

        port_results.append({"port": port, "up": success, "latency_ms": latency_ms})
        if success:
            overall_up = True
            if best_latency is None or (latency_ms is not None and latency_ms < best_latency):
                best_latency = latency_ms

    status = "UP" if overall_up else "DOWN"

    return {
        "timestamp": timestamp,
        "status": status,
        "latency_ms": best_latency,
        "ports_checked": port_results,
    }


def _append_history(server_id: str, record: dict):
    with _lock:
        if server_id not in _history:
            _history[server_id] = deque(maxlen=HISTORY_MAX_RECORDS)
        _history[server_id].append(record)


def get_history(server_id: str, limit: int = None) -> list:
    with _lock:
        records = list(_history.get(server_id, []))
    if limit:
        records = records[-limit:]
    return records


def clear_history(server_id: str):
    with _lock:
        _history.pop(server_id, None)


def check_now(server_id: str):
    """
    Run a single on-demand check outside the background loop (used by
    the /check-now endpoint). Records the result into history and
    updates the registry's live status, so manual and scheduled
    checks are indistinguishable in the history view.
    """
    if not registry.exists(server_id):
        return None, "Server not found."

    ip = registry.get_ip(server_id)
    ports = _default_check_ports(server_id)

    record = run_check(server_id, ip, ports)
    _append_history(server_id, record)
    _update_registry_status(server_id, record)

    return record, None


def _update_registry_status(server_id: str, record: dict):
    """
    Apply the consecutive-failure debounce: only report DOWN after
    CONSECUTIVE_FAILURES_FOR_DOWN consecutive failed checks, so one
    dropped packet doesn't flap the status. A single successful check
    immediately clears the failure streak and reports UP.
    """
    if record["status"] == "UP":
        registry.record_check_result(server_id, "UP", record["latency_ms"])
        return

    registry.record_check_result(server_id, "DOWN", None)
    updated = registry.get_server(server_id)
    if updated and updated["consecutive_failures"] < CONSECUTIVE_FAILURES_FOR_DOWN:
        logger.debug(
            "Server %s failed check %d/%d -- holding before reporting DOWN",
            server_id, updated["consecutive_failures"], CONSECUTIVE_FAILURES_FOR_DOWN,
        )


def _monitor_loop(server_id: str, stop_event: threading.Event):
    logger.info("Monitoring loop started for server %s", server_id)
    while not stop_event.is_set():
        interval = 60
        try:
            if not registry.exists(server_id):
                logger.info("Server %s no longer exists -- stopping its monitor loop", server_id)
                break

            ip = registry.get_ip(server_id)
            ports = _default_check_ports(server_id)
            record = run_check(server_id, ip, ports)
            _append_history(server_id, record)
            _update_registry_status(server_id, record)

            detail = registry.get_server(server_id)
            if detail:
                interval = detail["monitoring_interval_seconds"]
        except Exception:
            # A single server's monitoring failure must never kill its
            # own loop or any other server's loop (each runs on its
            # own thread).
            logger.exception("Unhandled error in monitor loop for server %s", server_id)

        stop_event.wait(interval)

    logger.info("Monitoring loop stopped for server %s", server_id)


def start_monitoring(server_id: str, interval_seconds: int = None, authorized_ports: list = None):
    """
    Start the background check loop for a server.

    Returns:
        (True, None) on success
        (False, "error message") on failure
    """
    if not registry.exists(server_id):
        return False, "Server not found."

    with _lock:
        if server_id in _threads and _threads[server_id].is_alive():
            return False, "Monitoring is already running for this server."

        registry.set_monitoring_config(
            server_id,
            enabled=True,
            interval_seconds=interval_seconds,
            authorized_ports=authorized_ports,
        )

        stop_event = threading.Event()
        thread = threading.Thread(
            target=_monitor_loop,
            args=(server_id, stop_event),
            name=f"monitor-{server_id}",
            daemon=True,
        )
        _stop_events[server_id] = stop_event
        _threads[server_id] = thread
        thread.start()

    logger.info("Monitoring started for server %s", server_id)
    return True, None


def stop_monitoring(server_id: str):
    """
    Signal the background loop for a server to stop and wait briefly
    for it to exit cleanly.
    """
    with _lock:
        stop_event = _stop_events.get(server_id)
        thread = _threads.get(server_id)

    if not stop_event or not thread:
        registry.set_monitoring_config(server_id, enabled=False)
        return False, "Monitoring is not currently running for this server."

    stop_event.set()
    thread.join(timeout=5)

    with _lock:
        _threads.pop(server_id, None)
        _stop_events.pop(server_id, None)

    registry.set_monitoring_config(server_id, enabled=False)
    logger.info("Monitoring stopped for server %s", server_id)
    return True, None


def is_monitoring(server_id: str) -> bool:
    with _lock:
        thread = _threads.get(server_id)
        return bool(thread and thread.is_alive())


def _reset_for_tests():
    """Test-only helper: stop all loops and clear history."""
    with _lock:
        server_ids = list(_stop_events.keys())
    for sid in server_ids:
        stop_monitoring(sid)
    with _lock:
        _history.clear()
