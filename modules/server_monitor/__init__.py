"""
Server Monitor blueprint
--------------------------
Routing layer for the Public/Private Server IP Monitoring & Intelligence
platform. The underlying logic lives in modules/server_monitor/monitor/*.py
and modules/server_monitor/config.py.

Phase 1.5 update:
    Every registry call now includes the current user_id from the
    Flask session, enabling multi-tenant server isolation.
"""

import logging
import socket
from datetime import datetime, timezone

from flask import Blueprint, jsonify, render_template, request, session

from modules.server_monitor.config import (
    INTERNAL_PORTS,
    ALLOWED_INTERVALS_SECONDS,
)
from modules.server_monitor.monitor.ip_intelligence import (
    get_geolocation,
    get_rdap_whois,
    get_reverse_dns,
    validate_public_ip,
    validate_private_ip,
)
from modules.server_monitor.monitor.service_monitor import scan_common_ports
from modules.server_monitor.monitor.http_monitor import get_http_headers
from modules.server_monitor.monitor.tls_monitor import get_ssl_cert_info
from modules.server_monitor.monitor.domain_discovery import run_domain_discovery
from modules.server_monitor.monitor import snmp_monitor
from modules.server_monitor.monitor import vpn_monitor
from modules.server_monitor.monitor import registry
from modules.server_monitor.monitor import network_monitor


# Logging is configured centrally by shared/logging_setup.py at app
# startup. This module just grabs its own named logger.
logger = logging.getLogger("server_monitor")


# ----------------------------------------------------------------------
# Session helper
# ----------------------------------------------------------------------

def _uid():
    """
    Get the current user_id from the Flask session.

    Every route that touches the registry (or any other user-owned
    data) MUST pass this to the registry function. The registry
    itself refuses operations when user_id is None/0, so a missing
    session results in an empty list rather than an unauthorized
    view of another user's data.
    """
    return session.get("user_id")


server_monitor_bp = Blueprint(
    "server_monitor",
    __name__,
    url_prefix="/server-monitor",
)


# ----------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------

@server_monitor_bp.route("/")
def console():
    return render_template("server_monitor/console.html", active="server")


@server_monitor_bp.route("/servers")
def servers_page():
    return render_template("server_monitor/servers.html", active="server")


# ----------------------------------------------------------------------
# API — one-shot lookup (no persistence)
# ----------------------------------------------------------------------

@server_monitor_bp.route("/api/lookup", methods=["POST"])
def lookup():
    payload = request.get_json(silent=True) or {}
    ip_str = (payload.get("ip") or "").strip()

    ip_obj, err = validate_public_ip(ip_str)
    if err:
        logger.info("Rejected lookup request for %r: %s", ip_str, err)
        return jsonify({"success": False, "error": err}), 400

    ip = str(ip_obj)
    logger.info("Running lookup for %s", ip)

    geo = get_geolocation(ip)
    rdns = get_reverse_dns(ip)
    whois_data = get_rdap_whois(ip)
    open_ports = scan_common_ports(ip)

    hostname = rdns.get("hostname")

    has_web_port = any(p["port"] in (80, 443) for p in open_ports)
    http_headers = (
        get_http_headers(ip, hostname=hostname)
        if has_web_port
        else {"note": "Ports 80/443 not open -- skipped HTTP check."}
    )

    has_tls_port = any(p["port"] == 443 for p in open_ports)
    ssl_info = (
        get_ssl_cert_info(ip, hostname=hostname)
        if has_tls_port
        else {"note": "Port 443 not open -- skipped SSL check."}
    )

    return jsonify({
        "success": True,
        "data": {
            "queried_ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "geolocation": geo,
            "reverse_dns": rdns,
            "whois_rdap": whois_data,
            "open_ports": open_ports,
            "http_headers": http_headers,
            "ssl_certificate": ssl_info,
        },
    })


# ----------------------------------------------------------------------
# API — persistent server registry
# ----------------------------------------------------------------------

@server_monitor_bp.route("/api/servers", methods=["POST"])
def create_server():
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    ip = payload.get("ip")

    server, err = registry.add_server(_uid(), name, ip)
    if err:
        logger.info("Rejected server registration (name=%r, ip=%r): %s",
                    name, ip, err)
        return jsonify({"success": False, "error": err}), 400

    return jsonify({"success": True, "data": server}), 201


@server_monitor_bp.route("/api/servers", methods=["GET"])
def list_servers_route():
    return jsonify({"success": True, "data": registry.list_servers(_uid())})


@server_monitor_bp.route("/api/servers/<server_id>", methods=["GET"])
def get_server_route(server_id):
    server = registry.get_server(_uid(), server_id)
    if not server:
        return jsonify({"success": False, "error": "Server not found."}), 404
    return jsonify({"success": True, "data": server})


@server_monitor_bp.route("/api/servers/<server_id>", methods=["DELETE"])
def delete_server_route(server_id):
    existed = registry.remove_server(_uid(), server_id)
    if not existed:
        return jsonify({"success": False, "error": "Server not found."}), 404
    return jsonify({"success": True, "data": {"id": server_id, "deleted": True}})


@server_monitor_bp.route("/api/servers/<server_id>/refresh-intelligence",
                        methods=["POST"])
def refresh_intelligence_route(server_id):
    server, err = registry.refresh_intelligence(_uid(), server_id)
    if err:
        return jsonify({"success": False, "error": err}), 404
    return jsonify({"success": True, "data": server})


@server_monitor_bp.route("/api/servers/<server_id>/start", methods=["POST"])
def start_monitoring_route(server_id):
    payload = request.get_json(silent=True) or {}
    interval = payload.get("interval_seconds")
    authorized_ports = payload.get("authorized_ports")

    if interval is not None and interval not in ALLOWED_INTERVALS_SECONDS:
        return jsonify({
            "success": False,
            "error": f"interval_seconds must be one of {ALLOWED_INTERVALS_SECONDS}",
        }), 400

    if authorized_ports is not None:
        if not isinstance(authorized_ports, list) or not all(
            isinstance(p, int) for p in authorized_ports
        ):
            return jsonify({
                "success": False,
                "error": "authorized_ports must be a list of integers.",
            }), 400

    # network_monitor is still in-memory in Phase 1.5. It signals
    # "server not found" the same way regardless — but we scope by
    # user_id first so users can't start monitoring on someone else's
    # server.
    if not registry.exists(_uid(), server_id):
        return jsonify({"success": False, "error": "Server not found."}), 404

    ok, err = network_monitor.start_monitoring(
        server_id, interval_seconds=interval, authorized_ports=authorized_ports
    )
    if not ok:
        status = 404 if err == "Server not found." else 409
        return jsonify({"success": False, "error": err}), status

    return jsonify({"success": True, "data": registry.get_server(_uid(), server_id)})


@server_monitor_bp.route("/api/servers/<server_id>/stop", methods=["POST"])
def stop_monitoring_route(server_id):
    if not registry.exists(_uid(), server_id):
        return jsonify({"success": False, "error": "Server not found."}), 404

    ok, err = network_monitor.stop_monitoring(server_id)
    if not ok:
        return jsonify({"success": False, "error": err}), 409

    return jsonify({"success": True, "data": registry.get_server(_uid(), server_id)})


@server_monitor_bp.route("/api/servers/<server_id>/status", methods=["GET"])
def server_status_route(server_id):
    server = registry.get_server(_uid(), server_id)
    if not server:
        return jsonify({"success": False, "error": "Server not found."}), 404
    return jsonify({
        "success": True,
        "data": {
            "id": server["id"],
            "name": server["name"],
            "ip": server["ip"],
            "monitoring_enabled": server["monitoring_enabled"],
            "is_running": network_monitor.is_monitoring(server_id),
            "current_status": server["current_status"],
            "current_latency_ms": server["current_latency_ms"],
            "last_checked_at": server["last_checked_at"],
            "consecutive_failures": server["consecutive_failures"],
        },
    })


@server_monitor_bp.route("/api/servers/<server_id>/history", methods=["GET"])
def server_history_route(server_id):
    if not registry.exists(_uid(), server_id):
        return jsonify({"success": False, "error": "Server not found."}), 404

    limit = request.args.get("limit", type=int)
    history = network_monitor.get_history(server_id, limit=limit)
    return jsonify({"success": True, "data": history})


@server_monitor_bp.route("/api/servers/<server_id>/check-now", methods=["POST"])
def check_now_route(server_id):
    if not registry.exists(_uid(), server_id):
        return jsonify({"success": False, "error": "Server not found."}), 404

    record, err = network_monitor.check_now(server_id)
    if err:
        return jsonify({"success": False, "error": err}), 404
    return jsonify({"success": True, "data": record})


@server_monitor_bp.route("/api/servers/<server_id>/discover-domains",
                        methods=["POST"])
def discover_domains_route(server_id):
    payload = request.get_json(silent=True) or {}
    extra_domains = payload.get("domains")
    if extra_domains is not None and not isinstance(extra_domains, list):
        return jsonify({
            "success": False,
            "error": "domains must be a list of strings.",
        }), 400

    server, err = registry.discover_domains(
        _uid(), server_id, extra_domains=extra_domains
    )
    if err:
        return jsonify({"success": False, "error": err}), 404
    return jsonify({"success": True, "data": server})


# ----------------------------------------------------------------------
# API — console (one-shot public scan / VPN monitoring)
# ----------------------------------------------------------------------

@server_monitor_bp.route("/api/console/public-scan", methods=["POST"])
def console_public_scan():
    payload = request.get_json(silent=True) or {}
    ip_str = (payload.get("ip") or "").strip()
    snmp_community = (payload.get("snmp_community") or "").strip() or None

    ip_obj, err = validate_public_ip(ip_str)
    if err:
        return jsonify({"success": False, "error": err}), 400

    ip = str(ip_obj)
    logger.info("Console public scan for %s (snmp=%s)", ip, bool(snmp_community))

    geo = get_geolocation(ip)
    rdns = get_reverse_dns(ip)
    whois_data = get_rdap_whois(ip)
    open_ports = scan_common_ports(ip)
    hostname = rdns.get("hostname")

    has_web_port = any(p["port"] in (80, 443) for p in open_ports)
    http_headers = (
        get_http_headers(ip, hostname=hostname)
        if has_web_port
        else {"note": "Ports 80/443 not open -- skipped HTTP check."}
    )

    has_tls_port = any(p["port"] == 443 for p in open_ports)
    ssl_info = (
        get_ssl_cert_info(ip, hostname=hostname)
        if has_tls_port
        else {"note": "Port 443 not open -- skipped SSL check."}
    )

    domain_discovery = run_domain_discovery(
        ip, open_ports=open_ports, rdns_hostname=hostname
    )

    snmp_result = None
    if snmp_community:
        snmp_result = snmp_monitor.get_system_info(ip, snmp_community, timeout=4)

    return jsonify({
        "success": True,
        "data": {
            "queried_ip": ip,
            "ip_type": "public",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "geolocation": geo,
            "reverse_dns": rdns,
            "whois_rdap": whois_data,
            "open_ports": open_ports,
            "http_headers": http_headers,
            "ssl_certificate": ssl_info,
            "domain_discovery": domain_discovery,
            "snmp": snmp_result,
        },
    })


@server_monitor_bp.route("/api/console/vpn-connect", methods=["POST"])
def console_vpn_connect():
    ip_str = (request.form.get("ip") or "").strip()
    username = request.form.get("vpn_username") or None
    password = request.form.get("vpn_password") or None
    snmp_community = (request.form.get("snmp_community") or "").strip() or None

    ip_obj, err = validate_private_ip(ip_str)
    if err:
        return jsonify({"success": False, "error": err}), 400
    ip = str(ip_obj)

    vpn_file = request.files.get("vpn_config")
    if not vpn_file or not vpn_file.filename:
        return jsonify({
            "success": False,
            "error": "A VPN .ovpn configuration file is required.",
        }), 400

    config_bytes = vpn_file.read()
    if not config_bytes:
        return jsonify({
            "success": False,
            "error": "The uploaded VPN configuration file is empty.",
        }), 400

    logger.info("Console VPN connect requested for %s (user=%s)",
                ip, username or "n/a")
    vpn_result = vpn_monitor.connect(
        config_bytes,
        filename=vpn_file.filename,
        username=username,
        password=password,
    )

    if not vpn_result.get("connected"):
        return jsonify({
            "success": False,
            "error": vpn_result.get("error", "VPN connection failed."),
            "vpn": vpn_result,
        }), 502

    open_ports = scan_common_ports(ip, ports=INTERNAL_PORTS)
    reachable, latency_ms = network_monitor.measure_tcp_latency(
        ip, open_ports[0]["port"] if open_ports else 445
    )

    hostname = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        pass

    has_web_port = any(p["port"] in (80, 443) for p in open_ports)
    http_headers = (
        get_http_headers(ip, hostname=hostname)
        if has_web_port
        else {"note": "No internal web port open."}
    )

    snmp_result = None
    if snmp_community:
        snmp_result = snmp_monitor.get_system_info(ip, snmp_community, timeout=4)

    return jsonify({
        "success": True,
        "data": {
            "queried_ip": ip,
            "ip_type": "private",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vpn": {
                "connection_id": vpn_result["connection_id"],
                "tunnel_ip": vpn_result.get("tunnel_ip"),
                "connected": True,
            },
            "hostname": hostname,
            "reachable": reachable,
            "latency_ms": latency_ms,
            "open_ports": open_ports,
            "http_headers": http_headers,
            "snmp": snmp_result,
        },
    })


@server_monitor_bp.route("/api/console/vpn-disconnect", methods=["POST"])
def console_vpn_disconnect():
    payload = request.get_json(silent=True) or {}
    connection_id = payload.get("connection_id")
    if not connection_id:
        return jsonify({
            "success": False,
            "error": "connection_id is required.",
        }), 400
    result = vpn_monitor.disconnect(connection_id)
    if not result.get("disconnected"):
        return jsonify({"success": False, "error": result.get("error")}), 404
    return jsonify({"success": True, "data": result})