"""
Server Monitor blueprint
--------------------------
Routing layer for the Public/Private Server IP Monitoring & Intelligence
platform. The actual logic lives, unmodified, in
modules/server_monitor/monitor/*.py and modules/server_monitor/config.py,
copied straight from the original Server-IP-Monitoring-Tool project.

Those files use absolute imports written for a flat project layout
(`import config`, `from monitor.xxx import ...`), so this package's own
directory is added to sys.path before importing them, letting them work
unmodified inside the unified app.
"""

import os
import sys
import logging
from datetime import datetime, timezone

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
if _THIS_DIR not in sys.path:
    sys.path.insert(0, _THIS_DIR)

from flask import Blueprint, jsonify, render_template, request

from config import LOG_FILE, INTERNAL_PORTS, ALLOWED_INTERVALS_SECONDS  # noqa: E402
from monitor.ip_intelligence import (  # noqa: E402
    get_geolocation,
    get_rdap_whois,
    get_reverse_dns,
    validate_public_ip,
    validate_private_ip,
)
from monitor.service_monitor import scan_common_ports  # noqa: E402
from monitor.http_monitor import get_http_headers  # noqa: E402
from monitor.tls_monitor import get_ssl_cert_info  # noqa: E402
from monitor.domain_discovery import run_domain_discovery  # noqa: E402
from monitor import snmp_monitor  # noqa: E402
from monitor import vpn_monitor  # noqa: E402
from monitor import registry  # noqa: E402
from monitor import network_monitor  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
logger = logging.getLogger("server_monitor")

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
    return render_template("server_monitor/console.html")


@server_monitor_bp.route("/servers")
def servers_page():
    return render_template("server_monitor/servers.html")


# ----------------------------------------------------------------------
# API
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


@server_monitor_bp.route("/api/servers", methods=["POST"])
def create_server():
    payload = request.get_json(silent=True) or {}
    name = payload.get("name")
    ip = payload.get("ip")

    server, err = registry.add_server(name, ip)
    if err:
        logger.info("Rejected server registration (name=%r, ip=%r): %s", name, ip, err)
        return jsonify({"success": False, "error": err}), 400

    return jsonify({"success": True, "data": server}), 201


@server_monitor_bp.route("/api/servers", methods=["GET"])
def list_servers_route():
    return jsonify({"success": True, "data": registry.list_servers()})


@server_monitor_bp.route("/api/servers/<server_id>", methods=["GET"])
def get_server_route(server_id):
    server = registry.get_server(server_id)
    if not server:
        return jsonify({"success": False, "error": "Server not found."}), 404
    return jsonify({"success": True, "data": server})


@server_monitor_bp.route("/api/servers/<server_id>", methods=["DELETE"])
def delete_server_route(server_id):
    existed = registry.remove_server(server_id)
    if not existed:
        return jsonify({"success": False, "error": "Server not found."}), 404
    return jsonify({"success": True, "data": {"id": server_id, "deleted": True}})


@server_monitor_bp.route("/api/servers/<server_id>/refresh-intelligence", methods=["POST"])
def refresh_intelligence_route(server_id):
    server, err = registry.refresh_intelligence(server_id)
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
        if not isinstance(authorized_ports, list) or not all(isinstance(p, int) for p in authorized_ports):
            return jsonify({"success": False, "error": "authorized_ports must be a list of integers."}), 400

    ok, err = network_monitor.start_monitoring(
        server_id, interval_seconds=interval, authorized_ports=authorized_ports
    )
    if not ok:
        status = 404 if err == "Server not found." else 409
        return jsonify({"success": False, "error": err}), status

    return jsonify({"success": True, "data": registry.get_server(server_id)})


@server_monitor_bp.route("/api/servers/<server_id>/stop", methods=["POST"])
def stop_monitoring_route(server_id):
    ok, err = network_monitor.stop_monitoring(server_id)
    if not ok:
        status = 404 if not registry.exists(server_id) else 409
        return jsonify({"success": False, "error": err}), status
    return jsonify({"success": True, "data": registry.get_server(server_id)})


@server_monitor_bp.route("/api/servers/<server_id>/status", methods=["GET"])
def server_status_route(server_id):
    server = registry.get_server(server_id)
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
    if not registry.exists(server_id):
        return jsonify({"success": False, "error": "Server not found."}), 404

    limit = request.args.get("limit", type=int)
    history = network_monitor.get_history(server_id, limit=limit)
    return jsonify({"success": True, "data": history})


@server_monitor_bp.route("/api/servers/<server_id>/check-now", methods=["POST"])
def check_now_route(server_id):
    record, err = network_monitor.check_now(server_id)
    if err:
        return jsonify({"success": False, "error": err}), 404
    return jsonify({"success": True, "data": record})


@server_monitor_bp.route("/api/servers/<server_id>/discover-domains", methods=["POST"])
def discover_domains_route(server_id):
    payload = request.get_json(silent=True) or {}
    extra_domains = payload.get("domains")
    if extra_domains is not None and not isinstance(extra_domains, list):
        return jsonify({"success": False, "error": "domains must be a list of strings."}), 400

    server, err = registry.discover_domains(server_id, extra_domains=extra_domains)
    if err:
        return jsonify({"success": False, "error": err}), 404
    return jsonify({"success": True, "data": server})


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

    domain_discovery = run_domain_discovery(ip, open_ports=open_ports, rdns_hostname=hostname)

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
        return jsonify({"success": False, "error": "A VPN .ovpn configuration file is required."}), 400

    config_bytes = vpn_file.read()
    if not config_bytes:
        return jsonify({"success": False, "error": "The uploaded VPN configuration file is empty."}), 400

    logger.info("Console VPN connect requested for %s (user=%s)", ip, username or "n/a")
    vpn_result = vpn_monitor.connect(
        config_bytes, filename=vpn_file.filename, username=username, password=password
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
        import socket
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    has_web_port = any(p["port"] in (80, 443) for p in open_ports)
    http_headers = get_http_headers(ip, hostname=hostname) if has_web_port else {"note": "No internal web port open."}

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
        return jsonify({"success": False, "error": "connection_id is required."}), 400
    result = vpn_monitor.disconnect(connection_id)
    if not result.get("disconnected"):
        return jsonify({"success": False, "error": result.get("error")}), 404
    return jsonify({"success": True, "data": result})