"""
Server Registry
----------------
In-memory registry of servers the user has registered for monitoring.
No database -- this is intentional per the project spec. Everything
here is lost on process restart; JSON export/import lands in a later
phase for anyone who needs to persist across restarts.

This module owns the *data* (what servers exist, their cached
intelligence snapshot). It does NOT run any background checks --
that's monitor/network_monitor.py, coming in Phase 3, which will read
from this same registry to know what to check.

Thread safety: Flask's dev server can handle requests on multiple
threads, so all mutations to the in-memory store go through a single
lock.
"""

import logging
import threading
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from monitor.ip_intelligence import (
    get_geolocation,
    get_rdap_whois,
    get_reverse_dns,
    validate_public_ip,
)
from monitor.service_monitor import scan_common_ports
from monitor.http_monitor import get_http_headers
from monitor.tls_monitor import get_ssl_cert_info
from monitor.domain_discovery import run_domain_discovery

logger = logging.getLogger("monitor.registry")

_lock = threading.Lock()
_servers: dict[str, "Server"] = {}


@dataclass
class Server:
    id: str
    name: str
    ip: str
    ip_version: int
    created_at: str

    # Monitoring configuration -- set via /start, used by
    # monitor/network_monitor.py's background engine (Phase 3).
    monitoring_enabled: bool = False
    monitoring_interval_seconds: int = 60
    authorized_ports: list = field(default_factory=list)

    # Live monitoring status -- written by the background engine, read
    # by the API/UI. None until the first check runs.
    current_status: Optional[str] = None          # "UP" | "DOWN" | None
    current_latency_ms: Optional[float] = None
    last_checked_at: Optional[str] = None
    consecutive_failures: int = 0
    monitoring_started_at: Optional[str] = None

    # Cached public intelligence snapshot -- gathered once at
    # registration time (and on manual refresh) rather than on every
    # request, per the project's "don't hammer external providers"
    # requirement.
    intelligence: Optional[dict] = None
    intelligence_fetched_at: Optional[str] = None

    # Domain/website discovery snapshot (Phase 4) -- candidate domains
    # from the TLS cert, DNS/HTTP verification results, and the
    # service->domain map. Cached the same way as intelligence; run
    # on demand via discover_domains() since it's several extra
    # network calls per candidate domain.
    domain_discovery: Optional[dict] = None
    domain_discovery_fetched_at: Optional[str] = None

    def to_summary(self) -> dict:
        """Compact representation for list views."""
        intel = self.intelligence or {}
        geo = intel.get("geolocation") or {}
        return {
            "id": self.id,
            "name": self.name,
            "ip": self.ip,
            "ip_version": self.ip_version,
            "created_at": self.created_at,
            "monitoring_enabled": self.monitoring_enabled,
            "monitoring_interval_seconds": self.monitoring_interval_seconds,
            "current_status": self.current_status,
            "current_latency_ms": self.current_latency_ms,
            "last_checked_at": self.last_checked_at,
            "country": geo.get("country"),
            "isp": geo.get("isp"),
            "intelligence_fetched_at": self.intelligence_fetched_at,
            "verified_website_count": sum(
                1 for d in (self.domain_discovery or {}).get("domains", [])
                if d.get("status") == "Verified Website"
            ) if self.domain_discovery else None,
        }

    def to_detail(self) -> dict:
        """Full representation for the server detail view."""
        return asdict(self)


def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _gather_intelligence(ip: str) -> dict:
    """
    Run the Phase 1 lookup functions once and bundle the result. This
    is the same data /api/lookup returns, cached onto the server
    record so the detail page doesn't re-query external providers on
    every view.
    """
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

    return {
        "geolocation": geo,
        "reverse_dns": rdns,
        "whois_rdap": whois_data,
        "open_ports": open_ports,
        "http_headers": http_headers,
        "ssl_certificate": ssl_info,
    }


def add_server(name: str, ip_str: str):
    """
    Register a new server.

    Returns:
        (server_dict, None) on success
        (None, "error message") on failure
    """
    name = (name or "").strip()
    if not name:
        return None, "Server name is required."
    if len(name) > 100:
        return None, "Server name is too long (max 100 characters)."

    ip_obj, err = validate_public_ip(ip_str)
    if err:
        return None, err

    ip = str(ip_obj)

    with _lock:
        # Prevent duplicate registration of the same IP.
        for existing in _servers.values():
            if existing.ip == ip:
                return None, f"This IP is already registered as '{existing.name}'."

        server = Server(
            id=_new_id(),
            name=name,
            ip=ip,
            ip_version=ip_obj.version,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        _servers[server.id] = server

    # Gather intelligence outside the lock -- it involves several
    # network calls and shouldn't block other registry operations.
    intel = _gather_intelligence(ip)
    with _lock:
        # Re-check the server wasn't removed while we were fetching.
        if server.id in _servers:
            _servers[server.id].intelligence = intel
            _servers[server.id].intelligence_fetched_at = datetime.now(timezone.utc).isoformat()

    logger.info("Server added: id=%s name=%r ip=%s", server.id, name, ip)
    return get_server(server.id), None


def list_servers() -> list:
    with _lock:
        return [s.to_summary() for s in sorted(_servers.values(), key=lambda s: s.created_at)]


def get_server(server_id: str) -> Optional[dict]:
    with _lock:
        server = _servers.get(server_id)
        return server.to_detail() if server else None


def remove_server(server_id: str) -> bool:
    with _lock:
        existed = server_id in _servers
        if existed:
            removed = _servers.pop(server_id)
            logger.info("Server removed: id=%s name=%r ip=%s", removed.id, removed.name, removed.ip)
        return existed


def refresh_intelligence(server_id: str):
    """
    Re-run the intelligence gather for an already-registered server
    (manual refresh, since the snapshot is otherwise cached).

    Returns:
        (server_dict, None) on success
        (None, "error message") if the server doesn't exist
    """
    with _lock:
        server = _servers.get(server_id)
        if not server:
            return None, "Server not found."
        ip = server.ip

    intel = _gather_intelligence(ip)
    with _lock:
        server = _servers.get(server_id)
        if not server:
            return None, "Server not found."
        server.intelligence = intel
        server.intelligence_fetched_at = datetime.now(timezone.utc).isoformat()

    logger.info("Intelligence refreshed: id=%s ip=%s", server_id, ip)
    return get_server(server_id), None


def get_ip(server_id: str) -> Optional[str]:
    """Lightweight accessor for just the IP -- used by the monitor
    engine, which shouldn't need to know about the full Server shape."""
    with _lock:
        server = _servers.get(server_id)
        return server.ip if server else None


def exists(server_id: str) -> bool:
    with _lock:
        return server_id in _servers


def set_monitoring_config(server_id: str, enabled: bool, interval_seconds: int = None, authorized_ports: list = None):
    """Update a server's monitoring configuration flags."""
    with _lock:
        server = _servers.get(server_id)
        if not server:
            return False
        server.monitoring_enabled = enabled
        if interval_seconds is not None:
            server.monitoring_interval_seconds = interval_seconds
        if authorized_ports is not None:
            server.authorized_ports = authorized_ports
        if enabled:
            server.monitoring_started_at = datetime.now(timezone.utc).isoformat()
        return True


def record_check_result(server_id: str, status: str, latency_ms: Optional[float]):
    """
    Called by the background monitor engine after each check to
    update the server's live status snapshot. Also tracks consecutive
    failures so the engine can apply a debounce before flipping to
    DOWN (see config.CONSECUTIVE_FAILURES_FOR_DOWN).
    """
    with _lock:
        server = _servers.get(server_id)
        if not server:
            return False
        server.current_status = status
        server.current_latency_ms = latency_ms
        server.last_checked_at = datetime.now(timezone.utc).isoformat()
        if status == "DOWN":
            server.consecutive_failures += 1
        else:
            server.consecutive_failures = 0
        return True


def get_authorized_ports(server_id: str) -> list:
    with _lock:
        server = _servers.get(server_id)
        return list(server.authorized_ports) if server else []


def discover_domains(server_id: str, extra_domains: list = None):
    """
    Run the Phase 4 domain/website discovery pipeline for a server and
    cache the result. Uses the open-port list from the cached
    intelligence snapshot (if available) to build the service->domain
    map; re-run refresh_intelligence() first if that snapshot is stale.

    Args:
        extra_domains: optional list of domain names the caller
            already knows about (e.g. from a hosting control panel)
            to verify alongside whatever auto-discovery finds -- see
            run_domain_discovery() docstring for why this matters on
            servers with many domains.

    Returns:
        (server_dict, None) on success
        (None, "error message") if the server doesn't exist
    """
    with _lock:
        server = _servers.get(server_id)
        if not server:
            return None, "Server not found."
        ip = server.ip
        open_ports = (server.intelligence or {}).get("open_ports", [])
        rdns_hostname = ((server.intelligence or {}).get("reverse_dns") or {}).get("hostname")

    result = run_domain_discovery(
        ip, open_ports=open_ports, rdns_hostname=rdns_hostname, extra_domains=extra_domains
    )

    with _lock:
        server = _servers.get(server_id)
        if not server:
            return None, "Server not found."
        server.domain_discovery = result
        server.domain_discovery_fetched_at = datetime.now(timezone.utc).isoformat()

    logger.info(
        "Domain discovery cached: id=%s ip=%s candidates=%d",
        server_id, ip, len(result.get("candidate_domains", [])),
    )
    return get_server(server_id), None


def _reset_for_tests():
    """Test-only helper to clear the registry between test cases."""
    with _lock:
        _servers.clear()
