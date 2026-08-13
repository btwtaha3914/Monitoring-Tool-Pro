"""
Server Registry — SQLite-backed
================================
Persistent registry of servers per user.

Phase 1.5: in-memory dict → SQLite tables (servers, server_intelligence,
server_domains). Every function takes user_id for multi-tenant isolation.

Phase 1.9 bug fix:
    - Removed the __discovery__ marker-row hack that violated the
      server_intelligence FK constraint. Domain discovery payload
      is now reconstructed from server_domains rows on read.
    - Added get_user_id_for_server() helper so background code
      (network_monitor) can find a server's owner without needing
      the Flask session.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from shared.db.sqlite_store import execute, fetch_all, fetch_one, get_conn

from modules.server_monitor.monitor.ip_intelligence import (
    get_geolocation,
    get_rdap_whois,
    get_reverse_dns,
    validate_public_ip,
)
from modules.server_monitor.monitor.service_monitor import scan_common_ports
from modules.server_monitor.monitor.http_monitor import get_http_headers
from modules.server_monitor.monitor.tls_monitor import get_ssl_cert_info
from modules.server_monitor.monitor.domain_discovery import run_domain_discovery

logger = logging.getLogger("monitor.registry")


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _new_id() -> str:
    return uuid.uuid4().hex[:12]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_user_id_for_server(server_id: str) -> Optional[int]:
    """
    Look up the owner of a server. Used by background code (like
    network_monitor) that has a server_id but no session context —
    it can find the owner from the DB and then call the user-scoped
    registry functions correctly.
    """
    row = fetch_one("SELECT user_id FROM servers WHERE id = ?", (server_id,))
    return row["user_id"] if row else None


def _row_to_summary(row: dict, intelligence_data: Optional[dict] = None,
                    verified_website_count: Optional[int] = None) -> dict:
    intel = intelligence_data or {}
    geo = intel.get("geolocation") or {}
    return {
        "id": row["id"],
        "name": row["name"],
        "ip": row["ip"],
        "ip_version": row["ip_version"],
        "created_at": row["created_at"],
        "monitoring_enabled": bool(row["monitoring_enabled"]),
        "monitoring_interval_seconds": row["monitoring_interval_seconds"],
        "current_status": row["current_status"],
        "current_latency_ms": row["current_latency_ms"],
        "last_checked_at": row["last_checked_at"],
        "country": geo.get("country"),
        "isp": geo.get("isp"),
        "intelligence_fetched_at": intel.get("_fetched_at"),
        "verified_website_count": verified_website_count,
    }


def _row_to_detail(row: dict, intelligence_data: Optional[dict],
                   intelligence_fetched_at: Optional[str],
                   domain_discovery_data: Optional[dict],
                   domain_discovery_fetched_at: Optional[str]) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "ip": row["ip"],
        "ip_version": row["ip_version"],
        "created_at": row["created_at"],
        "monitoring_enabled": bool(row["monitoring_enabled"]),
        "monitoring_interval_seconds": row["monitoring_interval_seconds"],
        "authorized_ports": json.loads(row["authorized_ports_json"] or "[]"),
        "current_status": row["current_status"],
        "current_latency_ms": row["current_latency_ms"],
        "last_checked_at": row["last_checked_at"],
        "consecutive_failures": row["consecutive_failures"],
        "monitoring_started_at": row["monitoring_started_at"],
        "intelligence": intelligence_data,
        "intelligence_fetched_at": intelligence_fetched_at,
        "domain_discovery": domain_discovery_data,
        "domain_discovery_fetched_at": domain_discovery_fetched_at,
    }


def _load_intelligence(server_id: str) -> tuple[Optional[dict], Optional[str]]:
    row = fetch_one(
        "SELECT data_json, fetched_at FROM server_intelligence WHERE server_id = ?",
        (server_id,),
    )
    if not row:
        return None, None
    try:
        data = json.loads(row["data_json"])
    except (json.JSONDecodeError, TypeError):
        logger.warning("Corrupt intelligence JSON for server_id=%s", server_id)
        return None, row["fetched_at"]
    return data, row["fetched_at"]


def _save_intelligence(server_id: str, intel: dict) -> None:
    now = _now()
    execute(
        """
        INSERT OR REPLACE INTO server_intelligence (server_id, data_json, fetched_at)
        VALUES (?, ?, ?)
        """,
        (server_id, json.dumps(intel), now),
    )


def _load_domain_discovery(server_id: str) -> tuple[Optional[dict], Optional[str], int]:
    """
    Phase 1.9 fix: reconstruct payload from server_domains rows.
    The previous version stored a "__discovery__<id>" marker row in
    server_intelligence, which violated the FK constraint. Now we
    just rebuild from the child rows — enough for the UI's domain
    table without needing a separate payload store.
    """
    rows = fetch_all(
        "SELECT domain, status, discovered_via, discovered_at "
        "FROM server_domains WHERE server_id = ? "
        "ORDER BY discovered_at DESC",
        (server_id,),
    )
    if not rows:
        return None, None, 0

    payload = {
        "domains": [
            {
                "domain": r["domain"],
                "status": r["status"],
                "source": r["discovered_via"],
            }
            for r in rows
        ],
        "candidate_domains": [r["domain"] for r in rows],
    }
    fetched_at = rows[0]["discovered_at"]
    verified_count = sum(1 for r in rows if r["status"] == "Verified Website")
    return payload, fetched_at, verified_count


def _save_domain_discovery(server_id: str, result: dict) -> None:
    """
    Persist domain discovery result. Phase 1.9 fix: no longer writes
    a __discovery__ marker row into server_intelligence. Only writes
    per-domain rows into server_domains, which is enough to
    reconstruct what the UI needs.
    """
    now = _now()

    # Clear prior discovery for this server
    execute("DELETE FROM server_domains WHERE server_id = ?", (server_id,))

    # Insert each domain
    domains = (result or {}).get("domains") or []
    for d in domains:
        try:
            execute(
                """
                INSERT INTO server_domains
                    (server_id, domain, status, discovered_via, discovered_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    server_id,
                    d.get("domain", ""),
                    d.get("status", "Candidate"),
                    d.get("source"),
                    now,
                ),
            )
        except Exception as e:
            logger.warning("Could not persist domain row %r: %s", d, e)


def _gather_intelligence(ip: str) -> dict:
    """
    Bundle IP intelligence. Cached on server_intelligence so we don't
    re-hit external providers on every request.
    """
    geo = get_geolocation(ip)
    rdns = get_reverse_dns(ip)
    whois_data = get_rdap_whois(ip)
    open_ports = scan_common_ports(ip)

    hostname = (rdns or {}).get("hostname")
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
        "_fetched_at": _now(),
    }


# ----------------------------------------------------------------------
# Public API — user_id-aware
# ----------------------------------------------------------------------

def add_server(user_id: int, name: str, ip_str: str):
    if not user_id:
        return None, "Not signed in."

    name = (name or "").strip()
    if not name:
        return None, "Server name is required."
    if len(name) > 100:
        return None, "Server name is too long (max 100 characters)."

    ip_obj, err = validate_public_ip(ip_str)
    if err:
        return None, err

    ip = str(ip_obj)

    existing = fetch_one(
        "SELECT name FROM servers WHERE user_id = ? AND ip = ?",
        (user_id, ip),
    )
    if existing:
        return None, f"This IP is already registered as '{existing['name']}'."

    server_id = _new_id()
    now = _now()

    try:
        execute(
            """
            INSERT INTO servers
                (id, user_id, name, ip, ip_version, created_at,
                 monitoring_enabled, monitoring_interval_seconds,
                 authorized_ports_json, consecutive_failures)
            VALUES (?, ?, ?, ?, ?, ?, 0, 60, '[]', 0)
            """,
            (server_id, user_id, name, ip, ip_obj.version, now),
        )
    except Exception as e:
        logger.exception("Failed to insert server for user %s ip %s", user_id, ip)
        return None, f"Could not register server: {e}"

    try:
        intel = _gather_intelligence(ip)
        _save_intelligence(server_id, intel)
    except Exception:
        logger.exception("Intelligence gathering failed for %s (server still registered)", ip)

    logger.info("Server added: user_id=%s id=%s name=%r ip=%s",
                user_id, server_id, name, ip)
    return get_server(user_id, server_id), None


def list_servers(user_id: int) -> list:
    if not user_id:
        return []

    rows = fetch_all(
        "SELECT * FROM servers WHERE user_id = ? ORDER BY created_at ASC",
        (user_id,),
    )

    result = []
    for row in rows:
        intel, _ = _load_intelligence(row["id"])
        _, _, verified_count = _load_domain_discovery(row["id"])
        result.append(_row_to_summary(row, intel, verified_count or None))
    return result


def get_server(user_id: int, server_id: str) -> Optional[dict]:
    if not user_id or not server_id:
        return None

    row = fetch_one(
        "SELECT * FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    if not row:
        return None

    intel, intel_at = _load_intelligence(server_id)
    disc, disc_at, _ = _load_domain_discovery(server_id)
    return _row_to_detail(row, intel, intel_at, disc, disc_at)


def remove_server(user_id: int, server_id: str) -> bool:
    """
    Phase 1.9 fix: removed the extra DELETE for the __discovery__
    marker row (that row is never created anymore).
    """
    if not user_id or not server_id:
        return False

    with get_conn() as conn:
        row = conn.execute(
            "SELECT name, ip FROM servers WHERE id = ? AND user_id = ?",
            (server_id, user_id),
        ).fetchone()
        if not row:
            return False

        conn.execute("DELETE FROM servers WHERE id = ? AND user_id = ?",
                     (server_id, user_id))

    logger.info("Server removed: user_id=%s id=%s name=%r ip=%s",
                user_id, server_id, row["name"], row["ip"])
    return True


def refresh_intelligence(user_id: int, server_id: str):
    if not user_id:
        return None, "Not signed in."

    row = fetch_one(
        "SELECT ip FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    if not row:
        return None, "Server not found."

    intel = _gather_intelligence(row["ip"])
    _save_intelligence(server_id, intel)

    logger.info("Intelligence refreshed: user_id=%s id=%s ip=%s",
                user_id, server_id, row["ip"])
    return get_server(user_id, server_id), None


def get_ip(user_id: int, server_id: str) -> Optional[str]:
    if not user_id or not server_id:
        return None
    row = fetch_one(
        "SELECT ip FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    return row["ip"] if row else None


def exists(user_id: int, server_id: str) -> bool:
    if not user_id or not server_id:
        return False
    row = fetch_one(
        "SELECT 1 FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    return row is not None


def set_monitoring_config(user_id: int, server_id: str, enabled: bool,
                          interval_seconds: Optional[int] = None,
                          authorized_ports: Optional[list] = None) -> bool:
    if not user_id:
        return False

    row = fetch_one(
        "SELECT id FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    if not row:
        return False

    fields = ["monitoring_enabled = ?"]
    params: list = [1 if enabled else 0]

    if interval_seconds is not None:
        fields.append("monitoring_interval_seconds = ?")
        params.append(int(interval_seconds))

    if authorized_ports is not None:
        fields.append("authorized_ports_json = ?")
        params.append(json.dumps(list(authorized_ports)))

    if enabled:
        fields.append("monitoring_started_at = ?")
        params.append(_now())

    params.extend([server_id, user_id])
    execute(
        f"UPDATE servers SET {', '.join(fields)} WHERE id = ? AND user_id = ?",
        tuple(params),
    )
    return True


def record_check_result(user_id: int, server_id: str, status: str,
                        latency_ms: Optional[float]) -> bool:
    if not user_id:
        return False

    row = fetch_one(
        "SELECT consecutive_failures FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    if not row:
        return False

    new_failures = (row["consecutive_failures"] + 1) if status == "DOWN" else 0
    execute(
        """
        UPDATE servers
        SET current_status = ?,
            current_latency_ms = ?,
            last_checked_at = ?,
            consecutive_failures = ?
        WHERE id = ? AND user_id = ?
        """,
        (status, latency_ms, _now(), new_failures, server_id, user_id),
    )

    execute(
        """
        INSERT INTO server_history (server_id, checked_at, status, latency_ms)
        VALUES (?, ?, ?, ?)
        """,
        (server_id, _now(), status, latency_ms),
    )
    return True


def get_authorized_ports(user_id: int, server_id: str) -> list:
    if not user_id or not server_id:
        return []
    row = fetch_one(
        "SELECT authorized_ports_json FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    if not row:
        return []
    try:
        return list(json.loads(row["authorized_ports_json"] or "[]"))
    except (json.JSONDecodeError, TypeError):
        return []


def discover_domains(user_id: int, server_id: str,
                     extra_domains: Optional[list] = None):
    if not user_id:
        return None, "Not signed in."

    row = fetch_one(
        "SELECT ip FROM servers WHERE id = ? AND user_id = ?",
        (server_id, user_id),
    )
    if not row:
        return None, "Server not found."

    ip = row["ip"]

    intel, _ = _load_intelligence(server_id)
    open_ports = (intel or {}).get("open_ports", [])
    rdns_hostname = ((intel or {}).get("reverse_dns") or {}).get("hostname")

    result = run_domain_discovery(
        ip,
        open_ports=open_ports,
        rdns_hostname=rdns_hostname,
        extra_domains=extra_domains,
    )

    _save_domain_discovery(server_id, result or {})

    logger.info(
        "Domain discovery cached: user_id=%s id=%s ip=%s candidates=%d",
        user_id, server_id, ip,
        len((result or {}).get("candidate_domains", [])),
    )
    return get_server(user_id, server_id), None


def _reset_for_tests(user_id: Optional[int] = None) -> None:
    if user_id is None:
        execute("DELETE FROM servers")
    else:
        execute("DELETE FROM servers WHERE user_id = ?", (user_id,))