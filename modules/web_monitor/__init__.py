"""
Web Monitor blueprint — Phase 1.8
===================================
Routing layer + persistence for the Web Monitor.

Phase 1.8 changes vs. earlier version:
  - Every scan is persisted to website_scans + website_scan_results,
    scoped to the current user_id (session["user_id"]).
  - New endpoints:
      GET  /web-monitor/api/history         — user's last 100 scans (summary)
      GET  /web-monitor/api/scan/<scan_id>  — full detail of one past scan
      POST /web-monitor/api/watch           — add a domain to monitored_websites
  - 100-scans-per-user retention cap enforced after every insert.
  - Existing route /web-monitor/monitor/<domain> preserved and unchanged
    from the frontend's perspective — same JSON shape, plus a few
    additive fields (scan_id, checked_at, final_url).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from flask import Blueprint, jsonify, render_template, request, session

from shared.db.sqlite_store import execute, fetch_all, fetch_one, get_conn

from .monitor import check_all_domains, discover_subdomains


logger = logging.getLogger(__name__)


web_monitor_bp = Blueprint(
    "web_monitor",
    __name__,
    url_prefix="/web-monitor",
)


# Retention cap: don't keep more than this many scans per user.
# Enforced after every new insert. See _prune_old_scans().
MAX_SCANS_PER_USER = 100


# ----------------------------------------------------------------------
# Session helper (same pattern as server_monitor)
# ----------------------------------------------------------------------

def _uid() -> Optional[int]:
    """Current user id from session, or None if not signed in."""
    return session.get("user_id")


# ----------------------------------------------------------------------
# Persistence helpers
# ----------------------------------------------------------------------

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _persist_scan(user_id: int, root_domain: str, results: list,
                  discovery_meta: dict, started_at: str) -> int:
    """
    Persist a scan run (parent row) + one child row per target result.

    Uses a single transaction so a mid-write crash never leaves an
    orphan parent scan with missing children.

    Returns: scan_id (int) of the newly-created row.
    """
    # Tally up/down/degraded counts once, here — so we don't compute
    # them again on every history read.
    up_count = down_count = degraded_count = 0
    for r in results:
        status = r.get("overall_status")
        if status == "UP":
            up_count += 1
        elif status == "DEGRADED":
            degraded_count += 1
        else:
            down_count += 1

    completed_at = _now()

    # Single transaction: both parent + all children succeed, or neither.
    with get_conn() as conn:
        cur = conn.execute(
            """
            INSERT INTO website_scans
                (user_id, root_domain, started_at, completed_at,
                 total_targets, up_count, down_count, degraded_count,
                 discovery_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                user_id, root_domain, started_at, completed_at,
                len(results), up_count, down_count, degraded_count,
                json.dumps(discovery_meta or {}),
            ),
        )
        scan_id = cur.lastrowid

        for r in results:
            conn.execute(
                """
                INSERT INTO website_scan_results
                    (scan_id, target, ip, dns_status,
                     server_status, server_port, server_response_time_ms,
                     website_status, protocol, http_status, response_time_ms,
                     overall_status, final_url, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    r.get("domain"),
                    r.get("ip"),
                    r.get("dns_status"),
                    r.get("server_status"),
                    r.get("server_port"),
                    r.get("server_response_time"),
                    r.get("website_status"),
                    r.get("protocol"),
                    r.get("http_status"),
                    r.get("response_time"),
                    r.get("overall_status", "DOWN"),
                    r.get("final_url"),
                    r.get("error"),
                ),
            )

    logger.info(
        "Persisted scan: user_id=%s scan_id=%s root=%s targets=%d",
        user_id, scan_id, root_domain, len(results),
    )

    _prune_old_scans(user_id)
    return scan_id


def _prune_old_scans(user_id: int) -> None:
    """
    Keep only the newest MAX_SCANS_PER_USER scans per user.
    Runs after every insert. Cheap because it uses the
    idx_website_scans_user_time index.

    Deleting a website_scans row cascades to its
    website_scan_results children automatically (FK ON DELETE CASCADE).
    """
    to_delete = fetch_all(
        """
        SELECT id FROM website_scans
        WHERE user_id = ?
        ORDER BY started_at DESC
        LIMIT -1 OFFSET ?
        """,
        (user_id, MAX_SCANS_PER_USER),
    )
    if not to_delete:
        return

    ids = [r["id"] for r in to_delete]
    placeholders = ",".join("?" for _ in ids)
    execute(
        f"DELETE FROM website_scans WHERE id IN ({placeholders})",
        tuple(ids),
    )
    logger.info(
        "Pruned %d old scans for user_id=%s (cap=%d)",
        len(ids), user_id, MAX_SCANS_PER_USER,
    )


def _clean_domain(raw: str) -> str:
    """Strip protocol prefixes and trailing slashes to get a bare domain."""
    d = (raw or "").strip().lower()
    d = d.replace("https://", "").replace("http://", "")
    return d.rstrip("/")


# ----------------------------------------------------------------------
# Pages
# ----------------------------------------------------------------------

@web_monitor_bp.route("/")
def index():
    return render_template("web_monitor.html", active="web")


# ----------------------------------------------------------------------
# API — run a scan (existing endpoint, now persistence-backed)
# ----------------------------------------------------------------------

@web_monitor_bp.route("/monitor/<path:domain>")
def monitor(domain):
    """
    Run a live scan of `domain` (and its discovered subdomains).

    Frontend contract: unchanged JSON shape. New keys added for
    Phase 1.8+ (scan_id, checked_at, final_url per result), but no
    existing keys removed — the current frontend keeps working.
    """
    started_at = _now()
    user_id = _uid()

    domain = _clean_domain(domain)
    if not domain:
        return _no_store(jsonify({"error": "Domain is required."})), 400

    logger.info("Web scan requested: user_id=%s domain=%s", user_id, domain)

    domains, discovery_meta = discover_subdomains(domain)

    try:
        results = asyncio.run(check_all_domains(domains))
    except Exception:
        logger.exception("Scan failed for domain=%s", domain)
        return _no_store(jsonify({
            "root_domain": domain,
            "total_targets": 0,
            "results": [],
            "discovery": discovery_meta,
            "error": "Scan failed. See server logs.",
        })), 500

    # Persist ONLY if we have a real signed-in user (never during
    # e.g. a health-check hitting this endpoint anonymously).
    scan_id = None
    if user_id:
        try:
            scan_id = _persist_scan(user_id, domain, results, discovery_meta, started_at)
        except Exception:
            # Persistence failures should never break the user's scan —
            # they still see the live results. Just log it.
            logger.exception(
                "Failed to persist scan (user_id=%s domain=%s) — returning live results only",
                user_id, domain,
            )

    return _no_store(jsonify({
        "root_domain": domain,
        "total_targets": len(domains),
        "results": results,
        "discovery": discovery_meta,
        "scan_id": scan_id,
        "scanned_at": started_at,
    }))


# ----------------------------------------------------------------------
# API — scan history (NEW)
# ----------------------------------------------------------------------

@web_monitor_bp.route("/api/history", methods=["GET"])
def list_history():
    """
    Return the current user's last MAX_SCANS_PER_USER scans as
    summaries (no per-target rows — that's /api/scan/<id>).
    """
    user_id = _uid()
    if not user_id:
        return _no_store(jsonify({"success": False, "error": "Not signed in."})), 401

    rows = fetch_all(
        """
        SELECT id, root_domain, started_at, completed_at,
               total_targets, up_count, down_count, degraded_count
        FROM website_scans
        WHERE user_id = ?
        ORDER BY started_at DESC
        LIMIT ?
        """,
        (user_id, MAX_SCANS_PER_USER),
    )

    return _no_store(jsonify({"success": True, "data": rows}))


@web_monitor_bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id: int):
    """
    Return full detail of one past scan — its summary row + every
    per-target result row.
    """
    user_id = _uid()
    if not user_id:
        return _no_store(jsonify({"success": False, "error": "Not signed in."})), 401

    scan = fetch_one(
        """
        SELECT id, root_domain, started_at, completed_at,
               total_targets, up_count, down_count, degraded_count,
               discovery_json
        FROM website_scans
        WHERE id = ? AND user_id = ?
        """,
        (scan_id, user_id),
    )
    if not scan:
        return _no_store(jsonify({"success": False, "error": "Scan not found."})), 404

    # Decode discovery JSON so the frontend doesn't have to parse it.
    try:
        scan["discovery"] = json.loads(scan.pop("discovery_json") or "{}")
    except (json.JSONDecodeError, TypeError):
        scan["discovery"] = {}

    results = fetch_all(
        """
        SELECT target, ip, dns_status,
               server_status, server_port, server_response_time_ms,
               website_status, protocol, http_status, response_time_ms,
               overall_status, final_url, error_message
        FROM website_scan_results
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    )

    return _no_store(jsonify({
        "success": True,
        "data": {"scan": scan, "results": results},
    }))


# ----------------------------------------------------------------------
# API — add to watchlist (NEW)
# ----------------------------------------------------------------------

@web_monitor_bp.route("/api/watch", methods=["POST"])
def watch_domain():
    """
    Save a domain to monitored_websites for the current user.

    Phase 1.8 stores the intent only. Automated recurring checks are
    a future phase (background scheduler). For now this just makes
    the domain appear in the user's watchlist and available for
    future recurring monitoring when we build it.
    """
    user_id = _uid()
    if not user_id:
        return _no_store(jsonify({"success": False, "error": "Not signed in."})), 401

    payload = request.get_json(silent=True) or {}
    url = _clean_domain(payload.get("url") or payload.get("domain") or "")
    label = (payload.get("label") or "").strip() or None
    interval = payload.get("check_interval_seconds") or 300

    if not url:
        return _no_store(jsonify({"success": False, "error": "URL/domain is required."})), 400

    if not isinstance(interval, int) or interval < 30:
        return _no_store(jsonify({
            "success": False,
            "error": "check_interval_seconds must be an integer >= 30.",
        })), 400

    existing = fetch_one(
        "SELECT id FROM monitored_websites WHERE user_id = ? AND url = ?",
        (user_id, url),
    )
    if existing:
        return _no_store(jsonify({
            "success": True,
            "data": {"id": existing["id"], "already_watched": True},
        }))

    try:
        new_id = execute(
            """
            INSERT INTO monitored_websites
                (user_id, url, label, check_interval_seconds, enabled, created_at)
            VALUES (?, ?, ?, ?, 1, ?)
            """,
            (user_id, url, label, interval, _now()),
        )
    except Exception as e:
        logger.exception("Failed to add %s to watchlist for user %s", url, user_id)
        return _no_store(jsonify({
            "success": False,
            "error": f"Could not save to watchlist: {e}",
        })), 500

    logger.info("Watchlist add: user_id=%s url=%s id=%s", user_id, url, new_id)
    return _no_store(jsonify({
        "success": True,
        "data": {"id": new_id, "url": url, "already_watched": False},
    })), 201


# ----------------------------------------------------------------------
# API — deep domain analysis (Phase 1.10 — click subdomain feature)
# ----------------------------------------------------------------------

@web_monitor_bp.route("/api/domain/<path:domain>/detail", methods=["GET"])
def domain_detail(domain):
    """
    Deep analysis of a single domain — DNS records (A/AAAA/CNAME/MX/TXT),
    HTTP headers + redirect chain, and full TLS/SSL certificate info.

    Called by the frontend when the user clicks a subdomain in the
    results table. On-demand only, not part of the bulk scan.
    """
    domain = _clean_domain(domain)
    if not domain:
        return _no_store(jsonify({
            "success": False, "error": "Domain is required."
        })), 400

    # Basic validation — reject obviously malformed input
    if len(domain) > 253 or any(c in domain for c in " ?&#/\\"):
        return _no_store(jsonify({
            "success": False, "error": "Invalid domain."
        })), 400

    logger.info("Deep domain detail requested: user_id=%s domain=%s",
                _uid(), domain)

    try:
        from .monitor import analyze_domain_deep
        detail = analyze_domain_deep(domain)
    except Exception:
        logger.exception("Deep analysis failed for domain=%s", domain)
        return _no_store(jsonify({
            "success": False,
            "error": "Deep analysis failed. See server logs.",
        })), 500

    return _no_store(jsonify({"success": True, "data": detail}))

# ----------------------------------------------------------------------
# Cache-control helper — every scan/history response must be fresh
# ----------------------------------------------------------------------

def _no_store(response):
    """
    Apply anti-caching headers. Every response from this blueprint
    represents a live/database read that should NEVER be served from
    a browser or proxy cache — stale monitoring data defeats the
    whole purpose of a monitor.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


# ----------------------------------------------------------------------
# API — subdomain history (Phase 1.10.3-4 — charts + uptime %)
# ----------------------------------------------------------------------

@web_monitor_bp.route("/api/domain/<path:domain>/history", methods=["GET"])
def domain_history(domain):
    """
    Historical scan results for one specific subdomain, scoped to the
    current user.

    Returns:
        - Every scan result row for this target across the user's scans
        - Uptime % calculated over 3 windows (24h / 7d / 30d)
        - Suitable for feeding directly to Chart.js on the frontend

    This is what powers the response-time chart and uptime badges on
    the deep detail modal.
    """
    domain = _clean_domain(domain)
    if not domain:
        return _no_store(jsonify({
            "success": False, "error": "Domain is required."
        })), 400

    user_id = _uid()
    if not user_id:
        return _no_store(jsonify({
            "success": False, "error": "Not signed in."
        })), 401

    # Pull every scan_result row for this target from any of the user's
    # scans. Ordered oldest-first so the chart plots left-to-right.
    rows = fetch_all(
        """
        SELECT ws.started_at AS checked_at,
               wsr.overall_status,
               wsr.http_status,
               wsr.response_time_ms
        FROM website_scan_results wsr
        JOIN website_scans ws ON ws.id = wsr.scan_id
        WHERE ws.user_id = ? AND wsr.target = ?
        ORDER BY ws.started_at ASC
        LIMIT 500
        """,
        (user_id, domain),
    )

    # Uptime buckets (24h / 7d / 30d)
    now = datetime.now(timezone.utc)
    buckets = {
        "24h": {"cutoff": now.timestamp() - 24 * 3600, "up": 0, "total": 0},
        "7d":  {"cutoff": now.timestamp() - 7 * 24 * 3600, "up": 0, "total": 0},
        "30d": {"cutoff": now.timestamp() - 30 * 24 * 3600, "up": 0, "total": 0},
    }

    for r in rows:
        try:
            # started_at is ISO 8601 string — parse to epoch for comparison
            ts = datetime.fromisoformat(r["checked_at"].replace("Z", "+00:00")).timestamp()
        except (ValueError, AttributeError):
            continue

        is_up = r["overall_status"] == "UP"
        for bucket in buckets.values():
            if ts >= bucket["cutoff"]:
                bucket["total"] += 1
                if is_up:
                    bucket["up"] += 1

    uptime = {}
    for name, b in buckets.items():
        if b["total"] == 0:
            uptime[name] = {"percent": None, "checks": 0}
        else:
            uptime[name] = {
                "percent": round((b["up"] / b["total"]) * 100, 2),
                "checks": b["total"],
            }

    return _no_store(jsonify({
        "success": True,
        "data": {
            "domain": domain,
            "total_checks": len(rows),
            "uptime": uptime,
            "history": rows,  # sample list for the chart
        },
    }))