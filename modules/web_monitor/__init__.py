"""
Web Monitor blueprint
-----------------------
Thin routing layer around modules/web_monitor/monitor.py (copied
unmodified from the original web-monitor-tool), which does async
subdomain discovery + HTTP/SSL/latency checks for a domain and its
discovered subdomains.
"""

import asyncio

from flask import Blueprint, jsonify, render_template

from .monitor import discover_subdomains, check_all_domains

web_monitor_bp = Blueprint(
    "web_monitor",
    __name__,
    url_prefix="/web-monitor",
)


@web_monitor_bp.route("/")
def index():
    return render_template("web_monitor.html")


@web_monitor_bp.route("/monitor/<path:domain>")
def monitor(domain):
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.rstrip("/")

    domains, discovery_error = discover_subdomains(domain)
    results = asyncio.run(check_all_domains(domains))

    return jsonify({
        "root_domain": domain,
        "total_targets": len(domains),
        "results": results,
        "subdomain_discovery_error": discovery_error,
    })
