"""
Central configuration for the Public IP Server Monitoring platform.

Phase 1 only needs the request/timeout values that the existing
lookup functions already relied on. Later phases (monitoring
intervals, thresholds, history size) will extend this file —
nothing here should need to move once that happens.
"""

import os

# ---- Network request timeouts -------------------------------------------
REQUEST_TIMEOUT = 5          # seconds, for HTTP/RDAP/geolocation API calls
PORT_CHECK_TIMEOUT = 1.2     # seconds, for the lightweight TCP connect check

# ---- Common services checked by the lightweight port check --------------
# NOTE: this is an explicit, small, well-known list — not a scan range.
# Phase 3 will turn this into a user-configurable "authorized services"
# list per server rather than a fixed global list.
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    27017: "MongoDB",
}

# ---- Extra ports checked once a private-network IP is reachable over a
# VPN tunnel -- internal services that would never be exposed publicly
# but are exactly what "see everything on this server" means on a LAN.
INTERNAL_EXTRA_PORTS = {
    445: "SMB",
    139: "NetBIOS",
    389: "LDAP",
    636: "LDAPS",
    88: "Kerberos",
    161: "SNMP",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    111: "RPCBind",
    2049: "NFS",
    9100: "Printer (JetDirect)",
    623: "IPMI",
}
INTERNAL_PORTS = {**COMMON_PORTS, **INTERNAL_EXTRA_PORTS}

# ---- Monitoring defaults (Phase 3) ---------------------------------------
# Interval choices offered to the user, in seconds.
ALLOWED_INTERVALS_SECONDS = [30, 60, 300, 600, 900, 1800, 3600]
DEFAULT_MONITORING_INTERVAL_SECONDS = 60

# How many history records to keep per server before the oldest are
# dropped. Keeps memory bounded since there's no database.
HISTORY_MAX_RECORDS = 500

# A server is considered DOWN after this many consecutive failed checks
# (avoids flapping on a single dropped packet).
CONSECUTIVE_FAILURES_FOR_DOWN = 2

# ---- Domain discovery (Certificate Transparency via crt.sh) --------------
CT_ENABLED = True
CT_TIMEOUT = 8               # seconds
CT_MAX_SEED_DOMAINS = 3      # how many registrable domains to query CT for
CT_MAX_RESULTS_PER_SEED = 100  # cap rows pulled back per CT query
MAX_CANDIDATE_DOMAINS = 200  # overall cap on candidate domains per server

# ---- Paths ----------------------------------------------------------------
if os.environ.get("VERCEL"):
    BASE_DIR = "/tmp/monitor_suite_server_monitor"
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "logs")
DATA_DIR = os.path.join(BASE_DIR, "data")
EXPORTS_DIR = os.path.join(BASE_DIR, "exports")

for _dir in (LOG_DIR, DATA_DIR, EXPORTS_DIR):
    os.makedirs(_dir, exist_ok=True)

LOG_FILE = os.path.join(LOG_DIR, "app.log")
