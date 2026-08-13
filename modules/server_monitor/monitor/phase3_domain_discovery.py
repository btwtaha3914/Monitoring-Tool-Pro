"""
Domain Discovery (Phase 3)
---------------------------
This is the pipeline described in the project spec, sections 3-8: given a
public server IP, collect *candidate* domain names from multiple public
signals, normalize them, deduplicate them, and hand back a labeled,
source-tagged list.

Sources implemented here:
    1. Reverse DNS / PTR      (monitor.ip_intelligence.get_reverse_dns)
    2. TLS Certificate SAN    (monitor.tls_monitor.get_ssl_cert_info)
    3. Certificate Transparency (crt.sh, public, no API key/auth)

WHAT THIS MODULE DELIBERATELY DOES NOT DO
    - It does not resolve DNS for candidates or check whether they
      currently point at the target IP. That's DNS correlation
      (Phase 4 -- monitor/domain_verification.py).
    - It does not make HTTP/HTTPS requests to candidates to verify a
      live website. Also Phase 4.
    - It does not assign a final "confidence" score. Everything coming
      out of this module is UNSCORED / NOT_CHECKED on those fields --
      Phase 4 fills them in.
    - It does not scan the target server itself beyond what Phases 1-2
      already do (TLS handshake, HTTP headers). Certificate Transparency
      is a lookup against a public third-party log, not a probe of the
      server.

A domain showing up here is a CANDIDATE ASSOCIATION, not proof the
domain is hosted on this server. See project spec section 3.
"""

import logging
import re
from typing import Iterable, Optional

import requests

from modules.server_monitor.config import (
    CT_ENABLED,
    CT_MAX_RESULTS_PER_SEED,
    CT_MAX_SEED_DOMAINS,
    CT_TIMEOUT,
    MAX_CANDIDATE_DOMAINS,
)

logger = logging.getLogger("monitor.domain_discovery")

# ---------------------------------------------------------------------------
# Source labels -- used consistently across this module and, later, the
# domain inventory UI (project spec sections 5-7, 16, 40).
# ---------------------------------------------------------------------------
SOURCE_PTR = "Reverse DNS (PTR)"
SOURCE_TLS = "TLS Certificate"
SOURCE_CT = "Certificate Transparency"

CATEGORY_REVERSE_DNS = "Reverse-DNS Hostname"
CATEGORY_CERT_ASSOCIATED = "Certificate-Associated"
CATEGORY_CANDIDATE = "Candidate"

# ---------------------------------------------------------------------------
# Hostname validation / normalization
# ---------------------------------------------------------------------------
# Deliberately conservative: label, dot, label..., dot, alpha TLD.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,63}$"
)

# A small set of known two-part public suffixes, used only to pick a
# sensible "registrable domain" as a Certificate Transparency query seed.
# This is NOT a full Public Suffix List -- good enough to turn
# "api.example.co.uk" into a CT query for "example.co.uk" rather than the
# useless "co.uk", but it will not be correct for every ccTLD. Phase 4 can
# swap in the `tldextract` package if more accuracy is needed there.
_MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "sch.uk", "ltd.uk", "me.uk",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in", "firm.in",
    "com.br", "net.br", "org.br", "gov.br",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "gov.za",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.mx", "com.sg", "com.hk", "com.tw",
}


def is_valid_hostname(name: str) -> bool:
    """Structural validity only -- does not check that the name resolves."""
    return bool(name) and bool(_HOSTNAME_RE.match(name))


def normalize_hostname(raw: str) -> Optional[str]:
    """
    Lowercase, strip trailing dot and leading wildcard label, drop any
    accidental scheme/port/path fragments, and validate. Returns None
    for anything that isn't a plausible hostname (e.g. an IP address
    presented as a SAN entry, or a malformed CT log row).
    """
    if not raw:
        return None
    name = raw.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    # Defensive: some CT rows / SAN entries include a scheme, port, or path.
    name = name.split("/")[0].split(" ")[0]
    if ":" in name and not name.count(":") > 1:  # keep IPv6-looking junk out below anyway
        name = name.split(":")[0]
    if not name or not is_valid_hostname(name):
        return None
    return name


def registrable_domain(hostname: str) -> str:
    """
    Best-effort eTLD+1 extraction (see module docstring caveat above).
    Used only to choose a Certificate Transparency query seed, never
    shown to the user as an authoritative answer.
    """
    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname
    last_two = ".".join(labels[-2:])
    if len(labels) >= 3:
        last_three = ".".join(labels[-3:])
        if last_two in _MULTI_PART_SUFFIXES:
            return last_three
    return last_two


# ---------------------------------------------------------------------------
# Source 3: Certificate Transparency (crt.sh)
# ---------------------------------------------------------------------------
def query_certificate_transparency(seed_domain: str, timeout: float = None):
    """
    Query crt.sh (a free, public Certificate Transparency log aggregator,
    no API key or authentication) for '%.<seed_domain>' -- i.e. the
    domain and any subdomains that have ever had a publicly-logged
    certificate.

    This queries a third-party public log about the *domain*, not the
    target server -- consistent with the project's "no aggressive
    scanning of the target" rule.

    Returns:
        (names, error) -- names is a sorted, deduplicated list of raw
        hostnames as they appeared in the log (wildcards/case not yet
        normalized -- callers should still run them through
        normalize_hostname). error is None on success, or a short
        human-readable string on failure. A failure here must not raise
        and must not break the rest of discovery (spec section 48).
    """
    timeout = timeout or CT_TIMEOUT
    try:
        resp = requests.get(
            "https://crt.sh/",
            params={"q": f"%.{seed_domain}", "output": "json"},
            headers={"Accept": "application/json", "User-Agent": "server-monitor-domain-discovery/1.0"},
            timeout=timeout,
        )
        resp.raise_for_status()
        rows = resp.json()
    except requests.exceptions.Timeout:
        logger.info("CT lookup timed out for seed %s", seed_domain)
        return [], "Certificate Transparency lookup timed out."
    except requests.exceptions.RequestException as e:
        logger.info("CT lookup failed for seed %s: %s", seed_domain, e)
        return [], f"Certificate Transparency lookup failed: {e}"
    except ValueError:
        logger.info("CT lookup for seed %s returned non-JSON response", seed_domain)
        return [], "Certificate Transparency service returned an unexpected response."

    if not isinstance(rows, list):
        return [], "Certificate Transparency service returned an unexpected response."

    names = set()
    for row in rows:
        name_value = (row or {}).get("name_value", "") if isinstance(row, dict) else ""
        # crt.sh packs multiple SANs from one certificate into one
        # newline-separated field.
        for line in name_value.splitlines():
            line = line.strip()
            if line:
                names.add(line)

    return sorted(names)[:CT_MAX_RESULTS_PER_SEED], None


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def _categorize(sources: set) -> str:
    if sources == {SOURCE_PTR}:
        return CATEGORY_REVERSE_DNS
    if SOURCE_TLS in sources or SOURCE_CT in sources:
        return CATEGORY_CERT_ASSOCIATED
    return CATEGORY_CANDIDATE


def _extract_san_dns_names(san_entries: Optional[Iterable]) -> list:
    """
    ssl.getpeercert()'s subjectAltName looks like:
        (("DNS", "example.com"), ("DNS", "*.example.com"), ("IP Address", "1.2.3.4"))
    We only want the DNS entries.
    """
    names = []
    if not san_entries:
        return names
    for entry in san_entries:
        if isinstance(entry, (list, tuple)) and len(entry) == 2 and entry[0] == "DNS":
            names.append(entry[1])
    return names


def discover_domains(ip: str, rdns_hostname: str = None, san_entries=None) -> dict:
    """
    Run the full Phase 3 discovery pipeline for one server and return a
    structured, source-labeled candidate list.

    Args:
        ip: the target public IP (recorded on the result for context).
        rdns_hostname: hostname from get_reverse_dns(ip), if any.
        san_entries: the 'san' field from get_ssl_cert_info(ip, ...), if
            any -- i.e. the raw subjectAltName tuple from the cert the
            server itself presented on :443.

    Returns a dict:
        {
          "target_ip": "...",
          "candidates": [
              {
                "domain": "api.example.com",
                "sources": ["TLS Certificate"],
                "category": "Certificate-Associated",
                "wildcard_derived": false,
                "dns_association": "NOT_CHECKED",
                "http_verification": "NOT_CHECKED",
                "confidence": "UNSCORED",
              },
              ...
          ],
          "ct_seed_domains": [...],
          "ct_query_results": {seed: {"count": N, "error": None|str}},
          "total_candidates": N,
          "truncated": bool,
          "note": "...",
        }
    """
    candidates: dict = {}

    def add(domain_raw, source, wildcard=False):
        domain = normalize_hostname(domain_raw)
        if not domain:
            return
        entry = candidates.setdefault(
            domain, {"domain": domain, "sources": set(), "wildcard_derived": False}
        )
        entry["sources"].add(source)
        if wildcard:
            entry["wildcard_derived"] = True

    # --- Source 1: Reverse DNS / PTR --------------------------------------
    if rdns_hostname:
        add(rdns_hostname, SOURCE_PTR)

    # --- Source 2: TLS certificate SAN ------------------------------------
    san_dns_names = _extract_san_dns_names(san_entries)
    for raw in san_dns_names:
        add(raw, SOURCE_TLS, wildcard=raw.startswith("*."))

    # --- Source 3: Certificate Transparency -------------------------------
    # Seed with registrable domains derived from what we already know
    # (PTR + TLS SAN) -- CT is queried by domain, not by IP, so we need
    # at least one real domain to search from.
    seeds = set()
    if rdns_hostname:
        norm = normalize_hostname(rdns_hostname)
        if norm:
            seeds.add(registrable_domain(norm))
    for raw in san_dns_names:
        norm = normalize_hostname(raw)
        if norm:
            seeds.add(registrable_domain(norm))
    seeds = sorted(seeds)[:CT_MAX_SEED_DOMAINS]

    ct_query_results = {}
    if CT_ENABLED:
        for seed in seeds:
            names, error = query_certificate_transparency(seed)
            ct_query_results[seed] = {"count": len(names), "error": error}
            for raw in names:
                add(raw, SOURCE_CT, wildcard=raw.startswith("*."))
    elif seeds:
        ct_query_results = {seed: {"count": 0, "error": "Certificate Transparency lookups are disabled."} for seed in seeds}

    # --- Finalize ----------------------------------------------------------
    result = []
    for domain, entry in candidates.items():
        sources = sorted(entry["sources"])
        result.append(
            {
                "domain": domain,
                "sources": sources,
                "category": _categorize(entry["sources"]),
                "wildcard_derived": entry["wildcard_derived"],
                # Explicitly not yet answered -- filled in by Phase 4's
                # DNS correlation / HTTP verification / confidence scoring.
                "dns_association": "NOT_CHECKED",
                "http_verification": "NOT_CHECKED",
                "confidence": "UNSCORED",
            }
        )
    result.sort(key=lambda r: r["domain"])

    truncated = len(result) > MAX_CANDIDATE_DOMAINS
    if truncated:
        result = result[:MAX_CANDIDATE_DOMAINS]

    return {
        "target_ip": ip,
        "candidates": result,
        "ct_seed_domains": seeds,
        "ct_query_results": ct_query_results,
        "total_candidates": len(result),
        "truncated": truncated,
        "note": (
            "Discovery only. A domain listed here has NOT been confirmed to "
            "currently resolve to or be hosted on this server -- that check "
            "(DNS resolution + IP match, then HTTP/HTTPS verification) is "
            "Phase 4. Certificate Transparency entries in particular prove a "
            "certificate existed for that name at some point, not that it "
            "is live on this server today."
        ),
    }
