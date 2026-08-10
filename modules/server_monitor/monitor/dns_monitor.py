"""
DNS Monitor
-----------
Forward DNS resolution for candidate domain names discovered elsewhere
(currently: TLS certificate CN/SAN fields -- see domain_discovery.py).
This complements ip_intelligence.get_reverse_dns(), which goes the
other direction (IP -> hostname).

A / AAAA resolution uses only the standard library (socket.getaddrinfo)
so no extra dependency is required for the core feature. CNAME lookups
need a real DNS resolver library; if `dnspython` isn't installed, CNAME
is reported as unavailable rather than raising -- the domain
verification pipeline works fine without it, just with one less field.
"""

import logging
import socket

logger = logging.getLogger("monitor.dns_monitor")

try:
    import dns.resolver as _dns_resolver  # dnspython, optional
    _HAS_DNSPYTHON = True
except ImportError:
    _dns_resolver = None
    _HAS_DNSPYTHON = False


def resolve_a_aaaa(domain: str) -> dict:
    """
    Resolve a domain's A/AAAA records via the stdlib resolver.

    Returns:
        {"resolved": True, "ips": [...]}  on success
        {"resolved": False, "ips": [], "error": "..."}  on failure
    """
    try:
        infos = socket.getaddrinfo(domain, None)
        ips = sorted({info[4][0] for info in infos})
        return {"resolved": True, "ips": ips}
    except socket.gaierror as e:
        return {"resolved": False, "ips": [], "error": str(e)}
    except Exception as e:
        logger.debug("Unexpected DNS resolution error for %s: %s", domain, e)
        return {"resolved": False, "ips": [], "error": str(e)}


def resolve_cname(domain: str):
    """
    Best-effort CNAME lookup. Returns the CNAME target string, or None
    if there isn't one / dnspython isn't installed / the lookup fails.
    This is a "nice to have" field, never required for the domain
    verification pipeline to function.
    """
    if not _HAS_DNSPYTHON:
        return None
    try:
        answer = _dns_resolver.resolve(domain, "CNAME")
        return str(answer[0].target).rstrip(".")
    except Exception:
        return None


def resolve_domain(domain: str) -> dict:
    """
    Full forward-resolution result for a candidate domain: A/AAAA
    addresses plus a best-effort CNAME. This is the primary function
    domain_discovery.py calls to check whether a domain currently
    points at a given target IP.
    """
    result = resolve_a_aaaa(domain)
    result["cname"] = resolve_cname(domain)
    result["dnspython_available"] = _HAS_DNSPYTHON
    return result
