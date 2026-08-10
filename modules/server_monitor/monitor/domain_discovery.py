"""
Domain Discovery
----------------
A single public IP can host many domains behind virtual hosting --
this module never assumes "one IP = one website" (per spec Section
13). It builds the confidence ladder your spec defines:

    Candidate
        -> found via TLS certificate (CN/SAN), Reverse DNS, a
           third-party reverse-IP lookup, or Certificate Transparency.
           Not yet confirmed to be *currently* associated with this
           server.
    DNS-Associated
        -> the domain resolves, but to a DIFFERENT IP than the one
           being monitored. Likely the certificate covers a domain
           that has since moved, or a SAN shared across servers.
    DNS-Verified
        -> the domain resolves and matches the target IP right now.
    Verified Website
        -> DNS-Verified AND an HTTP(S) request to the domain (via
           this IP) returned a successful response. This is the
           strongest classification available from a public IP alone.

Every record keeps its source ("TLS Certificate", "Reverse DNS",
"Reverse IP Lookup", "Certificate Transparency", "HTTPS") and
classification explicit -- nothing is ever presented as if it came
directly from the bare IP (spec Section 22).

CANDIDATE SOURCES, and why each exists:
  - TLS certificate CN/SAN, read WITH SNI set from whatever hostname
    we already have. Without a real SNI hostname, name-based virtual
    hosts return a default/catch-all cert, so this alone misses most
    shared hosting.
  - Reverse DNS (PTR). Cheap, but on shared hosting this is usually a
    generic provider hostname (e.g. "xxx.host.secureserver.net" on
    GoDaddy), not a real customer domain -- so it's necessary but not
    sufficient by itself.
  - Certificate Transparency (crt.sh), seeded from whatever domain(s)
    the above two produce. Surfaces subdomains missing from the
    *current* cert. Still needs a real seed domain to search from --
    if PTR/TLS only produced a generic hosting-provider hostname,
    this returns nothing useful for the customer's actual sites.
  - Reverse IP Lookup (HackerTarget's free API), queried directly by
    IP -- no seed domain needed. This is the one source that can find
    domains on shared hosting where the PTR is generic and there's no
    other seed at all; it works from a third-party database of
    historical hostname->IP associations, not a live probe of the
    server. Rate-limited (free tier) and best-effort: failures here
    never break the rest of discovery.
"""

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import requests

from config import COMMON_PORTS, REQUEST_TIMEOUT
from monitor.tls_monitor import get_ssl_cert_info
from monitor.http_monitor import get_http_headers
from monitor.dns_monitor import resolve_domain
from monitor.phase3_domain_discovery import (
    normalize_hostname,
    query_certificate_transparency,
    registrable_domain,
)

logger = logging.getLogger("monitor.domain_discovery")


def query_reverse_ip_lookup(ip: str, timeout: float = None):
    """
    Query HackerTarget's free Reverse IP Lookup API -- a third-party
    database of hostnames historically seen resolving to a given IP.
    This is the only source here that doesn't need a seed hostname,
    which makes it the one that can actually find customer domains on
    shared hosting where the PTR record is just the hosting
    provider's generic name (e.g. GoDaddy's "*.host.secureserver.net").

    Returns:
        (hostnames, error) -- hostnames is a list of raw hostnames
        (empty list if none / on error). error is None on success or
        a short human-readable string on failure. Never raises --
        a failure here must not break the rest of discovery.
    """
    timeout = timeout or REQUEST_TIMEOUT
    try:
        resp = requests.get(
            "https://api.hackertarget.com/reverseiplookup/",
            params={"q": ip},
            timeout=timeout,
            headers={"User-Agent": "server-monitor-domain-discovery/1.0"},
        )
        resp.raise_for_status()
        text = resp.text.strip()
    except requests.exceptions.Timeout:
        return [], "Reverse IP lookup timed out."
    except requests.exceptions.RequestException as e:
        return [], f"Reverse IP lookup failed: {e}"

    # The API returns plain text, one hostname per line, or a short
    # error/notice string (e.g. "No DNS A records found",
    # "API count exceeded") -- never raise on those, just treat as
    # "nothing found" so free-tier rate limits degrade gracefully.
    if not text or text.lower().startswith(("error", "no dns", "api count")):
        return [], (text or None)

    hostnames = [line.strip() for line in text.splitlines() if line.strip()]
    return hostnames, None


STATUS_CANDIDATE = "Candidate"
STATUS_DNS_ASSOCIATED = "DNS-Associated"
STATUS_DNS_VERIFIED = "DNS-Verified"
STATUS_VERIFIED_WEBSITE = "Verified Website"


def _parse_cert_domains(cert_info: dict) -> list:
    """
    Pull domain names out of an already-fetched certificate dict (see
    tls_monitor.get_ssl_cert_info). Pure parsing, no network -- kept
    separate from extract_candidate_domains() so it's testable without
    a live connection.
    """
    if not cert_info or cert_info.get("error"):
        return []

    domains = set()

    subject = cert_info.get("subject") or {}
    cn = subject.get("commonName")
    if cn:
        domains.add(cn)

    for entry in cert_info.get("san") or []:
        # ssl module returns SAN as a tuple of (type, value) pairs,
        # e.g. (('DNS', 'example.com'), ('DNS', 'www.example.com'))
        if isinstance(entry, (list, tuple)) and len(entry) == 2 and str(entry[0]).upper() == "DNS":
            domains.add(entry[1])

    return sorted(domains)


def extract_candidate_domains(ip: str, rdns_hostname: str = None) -> list:
    """
    Gather candidate domain names from three sources and merge them:

      1. TLS certificate CN/SAN -- read WITH the reverse-DNS hostname
         supplied as SNI when we have one. This matters: on any
         name-based virtual-hosted server (shared hosting, nginx SNI
         routing, a CDN, a load balancer -- i.e. most real servers),
         connecting with no SNI at all gets you back a default/
         catch-all certificate that has nothing to do with the real
         sites on the box. Previously this called get_ssl_cert_info(ip)
         with no hostname, which is why real candidates were being
         missed.
      2. The reverse-DNS (PTR) hostname itself, if any -- a domain
         that already resolves back to this exact IP is about as
         strong a candidate as it gets, and costs nothing extra.
      3. Certificate Transparency logs (crt.sh) for the registrable
         domain behind whatever we found in (1)/(2) -- this is what
         surfaces subdomains that aren't in the currently-live
         certificate at all (old certs, DNS-only subdomains, etc.).
    """
    candidates: dict = {}

    def add(domain_raw: str, source: str):
        domain = normalize_hostname(domain_raw)
        if not domain:
            return
        entry = candidates.setdefault(domain, {"domain": domain, "sources": set()})
        entry["sources"].add(source)

    # --- Source 1: TLS certificate, read with correct SNI -----------------
    cert_info = get_ssl_cert_info(ip, hostname=rdns_hostname)
    for d in _parse_cert_domains(cert_info):
        add(d, "TLS Certificate")

    # Fall back to an unauthenticated read (no SNI) too, in case the
    # default vhost cert also happens to list something useful -- it
    # never hurts to merge both, we only skip it if it's the same call.
    if rdns_hostname:
        fallback_cert_info = get_ssl_cert_info(ip)
        for d in _parse_cert_domains(fallback_cert_info):
            add(d, "TLS Certificate (default vhost)")

    # --- Source 2: reverse DNS hostname ------------------------------------
    if rdns_hostname:
        add(rdns_hostname, "Reverse DNS (PTR)")

    # --- Source 3: Reverse IP Lookup (third-party database, no seed -------
    #     needed) -- the source that actually finds customer domains on
    #     shared hosting when the PTR is just the host provider's generic
    #     name. Best-effort: a failure/rate-limit here is logged and
    #     skipped, never raised.
    rip_hostnames, rip_error = query_reverse_ip_lookup(ip)
    if rip_error:
        logger.info("Reverse IP lookup for %s: %s", ip, rip_error)
    for raw in rip_hostnames:
        add(raw, "Reverse IP Lookup")

    # --- Source 4: Certificate Transparency (crt.sh), for subdomains ------
    seeds = set()
    for domain in list(candidates.keys()):
        seeds.add(registrable_domain(domain))
    for seed in seeds:
        names, error = query_certificate_transparency(seed)
        if error:
            logger.info("CT lookup for seed %s failed: %s", seed, error)
            continue
        for raw in names:
            add(raw, "Certificate Transparency")

    return [
        {"domain": d, "source": ", ".join(sorted(entry["sources"])), "status": STATUS_CANDIDATE}
        for d, entry in sorted(candidates.items())
    ]


def verify_domain(ip: str, domain: str) -> dict:
    """
    Run one candidate domain through the DNS -> HTTP verification
    chain and return its full classified record.
    """
    dns_result = resolve_domain(domain)

    record = {
        "domain": domain,
        "source": "TLS Certificate",
        "dns_resolved": dns_result["resolved"],
        "resolved_ips": dns_result["ips"],
        "cname": dns_result.get("cname"),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }

    if not dns_result["resolved"]:
        record["status"] = STATUS_CANDIDATE
        record["dns_match"] = None
        record["classification_reason"] = (
            "Found in the server's TLS certificate, but the domain does not "
            "currently resolve -- cannot confirm it's associated with this server."
        )
        return record

    dns_match = ip in dns_result["ips"]
    record["dns_match"] = dns_match

    if not dns_match:
        record["status"] = STATUS_DNS_ASSOCIATED
        record["classification_reason"] = (
            "Domain resolves, but to a different IP than the one being "
            "monitored -- likely no longer hosted here, or the certificate "
            "covers multiple servers."
        )
        return record

    # DNS matches -- attempt an HTTP(S) check to confirm a live website,
    # and read the certificate the server presents specifically for
    # this domain (SNI = domain, connecting to the pinned target IP).
    record["status"] = STATUS_DNS_VERIFIED
    http_result = get_http_headers(ip, hostname=domain)
    record["http_check"] = http_result
    record["ssl_certificate"] = get_ssl_cert_info(ip, hostname=domain)

    https_info = http_result.get("https") or {}
    http_info = http_result.get("http") or {}
    status_code = https_info.get("status_code") or http_info.get("status_code")

    if status_code and 200 <= status_code < 400:
        record["status"] = STATUS_VERIFIED_WEBSITE
        record["classification_reason"] = (
            "Domain resolves to the target IP and responded successfully "
            "over HTTP(S) -- strongest available confirmation from a public IP."
        )
    else:
        record["classification_reason"] = (
            "Domain resolves to the target IP, but an HTTP(S) request did not "
            "get a successful response -- DNS association is confirmed, the "
            "website itself is not."
        )

    return record


def build_service_domain_map(ip: str, open_ports: list, domain_records: list) -> dict:
    """
    Assemble the IP -> port -> domain(s) tree your spec calls for
    (Section 14). Only web-facing ports (80/8080 for HTTP, 443/8443
    for HTTPS) get domains attached, based on which domains actually
    produced a response on that scheme during verification. Every
    other open port is still listed, just with an empty domain list --
    a service existing without an associated domain is a normal,
    expected result (e.g. SSH, a database port), not a gap.
    """
    services = []
    for port_info in open_ports or []:
        port = port_info["port"]
        entry = {"port": port, "service": port_info.get("service", COMMON_PORTS.get(port, "Unknown")), "domains": []}

        if port in (80, 8080):
            entry["domains"] = [
                r["domain"] for r in domain_records
                if (r.get("http_check") or {}).get("http", {}).get("status_code")
            ]
        elif port in (443, 8443):
            entry["domains"] = [
                r["domain"] for r in domain_records
                if (r.get("http_check") or {}).get("https", {}).get("status_code")
            ]

        services.append(entry)

    return {"ip": ip, "services": services}


def run_domain_discovery(
    ip: str,
    open_ports: list = None,
    rdns_hostname: str = None,
    extra_domains: list = None,
    max_workers: int = 20,
) -> dict:
    """
    Full pipeline: extract candidates (TLS cert w/ correct SNI, PTR
    hostname, Reverse IP Lookup, Certificate Transparency), merge in
    any manually-supplied domains, verify every one of them (in
    parallel -- a server with hundreds of candidates would otherwise
    take many minutes doing this one at a time, sequentially, inside
    a single web request, which is indistinguishable from "it doesn't
    work"), and build the service->domain map.

    Args:
        extra_domains: domain names the caller already knows about
            (e.g. exported from a hosting control panel) and wants
            verified alongside whatever auto-discovery finds. This is
            the reliable way to get a complete list on a server with
            many domains -- free public discovery sources (crt.sh,
            reverse-IP lookups) are result-capped by the provider and
            cannot be relied on to enumerate hundreds of domains by
            themselves.
        max_workers: how many domains to verify concurrently.
    """
    candidates = extract_candidate_domains(ip, rdns_hostname=rdns_hostname)

    candidate_names = {c["domain"] for c in candidates}
    for raw in extra_domains or []:
        name = (raw or "").strip().lower().rstrip(".")
        if name and name not in candidate_names:
            candidates.append({"domain": name, "source": "Manually Added", "status": STATUS_CANDIDATE})
            candidate_names.add(name)
    candidates.sort(key=lambda c: c["domain"])

    domain_records = []
    if candidates:
        with ThreadPoolExecutor(max_workers=max(1, min(max_workers, len(candidates)))) as pool:
            futures = {pool.submit(verify_domain, ip, c["domain"]): c for c in candidates}
            for future in as_completed(futures):
                c = futures[future]
                try:
                    record = future.result()
                except Exception as e:
                    logger.warning("Verification failed for %s: %s", c["domain"], e)
                    record = {
                        "domain": c["domain"],
                        "source": c["source"],
                        "status": STATUS_CANDIDATE,
                        "classification_reason": f"Verification failed unexpectedly: {e}",
                    }
                record["source"] = c["source"]
                domain_records.append(record)
        domain_records.sort(key=lambda r: r["domain"])

    service_map = build_service_domain_map(ip, open_ports or [], domain_records)

    verified_count = sum(1 for r in domain_records if r["status"] == STATUS_VERIFIED_WEBSITE)
    logger.info(
        "Domain discovery for %s: %d candidate(s), %d verified website(s)",
        ip, len(candidates), verified_count,
    )

    return {
        "candidate_domains": candidates,
        "domains": domain_records,
        "service_domain_map": service_map,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
