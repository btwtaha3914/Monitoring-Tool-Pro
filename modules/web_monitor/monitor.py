"""
Web Monitor — core scanning engine
====================================
Async subdomain discovery + per-target HTTP/DNS/SSL/latency checks.

Phase 1.8 changes vs. the pre-refactor CLI version:
  - print() output replaced with logger calls (see shared/logging_setup.py).
  - Dead CLI main() removed; this file is now a library only.
  - Retry backoff capped so a slow/broken crt.sh can't stall a request
    for more than ~7 seconds total.
  - Each result carries checked_at + final_url for the persistence
    layer in modules/web_monitor/__init__.py.
  - Public API preserved: discover_subdomains(domain) and
    check_all_domains(domains) work exactly as before.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Optional

import httpx
import requests

logger = logging.getLogger(__name__)


# ============================================================
# CONFIGURATION
# ============================================================

MAX_CONCURRENT_CHECKS = 10
REQUEST_TIMEOUT = 10
SERVER_TIMEOUT = 5

# crt.sh + hackertarget: free public sources for subdomain discovery.
# Not caching, not persisting — every call fetches fresh, so "up right
# now" answers are current. We do retry with backoff because both
# services occasionally rate-limit or time out under load.
CRTSH_ATTEMPTS = 3
CRTSH_TIMEOUT = 6           # per-attempt (was 20 — too long; UI froze)
CRTSH_BACKOFF_SECONDS = 1   # doubles each retry: 1s, 2s, 4s — capped below
CRTSH_MAX_TOTAL_SECONDS = 7 # hard ceiling — never spend longer than this
                             # on subdomain discovery even across retries

DISCOVERY_HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; MonitorSuite-WebMonitor/1.2)",
    "Accept": "application/json",
}


# ============================================================
# 1. DISCOVER SUBDOMAINS
# ============================================================

def _extract_names_from_crtsh(certificates, domain: str, subdomains: set) -> None:
    """Pull subdomain-shaped names out of a crt.sh JSON response."""
    for certificate in certificates:
        names = certificate.get("name_value", "")
        for name in names.splitlines():
            name = name.strip().lower()
            if name.startswith("*."):
                name = name[2:]
            if name == domain or name.endswith("." + domain):
                subdomains.add(name)


def _query_crtsh(domain: str, session: requests.Session):
    """
    Single attempt against crt.sh. Raises on any failure so the
    caller can decide whether to retry.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = session.get(url, timeout=CRTSH_TIMEOUT, headers=DISCOVERY_HEADERS)
    response.raise_for_status()

    # crt.sh sometimes returns empty/truncated bodies under load —
    # treat that as a failure (retry) rather than "zero subdomains".
    text = response.text.strip()
    if not text:
        raise ValueError("crt.sh returned an empty response")
    return json.loads(text)


def _query_hackertarget(domain: str, session: requests.Session) -> set:
    """
    Fallback source. Returns "subdomain,ip" plain-text lines.
    Only called if crt.sh failed all retries.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    response = session.get(url, timeout=CRTSH_TIMEOUT, headers=DISCOVERY_HEADERS)
    response.raise_for_status()

    text = response.text.strip()
    if not text or "error" in text.lower() or "API count exceeded" in text:
        raise ValueError(f"hackertarget lookup unavailable: {text[:120]}")

    found = set()
    for line in text.splitlines():
        name = line.split(",")[0].strip().lower()
        if name == domain or name.endswith("." + domain):
            found.add(name)
    return found


def discover_subdomains(domain: str):
    """
    Returns (sorted_subdomain_list, meta).

    meta shape:
        {
            "source": "crt.sh" | "hackertarget.com" | "crt.sh + hackertarget.com"
                      | "root domain only (discovery unavailable)",
            "degraded": bool,
            "warning": str | None,
        }

    The root domain is ALWAYS included in the return list, even if
    both discovery sources fail — so a scan still runs against the
    domain the user typed.
    """
    logger.info("Discovering subdomains for: %s", domain)

    subdomains: set = set()
    meta = {"source": None, "degraded": False, "warning": None}

    started = time.monotonic()
    session = requests.Session()

    # ---- Primary: crt.sh, with backoff and a hard total-time cap ----
    last_error: Optional[Exception] = None
    for attempt in range(1, CRTSH_ATTEMPTS + 1):
        if time.monotonic() - started > CRTSH_MAX_TOTAL_SECONDS:
            logger.warning(
                "crt.sh discovery hit total-time ceiling (%.1fs) after %d attempt(s)",
                CRTSH_MAX_TOTAL_SECONDS, attempt - 1,
            )
            break

        try:
            certificates = _query_crtsh(domain, session)
            _extract_names_from_crtsh(certificates, domain, subdomains)
            meta["source"] = "crt.sh"
            last_error = None
            break
        except (requests.RequestException, ValueError, json.JSONDecodeError) as error:
            last_error = error
            logger.warning(
                "crt.sh attempt %d/%d failed: %s",
                attempt, CRTSH_ATTEMPTS, error,
            )
            if attempt < CRTSH_ATTEMPTS:
                # Respect the total-time cap for the sleep too.
                remaining = CRTSH_MAX_TOTAL_SECONDS - (time.monotonic() - started)
                sleep_for = min(CRTSH_BACKOFF_SECONDS * attempt, max(remaining, 0))
                if sleep_for > 0:
                    time.sleep(sleep_for)

    # ---- Fallback: hackertarget, only if crt.sh gave us nothing ----
    if last_error is not None or not subdomains:
        try:
            fallback_names = _query_hackertarget(domain, session)
            if fallback_names:
                subdomains |= fallback_names
                meta["source"] = (
                    "crt.sh + hackertarget.com" if meta["source"] else "hackertarget.com"
                )
        except (requests.RequestException, ValueError) as fallback_error:
            logger.warning("hackertarget fallback failed: %s", fallback_error)
            if last_error is not None:
                meta["degraded"] = True
                meta["warning"] = (
                    "Both subdomain-discovery sources were temporarily "
                    "unreachable, so only the domain you entered was checked. "
                    "Try again in a minute."
                )

    # Always include the root — no matter what discovery returned.
    subdomains.add(domain)

    if meta["source"] is None:
        meta["source"] = "root domain only (discovery unavailable)"

    logger.info(
        "Subdomain discovery for %s: %d found (source=%s, degraded=%s)",
        domain, len(subdomains), meta["source"], meta["degraded"],
    )
    return sorted(subdomains), meta


# ============================================================
# 2. RESOLVE DOMAIN → IP
# ============================================================

async def resolve_ip(domain: str) -> dict:
    try:
        loop = asyncio.get_running_loop()
        ip = await loop.run_in_executor(None, lambda: socket.gethostbyname(domain))
        return {"success": True, "ip": ip, "error": None}
    except socket.gaierror as error:
        return {"success": False, "ip": None, "error": str(error)}


# ============================================================
# 3. CHECK SERVER / TCP CONNECTIVITY
# ============================================================

async def check_server(ip: str, ports=(443, 80)) -> dict:
    loop = asyncio.get_running_loop()

    for port in ports:
        try:
            start = time.perf_counter()
            sock = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda p=port: socket.create_connection((ip, p), timeout=SERVER_TIMEOUT),
                ),
                timeout=SERVER_TIMEOUT + 1,
            )
            end = time.perf_counter()
            sock.close()
            return {
                "success": True,
                "port": port,
                "response_time": round((end - start) * 1000, 2),
                "error": None,
            }
        except Exception:
            continue

    return {
        "success": False,
        "port": None,
        "response_time": None,
        "error": "TCP connection failed on ports 443 and 80",
    }


# ============================================================
# 4. CHECK WEBSITE (HTTP/HTTPS)
# ============================================================

async def check_website(client: httpx.AsyncClient, domain: str) -> dict:
    last_error = None

    for protocol in ("https", "http"):
        url = f"{protocol}://{domain}"
        try:
            start = time.perf_counter()
            response = await client.get(
                url, timeout=REQUEST_TIMEOUT, follow_redirects=True,
            )
            end = time.perf_counter()
            response_time = (end - start) * 1000
            status_code = response.status_code

            if 200 <= status_code < 400:
                status = "UP"
            elif 400 <= status_code < 500:
                status = "DEGRADED"
            else:
                status = "DOWN"

            return {
                "success": True,
                "protocol": protocol.upper(),
                "status": status,
                "http_status": status_code,
                "response_time": round(response_time, 2),
                "final_url": str(response.url),
                "error": None,
            }
        except httpx.RequestError as error:
            last_error = str(error)

    return {
        "success": False,
        "protocol": None,
        "status": "DOWN",
        "http_status": None,
        "response_time": None,
        "final_url": None,
        "error": last_error,
    }


# ============================================================
# 5. CHECK ONE DOMAIN (composed of steps 2-4 above)
# ============================================================

async def check_domain(client: httpx.AsyncClient, domain: str,
                       semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        result = {
            "domain": domain,
            "checked_at": datetime.now(timezone.utc).isoformat(),

            # DNS
            "ip": None,
            "dns_status": "FAILED",

            # Server (TCP)
            "server_status": "UNKNOWN",
            "server_port": None,
            "server_response_time": None,

            # Website (HTTP)
            "website_status": "DOWN",
            "protocol": None,
            "http_status": None,
            "response_time": None,
            "final_url": None,

            # Diagnosis
            "overall_status": "DOWN",
            "error": None,
        }

        # --- Step A: DNS ---
        dns_result = await resolve_ip(domain)
        if not dns_result["success"]:
            result["overall_status"] = "DNS_FAILED"
            result["error"] = "DNS resolution failed"
            return result

        result["dns_status"] = "UP"
        result["ip"] = dns_result["ip"]

        # --- Step B: TCP ---
        server_result = await check_server(result["ip"])
        if server_result["success"]:
            result["server_status"] = "UP"
            result["server_port"] = server_result["port"]
            result["server_response_time"] = server_result["response_time"]
        else:
            result["server_status"] = "DOWN"

        # --- Step C: HTTP ---
        website_result = await check_website(client, domain)
        result["website_status"] = website_result["status"]
        result["protocol"] = website_result["protocol"]
        result["http_status"] = website_result["http_status"]
        result["response_time"] = website_result["response_time"]
        result["final_url"] = website_result["final_url"]

        # --- Step D: Diagnosis ---
        if website_result["status"] == "UP":
            result["overall_status"] = "UP"
            # If our raw TCP check failed but HTTP worked, the target is
            # reachable via a proxy / load balancer / CDN.
            if result["server_status"] == "DOWN":
                result["server_status"] = "REACHABLE_VIA_HTTP"

        elif website_result["status"] == "DEGRADED":
            result["overall_status"] = "DEGRADED"
            result["error"] = f"Website returned HTTP {website_result['http_status']}"

        else:
            if result["server_status"] == "UP":
                result["overall_status"] = "WEBSITE_DOWN"
                result["error"] = "Server is reachable, but website is not responding"
            elif result["server_status"] == "DOWN":
                result["overall_status"] = "SERVER_DOWN"
                result["error"] = "Server is not reachable and website is unavailable"
            else:
                result["overall_status"] = "WEBSITE_DOWN"

        return result


# ============================================================
# 6. CHECK ALL DOMAINS IN PARALLEL
# ============================================================

async def check_all_domains(domains: list) -> list:
    """
    Runs check_domain concurrently across all targets, but limits
    simultaneous checks to MAX_CONCURRENT_CHECKS so we don't hammer
    DNS or trigger rate limits.
    """
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CHECKS)

    async with httpx.AsyncClient(
        headers={"User-Agent": "MonitorSuite-WebMonitor/1.2"}
    ) as client:
        tasks = [check_domain(client, domain, semaphore) for domain in domains]
        return await asyncio.gather(*tasks)


# ============================================================
# 7. STATUS ICON HELPER
# ============================================================
# Used by any consumer that wants a human icon per status. Kept
# here so the classification is defined once, not duplicated in the
# frontend and any downstream reports.

def get_status_icon(status: str) -> str:
    if status in ("UP", "REACHABLE_VIA_HTTP"):
        return "🟢"
    if status == "DEGRADED":
        return "🟡"
    if status in ("WEBSITE_DOWN", "SERVER_DOWN", "DNS_FAILED", "DOWN"):
        return "🔴"
    return "⚪"



# ============================================================
# 8. DEEP DOMAIN ANALYSIS (Phase 1.10)
# ============================================================
# Full deep-dive against a single domain when the user clicks it
# in the results table. Returns DNS records (A/AAAA/CNAME/MX/TXT),
# HTTP headers + redirect chain, and full SSL/TLS certificate info.
#
# This is on-demand only (fired when the user opens the detail
# modal), not part of the bulk scan — several extra network calls
# per invocation, so we keep it lazy.


def _get_all_dns_records(domain: str) -> dict:
    """
    Query the four record types most useful for diagnosis:
    A (IPv4), AAAA (IPv6), CNAME, MX (mail), TXT.

    Uses socket.getaddrinfo() for A/AAAA (always available in
    stdlib) and dnspython for CNAME/MX/TXT if installed. Falls
    back gracefully if dnspython isn't available.
    """
    import socket

    result = {
        "a": [],
        "aaaa": [],
        "cname": [],
        "mx": [],
        "txt": [],
        "errors": [],
    }

    # A + AAAA via stdlib
    try:
        infos = socket.getaddrinfo(domain, None)
        for info in infos:
            family, _, _, _, sockaddr = info
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in result["a"]:
                result["a"].append(addr)
            elif family == socket.AF_INET6 and addr not in result["aaaa"]:
                result["aaaa"].append(addr)
    except socket.gaierror as e:
        result["errors"].append(f"A/AAAA lookup failed: {e}")

    # CNAME + MX + TXT via dnspython (optional dependency)
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.timeout = 3
        resolver.lifetime = 5

        for rtype in ("CNAME", "MX", "TXT"):
            try:
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    if rtype == "CNAME":
                        result["cname"].append(str(rdata.target).rstrip("."))
                    elif rtype == "MX":
                        result["mx"].append({
                            "priority": rdata.preference,
                            "exchange": str(rdata.exchange).rstrip("."),
                        })
                    elif rtype == "TXT":
                        # TXT records come as byte strings; decode + strip quotes
                        txt_val = b"".join(rdata.strings).decode("utf-8", errors="replace")
                        result["txt"].append(txt_val)
            except dns.resolver.NoAnswer:
                pass  # normal — not every domain has every record type
            except dns.resolver.NXDOMAIN:
                result["errors"].append(f"{rtype}: domain does not exist")
                break
            except Exception as e:
                logger.debug("DNS %s lookup for %s failed: %s", rtype, domain, e)

    except ImportError:
        result["errors"].append(
            "dnspython not installed — CNAME/MX/TXT records unavailable. "
            "Install with: pip install dnspython"
        )

    return result


def _get_http_deep(domain: str) -> dict:
    """
    Full HTTP inspection: status, all headers, redirect chain,
    final URL, response size.
    """
    result = {
        "reachable": False,
        "status_code": None,
        "headers": {},
        "redirect_chain": [],
        "final_url": None,
        "response_time_ms": None,
        "content_length": None,
        "error": None,
    }

    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        try:
            start = time.perf_counter()
            response = requests.get(
                url,
                timeout=REQUEST_TIMEOUT,
                allow_redirects=True,
                headers={"User-Agent": "MonitorSuite-WebMonitor/1.2"},
            )
            elapsed = round((time.perf_counter() - start) * 1000, 2)

            result["reachable"] = True
            result["status_code"] = response.status_code
            result["response_time_ms"] = elapsed
            result["final_url"] = response.url
            result["content_length"] = len(response.content)

            # Copy headers into a plain dict (case preserved from server)
            result["headers"] = dict(response.headers)

            # Redirect chain — every hop with status code
            chain = []
            for r in response.history:
                chain.append({
                    "url": r.url,
                    "status_code": r.status_code,
                    "location": r.headers.get("Location", ""),
                })
            if chain:
                chain.append({
                    "url": response.url,
                    "status_code": response.status_code,
                    "location": "(final)",
                })
            result["redirect_chain"] = chain

            return result

        except requests.RequestException as e:
            result["error"] = f"{scheme}: {e}"
            continue

    return result


def _get_ssl_deep(domain: str) -> dict:
    """
    Full TLS/SSL certificate inspection.
    """
    import socket
    import ssl
    from datetime import datetime as _dt

    result = {
        "available": False,
        "issuer": None,
        "subject": None,
        "valid_from": None,
        "valid_until": None,
        "days_remaining": None,
        "sans": [],
        "tls_version": None,
        "cipher": None,
        "error": None,
    }

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as tls_sock:
                cert = tls_sock.getpeercert()
                cipher_info = tls_sock.cipher()
                tls_version = tls_sock.version()

                result["available"] = True
                result["tls_version"] = tls_version
                if cipher_info:
                    result["cipher"] = cipher_info[0]  # cipher name

                # Subject / Issuer come as tuples of tuples; flatten to dict
                def _dn_to_dict(dn):
                    d = {}
                    for rdn in dn:
                        for k, v in rdn:
                            d[k] = v
                    return d

                subject_dict = _dn_to_dict(cert.get("subject", []))
                issuer_dict = _dn_to_dict(cert.get("issuer", []))

                result["subject"] = subject_dict.get("commonName") or "Unknown"
                result["issuer"] = (
                    issuer_dict.get("organizationName")
                    or issuer_dict.get("commonName")
                    or "Unknown"
                )

                # Dates — ssl returns them as strings like "Jan  1 12:00:00 2026 GMT"
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                if not_before:
                    result["valid_from"] = not_before
                if not_after:
                    result["valid_until"] = not_after
                    try:
                        expiry = _dt.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        remaining = (expiry - _dt.utcnow()).days
                        result["days_remaining"] = remaining
                    except ValueError:
                        pass

                # SANs (Subject Alternative Names)
                for san_type, san_value in cert.get("subjectAltName", []):
                    result["sans"].append(san_value)

    except socket.timeout:
        result["error"] = "TLS handshake timed out"
    except socket.gaierror:
        result["error"] = "Could not resolve domain"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except ConnectionRefusedError:
        result["error"] = "Port 443 refused connection (no HTTPS)"
    except Exception as e:
        logger.debug("SSL deep-inspect failed for %s: %s", domain, e)
        result["error"] = f"Unexpected error: {e}"

    return result


def analyze_domain_deep(domain: str) -> dict:
    """
    Public entry point. Runs DNS + HTTP + SSL inspection concurrently
    and returns everything in one dict.

    Called by the /api/domain/<name>/detail endpoint.
    """
    logger.info("Deep domain analysis started for %s", domain)
    started = time.perf_counter()

    # Concurrency: 3 independent network calls, so run in parallel.
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=3) as pool:
        dns_future = pool.submit(_get_all_dns_records, domain)
        http_future = pool.submit(_get_http_deep, domain)
        ssl_future = pool.submit(_get_ssl_deep, domain)

        dns_data = dns_future.result()
        http_data = http_future.result()
        ssl_data = ssl_future.result()

    elapsed = round((time.perf_counter() - started) * 1000, 2)
    logger.info("Deep domain analysis for %s completed in %sms", domain, elapsed)

    # Primary IP from DNS (for the "click IP" cross-link feature)
    primary_ip = None
    if dns_data["a"]:
        primary_ip = dns_data["a"][0]
    elif dns_data["aaaa"]:
        primary_ip = dns_data["aaaa"][0]

    return {
        "domain": domain,
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
        "analysis_duration_ms": elapsed,
        "overview": {
            "ip": primary_ip,
            "reachable": http_data["reachable"],
            "status_code": http_data["status_code"],
            "response_time_ms": http_data["response_time_ms"],
            "https_available": ssl_data["available"],
        },
        "dns": dns_data,
        "http": http_data,
        "ssl": ssl_data,
    }