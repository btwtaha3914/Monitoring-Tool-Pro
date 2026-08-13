"""
IP Intelligence
---------------
Passive, publicly-sourced information about an IP address:
validation, geolocation, RDAP/WHOIS ownership data, and reverse DNS.

Every function here only talks to public registries/APIs — it never
contacts the target server itself. That distinction matters: this
module answers "what does the internet's public record say about
this IP", not "is this specific server up right now" (that's
service_monitor / http_monitor / tls_monitor).

All results should be treated as PUBLIC INTELLIGENCE, not OBSERVED
fact about the server itself — see the "source" labelling convention
used throughout the project.
"""

import ipaddress
import logging
import socket

import requests

from modules.server_monitor.config import REQUEST_TIMEOUT

logger = logging.getLogger("monitor.ip_intelligence")


def validate_public_ip(ip_str: str):
    """
    Validate that a string is a real IP address AND that it is public
    (i.e. not private, loopback, link-local, multicast, reserved, or
    unspecified).

    Returns:
        (ip_obj, None) on success
        (None, "human readable reason") on failure
    """
    ip_str = (ip_str or "").strip()

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, "Invalid IP address. Please enter a valid public IPv4 or IPv6 address."

    if (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    ):
        return None, "This is a private/reserved/non-routable IP, not a public one."

    return ip_obj, None


def validate_private_ip(ip_str: str):
    """
    Mirror of validate_public_ip() for the VPN/private-network path:
    accepts RFC1918 private ranges and loopback (useful for testing
    against localhost), rejects anything publicly routable so a user
    doesn't accidentally point the "connect via VPN" flow at a public
    IP believing it needs a tunnel.

    Returns:
        (ip_obj, None) on success
        (None, "human readable reason") on failure
    """
    ip_str = (ip_str or "").strip()

    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None, "Invalid IP address. Please enter a valid private IPv4 or IPv6 address."

    if not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local):
        return None, "This looks like a public IP — use Public Server Monitoring instead."

    if ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
        return None, "This is a multicast/reserved/unspecified address, not a usable private host IP."

    return ip_obj, None


def _haversine_km(lat1, lon1, lat2, lon2):
    """Great-circle distance between two lat/lon points, in km."""
    import math
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi = math.radians(lat2 - lat1)
    dlmb = math.radians(lon2 - lon1)
    a = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dlmb / 2) ** 2
    return 2 * r * math.asin(min(1, math.sqrt(a)))


def _query_ip_api(ip):
    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,country,countryCode,region,regionName,"
        "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
    )
    resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    data = resp.json()
    if data.get("status") != "success":
        raise ValueError(data.get("message", "ip-api.com lookup failed"))
    return {
        "ip": data.get("query"),
        "country": data.get("country"),
        "country_code": data.get("countryCode"),
        "region": data.get("regionName"),
        "city": data.get("city"),
        "zip": data.get("zip"),
        "latitude": data.get("lat"),
        "longitude": data.get("lon"),
        "timezone": data.get("timezone"),
        "isp": data.get("isp"),
        "organization": data.get("org"),
        "asn": data.get("as"),
        "as_name": data.get("asname"),
        "reverse_dns_hint": data.get("reverse"),
        "provider": "ip-api.com",
    }


def _query_ipwho(ip):
    """Second, independent provider (HTTPS, no key required) used to
    cross-check ip-api.com and as a fallback if it's unreachable."""
    url = f"https://ipwho.is/{ip}"
    resp = requests.get(url, timeout=REQUEST_TIMEOUT)
    data = resp.json()
    if not data.get("success", False):
        raise ValueError(data.get("message", "ipwho.is lookup failed"))
    conn = data.get("connection", {}) or {}
    tz = data.get("timezone", {}) or {}
    return {
        "ip": data.get("ip"),
        "country": data.get("country"),
        "country_code": data.get("country_code"),
        "region": data.get("region"),
        "city": data.get("city"),
        "zip": data.get("postal"),
        "latitude": data.get("latitude"),
        "longitude": data.get("longitude"),
        "timezone": tz.get("id"),
        "isp": conn.get("isp"),
        "organization": conn.get("org"),
        "asn": f"AS{conn.get('asn')}" if conn.get("asn") else None,
        "as_name": conn.get("org"),
        "reverse_dns_hint": None,
        "provider": "ipwho.is",
    }


def get_geolocation(ip: str) -> dict:
    """
    Best-effort geolocation + network ownership, cross-checked across
    two independent public IP-geolocation providers.

    IMPORTANT, and this cannot be engineered away: IP geolocation is
    always an ESTIMATE derived from how the IP block is registered
    and routed -- it is not GPS and cannot guarantee an exact
    lat/long. Accuracy is typically good at the country/region level,
    often good at the city level, and gets progressively less
    reliable for mobile carriers, VPNs, CDNs, and cloud providers
    whose IPs may be registered far from where traffic actually
    originates. No public IP database can promise pinpoint accuracy
    from an IP address alone -- any tool that claims otherwise is
    overstating what's possible.

    What we DO to maximize reliability here:
      - Query two independent providers.
      - If they agree closely (< ~50km apart), report the primary
        result with HIGH confidence.
      - If they disagree, report the primary result but flag LOW
        confidence and show both, so the discrepancy is visible
        rather than hidden.
      - If the primary provider is unreachable, fall back to the
        secondary automatically instead of failing outright.
    """
    primary, secondary = None, None
    primary_error, secondary_error = None, None

    try:
        primary = _query_ip_api(ip)
    except (requests.RequestException, ValueError) as e:
        primary_error = str(e)
        logger.warning("Primary geolocation provider failed for %s: %s", ip, e)

    try:
        secondary = _query_ipwho(ip)
    except (requests.RequestException, ValueError) as e:
        secondary_error = str(e)
        logger.warning("Secondary geolocation provider failed for %s: %s", ip, e)

    if primary is None and secondary is None:
        return {
            "error": f"Both geolocation providers failed "
                     f"(ip-api.com: {primary_error}; ipwho.is: {secondary_error})"
        }

    result = dict(primary) if primary else dict(secondary)
    result["source"] = "Public IP databases (cross-checked)"
    result["providers_used"] = [
        p for p in [
            primary.get("provider") if primary else None,
            secondary.get("provider") if secondary else None,
        ] if p
    ]

    if primary and secondary and primary.get("latitude") and secondary.get("latitude"):
        try:
            distance_km = round(_haversine_km(
                float(primary["latitude"]), float(primary["longitude"]),
                float(secondary["latitude"]), float(secondary["longitude"]),
            ), 1)
        except (TypeError, ValueError):
            distance_km = None

        if distance_km is not None:
            result["cross_check_distance_km"] = distance_km
            result["confidence"] = "high" if distance_km <= 50 else "low"
            result["accuracy_note"] = (
                f"Two independent providers agree within {distance_km} km — this is "
                f"an estimated location, not a confirmed physical address."
                if distance_km <= 50 else
                f"Providers disagree by ~{distance_km} km — treat this location as a "
                f"rough estimate only (common for VPNs, CDNs, and mobile/cloud IPs)."
            )
        else:
            result["confidence"] = "unknown"
    elif primary and not secondary:
        result["confidence"] = "single-source"
        result["accuracy_note"] = (
            "Only one geolocation provider responded — this is an estimate and "
            "could not be cross-checked this run."
        )
    else:
        result["confidence"] = "unknown"

    return result


def get_rdap_whois(ip: str) -> dict:
    """
    RDAP lookup (modern WHOIS replacement) via rdap.org.
    Returns registry ownership/network-range data. Missing fields are
    reported as "not available", never guessed.
    """
    try:
        resp = requests.get(f"https://rdap.org/ip/{ip}", timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            logger.warning("RDAP lookup for %s returned status %s", ip, resp.status_code)
            return {"error": f"RDAP lookup returned status {resp.status_code}"}

        data = resp.json()

        network_range = None
        if "startAddress" in data and "endAddress" in data:
            network_range = f"{data['startAddress']} - {data['endAddress']}"
        elif "cidr0_cidrs" in data:
            network_range = ", ".join(
                f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}"
                for c in data.get("cidr0_cidrs", [])
            )

        entities = []
        for ent in data.get("entities", []):
            name = None
            role = ", ".join(ent.get("roles", []))
            vcard = ent.get("vcardArray")
            if vcard and len(vcard) > 1:
                for field in vcard[1]:
                    if field[0] == "fn":
                        name = field[3]
            entities.append({"name": name or ent.get("handle"), "role": role})

        return {
            "handle": data.get("handle"),
            "name": data.get("name"),
            "type": data.get("type"),
            "country": data.get("country"),
            "network_range": network_range,
            "parent_handle": data.get("parentHandle"),
            "status": data.get("status"),
            "entities": entities,
            "registry": data.get("port43"),
            "source": "RDAP (rdap.org)",
        }
    except requests.RequestException as e:
        logger.error("RDAP provider unreachable for %s: %s", ip, e)
        return {"error": f"RDAP/WHOIS lookup failed: {e}"}
    except (ValueError, KeyError) as e:
        logger.error("Could not parse RDAP response for %s: %s", ip, e)
        return {"error": f"Could not parse RDAP response: {e}"}


def get_reverse_dns(ip: str) -> dict:
    """
    Reverse DNS (PTR) lookup. Absence of a PTR record is normal and
    reported plainly, not as an error.
    """
    try:
        hostname, aliases, _ = socket.gethostbyaddr(ip)
        return {"hostname": hostname, "aliases": aliases, "source": "DNS (PTR record)"}
    except socket.herror:
        return {"hostname": None, "note": "No PTR record found.", "source": "DNS (PTR record)"}
    except Exception as e:
        logger.error("Reverse DNS lookup failed for %s: %s", ip, e)
        return {"hostname": None, "error": str(e), "source": "DNS (PTR record)"}
