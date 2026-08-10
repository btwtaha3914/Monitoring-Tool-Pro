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

from config import REQUEST_TIMEOUT

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


def get_geolocation(ip: str) -> dict:
    """
    Approximate geolocation + network ownership via ip-api.com.

    IMPORTANT: this is an estimate based on where the IP block was
    registered / how routing announces it — it is NOT proof of the
    server's physical location. Callers should always present this
    as "Approximate IP geolocation", never as a confirmed location.
    """
    try:
        url = (
            f"http://ip-api.com/json/{ip}"
            "?fields=status,message,country,countryCode,region,regionName,"
            "city,zip,lat,lon,timezone,isp,org,as,asname,reverse,query"
        )
        resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        data = resp.json()

        if data.get("status") != "success":
            logger.warning("Geolocation lookup failed for %s: %s", ip, data.get("message"))
            return {"error": data.get("message", "Lookup failed")}

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
            "source": "Public IP database (ip-api.com)",
        }
    except requests.RequestException as e:
        logger.error("Geolocation provider unreachable for %s: %s", ip, e)
        return {"error": f"Geolocation lookup failed: {e}"}


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
