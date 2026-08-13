"""
HTTP Monitor
------------
Inspects publicly-visible HTTP/HTTPS response data for an IP:
status code, headers, redirects.

IMPORTANT CHANGE FROM THE ORIGINAL APP.PY:
The original prototype used `verify=False` for the HTTPS request,
which silently accepts invalid/expired/mismatched certificates. That
is not acceptable for a monitoring product, since "is the cert
valid" is exactly the kind of thing a monitoring tool must report
honestly. This module now verifies certificates properly and reports
a distinct, explicit "tls_validation_error" instead of masking it.

Caveat worth knowing (and worth showing users in the UI): connecting
directly to a bare IP means there's no hostname for the server to
present a matching certificate for via SNI, so many legitimate sites
will fail verification when checked this way even though they'd
verify fine at their real domain. When a hostname is available
(e.g. from reverse DNS), pass it in — it produces a much more
meaningful verification result.
"""

import logging

import requests

from modules.server_monitor.config import REQUEST_TIMEOUT

logger = logging.getLogger("monitor.http_monitor")


def get_http_headers(ip: str, hostname: str = None) -> dict:
    """
    GET the server over HTTPS then HTTP, returning status/headers for
    whichever schemes respond.

    Args:
        ip: the public IP to connect to.
        hostname: optional hostname to send via the Host header / SNI
            and to verify the certificate against. If omitted, the
            raw IP is used, which will fail certificate verification
            for the vast majority of real-world certificates -- see
            module docstring.
    """
    headers_info = {}

    for scheme, port in (("https", 443), ("http", 80)):
        request_kwargs = {"timeout": REQUEST_TIMEOUT, "allow_redirects": True}

        if hostname:
            # IMPORTANT: request the hostname itself, not the bare IP.
            # A Host header alone does NOT set SNI for `requests` --
            # SNI is derived from the connection target in the URL. If
            # we connect to https://{ip} and only spoof the Host
            # header, the server still receives the IP as SNI and, on
            # any name-based/virtual-hosted server, hands back the
            # wrong (default/catch-all) certificate -- causing real,
            # correctly-DNS-verified domains to show as SSL/HTTP
            # failures. Requesting https://{hostname} directly gives
            # correct SNI, correct vhost routing, and a meaningful
            # certificate check. (DNS resolution to the target IP is
            # already confirmed by the caller before this is invoked.)
            url = f"{scheme}://{hostname}"
        else:
            url = f"{scheme}://{ip}"

        try:
            resp = requests.get(url, **request_kwargs)
            headers_info[scheme] = {
                "status_code": resp.status_code,
                "server": resp.headers.get("Server"),
                "powered_by": resp.headers.get("X-Powered-By"),
                "content_type": resp.headers.get("Content-Type"),
                "content_length": resp.headers.get("Content-Length"),
                # Small text preview only -- enough to confirm a real
                # page came back (title/snippet), not a full body dump.
                "content_preview": resp.text[:300] if resp.text else None,
                "final_url": resp.url,
                "tls_validation_error": None,
            }
        except requests.exceptions.SSLError as e:
            if scheme == "https":
                headers_info[scheme] = {
                    "status_code": None,
                    "tls_validation_error": (
                        "TLS certificate validation failed. This can mean the "
                        "certificate is invalid/expired, or that it simply "
                        "isn't issued for the bare IP address (common when no "
                        "hostname is supplied)."
                    ),
                    "raw_error": str(e),
                }
                logger.info("TLS validation failed for %s: %s", ip, e)
        except requests.exceptions.Timeout:
            headers_info[scheme] = {"status_code": None, "error": "Connection timed out."}
        except requests.exceptions.ConnectionError as e:
            logger.debug("%s connection failed for %s: %s", scheme.upper(), ip, e)
            # No entry for this scheme -- it simply isn't listening / reachable.
            continue
        except requests.RequestException as e:
            headers_info[scheme] = {"status_code": None, "error": str(e)}

    return headers_info or {"note": "No HTTP(S) response received."}
