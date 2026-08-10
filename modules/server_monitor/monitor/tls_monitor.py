"""
TLS Monitor
-----------
Reads the certificate a server presents on port 443: subject, issuer,
validity window, SAN. This is passive inspection of what the server
publicly presents to any client that connects -- the same thing a
browser reads before showing its padlock icon.

BUGFIX (see notes below get_ssl_cert_info): the previous version asked
Python's ssl module for the *dict* form of the certificate
(getpeercert(binary_form=False)) while connecting with
verify_mode=ssl.CERT_NONE. CPython only populates that dict as a
side effect of certificate *validation* -- with CERT_NONE it always
returns {}, even though a real certificate was presented. That silently
broke every unverified lookup (which is every lookup domain_discovery.py
makes, since it deliberately doesn't have a hostname yet). Fixed by
always reading the certificate in binary (DER) form -- which OpenSSL
returns regardless of verify_mode -- and parsing it ourselves with the
`cryptography` library.
"""

import logging
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID

from config import REQUEST_TIMEOUT

logger = logging.getLogger("monitor.tls_monitor")


def _days_until(expiry_dt: datetime):
    if not expiry_dt:
        return None
    if expiry_dt.tzinfo is None:
        expiry_dt = expiry_dt.replace(tzinfo=timezone.utc)
    return (expiry_dt - datetime.now(timezone.utc)).days


def _name_attr(name: x509.Name, oid) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return values[0].value if values else None


def _extract_san(cert: x509.Certificate) -> list:
    """Returns [("DNS", "example.com"), ...] -- same shape the old code
    expected from ssl's dict-form subjectAltName, so domain_discovery.py
    (which reads entry[0] == 'DNS') keeps working unchanged."""
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    return [("DNS", name) for name in ext.value.get_values_for_type(x509.DNSName)]


def _fetch_der_cert(ip: str, target_host: str, timeout: float) -> bytes:
    """Connect on 443 and return the raw DER certificate bytes. Uses
    CERT_NONE deliberately -- we want to READ whatever cert is presented
    even if it's self-signed/expired/hostname-mismatched; trust is
    assessed separately (see verified_by_default_trust below)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, 443), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=target_host) as ssock:
            der = ssock.getpeercert(binary_form=True)
            tls_version = ssock.version()
    return der, tls_version


def _check_trust(ip: str, hostname: str, timeout: float) -> tuple[bool, str | None]:
    """Separate strict connection: does this cert validate AND match the
    hostname using the system trust store? Only meaningful when a
    hostname is supplied."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((ip, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                pass
        return True, None
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def get_ssl_cert_info(ip: str, hostname: str = None) -> dict:
    """
    Connect on port 443 and read the presented certificate's fields.
    Always succeeds at reading the cert's own stated fields (even if
    self-signed / expired / for a different name) -- that's the whole
    point of domain_discovery.py's candidate-extraction step. Trust
    ("is this actually valid for `hostname`") is reported separately
    as `verified`/`verification_note` and never blocks field extraction.
    """
    target_host = hostname or ip

    try:
        der, tls_version = _fetch_der_cert(ip, target_host, REQUEST_TIMEOUT)
    except Exception as e:
        logger.debug("SSL cert retrieval failed for %s: %s", ip, e)
        return {"error": f"Could not retrieve certificate: {e}"}

    if not der:
        return {"error": "Server did not present a certificate."}

    try:
        cert = x509.load_der_x509_certificate(der, default_backend())
    except Exception as e:
        return {"error": f"Certificate presented but could not be parsed: {e}"}

    subject_cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    issuer_cn = _name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_org = _name_attr(cert.issuer, NameOID.ORGANIZATION_NAME)

    not_after = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after
    not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before

    verified, verification_error = (False, None)
    if hostname:
        verified, verification_error = _check_trust(ip, hostname, REQUEST_TIMEOUT)

    return {
        "subject": {"commonName": subject_cn} if subject_cn else None,
        "issuer": {"commonName": issuer_cn, "organizationName": issuer_org},
        "valid_from": not_before.strftime("%b %d %H:%M:%S %Y GMT") if not_before else None,
        "valid_until": not_after.strftime("%b %d %H:%M:%S %Y GMT") if not_after else None,
        "remaining_days": _days_until(not_after),
        "san": _extract_san(cert),
        "tls_version": tls_version,
        "verified": verified,
        "verification_note": (
            "Verified against hostname (trusted CA + name match)."
            if verified
            else (
                f"Not verified: {verification_error}" if hostname
                else "Not verified against a hostname -- fields shown are as "
                     "presented by the server, not confirmed trustworthy."
            )
        ),
    }
