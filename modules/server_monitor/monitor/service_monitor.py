"""
Service Monitor
----------------
Lightweight TCP connectivity checks against a small, explicit list of
well-known ports. This is intentionally NOT a port scanner:

  - It only checks the ports in config.COMMON_PORTS (~15 well-known
    services), never a range or "all ports".
  - Each check is a single TCP connect attempt with a short timeout —
    functionally identical to what a browser does when it opens a
    connection to a website.
  - It performs no banner grabbing, no protocol fuzzing, no exploit
    attempts.

Per the project's security requirements, this module must only ever
be pointed at servers the user owns or is explicitly authorized to
monitor. Phase 3 will turn COMMON_PORTS into a per-server, explicitly
opted-in list rather than a fixed global one, so a user actively
chooses which services they're authorized to check ("HTTPS", "SSH")
instead of everything being probed by default.
"""

import concurrent.futures
import logging
import socket

from config import COMMON_PORTS, PORT_CHECK_TIMEOUT

logger = logging.getLogger("monitor.service_monitor")


def check_port(ip: str, port: int):
    """
    Attempt a single TCP connect to (ip, port). Returns (port, is_open).
    Any exception (timeout, refused, network unreachable) is treated
    as "not open" rather than raised, so one bad port never breaks a
    batch of checks.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(PORT_CHECK_TIMEOUT)
            result = s.connect_ex((ip, port))
            return port, (result == 0)
    except Exception as e:
        logger.debug("Port check failed for %s:%s -> %s", ip, port, e)
        return port, False


def scan_common_ports(ip: str, ports: dict = None) -> list:
    """
    Check every port in `ports` (defaults to the global COMMON_PORTS
    list) concurrently. Returns only the ports that responded, each
    with its conventional service name. Pass config.INTERNAL_PORTS for
    the broader internal-service list used once a private IP is
    reachable over a VPN tunnel.
    """
    ports = ports or COMMON_PORTS
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(len(ports), 1)) as executor:
        futures = [executor.submit(check_port, ip, p) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append({"port": port, "service": ports[port]})

    return sorted(open_ports, key=lambda x: x["port"])
