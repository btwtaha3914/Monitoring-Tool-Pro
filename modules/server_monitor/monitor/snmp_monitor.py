"""
SNMP Monitor
------------
A minimal, dependency-free SNMP v2c client: hand-rolled BER/ASN.1
encoding over UDP/161. Used to pull system info and a service/interface
inventory from a device when the user supplies a read-only SNMP
community string -- the same mechanism PRTG/Zabbix/Nagios use to see
"inside" a device beyond what a port scan alone reveals.

Why hand-rolled instead of pysnmp: pysnmp is a heavy optional
dependency (and its actively-maintained fork, pysnmp-lextudio, isn't
always available in minimal environments). SNMP v1/v2c GET/GETNEXT is
a small, stable, well-documented wire format, so a ~150-line client
covering GET and a bounded GETNEXT walk is more portable than adding
a large dependency for five operations.

SECURITY NOTE: SNMP v1/v2c community strings are sent in PLAINTEXT
over UDP -- there is no encryption. This module must only be pointed
at devices you own or are authorized to query, ideally over a private
network or VPN tunnel, never a public community string guessed
against someone else's infrastructure.
"""

import logging
import socket
import struct

logger = logging.getLogger("monitor.snmp_monitor")

SNMP_PORT = 161
DEFAULT_TIMEOUT = 3

# ---- Well-known scalar OIDs (SNMPv2-MIB) ---------------------------------
OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0"
OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0"
OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0"
OID_SYS_NAME = "1.3.6.1.2.1.1.5.0"
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"

# Interface table columns walked to build a "services/interfaces" list,
# similar to what PRTG's SNMP sensors show, plus in/out traffic counters
# so the interface list also shows how much data has moved through each
# NIC ("server traffic").
OID_IF_DESCR = "1.3.6.1.2.1.2.2.1.2"
OID_IF_OPER_STATUS = "1.3.6.1.2.1.2.2.1.8"
OID_IF_SPEED = "1.3.6.1.2.1.2.2.1.5"
OID_IF_IN_OCTETS = "1.3.6.1.2.1.2.2.1.10"
OID_IF_OUT_OCTETS = "1.3.6.1.2.1.2.2.1.16"

# ---- HOST-RESOURCES-MIB (RFC 2790) -- CPU / memory / disk / processes ----
# Supported by Net-SNMP (Linux/BSD), Windows' built-in SNMP service, and
# most server-class SNMP agents. Not supported by plain switches/routers,
# which only implement the base MIB-II tables above -- that's normal, and
# handled as a soft "not exposed" note rather than an error.
OID_HR_SYSTEM_UPTIME = "1.3.6.1.2.1.25.1.1.0"
OID_HR_SYSTEM_NUM_USERS = "1.3.6.1.2.1.25.1.5.0"
OID_HR_SYSTEM_PROCESSES = "1.3.6.1.2.1.25.1.6.0"

OID_HR_PROCESSOR_LOAD = "1.3.6.1.2.1.25.3.3.1.2"  # walk: % CPU load per core

OID_HR_STORAGE_TYPE = "1.3.6.1.2.1.25.2.3.1.2"
OID_HR_STORAGE_DESCR = "1.3.6.1.2.1.25.2.3.1.3"
OID_HR_STORAGE_ALLOC_UNITS = "1.3.6.1.2.1.25.2.3.1.4"
OID_HR_STORAGE_SIZE = "1.3.6.1.2.1.25.2.3.1.5"
OID_HR_STORAGE_USED = "1.3.6.1.2.1.25.2.3.1.6"

# hrStorageType values that identify a row as RAM vs. swap vs. a real disk.
HRSTORAGE_RAM = "1.3.6.1.2.1.25.2.1.2"
HRSTORAGE_VIRTUAL_MEMORY = "1.3.6.1.2.1.25.2.1.3"

OID_HR_SW_RUN_NAME = "1.3.6.1.2.1.25.4.2.1.2"    # walk: running process/service names
OID_HR_SW_RUN_STATUS = "1.3.6.1.2.1.25.4.2.1.7"  # walk: 1=running 2=runnable 3=notRunnable 4=invalid

# ---- UCD-SNMP-MIB (Net-SNMP specific) -- supplementary CPU/RAM numbers,
# only present on Linux/BSD hosts running net-snmp, but often more precise
# (actual %CPU user/system/idle and load averages) than HOST-RESOURCES-MIB
# alone provides. Queried as a bonus, never required.
OID_UCD_MEM_TOTAL_REAL = "1.3.6.1.4.1.2021.4.5.0"   # KB
OID_UCD_MEM_AVAIL_REAL = "1.3.6.1.4.1.2021.4.6.0"   # KB
OID_UCD_LA_1MIN = "1.3.6.1.4.1.2021.10.1.3.1"
OID_UCD_LA_5MIN = "1.3.6.1.4.1.2021.10.1.3.2"
OID_UCD_LA_15MIN = "1.3.6.1.4.1.2021.10.1.3.3"
OID_UCD_CPU_USER = "1.3.6.1.4.1.2021.11.9.0"
OID_UCD_CPU_SYSTEM = "1.3.6.1.4.1.2021.11.10.0"
OID_UCD_CPU_IDLE = "1.3.6.1.4.1.2021.11.11.0"

MAX_WALK_ROWS = 64      # hard cap so a misbehaving agent can't hang the request
MAX_PROCESS_ROWS = 150  # process/service lists are usually longer than interface lists


# =====================================================================
# BER/DER encoding
# =====================================================================
def _encode_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = []
    while n:
        body.insert(0, n & 0xFF)
        n >>= 8
    return bytes([0x80 | len(body)]) + bytes(body)


def _tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(value)) + value


def _encode_integer(n: int) -> bytes:
    if n == 0:
        body = b"\x00"
    else:
        body = n.to_bytes((n.bit_length() + 8) // 8, "big", signed=True)
    return _tlv(0x02, body)


def _encode_octet_string(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    return _tlv(0x04, s)


def _encode_null() -> bytes:
    return _tlv(0x05, b"")


def _encode_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.strip(".").split(".")]
    body = bytes([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        if p == 0:
            body += b"\x00"
            continue
        chunk = []
        while p:
            chunk.insert(0, p & 0x7F)
            p >>= 7
        for i in range(len(chunk) - 1):
            chunk[i] |= 0x80
        body += bytes(chunk)
    return _tlv(0x06, body)


def _encode_sequence(*items: bytes) -> bytes:
    return _tlv(0x30, b"".join(items))


def _build_request(community: str, oids: list, pdu_tag: int, request_id: int = 1) -> bytes:
    varbinds = _encode_sequence(*[
        _encode_sequence(_encode_oid(oid), _encode_null()) for oid in oids
    ])
    pdu_body = (
        _encode_integer(request_id)
        + _encode_integer(0)  # error-status
        + _encode_integer(0)  # error-index
        + varbinds
    )
    pdu = _tlv(pdu_tag, pdu_body)
    message = (
        _encode_integer(1)  # version: 1 == SNMPv2c
        + _encode_octet_string(community)
        + pdu
    )
    return _encode_sequence(message)


# =====================================================================
# BER/DER decoding
# =====================================================================
def _read_length(data: bytes, pos: int):
    first = data[pos]
    pos += 1
    if first < 0x80:
        return first, pos
    num_bytes = first & 0x7F
    length = int.from_bytes(data[pos:pos + num_bytes], "big")
    return length, pos + num_bytes


def _decode_oid(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    parts = [first // 40, first % 40]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not (byte & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


def _decode_value(tag: int, body: bytes):
    if tag == 0x02:  # INTEGER
        return int.from_bytes(body, "big", signed=True)
    if tag == 0x04:  # OCTET STRING
        try:
            return body.decode("utf-8")
        except UnicodeDecodeError:
            return body.hex()
    if tag == 0x05:  # NULL
        return None
    if tag == 0x06:  # OID
        return _decode_oid(body)
    if tag == 0x40:  # IpAddress
        return ".".join(str(b) for b in body)
    if tag in (0x41, 0x42, 0x46):  # Counter32 / Gauge32 / Counter64
        return int.from_bytes(body, "big")
    if tag == 0x43:  # TimeTicks (hundredths of a second)
        return int.from_bytes(body, "big")
    if tag == 0x80:
        return "<noSuchObject>"
    if tag == 0x81:
        return "<noSuchInstance>"
    if tag == 0x82:
        return "<endOfMibView>"
    return body.hex()


def _parse_varbinds(data: bytes) -> list:
    """Parses a full SNMP message and returns [(oid, value), ...]."""
    pos = 0
    assert data[pos] == 0x30
    pos += 1
    _, pos = _read_length(data, pos)

    pos += 1  # version tag
    vlen, pos = _read_length(data, pos)
    pos += vlen

    pos += 1  # community tag
    clen, pos = _read_length(data, pos)
    pos += clen

    pdu_tag = data[pos]
    pos += 1
    _, pos = _read_length(data, pos)

    if pdu_tag not in (0xA2,):  # GetResponse-PDU
        raise ValueError(f"Unexpected PDU tag in response: {pdu_tag:#x}")

    for _ in range(3):  # request-id, error-status, error-index
        pos += 1
        ilen, pos = _read_length(data, pos)
        pos += ilen

    assert data[pos] == 0x30  # varbind list
    pos += 1
    list_len, pos = _read_length(data, pos)
    end = pos + list_len

    results = []
    while pos < end:
        assert data[pos] == 0x30  # one varbind
        pos += 1
        _, pos = _read_length(data, pos)

        assert data[pos] == 0x06  # OID
        pos += 1
        oid_len, pos = _read_length(data, pos)
        oid = _decode_oid(data[pos:pos + oid_len])
        pos += oid_len

        val_tag = data[pos]
        pos += 1
        val_len, pos = _read_length(data, pos)
        value = _decode_value(val_tag, data[pos:pos + val_len])
        pos += val_len

        results.append((oid, value))
    return results


# =====================================================================
# Public API
# =====================================================================
def _send_request(ip: str, community: str, oids: list, pdu_tag: int, timeout: float):
    packet = _build_request(community, oids, pdu_tag)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, SNMP_PORT))
        data, _ = sock.recvfrom(4096)
    return _parse_varbinds(data)


def get(ip: str, community: str, oids: list, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """SNMP GET for one or more scalar OIDs. Returns {oid: value}."""
    varbinds = _send_request(ip, community, oids, pdu_tag=0xA0, timeout=timeout)
    return dict(varbinds)


def walk(ip: str, community: str, base_oid: str, timeout: float = DEFAULT_TIMEOUT,
          max_rows: int = MAX_WALK_ROWS) -> list:
    """SNMP GETNEXT walk of everything under base_oid. Returns [(oid, value), ...].

    Terminates on either a compliant agent's endOfMibView exception OR a
    response OID that has walked past base_oid's subtree (normal end of
    table) OR a timeout (some embedded/non-compliant agents simply stop
    responding at the table boundary instead of replying with the next
    OID outside it -- treated as "walk complete", not a failure, so one
    quiet agent doesn't lose the rows already collected)."""
    rows = []
    current = base_oid
    for _ in range(max_rows):
        try:
            varbinds = _send_request(ip, community, [current], pdu_tag=0xA1, timeout=timeout)
        except socket.timeout:
            break
        if not varbinds:
            break
        next_oid, value = varbinds[0]
        if not next_oid.startswith(base_oid + ".") or value in ("<endOfMibView>",):
            break
        rows.append((next_oid, value))
        current = next_oid
    return rows


def get_system_info(ip: str, community: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    High-level check: system identity, CPU load, RAM/swap usage, disk
    usage, running processes/services, and an interface/traffic
    inventory -- the private, "owner's-eye" view of the box, the same
    things a PRTG/Zabbix SNMP sensor set shows. Fails soft with an
    `error` key on timeout/wrong community/SNMP disabled -- SNMP being
    unreachable is the normal case for most public IPs and is not
    treated as a crash. Each individual section (cpu/memory/disks/
    processes) also fails soft on its own if the target agent doesn't
    implement HOST-RESOURCES-MIB (common on switches/routers, which
    only expose the base MIB-II tables) -- you still get whatever the
    agent does support instead of an all-or-nothing result.
    """
    try:
        system = get(ip, community, [
            OID_SYS_DESCR, OID_SYS_UPTIME, OID_SYS_CONTACT, OID_SYS_NAME, OID_SYS_LOCATION,
            OID_HR_SYSTEM_PROCESSES, OID_HR_SYSTEM_NUM_USERS,
        ], timeout=timeout)
    except socket.timeout:
        return {
            "available": False,
            "error": "No SNMP response (device unreachable, SNMP disabled, or wrong community string).",
        }
    except Exception as e:
        logger.debug("SNMP GET failed for %s: %s", ip, e)
        return {"available": False, "error": f"SNMP query failed: {e}"}

    result = {
        "available": True,
        "sys_descr": system.get(OID_SYS_DESCR),
        "sys_uptime_ticks": system.get(OID_SYS_UPTIME),
        "sys_uptime_readable": _ticks_to_readable(system.get(OID_SYS_UPTIME)),
        "sys_contact": system.get(OID_SYS_CONTACT),
        "sys_name": system.get(OID_SYS_NAME),
        "sys_location": system.get(OID_SYS_LOCATION),
        "process_count": _clean_scalar(system.get(OID_HR_SYSTEM_PROCESSES)),
        "logged_in_users": _clean_scalar(system.get(OID_HR_SYSTEM_NUM_USERS)),
        "interfaces": [],
        "cpu": {},
        "memory": {},
        "disks": [],
        "processes": [],
    }

    # ---- Interfaces + traffic (in/out bytes per NIC) ----------------
    try:
        descr_rows = walk(ip, community, OID_IF_DESCR, timeout=timeout)
        status_rows = dict(walk(ip, community, OID_IF_OPER_STATUS, timeout=timeout))
        speed_rows = dict(walk(ip, community, OID_IF_SPEED, timeout=timeout))
        in_rows = dict(walk(ip, community, OID_IF_IN_OCTETS, timeout=timeout))
        out_rows = dict(walk(ip, community, OID_IF_OUT_OCTETS, timeout=timeout))

        def _by_index(rows):
            return {oid.rsplit(".", 1)[-1]: v for oid, v in rows.items()}

        status_by_index = _by_index(status_rows)
        speed_by_index = _by_index(speed_rows)
        in_by_index = _by_index(in_rows)
        out_by_index = _by_index(out_rows)

        for oid, name in descr_rows:
            idx = oid.rsplit(".", 1)[-1]
            status_val = status_by_index.get(idx)
            in_bytes = in_by_index.get(idx)
            out_bytes = out_by_index.get(idx)
            result["interfaces"].append({
                "index": idx,
                "name": name,
                "status": {1: "up", 2: "down", 3: "testing"}.get(status_val, "unknown"),
                "speed_mbps": round(speed_by_index[idx] / 1_000_000, 1) if speed_by_index.get(idx) else None,
                "traffic_in_bytes": in_bytes,
                "traffic_out_bytes": out_bytes,
                "traffic_in_readable": _bytes_to_readable(in_bytes),
                "traffic_out_readable": _bytes_to_readable(out_bytes),
            })
    except Exception as e:
        logger.debug("SNMP interface walk failed for %s: %s", ip, e)
        result["interfaces_note"] = f"Interface walk incomplete: {e}"

    # ---- CPU load -----------------------------------------------------
    result["cpu"] = _get_cpu_info(ip, community, timeout)

    # ---- RAM / swap / disks --------------------------------------------
    memory, disks = _get_memory_and_disks(ip, community, timeout)
    result["memory"] = memory
    result["disks"] = disks

    # ---- Running processes / internal services -------------------------
    result["processes"] = _get_running_processes(ip, community, timeout)

    return result


def _get_cpu_info(ip: str, community: str, timeout: float) -> dict:
    """Per-core CPU load (HOST-RESOURCES-MIB) plus, on Linux/BSD net-snmp
    agents, more precise user/system/idle percentages and load averages
    (UCD-SNMP-MIB). Either source can be missing independently -- the
    result includes whatever the agent actually exposes."""
    cpu: dict = {}

    try:
        rows = walk(ip, community, OID_HR_PROCESSOR_LOAD, timeout=timeout)
        loads = [v for _, v in rows if isinstance(v, int)]
        if loads:
            cpu["per_core_load_percent"] = loads
            cpu["average_load_percent"] = round(sum(loads) / len(loads), 1)
    except Exception as e:
        logger.debug("SNMP hrProcessorLoad walk failed for %s: %s", ip, e)

    try:
        ucd = get(ip, community, [
            OID_UCD_LA_1MIN, OID_UCD_LA_5MIN, OID_UCD_LA_15MIN,
            OID_UCD_CPU_USER, OID_UCD_CPU_SYSTEM, OID_UCD_CPU_IDLE,
        ], timeout=timeout)

        la1, la5, la15 = ucd.get(OID_UCD_LA_1MIN), ucd.get(OID_UCD_LA_5MIN), ucd.get(OID_UCD_LA_15MIN)
        if all(_is_real_value(v) for v in (la1, la5, la15)):
            cpu["load_average"] = {"1min": la1, "5min": la5, "15min": la15}

        user, system_, idle = ucd.get(OID_UCD_CPU_USER), ucd.get(OID_UCD_CPU_SYSTEM), ucd.get(OID_UCD_CPU_IDLE)
        if all(_is_real_value(v) for v in (user, system_, idle)):
            cpu["user_percent"] = user
            cpu["system_percent"] = system_
            cpu["idle_percent"] = idle
            cpu["busy_percent"] = round(100 - idle, 1) if isinstance(idle, (int, float)) else None
    except (socket.timeout, Exception) as e:
        logger.debug("SNMP UCD CPU query failed for %s: %s", ip, e)

    if not cpu:
        cpu["note"] = ("This agent doesn't expose CPU counters (HOST-RESOURCES-MIB / "
                        "UCD-SNMP-MIB) -- common on switches/routers, which typically "
                        "only implement the base interface tables.")
    return cpu


def _get_memory_and_disks(ip: str, community: str, timeout: float):
    """Walks hrStorageTable (HOST-RESOURCES-MIB) and splits rows into RAM,
    swap, and disk/filesystem entries by their hrStorageType. Falls back to
    UCD-SNMP-MIB's memTotalReal/memAvailReal for RAM if the agent didn't
    report a RAM row (some minimal agents omit it from hrStorageTable)."""
    memory: dict = {}
    disks: list = []

    try:
        descr_rows = walk(ip, community, OID_HR_STORAGE_DESCR, timeout=timeout)
        type_rows = dict(walk(ip, community, OID_HR_STORAGE_TYPE, timeout=timeout))
        units_rows = dict(walk(ip, community, OID_HR_STORAGE_ALLOC_UNITS, timeout=timeout))
        size_rows = dict(walk(ip, community, OID_HR_STORAGE_SIZE, timeout=timeout))
        used_rows = dict(walk(ip, community, OID_HR_STORAGE_USED, timeout=timeout))

        def _by_index(rows):
            return {oid.rsplit(".", 1)[-1]: v for oid, v in rows.items()}

        type_by_idx = _by_index(type_rows)
        units_by_idx = _by_index(units_rows)
        size_by_idx = _by_index(size_rows)
        used_by_idx = _by_index(used_rows)

        for oid, descr in descr_rows:
            idx = oid.rsplit(".", 1)[-1]
            units = units_by_idx.get(idx) or 1
            size = size_by_idx.get(idx)
            used = used_by_idx.get(idx)
            if not isinstance(size, int) or not isinstance(used, int):
                continue

            total_bytes = size * units
            used_bytes = used * units
            percent = round(used_bytes / total_bytes * 100, 1) if total_bytes else None
            entry = {
                "description": descr,
                "total_bytes": total_bytes,
                "used_bytes": used_bytes,
                "used_percent": percent,
                "total_readable": _bytes_to_readable(total_bytes),
                "used_readable": _bytes_to_readable(used_bytes),
            }

            stype = type_by_idx.get(idx)
            if stype == HRSTORAGE_RAM:
                memory["ram"] = entry
            elif stype == HRSTORAGE_VIRTUAL_MEMORY:
                memory["swap"] = entry
            else:
                disks.append(entry)
    except Exception as e:
        logger.debug("SNMP hrStorageTable walk failed for %s: %s", ip, e)

    if "ram" not in memory:
        try:
            ucd = get(ip, community, [OID_UCD_MEM_TOTAL_REAL, OID_UCD_MEM_AVAIL_REAL], timeout=timeout)
            total_kb, avail_kb = ucd.get(OID_UCD_MEM_TOTAL_REAL), ucd.get(OID_UCD_MEM_AVAIL_REAL)
            if isinstance(total_kb, int) and isinstance(avail_kb, int) and total_kb > 0:
                used_kb = total_kb - avail_kb
                memory["ram"] = {
                    "description": "Physical memory (UCD-SNMP-MIB)",
                    "total_bytes": total_kb * 1024,
                    "used_bytes": used_kb * 1024,
                    "used_percent": round(used_kb / total_kb * 100, 1),
                    "total_readable": _bytes_to_readable(total_kb * 1024),
                    "used_readable": _bytes_to_readable(used_kb * 1024),
                }
        except (socket.timeout, Exception) as e:
            logger.debug("SNMP UCD memory query failed for %s: %s", ip, e)

    if not memory and not disks:
        memory["note"] = ("This agent doesn't expose memory/disk counters "
                           "(HOST-RESOURCES-MIB hrStorageTable) -- common on "
                           "switches/routers, which don't track local storage.")

    return memory, disks


def _get_running_processes(ip: str, community: str, timeout: float, max_rows: int = MAX_PROCESS_ROWS) -> list:
    """Walks hrSWRunTable -- the running-process/service list HOST-RESOURCES-MIB
    exposes. This is the closest SNMP equivalent of "what's running on the
    box" (like `ps`/Task Manager), and is what shows internal services a
    port scan alone can't see (things not listening on the network)."""
    try:
        name_rows = walk(ip, community, OID_HR_SW_RUN_NAME, timeout=timeout, max_rows=max_rows)
        status_rows = dict(walk(ip, community, OID_HR_SW_RUN_STATUS, timeout=timeout, max_rows=max_rows))
        status_by_idx = {oid.rsplit(".", 1)[-1]: v for oid, v in status_rows.items()}
        status_map = {1: "running", 2: "runnable", 3: "not runnable", 4: "invalid"}

        processes = []
        for oid, name in name_rows:
            idx = oid.rsplit(".", 1)[-1]
            processes.append({
                "name": name,
                "status": status_map.get(status_by_idx.get(idx), "unknown"),
            })
        return processes
    except Exception as e:
        logger.debug("SNMP hrSWRunTable walk failed for %s: %s", ip, e)
        return []


def _is_real_value(v) -> bool:
    return isinstance(v, (int, float)) and v not in ("<noSuchObject>", "<noSuchInstance>")


def _clean_scalar(v):
    return v if _is_real_value(v) else None


def _bytes_to_readable(n) -> str | None:
    if not isinstance(n, (int, float)):
        return None
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{int(n)} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def _ticks_to_readable(ticks) -> str | None:
    if ticks is None:
        return None
    seconds = ticks / 100
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{int(days)}d {int(hours)}h {int(minutes)}m"