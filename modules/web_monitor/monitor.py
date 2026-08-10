import asyncio
import socket
import time

import httpx
import requests


# ============================================================
# CONFIGURATION
# ============================================================

MAX_CONCURRENT_CHECKS = 10
REQUEST_TIMEOUT = 10
SERVER_TIMEOUT = 5


# ============================================================
# 1. DISCOVER SUBDOMAINS
# ============================================================

def discover_subdomains(domain):

    print(f"\nDiscovering subdomains for: {domain}")
    print("-" * 60)

    url = f"https://crt.sh/?q=%25.{domain}&output=json"

    subdomains = set()

    try:

        response = requests.get(
            url,
            timeout=2000
        )

        response.raise_for_status()

        certificates = response.json()

        for certificate in certificates:

            names = certificate.get(
                "name_value",
                ""
            )

            for name in names.splitlines():

                name = name.strip().lower()

                # Remove wildcard
                if name.startswith("*."):
                    name = name[2:]

                # Only keep root domain and
                # its subdomains
                if (
                    name == domain
                    or name.endswith("." + domain)
                ):
                    subdomains.add(name)

    except requests.RequestException as error:

        print(
            f"Subdomain discovery failed: {error}"
        )

    # IMPORTANT:
    # Always monitor the main/root domain.
    subdomains.add(domain)

    return sorted(subdomains)


# ============================================================
# 2. RESOLVE DOMAIN → IP
# ============================================================

async def resolve_ip(domain):

    try:

        loop = asyncio.get_running_loop()

        ip = await loop.run_in_executor(
            None,
            lambda: socket.gethostbyname(domain)
        )

        return {
            "success": True,
            "ip": ip,
            "error": None
        }

    except socket.gaierror as error:

        return {
            "success": False,
            "ip": None,
            "error": str(error)
        }


# ============================================================
# 3. CHECK SERVER / TCP CONNECTIVITY
# ============================================================

async def check_server(ip, ports=(443, 80)):

    loop = asyncio.get_running_loop()

    for port in ports:

        try:

            start = time.perf_counter()

            # socket.create_connection is blocking,
            # so run it in a thread.
            sock = await asyncio.wait_for(

                loop.run_in_executor(
                    None,
                    lambda: socket.create_connection(
                        (ip, port),
                        timeout=SERVER_TIMEOUT
                    )
                ),

                timeout=SERVER_TIMEOUT + 1
            )

            end = time.perf_counter()

            sock.close()

            response_time = (
                end - start
            ) * 1000

            return {
                "success": True,
                "port": port,
                "response_time": round(
                    response_time,
                    2
                ),
                "error": None
            }

        except Exception:
            continue

    return {
        "success": False,
        "port": None,
        "response_time": None,
        "error": "TCP connection failed on ports 443 and 80"
    }


# ============================================================
# 4. CHECK WEBSITE
# ============================================================

async def check_website(
    client,
    domain
):

    protocols = [
        "https",
        "http"
    ]

    last_error = None

    for protocol in protocols:

        url = f"{protocol}://{domain}"

        try:

            start = time.perf_counter()

            response = await client.get(

                url,

                timeout=REQUEST_TIMEOUT,

                follow_redirects=True
            )

            end = time.perf_counter()

            response_time = (
                end - start
            ) * 1000

            status_code = response.status_code

            # ------------------------------------------------
            # HTTP STATUS CLASSIFICATION
            # ------------------------------------------------

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
                "response_time": round(
                    response_time,
                    2
                ),
                "final_url": str(
                    response.url
                ),
                "error": None
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
        "error": last_error
    }


# ============================================================
# 5. CHECK ONE DOMAIN
# ============================================================

async def check_domain(
    client,
    domain,
    semaphore
):

    # Limit concurrent checks
    async with semaphore:

        result = {

            "domain": domain,

            # DNS
            "ip": None,
            "dns_status": "FAILED",

            # Server
            "server_status": "UNKNOWN",
            "server_port": None,
            "server_response_time": None,

            # Website
            "website_status": "DOWN",
            "protocol": None,
            "http_status": None,
            "response_time": None,

            # Final diagnosis
            "overall_status": "DOWN",

            "error": None
        }

        # ====================================================
        # STEP 1 — DNS / IP RESOLUTION
        # ====================================================

        dns_result = await resolve_ip(domain)

        if not dns_result["success"]:

            result["dns_status"] = "FAILED"

            result["server_status"] = "UNKNOWN"

            result["website_status"] = "DOWN"

            result["overall_status"] = "DNS_FAILED"

            result["error"] = (
                "DNS resolution failed"
            )

            return result

        # DNS successful
        result["dns_status"] = "UP"

        result["ip"] = dns_result["ip"]

        # ====================================================
        # STEP 2 — SERVER CONNECTIVITY
        # ====================================================

        server_result = await check_server(
            result["ip"]
        )

        if server_result["success"]:

            result["server_status"] = "UP"

            result["server_port"] = (
                server_result["port"]
            )

            result["server_response_time"] = (
                server_result["response_time"]
            )

        else:

            result["server_status"] = "DOWN"

        # ====================================================
        # STEP 3 — WEBSITE CHECK
        # ====================================================

        website_result = await check_website(
            client,
            domain
        )

        result["website_status"] = (
            website_result["status"]
        )

        result["protocol"] = (
            website_result["protocol"]
        )

        result["http_status"] = (
            website_result["http_status"]
        )

        result["response_time"] = (
            website_result["response_time"]
        )

        # ====================================================
        # STEP 4 — FINAL DIAGNOSIS
        # ====================================================

        # ----------------------------------------------------
        # Website is working
        # ----------------------------------------------------

        if website_result["status"] == "UP":

            result["overall_status"] = "UP"

            # Server might not have been detected by
            # our TCP check because of a proxy/load balancer.
            if result["server_status"] == "DOWN":

                result["server_status"] = (
                    "REACHABLE_VIA_HTTP"
                )

        # ----------------------------------------------------
        # Website responds with 4xx
        # ----------------------------------------------------

        elif website_result["status"] == "DEGRADED":

            result["overall_status"] = "DEGRADED"

            result["error"] = (
                f"Website returned HTTP "
                f"{website_result['http_status']}"
            )

        # ----------------------------------------------------
        # Website doesn't respond
        # ----------------------------------------------------

        else:

            # Server reachable but website failed
            if result["server_status"] == "UP":

                result["overall_status"] = (
                    "WEBSITE_DOWN"
                )

                result["error"] = (
                    "Server is reachable, "
                    "but website is not responding"
                )

            # Server itself unavailable
            elif result["server_status"] == "DOWN":

                result["overall_status"] = (
                    "SERVER_DOWN"
                )

                result["error"] = (
                    "Server is not reachable "
                    "and website is unavailable"
                )

            else:

                result["overall_status"] = (
                    "WEBSITE_DOWN"
                )

        return result


# ============================================================
# 6. CHECK ALL DOMAINS IN PARALLEL
# ============================================================

async def check_all_domains(domains):

    # Example:
    #
    # 50 domains
    #     ↓
    # 10 simultaneous checks
    #
    semaphore = asyncio.Semaphore(
        MAX_CONCURRENT_CHECKS
    )

    async with httpx.AsyncClient(

        headers={
            "User-Agent": "DomainMonitor/1.0"
        }

    ) as client:

        tasks = [

            check_domain(
                client,
                domain,
                semaphore
            )

            for domain in domains
        ]

        # All tasks are created together.
        #
        # Semaphore controls the maximum
        # number running simultaneously.
        results = await asyncio.gather(
            *tasks
        )

        return results


# ============================================================
# 7. STATUS ICON
# ============================================================

def get_status_icon(status):

    if status in [
        "UP",
        "REACHABLE_VIA_HTTP"
    ]:

        return "🟢"

    elif status == "DEGRADED":

        return "🟡"

    elif status == "WEBSITE_DOWN":

        return "🔴"

    elif status == "SERVER_DOWN":

        return "🔴"

    elif status == "DNS_FAILED":

        return "🔴"

    return "⚪"


# ============================================================
# 8. DISPLAY DETAILED RESULTS
# ============================================================

def display_results(results):

    print("\n")

    print("=" * 110)

    print(
        "                    MONITORING RESULTS"
    )

    print("=" * 110)

    for number, result in enumerate(
        results,
        start=1
    ):

        icon = get_status_icon(
            result["overall_status"]
        )

        print(
            f"\n{number}. "
            f"{icon} "
            f"{result['domain']}"
        )

        print("-" * 110)

        # ----------------------------------------------------
        # DNS
        # ----------------------------------------------------

        print(
            f"   DNS Status       : "
            f"{result['dns_status']}"
        )

        print(
            f"   IP Address       : "
            f"{result['ip'] or 'N/A'}"
        )

        # ----------------------------------------------------
        # SERVER
        # ----------------------------------------------------

        print(
            f"   Server Status    : "
            f"{result['server_status']}"
        )

        if result["server_port"]:

            print(
                f"   Server Port      : "
                f"{result['server_port']}"
            )

        if result["server_response_time"]:

            print(
                f"   TCP Response     : "
                f"{result['server_response_time']} ms"
            )

        # ----------------------------------------------------
        # WEBSITE
        # ----------------------------------------------------

        print(
            f"   Website Status   : "
            f"{result['website_status']}"
        )

        print(
            f"   Protocol         : "
            f"{result['protocol'] or 'N/A'}"
        )

        print(
            f"   HTTP Status      : "
            f"{result['http_status'] or 'N/A'}"
        )

        print(
            f"   HTTP Response    : "
            f"{result['response_time'] or 'N/A'} ms"
        )

        # ----------------------------------------------------
        # FINAL DIAGNOSIS
        # ----------------------------------------------------

        print(
            f"\n   FINAL DIAGNOSIS  : "
            f"{result['overall_status']}"
        )

        if result["error"]:

            print(
                f"   Explanation      : "
                f"{result['error']}"
            )

    # ========================================================
    # SUMMARY
    # ========================================================

    total = len(results)

    up = sum(
        1
        for r in results
        if r["overall_status"] == "UP"
    )

    degraded = sum(
        1
        for r in results
        if r["overall_status"] == "DEGRADED"
    )

    website_down = sum(
        1
        for r in results
        if r["overall_status"] == "WEBSITE_DOWN"
    )

    server_down = sum(
        1
        for r in results
        if r["overall_status"] == "SERVER_DOWN"
    )

    dns_failed = sum(
        1
        for r in results
        if r["overall_status"] == "DNS_FAILED"
    )

    print("\n")

    print("=" * 110)

    print(
        "                         SUMMARY"
    )

    print("=" * 110)

    print(
        f"   Total Targets     : {total}"
    )

    print(
        f"   🟢 Website UP      : {up}"
    )

    print(
        f"   🟡 Degraded        : {degraded}"
    )

    print(
        f"   🔴 Website DOWN    : {website_down}"
    )

    print(
        f"   🔴 Server DOWN     : {server_down}"
    )

    print(
        f"   🔴 DNS Failed      : {dns_failed}"
    )

    print("=" * 110)


# ============================================================
# 9. MAIN PROGRAM
# ============================================================

def main():

    print("=" * 70)

    print(
        "       DOMAIN / SERVER MONITORING TOOL"
    )

    print("=" * 70)

    domain = input(
        "\nEnter domain or server name: "
    ).strip().lower()

    # --------------------------------------------------------
    # CLEAN INPUT
    # --------------------------------------------------------

    domain = domain.replace(
        "https://",
        ""
    )

    domain = domain.replace(
        "http://",
        ""
    )

    domain = domain.rstrip("/")

    if not domain:

        print(
            "\n❌ Please enter a valid domain."
        )

        return

    # --------------------------------------------------------
    # DISCOVER SUBDOMAINS
    # --------------------------------------------------------

    domains = discover_subdomains(
        domain
    )

    print(
        f"\nTotal monitoring targets found: "
        f"{len(domains)}"
    )

    print("\nTargets:")

    for item in domains:

        print(
            f"  - {item}"
        )

    # --------------------------------------------------------
    # PARALLEL MONITORING
    # --------------------------------------------------------

    print(
        "\nStarting parallel monitoring..."
    )

    print(
        f"Maximum simultaneous checks: "
        f"{MAX_CONCURRENT_CHECKS}"
    )

    start_time = time.perf_counter()

    results = asyncio.run(
        check_all_domains(domains)
    )

    end_time = time.perf_counter()

    # --------------------------------------------------------
    # DISPLAY RESULTS
    # --------------------------------------------------------

    display_results(results)

    total_time = (
        end_time - start_time
    )

    print(
        f"\nTotal monitoring time: "
        f"{total_time:.2f} seconds"
    )


# ============================================================
# RUN PROGRAM
# ============================================================

if __name__ == "__main__":

    main()
