"""
main.py - Entry point for the Vulnerability Scanner CLI.

Orchestrates host discovery, port scanning, and service detection
with a professional coloured terminal interface.
"""

import sys
import re
import time
import ipaddress
from datetime import datetime

# Third-party
from colorama import init as colorama_init, Fore, Style

# Project modules
from logger import setup_logger
from scanner.host_discovery import HostDiscovery
from scanner.port_scanner import PortScanner, COMMON_PORTS
from scanner.service_detection import ServiceDetector

# ── Initialise colorama (required on Windows) ──────────────────────────
colorama_init(autoreset=True)

# ── Logger ──────────────────────────────────────────────────────────────
logger = setup_logger()

# ── Constants ───────────────────────────────────────────────────────────
BANNER = rf"""
{Fore.CYAN}{Style.BRIGHT}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
 ██║   ██║██║   ██║██║     ████╗  ██║    ██╔════╝██╔════╝██╔══██╗████╗  ██║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║    ███████╗██║     ███████║██╔██╗ ██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║    ╚════██║██║     ██╔══██║██║╚██╗██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║    ███████║╚██████╗██║  ██║██║ ╚████║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Style.RESET_ALL}
{Fore.WHITE}  ─────────────────────────────────────────────────────────────────────
{Fore.YELLOW}   Professional Modular Vulnerability Scanner  v1.0
{Fore.WHITE}  ─────────────────────────────────────────────────────────────────────
"""

DIVIDER = f"{Fore.WHITE}  {'─' * 65}"


# ══════════════════════════════════════════════════════════════════════ #
#  Helper utilities
# ══════════════════════════════════════════════════════════════════════ #
def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_target(target: str) -> bool:
    """
    Accept an IPv4/IPv6 address **or** a hostname (basic regex check).
    """
    if validate_ip(target):
        return True
    # Simple hostname validation (RFC 1123)
    hostname_re = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    )
    return hostname_re.match(target) is not None


def get_port_range() -> tuple:
    """Prompt the user for a port range and return (start, end)."""
    print(f"\n{Fore.CYAN}  [?] Enter port range to scan")
    start = input(f"{Fore.WHITE}      Start port (default 1): {Fore.GREEN}").strip()
    end = input(f"{Fore.WHITE}      End port   (default 1024): {Fore.GREEN}").strip()

    start_port = int(start) if start.isdigit() else 1
    end_port = int(end) if end.isdigit() else 1024

    start_port = max(1, min(start_port, 65535))
    end_port = max(1, min(end_port, 65535))

    if start_port > end_port:
        start_port, end_port = end_port, start_port

    return start_port, end_port


def elapsed(start: float) -> str:
    """Return a human-friendly elapsed-time string."""
    secs = time.time() - start
    if secs < 60:
        return f"{secs:.2f}s"
    mins = int(secs // 60)
    remaining = secs % 60
    return f"{mins}m {remaining:.1f}s"


# ══════════════════════════════════════════════════════════════════════ #
#  Pretty-print helpers
# ══════════════════════════════════════════════════════════════════════ #
def print_section(title: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  ► {title}")
    print(DIVIDER)


def print_open_ports(ports: list) -> None:
    """Display open ports in a neat table."""
    print(f"\n{Fore.GREEN}{Style.BRIGHT}  {'PORT':<10} {'STATE':<10} {'SERVICE'}")
    print(f"  {'─'*10} {'─'*10} {'─'*20}")
    for port in ports:
        service = COMMON_PORTS.get(port, "unknown")
        print(
            f"  {Fore.WHITE}{port:<10} "
            f"{Fore.GREEN}{'open':<10} "
            f"{Fore.YELLOW}{service}"
        )


def print_services(services: dict) -> None:
    """Display nmap service detection results."""
    print(
        f"\n{Fore.GREEN}{Style.BRIGHT}"
        f"  {'PORT':<8} {'STATE':<8} {'SERVICE':<12} {'PRODUCT':<22} {'VERSION'}"
    )
    print(f"  {'─'*8} {'─'*8} {'─'*12} {'─'*22} {'─'*15}")
    for port, info in sorted(services.items()):
        print(
            f"  {Fore.WHITE}{port:<8} "
            f"{Fore.GREEN}{info['state']:<8} "
            f"{Fore.CYAN}{info['service']:<12} "
            f"{Fore.YELLOW}{info['product']:<22} "
            f"{Fore.MAGENTA}{info['version']}"
        )


# ══════════════════════════════════════════════════════════════════════ #
#  Main workflow
# ══════════════════════════════════════════════════════════════════════ #
def main() -> None:
    print(BANNER)

    scan_start = time.time()
    logger.info("=== Scan session started ===")

    # ── 1. Target input ────────────────────────────────────────────────
    target = input(
        f"{Fore.CYAN}  [?] Enter target IP or hostname: {Fore.GREEN}"
    ).strip()

    if not target:
        print(f"\n{Fore.RED}  [!] No target provided. Exiting.")
        logger.error("No target provided – aborting")
        sys.exit(1)

    if not validate_target(target):
        print(f"\n{Fore.RED}  [!] Invalid target: {target}")
        logger.error("Invalid target '%s' – aborting", target)
        sys.exit(1)

    print(f"\n{Fore.WHITE}  [*] Target set → {Fore.GREEN}{Style.BRIGHT}{target}")
    logger.info("Target: %s", target)

    # ── 2. Host Discovery ──────────────────────────────────────────────
    print_section("HOST DISCOVERY")
    print(f"{Fore.WHITE}  [*] Pinging {target} …")

    hd = HostDiscovery(timeout=2)
    host_alive = hd.ping_host(target)

    if host_alive:
        print(f"{Fore.GREEN}{Style.BRIGHT}  [✔] Host {target} is UP")
    else:
        print(f"{Fore.RED}  [✘] Host {target} appears DOWN")
        print(f"{Fore.YELLOW}  [!] Proceeding with scan anyway …")
        logger.warning("Host %s appears down – continuing scan", target)

    # ── 3. Port Scanning ──────────────────────────────────────────────
    print_section("PORT SCANNING")
    start_port, end_port = get_port_range()

    print(
        f"{Fore.WHITE}  [*] Scanning ports {Fore.YELLOW}{start_port}–{end_port}"
        f"{Fore.WHITE} on {Fore.GREEN}{target}{Fore.WHITE} …\n"
    )

    ps = PortScanner(timeout=1.0, max_threads=100)
    port_start_time = time.time()
    open_ports = ps.scan(target, start_port, end_port)
    port_elapsed = elapsed(port_start_time)

    if open_ports:
        print_open_ports(open_ports)
        print(
            f"\n{Fore.WHITE}  [*] {Fore.GREEN}{len(open_ports)} open port(s)"
            f"{Fore.WHITE} found in {Fore.YELLOW}{port_elapsed}"
        )
    else:
        print(f"{Fore.RED}  [!] No open ports found in range {start_port}–{end_port}")

    # ── 4. Service Detection ──────────────────────────────────────────
    if open_ports:
        print_section("SERVICE DETECTION (nmap -sV)")
        print(f"{Fore.WHITE}  [*] Identifying services on {len(open_ports)} port(s) …\n")

        sd = ServiceDetector()
        svc_start_time = time.time()
        services = sd.detect_services(target, open_ports)
        svc_elapsed = elapsed(svc_start_time)

        if services:
            print_services(services)
            print(
                f"\n{Fore.WHITE}  [*] Service detection completed in"
                f" {Fore.YELLOW}{svc_elapsed}"
            )
        else:
            print(
                f"{Fore.YELLOW}  [!] Service detection returned no results."
                f"  (Is nmap installed?)"
            )

    # ── 5. Summary ────────────────────────────────────────────────────
    total_elapsed = elapsed(scan_start)
    print_section("SCAN SUMMARY")
    print(f"{Fore.WHITE}  Target       : {Fore.GREEN}{target}")
    print(f"{Fore.WHITE}  Host status  : {Fore.GREEN if host_alive else Fore.RED}{'UP' if host_alive else 'DOWN'}")
    print(f"{Fore.WHITE}  Ports scanned: {Fore.YELLOW}{start_port}–{end_port}")
    print(f"{Fore.WHITE}  Open ports   : {Fore.GREEN}{len(open_ports)}")
    print(f"{Fore.WHITE}  Total time   : {Fore.YELLOW}{total_elapsed}")
    print(DIVIDER)

    logger.info(
        "=== Scan session finished – %s, %d open ports in %s ===",
        target,
        len(open_ports),
        total_elapsed,
    )

    print(
        f"\n{Fore.CYAN}  [✔] Scan complete. "
        f"Logs saved to {Fore.YELLOW}logs/{Style.RESET_ALL}\n"
    )


# ══════════════════════════════════════════════════════════════════════ #
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(
            f"\n\n{Fore.YELLOW}  [!] Scan interrupted by user (Ctrl+C)."
            f"  Shutting down gracefully …{Style.RESET_ALL}\n"
        )
        logger.warning("Scan interrupted by user (KeyboardInterrupt)")
        sys.exit(0)
    except Exception as exc:
        print(f"\n{Fore.RED}  [✘] Fatal error: {exc}{Style.RESET_ALL}\n")
        logger.critical("Fatal error: %s", exc, exc_info=True)
        sys.exit(1)
