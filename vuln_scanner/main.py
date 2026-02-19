"""
main.py - Entry point for the Vulnerability Scanner CLI  v3.0

Orchestrates host discovery, port scanning, service detection,
vulnerability analysis, and multi-format report generation with
a professional coloured terminal interface.
"""

import sys
import re
import os
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
from scanner.vuln_detection import VulnerabilityDetector
from report_generator import (
    ScanReport,
    generate_txt_report,
    generate_json_report,
    generate_pdf_report,
)

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
{Fore.YELLOW}   Professional Modular Vulnerability Scanner  v3.0
{Fore.WHITE}  ─────────────────────────────────────────────────────────────────────
"""

DIVIDER = f"{Fore.WHITE}  {'─' * 65}"

RATING_COLORS = {
    "Critical": Fore.RED + Style.BRIGHT,
    "High": Fore.RED,
    "Medium": Fore.YELLOW,
    "Low": Fore.CYAN,
    "Clean": Fore.GREEN + Style.BRIGHT,
}

SEVERITY_COLORS = {
    "CRITICAL": Fore.RED + Style.BRIGHT,
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.CYAN,
    "INFO": Fore.WHITE,
}


# ══════════════════════════════════════════════════════════════════════ #
#  Input validation
# ══════════════════════════════════════════════════════════════════════ #
def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_target(target: str) -> bool:
    """Accept an IPv4/IPv6 address **or** a hostname (RFC 1123)."""
    if validate_ip(target):
        return True
    hostname_re = re.compile(
        r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*$"
    )
    return hostname_re.match(target) is not None


# ══════════════════════════════════════════════════════════════════════ #
#  User prompts
# ══════════════════════════════════════════════════════════════════════ #
def get_port_range() -> tuple:
    """Prompt for port range; return (start, end)."""
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


def get_rate_limit() -> float:
    """Prompt for optional rate-limit delay between batches."""
    val = input(
        f"{Fore.WHITE}      Rate limit delay between batches in seconds "
        f"(default 0 = off): {Fore.GREEN}"
    ).strip()
    try:
        return max(0.0, float(val)) if val else 0.0
    except ValueError:
        return 0.0


# ══════════════════════════════════════════════════════════════════════ #
#  Timing helper
# ══════════════════════════════════════════════════════════════════════ #
def elapsed(start: float) -> str:
    """Return a human-friendly elapsed-time string."""
    secs = time.time() - start
    if secs < 60:
        return f"{secs:.2f}s"
    mins = int(secs // 60)
    remaining = secs % 60
    return f"{mins}m {remaining:.1f}s"


def elapsed_raw(start: float) -> float:
    """Return raw seconds since *start*."""
    return round(time.time() - start, 3)


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
    """Display service detection results."""
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


def print_vulns(vulns: list) -> None:
    """Display vulnerabilities with table + detail tree."""
    print(
        f"\n{Fore.RED}{Style.BRIGHT}"
        f"  {'SEV':<10} {'PORT':<8} {'TITLE':<42} {'SOURCE'}"
    )
    print(f"  {'─'*10} {'─'*8} {'─'*42} {'─'*16}")
    for v in vulns:
        sev = v["severity"].upper()
        color = SEVERITY_COLORS.get(sev, Fore.WHITE)
        print(
            f"  {color}{sev:<10} "
            f"{Fore.WHITE}{v['port']:<8} "
            f"{Fore.YELLOW}{v['title'][:40]:<42} "
            f"{Fore.MAGENTA}{v['source']}"
        )
    # Detail tree
    print(f"\n{Fore.WHITE}  ┌─ Vulnerability Details")
    for v in vulns:
        sev = v["severity"].upper()
        color = SEVERITY_COLORS.get(sev, Fore.WHITE)
        print(f"{Fore.WHITE}  │")
        print(f"{Fore.WHITE}  ├─ [{color}{sev}{Fore.WHITE}] {Fore.YELLOW}{v['title']}")
        print(
            f"{Fore.WHITE}  │   Port {v['port']} · {v['service']} · Source: {v['source']}"
        )
        print(f"{Fore.WHITE}  │   {Fore.CYAN}{v['description'][:160]}")
    print(f"{Fore.WHITE}  └{'─'*64}")


def print_risk_score(risk: dict) -> None:
    """Display the aggregate risk score panel."""
    rc = RATING_COLORS.get(risk["rating"], Fore.WHITE)

    print(f"\n{Fore.WHITE}  ┌{'─'*44}┐")
    print(
        f"{Fore.WHITE}  │{Fore.RED}{Style.BRIGHT}"
        f"  ⚠  RISK ASSESSMENT{' '*24}{Fore.WHITE}│"
    )
    print(f"{Fore.WHITE}  ├{'─'*44}┤")
    print(
        f"{Fore.WHITE}  │  Overall Score : {rc}{risk['score']}/10"
        f"{Style.RESET_ALL}{' '*(22 - len(str(risk['score'])))}│"
    )
    print(
        f"{Fore.WHITE}  │  Rating        : {rc}{risk['rating']}"
        f"{Style.RESET_ALL}{' '*(24 - len(risk['rating']))}│"
    )
    print(
        f"{Fore.WHITE}  │  Total Findings: {Fore.YELLOW}{risk['total']}"
        f"{Style.RESET_ALL}{' '*(24 - len(str(risk['total'])))}│"
    )
    print(f"{Fore.WHITE}  ├{'─'*44}┤")
    for label, key, color in [
        ("CRITICAL", "critical", Fore.RED + Style.BRIGHT),
        ("HIGH",     "high",     Fore.RED),
        ("MEDIUM",   "medium",   Fore.YELLOW),
        ("LOW",      "low",      Fore.CYAN),
        ("INFO",     "info",     Fore.WHITE),
    ]:
        val = str(risk[key])
        pad = 31 - len(val)
        print(
            f"{Fore.WHITE}  │  {color}{label:<9}: {val}"
            f"{Style.RESET_ALL}{' '*pad}│"
        )
    print(f"{Fore.WHITE}  └{'─'*44}┘")


def print_phase_timings(timings: dict) -> None:
    """Display phase-level timing breakdown."""
    print(f"\n{Fore.WHITE}  ┌─ Phase Timings")
    for phase, dur in timings.items():
        print(f"{Fore.WHITE}  │  {Fore.CYAN}{phase:<30} {Fore.YELLOW}{dur}")
    print(f"{Fore.WHITE}  └{'─'*44}")


def print_report_paths(paths: dict) -> None:
    """Display generated report file paths."""
    print(f"\n{Fore.WHITE}  ┌─ Generated Reports")
    for fmt, path in paths.items():
        if path:
            basename = os.path.basename(path)
            print(f"{Fore.WHITE}  │  {Fore.CYAN}{fmt:<6} {Fore.GREEN}{basename}")
        else:
            print(f"{Fore.WHITE}  │  {Fore.CYAN}{fmt:<6} {Fore.RED}skipped")
    print(f"{Fore.WHITE}  └{'─'*44}")


# ══════════════════════════════════════════════════════════════════════ #
#  Main workflow
# ══════════════════════════════════════════════════════════════════════ #
def main() -> None:
    print(BANNER)

    scan_start = time.time()
    phase_timings: dict = {}
    logger.info("=== Scan session started ===")

    # ── 1. Target Input ───────────────────────────────────────────────
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

    # ── 2. Host Discovery ─────────────────────────────────────────────
    print_section("PHASE 1 › HOST DISCOVERY")
    print(f"{Fore.WHITE}  [*] Pinging {target} …")

    t0 = time.time()
    hd = HostDiscovery(timeout=2)
    host_alive = hd.ping_host(target)
    phase_timings["Host Discovery"] = elapsed(t0)

    if host_alive:
        print(f"{Fore.GREEN}{Style.BRIGHT}  [✔] Host {target} is UP")
    else:
        print(f"{Fore.RED}  [✘] Host {target} appears DOWN")
        print(f"{Fore.YELLOW}  [!] Proceeding with scan anyway …")
        logger.warning("Host %s appears down – continuing scan", target)

    print(
        f"{Fore.WHITE}  [⏱] Host discovery completed in "
        f"{Fore.YELLOW}{phase_timings['Host Discovery']}"
    )

    # ── 3. Port Scanning ──────────────────────────────────────────────
    print_section("PHASE 2 › PORT SCANNING")
    start_port, end_port = get_port_range()
    rate_limit = get_rate_limit()

    total_ports = end_port - start_port + 1
    print(
        f"\n{Fore.WHITE}  [*] Scanning {Fore.YELLOW}{total_ports}"
        f"{Fore.WHITE} ports ({start_port}–{end_port}) on "
        f"{Fore.GREEN}{target}{Fore.WHITE} …"
    )
    if rate_limit > 0:
        print(
            f"{Fore.WHITE}  [*] Rate limit: {Fore.YELLOW}{rate_limit}s"
            f"{Fore.WHITE} delay between batches"
        )
    print()

    t0 = time.time()
    ps = PortScanner(timeout=1.0, max_threads=100, rate_limit=rate_limit)
    open_ports = ps.scan(target, start_port, end_port)
    phase_timings["Port Scanning"] = elapsed(t0)

    if open_ports:
        print_open_ports(open_ports)
        print(
            f"\n{Fore.WHITE}  [*] {Fore.GREEN}{len(open_ports)} open port(s)"
            f"{Fore.WHITE} found in {Fore.YELLOW}{phase_timings['Port Scanning']}"
        )
    else:
        print(
            f"{Fore.RED}  [!] No open ports found in range {start_port}–{end_port}"
        )

    logger.info(
        "Port scan duration: %s – %d open ports",
        phase_timings["Port Scanning"],
        len(open_ports),
    )

    # ── 4. Service Detection ──────────────────────────────────────────
    services: dict = {}
    if open_ports:
        print_section("PHASE 3 › SERVICE DETECTION (nmap -sV)")
        print(
            f"{Fore.WHITE}  [*] Identifying services on "
            f"{len(open_ports)} port(s) …\n"
        )

        t0 = time.time()
        sd = ServiceDetector()
        services = sd.detect_services(target, open_ports)
        phase_timings["Service Detection"] = elapsed(t0)

        if services:
            print_services(services)
        else:
            print(
                f"{Fore.YELLOW}  [!] Service detection returned no results."
                f"  (Is nmap installed?)"
            )
        print(
            f"\n{Fore.WHITE}  [⏱] Service detection completed in "
            f"{Fore.YELLOW}{phase_timings['Service Detection']}"
        )
    else:
        phase_timings["Service Detection"] = "skipped"

    # ── 5. Vulnerability Detection ────────────────────────────────────
    vulns: list = []
    risk = {
        "total": 0, "critical": 0, "high": 0,
        "medium": 0, "low": 0, "info": 0,
        "score": 0, "rating": "Clean",
    }
    if open_ports:
        print_section("PHASE 4 › VULNERABILITY DETECTION")
        print(f"{Fore.WHITE}  [*] Running vulnerability engine …\n")

        t0 = time.time()
        vd = VulnerabilityDetector()
        vulns = vd.run_all(target, open_ports, services)
        phase_timings["Vuln Detection"] = elapsed(t0)

        if vulns:
            print_vulns(vulns)
        else:
            print(f"{Fore.GREEN}{Style.BRIGHT}  [✔] No vulnerabilities detected")

        risk = VulnerabilityDetector.compute_risk_score(vulns)
        print_risk_score(risk)

        print(
            f"\n{Fore.WHITE}  [⏱] Vulnerability scan completed in "
            f"{Fore.YELLOW}{phase_timings['Vuln Detection']}"
        )
    else:
        phase_timings["Vuln Detection"] = "skipped"

    # ── 6. Report Generation ──────────────────────────────────────────
    total_elapsed = elapsed(scan_start)
    phase_timings["Total"] = total_elapsed

    print_section("PHASE 5 › REPORT GENERATION")
    print(f"{Fore.WHITE}  [*] Generating reports …\n")

    t0 = time.time()
    scan_report = ScanReport(
        target=target,
        host_alive=host_alive,
        start_port=start_port,
        end_port=end_port,
        open_ports=open_ports,
        services=services,
        vulnerabilities=vulns,
        risk=risk,
        scan_duration=total_elapsed,
        phase_timings=phase_timings,
    )

    report_paths = {}

    # TXT
    try:
        report_paths["TXT"] = generate_txt_report(scan_report)
        print(
            f"  {Fore.GREEN}  [✔] TXT  → {Fore.WHITE}"
            f"{os.path.basename(report_paths['TXT'])}"
        )
    except Exception as exc:
        report_paths["TXT"] = None
        logger.error("TXT report failed: %s", exc)
        print(f"  {Fore.RED}  [✘] TXT report failed: {exc}")

    # JSON
    try:
        report_paths["JSON"] = generate_json_report(scan_report)
        print(
            f"  {Fore.GREEN}  [✔] JSON → {Fore.WHITE}"
            f"{os.path.basename(report_paths['JSON'])}"
        )
    except Exception as exc:
        report_paths["JSON"] = None
        logger.error("JSON report failed: %s", exc)
        print(f"  {Fore.RED}  [✘] JSON report failed: {exc}")

    # PDF
    try:
        pdf_path = generate_pdf_report(scan_report)
        report_paths["PDF"] = pdf_path
        if pdf_path:
            print(
                f"  {Fore.GREEN}  [✔] PDF  → {Fore.WHITE}"
                f"{os.path.basename(pdf_path)}"
            )
        else:
            print(
                f"  {Fore.YELLOW}  [!] PDF  → skipped (reportlab not installed)"
            )
    except Exception as exc:
        report_paths["PDF"] = None
        logger.error("PDF report failed: %s", exc)
        print(f"  {Fore.RED}  [✘] PDF report failed: {exc}")

    phase_timings["Report Generation"] = elapsed(t0)
    logger.info("Report generation duration: %s", phase_timings["Report Generation"])

    # ── 7. Final Summary ──────────────────────────────────────────────
    # Recalculate total after reports
    total_elapsed = elapsed(scan_start)
    phase_timings["Total"] = total_elapsed

    print_section("SCAN SUMMARY")

    # Main stats
    print(f"{Fore.WHITE}  Target         : {Fore.GREEN}{Style.BRIGHT}{target}")
    print(
        f"{Fore.WHITE}  Host status    : "
        f"{Fore.GREEN if host_alive else Fore.RED}"
        f"{'UP' if host_alive else 'DOWN'}"
    )
    print(f"{Fore.WHITE}  Port range     : {Fore.YELLOW}{start_port}–{end_port}")
    print(f"{Fore.WHITE}  Total scanned  : {Fore.YELLOW}{total_ports}")
    print(f"{Fore.WHITE}  Open ports     : {Fore.GREEN}{len(open_ports)}")
    print(
        f"{Fore.WHITE}  Vulnerabilities: "
        f"{Fore.RED if risk['total'] > 0 else Fore.GREEN}{risk['total']}"
    )

    if risk["total"] > 0:
        rc = RATING_COLORS.get(risk["rating"], Fore.WHITE)
        print(
            f"{Fore.WHITE}  Risk rating    : "
            f"{rc}{risk['rating']} ({risk['score']}/10){Style.RESET_ALL}"
        )
        # Severity breakdown inline
        sev_parts = []
        for label, key, color in [
            ("C", "critical", Fore.RED + Style.BRIGHT),
            ("H", "high", Fore.RED),
            ("M", "medium", Fore.YELLOW),
            ("L", "low", Fore.CYAN),
        ]:
            if risk[key] > 0:
                sev_parts.append(f"{color}{risk[key]}{label}{Style.RESET_ALL}")
        if sev_parts:
            print(
                f"{Fore.WHITE}  Risk breakdown : "
                + f"{Fore.WHITE} / ".join(sev_parts)
            )

    print(f"{Fore.WHITE}  Total time     : {Fore.YELLOW}{total_elapsed}")

    # Phase timings
    print_phase_timings(phase_timings)

    # Report paths
    print_report_paths(report_paths)

    print(DIVIDER)

    logger.info(
        "=== Scan session finished – %s, %d open ports, %d vulns, "
        "risk=%s (%s/10) in %s ===",
        target,
        len(open_ports),
        risk["total"],
        risk["rating"],
        risk["score"],
        total_elapsed,
    )

    print(
        f"\n{Fore.CYAN}  [✔] Scan complete. "
        f"Logs → {Fore.YELLOW}logs/{Fore.CYAN}  "
        f"Reports → {Fore.YELLOW}reports/{Style.RESET_ALL}\n"
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
