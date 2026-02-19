"""
vuln_detection.py - Vulnerability detection engine.

Three complementary detection strategies:
  1. Rule-based heuristic checks (no external tools required)
  2. Nmap NSE vulnerability scripts (--script vuln)
  3. CVE correlation against a local knowledge-base of known-bad versions
"""

import re
import logging
from typing import Dict, List, Optional

logger = logging.getLogger("vuln_scanner")

# Attempt to import python-nmap (reused from service_detection)
try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════ #
#  Severity helpers
# ══════════════════════════════════════════════════════════════════════ #
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _sev_value(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.upper(), 0)


# ══════════════════════════════════════════════════════════════════════ #
#  Local CVE knowledge-base  (example entries – extend as needed)
# ══════════════════════════════════════════════════════════════════════ #
# Key: (product_lower, version_prefix) → list of CVE dicts
CVE_DATABASE: Dict[tuple, List[dict]] = {
    ("apache httpd", "2.4.49"): [
        {
            "cve": "CVE-2021-41773",
            "severity": "CRITICAL",
            "description": "Path traversal and RCE in Apache 2.4.49",
        },
    ],
    ("apache httpd", "2.4.50"): [
        {
            "cve": "CVE-2021-42013",
            "severity": "CRITICAL",
            "description": "Incomplete fix for CVE-2021-41773 in Apache 2.4.50",
        },
    ],
    ("openssh", "7."): [
        {
            "cve": "CVE-2018-15473",
            "severity": "MEDIUM",
            "description": "OpenSSH <= 7.x user enumeration vulnerability",
        },
    ],
    ("openssh", "8.0"): [
        {
            "cve": "CVE-2020-15778",
            "severity": "HIGH",
            "description": "OpenSSH 8.0 scp command injection",
        },
    ],
    ("proftpd", "1.3.5"): [
        {
            "cve": "CVE-2015-3306",
            "severity": "CRITICAL",
            "description": "ProFTPD 1.3.5 mod_copy remote code execution",
        },
    ],
    ("vsftpd", "2.3.4"): [
        {
            "cve": "CVE-2011-2523",
            "severity": "CRITICAL",
            "description": "vsftpd 2.3.4 backdoor command execution",
        },
    ],
    ("microsoft iis", "7."): [
        {
            "cve": "CVE-2017-7269",
            "severity": "CRITICAL",
            "description": "IIS 6.0/7.x WebDAV ScStoragePathFromUrl buffer overflow",
        },
    ],
    ("nginx", "1.17."): [
        {
            "cve": "CVE-2019-20372",
            "severity": "MEDIUM",
            "description": "Nginx <= 1.17.7 HTTP request smuggling",
        },
    ],
    ("mysql", "5.7."): [
        {
            "cve": "CVE-2020-14812",
            "severity": "MEDIUM",
            "description": "MySQL 5.7.x Optimizer DoS vulnerability",
        },
    ],
    ("postgresql", "9."): [
        {
            "cve": "CVE-2019-10164",
            "severity": "HIGH",
            "description": "PostgreSQL 9.x stack buffer overflow in password auth",
        },
    ],
}


# ══════════════════════════════════════════════════════════════════════ #
#  VulnerabilityDetector class
# ══════════════════════════════════════════════════════════════════════ #
class VulnerabilityDetector:
    """
    Multi-strategy vulnerability detection engine.

    Every public method returns a list of vulnerability dicts with keys:
        port, service, severity, title, description, source
    """

    # ── 1. Rule-based heuristic detection ─────────────────────────────
    def rule_based_scan(
        self,
        open_ports: List[int],
        services: Dict[int, Dict[str, str]],
    ) -> List[dict]:
        """
        Apply heuristic rules to open ports / detected services.

        Rules evaluated:
          • FTP (21) open  → anonymous-login risk
          • Telnet (23) open → high risk (cleartext protocol)
          • SMB (445) open → medium risk (worm-friendly surface)
          • Outdated Apache → flag known-bad version ranges
          • RDP (3389) open → medium risk (brute-force surface)
          • MongoDB (27017) open → medium risk (often unauthenticated)

        Returns:
            List of vulnerability dictionaries.
        """
        vulns: List[dict] = []
        logger.info("Running rule-based vulnerability checks …")

        # --- FTP anonymous login risk ---
        if 21 in open_ports:
            vulns.append(
                {
                    "port": 21,
                    "service": "FTP",
                    "severity": "HIGH",
                    "title": "FTP Service Detected – Anonymous Login Risk",
                    "description": (
                        "FTP is open on port 21. Anonymous login may be enabled, "
                        "allowing unauthenticated file access. Verify configuration."
                    ),
                    "source": "rule-engine",
                }
            )

        # --- Telnet cleartext risk ---
        if 23 in open_ports:
            vulns.append(
                {
                    "port": 23,
                    "service": "Telnet",
                    "severity": "HIGH",
                    "title": "Telnet Service Detected – Cleartext Protocol",
                    "description": (
                        "Telnet transmits credentials in cleartext. "
                        "Replace with SSH immediately."
                    ),
                    "source": "rule-engine",
                }
            )

        # --- SMB worm surface ---
        if 445 in open_ports:
            vulns.append(
                {
                    "port": 445,
                    "service": "SMB",
                    "severity": "MEDIUM",
                    "title": "SMB Service Exposed",
                    "description": (
                        "SMB (port 445) is reachable. Historically targeted by "
                        "worms (WannaCry, EternalBlue). Restrict access via firewall."
                    ),
                    "source": "rule-engine",
                }
            )

        # --- RDP brute-force surface ---
        if 3389 in open_ports:
            vulns.append(
                {
                    "port": 3389,
                    "service": "RDP",
                    "severity": "MEDIUM",
                    "title": "RDP Service Exposed",
                    "description": (
                        "Remote Desktop (port 3389) is externally accessible. "
                        "Enable NLA, use a VPN or gateway, and enforce MFA."
                    ),
                    "source": "rule-engine",
                }
            )

        # --- MongoDB unauthenticated ---
        if 27017 in open_ports:
            vulns.append(
                {
                    "port": 27017,
                    "service": "MongoDB",
                    "severity": "MEDIUM",
                    "title": "MongoDB Exposed Without Authentication",
                    "description": (
                        "MongoDB default port is open. If authentication is not "
                        "enabled, the database may be publicly writable."
                    ),
                    "source": "rule-engine",
                }
            )

        # --- Outdated Apache detection (from service info) ---
        for port, info in services.items():
            product = info.get("product", "").lower()
            version = info.get("version", "")

            if "apache" in product and version:
                try:
                    parts = version.split(".")
                    major, minor = int(parts[0]), int(parts[1])
                    # Apache < 2.4.52 considered outdated
                    if major < 2 or (major == 2 and minor < 4):
                        severity = "HIGH"
                    elif major == 2 and minor == 4:
                        patch = int(parts[2]) if len(parts) > 2 else 0
                        severity = "HIGH" if patch < 52 else "LOW"
                    else:
                        severity = "LOW"

                    if severity in ("HIGH", "MEDIUM"):
                        vulns.append(
                            {
                                "port": port,
                                "service": info.get("service", "http"),
                                "severity": severity,
                                "title": f"Outdated Apache Version ({version})",
                                "description": (
                                    f"Apache {version} is outdated and may contain "
                                    f"known vulnerabilities. Upgrade to latest stable."
                                ),
                                "source": "rule-engine",
                            }
                        )
                except (ValueError, IndexError):
                    pass  # unparseable version – skip

        logger.info("Rule-based scan complete – %d issue(s)", len(vulns))
        return vulns

    # ── 2. Nmap NSE vulnerability scripts ─────────────────────────────
    def nmap_vuln_scan(
        self,
        host: str,
        ports: List[int],
    ) -> List[dict]:
        """
        Run nmap --script vuln against open ports and extract CVE IDs.

        Returns:
            List of vulnerability dicts parsed from nmap script output.
        """
        vulns: List[dict] = []

        if not NMAP_AVAILABLE:
            logger.warning("python-nmap unavailable – skipping NSE vuln scan")
            return vulns

        try:
            scanner = nmap.PortScanner()
        except nmap.PortScannerError as exc:
            logger.error("nmap binary not found – NSE scan skipped (%s)", exc)
            return vulns

        if not ports:
            return vulns

        port_str = ",".join(str(p) for p in ports)
        logger.info("Running nmap --script vuln on %s ports %s", host, port_str)

        try:
            scanner.scan(hosts=host, ports=port_str, arguments="--script vuln")
        except Exception as exc:
            logger.error("nmap vuln script scan failed: %s", exc)
            return vulns

        # Parse script output for each port
        cve_pattern = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

        try:
            if host not in scanner.all_hosts():
                return vulns

            host_info = scanner[host]
            for proto in host_info.all_protocols():
                for port in host_info[proto]:
                    port_data = host_info[proto][port]
                    scripts = port_data.get("script", {})

                    for script_name, output in scripts.items():
                        # Extract all CVE IDs from the script output
                        cves = cve_pattern.findall(output)
                        # Determine severity from output text
                        severity = self._parse_nse_severity(output)

                        if cves:
                            for cve_id in set(cves):
                                vulns.append(
                                    {
                                        "port": port,
                                        "service": port_data.get("name", "unknown"),
                                        "severity": severity,
                                        "title": f"{cve_id} ({script_name})",
                                        "description": output.strip()[:200],
                                        "source": "nmap-nse",
                                    }
                                )
                        elif "VULNERABLE" in output.upper():
                            # Script flagged a vuln but no CVE extracted
                            vulns.append(
                                {
                                    "port": port,
                                    "service": port_data.get("name", "unknown"),
                                    "severity": severity,
                                    "title": f"NSE: {script_name}",
                                    "description": output.strip()[:200],
                                    "source": "nmap-nse",
                                }
                            )
        except KeyError as exc:
            logger.error("Error parsing nmap NSE results: %s", exc)

        logger.info("NSE vuln scan complete – %d finding(s)", len(vulns))
        return vulns

    # ── 3. CVE correlation ────────────────────────────────────────────
    def cve_correlate(
        self,
        services: Dict[int, Dict[str, str]],
    ) -> List[dict]:
        """
        Match detected service versions against the local CVE knowledge-base.

        Returns:
            List of vulnerability dicts with CVE references.
        """
        vulns: List[dict] = []
        logger.info("Running CVE correlation against %d service(s)", len(services))

        for port, info in services.items():
            product = info.get("product", "").strip()
            version = info.get("version", "").strip()
            service = info.get("service", "unknown")

            if not product:
                continue

            product_lower = product.lower()

            for (db_product, db_version_prefix), cve_list in CVE_DATABASE.items():
                if db_product in product_lower and version.startswith(db_version_prefix):
                    for cve in cve_list:
                        vulns.append(
                            {
                                "port": port,
                                "service": service,
                                "severity": cve["severity"],
                                "title": f"{cve['cve']} – {product} {version}",
                                "description": cve["description"],
                                "source": "cve-correlation",
                            }
                        )

        logger.info("CVE correlation complete – %d match(es)", len(vulns))
        return vulns

    # ── Public orchestrator ───────────────────────────────────────────
    def run_all(
        self,
        host: str,
        open_ports: List[int],
        services: Dict[int, Dict[str, str]],
    ) -> List[dict]:
        """
        Execute all three detection strategies and return a unified,
        de-duplicated, severity-sorted vulnerability list.
        """
        logger.info("=== Vulnerability detection engine started ===")

        all_vulns: List[dict] = []

        # Strategy 1 – rule-based
        all_vulns.extend(self.rule_based_scan(open_ports, services))

        # Strategy 2 – nmap NSE scripts
        all_vulns.extend(self.nmap_vuln_scan(host, open_ports))

        # Strategy 3 – CVE correlation
        all_vulns.extend(self.cve_correlate(services))

        # De-duplicate by (port, title)
        seen = set()
        unique: List[dict] = []
        for v in all_vulns:
            key = (v["port"], v["title"])
            if key not in seen:
                seen.add(key)
                unique.append(v)

        # Sort by severity (CRITICAL first)
        unique.sort(key=lambda v: _sev_value(v["severity"]), reverse=True)

        logger.info(
            "=== Vulnerability detection complete – %d unique finding(s) ===",
            len(unique),
        )
        return unique

    # ── Internal helpers ──────────────────────────────────────────────
    @staticmethod
    def _parse_nse_severity(output: str) -> str:
        """Attempt to extract a severity level from nmap script output text."""
        upper = output.upper()
        if "CRITICAL" in upper:
            return "CRITICAL"
        if "HIGH" in upper:
            return "HIGH"
        if "MEDIUM" in upper:
            return "MEDIUM"
        if "LOW" in upper:
            return "LOW"
        # Default when no severity is parsed
        return "HIGH"

    # ── Risk score computation ────────────────────────────────────────
    @staticmethod
    def compute_risk_score(vulns: List[dict]) -> dict:
        """
        Compute an aggregate risk summary from the vulnerability list.

        Returns:
            {
                "total":    int,
                "critical": int,
                "high":     int,
                "medium":   int,
                "low":      int,
                "info":     int,
                "score":    float   (0-10 scale),
                "rating":   str     ("Critical" / "High" / "Medium" / "Low" / "Clean"),
            }
        """
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

        total = len(vulns)

        # Weighted score  (max capped at 10.0)
        raw = (
            counts["CRITICAL"] * 4.0
            + counts["HIGH"] * 2.5
            + counts["MEDIUM"] * 1.5
            + counts["LOW"] * 0.5
            + counts["INFO"] * 0.1
        )
        score = min(round(raw, 1), 10.0)

        if score >= 8.0:
            rating = "Critical"
        elif score >= 5.0:
            rating = "High"
        elif score >= 2.5:
            rating = "Medium"
        elif score > 0:
            rating = "Low"
        else:
            rating = "Clean"

        return {
            "total": total,
            "critical": counts["CRITICAL"],
            "high": counts["HIGH"],
            "medium": counts["MEDIUM"],
            "low": counts["LOW"],
            "info": counts["INFO"],
            "score": score,
            "rating": rating,
        }
