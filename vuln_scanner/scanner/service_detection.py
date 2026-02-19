"""
service_detection.py - Service / version detection via python-nmap.

Wraps nmap's -sV probe to identify running services, product names,
and version strings for each open port.
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger("vuln_scanner")

# Attempt to import python-nmap; gracefully handle its absence
try:
    import nmap

    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    logger.warning(
        "python-nmap is not installed. Install it with:  pip install python-nmap"
    )


class ServiceDetector:
    """Detect services and versions on open ports using nmap -sV."""

    def __init__(self) -> None:
        self._scanner: Optional[object] = None

        if not NMAP_AVAILABLE:
            logger.error("python-nmap library is unavailable – service detection disabled")
            return

        # Verify that the nmap binary is reachable
        try:
            self._scanner = nmap.PortScanner()
            logger.debug("nmap binary located successfully")
        except nmap.PortScannerError as exc:
            logger.error(
                "nmap binary not found on PATH. "
                "Please install nmap: https://nmap.org/download.html  (%s)",
                exc,
            )
            self._scanner = None

    # ------------------------------------------------------------------ #
    #  Public API
    # ------------------------------------------------------------------ #
    def detect_services(
        self,
        host: str,
        ports: List[int],
    ) -> Dict[int, Dict[str, str]]:
        """
        Run nmap -sV against *host* on the specified *ports*.

        Args:
            host:  Target IP address or hostname.
            ports: List of port numbers to probe.

        Returns:
            Dictionary keyed by port number, each value being a dict with:
                - service  : service protocol name (e.g. 'http')
                - product  : software product name (e.g. 'Apache httpd')
                - version  : version string (e.g. '2.4.54')
                - extrainfo: additional details from nmap
                - state    : port state reported by nmap

            Returns an empty dict if nmap is unavailable or no ports given.
        """
        if self._scanner is None:
            logger.error("Service detection skipped – nmap is not available")
            return {}

        if not ports:
            logger.warning("No ports supplied for service detection")
            return {}

        port_str = ",".join(str(p) for p in ports)
        logger.info(
            "Running nmap service detection (-sV) on %s  ports: %s", host, port_str
        )

        try:
            self._scanner.scan(
                hosts=host,
                ports=port_str,
                arguments="-sV",
            )
        except nmap.PortScannerError as exc:
            logger.error("nmap scan failed: %s", exc)
            return {}
        except Exception as exc:
            logger.error("Unexpected error during nmap scan: %s", exc)
            return {}

        results: Dict[int, Dict[str, str]] = {}

        # Parse nmap output
        try:
            if host not in self._scanner.all_hosts():
                logger.warning("Host %s not found in nmap results", host)
                return {}

            host_info = self._scanner[host]

            for proto in host_info.all_protocols():
                for port in host_info[proto].keys():
                    port_data = host_info[proto][port]
                    results[port] = {
                        "service": port_data.get("name", "unknown"),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                        "extrainfo": port_data.get("extrainfo", ""),
                        "state": port_data.get("state", "unknown"),
                    }
                    logger.info(
                        "  Port %d/%s  →  %s %s %s",
                        port,
                        proto,
                        results[port]["service"],
                        results[port]["product"],
                        results[port]["version"],
                    )

        except KeyError as exc:
            logger.error("Error parsing nmap results: %s", exc)

        logger.info("Service detection complete – %d service(s) identified", len(results))
        return results
