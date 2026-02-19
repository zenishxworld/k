"""
port_scanner.py - Multi-threaded TCP connect port scanner.

Uses raw sockets (no external libraries) with ThreadPoolExecutor
to rapidly scan a target for open TCP ports.
"""

import socket
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Tuple

logger = logging.getLogger("vuln_scanner")

# Well-known port names for quick reference
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


class PortScanner:
    """TCP connect-scan port scanner with multi-threading."""

    def __init__(self, timeout: float = 1.0, max_threads: int = 100) -> None:
        """
        Args:
            timeout:     Socket connection timeout in seconds.
            max_threads: Maximum number of concurrent scanning threads (cap 100).
        """
        self.timeout = timeout
        self.max_threads = min(max_threads, 100)  # hard cap at 100

    # ------------------------------------------------------------------ #
    #  Single port probe
    # ------------------------------------------------------------------ #
    def _scan_port(self, host: str, port: int) -> Tuple[int, bool]:
        """
        Attempt a TCP connect to *host*:*port*.

        Returns:
            Tuple of (port, is_open).
        """
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((host, port))
                return (port, result == 0)
        except socket.timeout:
            logger.debug("Port %d on %s timed out", port, host)
            return (port, False)
        except socket.error as exc:
            logger.debug("Socket error on %s:%d – %s", host, port, exc)
            return (port, False)
        except Exception as exc:
            logger.error("Unexpected error scanning %s:%d – %s", host, port, exc)
            return (port, False)

    # ------------------------------------------------------------------ #
    #  Range scan
    # ------------------------------------------------------------------ #
    def scan(
        self,
        host: str,
        start_port: int = 1,
        end_port: int = 1024,
    ) -> List[int]:
        """
        Scan a range of TCP ports on *host* using a thread pool.

        Args:
            host:       Target IP / hostname.
            start_port: First port in the range (inclusive).
            end_port:   Last port in the range (inclusive).

        Returns:
            Sorted list of open port numbers.
        """
        # Validate port range
        start_port = max(1, start_port)
        end_port = min(65535, end_port)
        if start_port > end_port:
            logger.error("Invalid port range: %d-%d", start_port, end_port)
            return []

        total = end_port - start_port + 1
        logger.info(
            "Starting TCP connect scan on %s  ports %d–%d (%d ports, %d threads)",
            host,
            start_port,
            end_port,
            total,
            self.max_threads,
        )

        open_ports: List[int] = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, host, port): port
                for port in range(start_port, end_port + 1)
            }
            for future in as_completed(futures):
                port_num = futures[future]
                try:
                    port, is_open = future.result()
                    if is_open:
                        service = COMMON_PORTS.get(port, "unknown")
                        logger.info("  ✔ Port %d/tcp OPEN  (%s)", port, service)
                        open_ports.append(port)
                except Exception as exc:
                    logger.error("Error scanning port %d: %s", port_num, exc)

        open_ports.sort()
        logger.info(
            "Port scan complete – %d open port(s) found on %s",
            len(open_ports),
            host,
        )
        return open_ports
