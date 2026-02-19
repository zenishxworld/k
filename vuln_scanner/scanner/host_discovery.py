"""
host_discovery.py - Network host discovery module.

Uses ICMP ping (via subprocess) to determine whether individual hosts
or entire subnets are alive.
"""

import ipaddress
import platform
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

logger = logging.getLogger("vuln_scanner")


class HostDiscovery:
    """Discover live hosts on a network using ICMP ping."""

    def __init__(self, timeout: int = 2) -> None:
        """
        Args:
            timeout: Seconds to wait for a ping reply.
        """
        self.timeout = timeout
        # Windows uses -n for count and -w for timeout (ms); Unix uses -c and -W (s)
        self._is_windows = platform.system().lower() == "windows"

    # ------------------------------------------------------------------ #
    #  Single-host ping
    # ------------------------------------------------------------------ #
    def ping_host(self, host: str) -> bool:
        """
        Ping a single host and return True if it responds.

        Args:
            host: IP address or hostname to ping.

        Returns:
            True if the host is alive, False otherwise.
        """
        try:
            if self._is_windows:
                cmd = ["ping", "-n", "1", "-w", str(self.timeout * 1000), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(self.timeout), host]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=self.timeout + 3,  # generous OS-level timeout
            )
            alive = result.returncode == 0
            if alive:
                logger.info("Host %s is UP", host)
            else:
                logger.debug("Host %s is DOWN", host)
            return alive

        except subprocess.TimeoutExpired:
            logger.warning("Ping to %s timed out", host)
            return False
        except FileNotFoundError:
            logger.error("'ping' command not found on the system")
            return False
        except Exception as exc:
            logger.error("Unexpected error pinging %s: %s", host, exc)
            return False

    # ------------------------------------------------------------------ #
    #  Subnet scan
    # ------------------------------------------------------------------ #
    def scan_subnet(self, subnet: str, max_threads: int = 50) -> List[str]:
        """
        Scan an entire subnet for live hosts using multi-threaded pings.

        Args:
            subnet: CIDR notation (e.g. '192.168.1.0/24').
            max_threads: Maximum concurrent ping threads.

        Returns:
            Sorted list of IP addresses that responded.
        """
        try:
            network = ipaddress.ip_network(subnet, strict=False)
        except ValueError as exc:
            logger.error("Invalid subnet '%s': %s", subnet, exc)
            return []

        hosts = [str(ip) for ip in network.hosts()]
        logger.info(
            "Starting subnet scan on %s (%d hosts, %d threads)",
            subnet,
            len(hosts),
            max_threads,
        )

        live_hosts: List[str] = []

        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_host = {
                executor.submit(self.ping_host, host): host for host in hosts
            }
            for future in as_completed(future_to_host):
                host = future_to_host[future]
                try:
                    if future.result():
                        live_hosts.append(host)
                except Exception as exc:
                    logger.error("Error scanning host %s: %s", host, exc)

        live_hosts.sort(key=lambda ip: ipaddress.ip_address(ip))
        logger.info("Subnet scan complete – %d live host(s) found", len(live_hosts))
        return live_hosts
