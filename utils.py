"""
Utility helpers: host resolution, port parsing, CIDR expansion, validation.
"""

import ipaddress
import re
import socket
from typing import Generator


def resolve_host(host: str) -> str:
    """Resolve hostname to IP. Returns IP unchanged if already numeric."""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror as exc:
        raise ValueError(f"Cannot resolve host '{host}': {exc}") from exc


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str) -> Generator[str, None, None]:
    """Yield all host IPs in a CIDR block (e.g. '192.168.1.0/24')."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        for host in network.hosts():
            yield str(host)
    except ValueError as exc:
        raise ValueError(f"Invalid CIDR notation '{cidr}': {exc}") from exc


def parse_ports(port_str: str) -> list[int]:
    """
    Parse a port specification string into a sorted list of unique port numbers.

    Supported formats:
      - Single:  "80"
      - Range:   "20-25"
      - List:    "22,80,443"
      - Mixed:   "22,80,100-200,443"
      - Named:   "common"  → top 1000 common ports
      - All:     "all"     → 1-65535
    """
    port_str = port_str.strip().lower()

    if port_str in ("all", "-"):
        return list(range(1, 65536))

    if port_str == "common":
        return COMMON_PORTS

    ports: set[int] = set()
    for token in port_str.split(","):
        token = token.strip()
        if "-" in token:
            parts = token.split("-", 1)
            try:
                start, end = int(parts[0]), int(parts[1])
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    raise ValueError
                ports.update(range(start, end + 1))
            except (ValueError, IndexError):
                raise ValueError(
                    f"Invalid port range '{token}'. Use format: start-end (e.g. 80-443)"
                )
        else:
            try:
                p = int(token)
                if not 1 <= p <= 65535:
                    raise ValueError
                ports.add(p)
            except ValueError:
                raise ValueError(
                    f"Invalid port '{token}'. Ports must be integers 1–65535."
                )

    return sorted(ports)


# Top 1000 most scanned ports (Nmap default list — condensed)
COMMON_PORTS: list[int] = sorted([
    1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 26, 37, 53, 79, 80,
    81, 88, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179, 199,
    389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548, 554,
    587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029,
    1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717,
    3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060, 5101,
    5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 6881,
    7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000,
    32768, 49152, 49153, 49154, 49155, 49156, 49157,
])
