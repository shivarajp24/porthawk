"""
Core scanning engine for PortHawk.
Handles TCP connect, SYN-style (raw), UDP, and banner grabbing.
"""

import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional
from .utils import resolve_host, is_valid_ip


@dataclass
class PortResult:
    port: int
    state: str = "unknown"   # open / closed / filtered
    service: str = ""
    banner: str = ""
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    host: str
    ip: str
    scan_type: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.state == "open"]

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 2)


# Common service names (port → service)
COMMON_SERVICES: dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Try to grab a banner from an open port."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            # Send HTTP request for web ports, else just read
            if port in (80, 8080, 8000, 8443, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
            # Return first non-empty line
            for line in banner.splitlines():
                line = line.strip()
                if line:
                    return line[:120]
    except Exception:
        pass
    return ""


def tcp_connect_scan(
    ip: str,
    port: int,
    timeout: float = 1.0,
    grab_banners: bool = False,
) -> PortResult:
    """Standard TCP connect scan (no root needed)."""
    start = time.monotonic()
    result = PortResult(port=port, service=COMMON_SERVICES.get(port, ""))

    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            result.state = "open"
            result.latency_ms = round(latency, 2)
            if grab_banners:
                result.banner = grab_banner(ip, port, timeout)
    except ConnectionRefusedError:
        result.state = "closed"
    except (socket.timeout, OSError):
        result.state = "filtered"

    return result


def udp_scan(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    """
    Basic UDP probe.
    Note: UDP scanning is inherently unreliable without root for ICMP responses.
    """
    result = PortResult(port=port, service=COMMON_SERVICES.get(port, ""))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00" * 8, (ip, port))
        sock.recvfrom(1024)
        result.state = "open"
    except socket.timeout:
        result.state = "open|filtered"   # No ICMP = might be open
    except ConnectionRefusedError:
        result.state = "closed"
    except Exception:
        result.state = "filtered"
    finally:
        sock.close()
    return result


class Scanner:
    """
    Multi-threaded port scanner with TCP and UDP support.

    Usage:
        scanner = Scanner(host="192.168.1.1", ports=range(1, 1025))
        result = scanner.run()
    """

    def __init__(
        self,
        host: str,
        ports: list[int] | range,
        scan_type: str = "tcp",
        threads: int = 100,
        timeout: float = 1.0,
        grab_banners: bool = False,
    ):
        self.host = host
        self.ports = list(ports)
        self.scan_type = scan_type.lower()
        self.threads = min(threads, 500)   # Safety cap
        self.timeout = timeout
        self.grab_banners = grab_banners
        self._stop_event = threading.Event()

    def _scan_port(self, ip: str, port: int) -> Optional[PortResult]:
        if self._stop_event.is_set():
            return None
        if self.scan_type == "udp":
            return udp_scan(ip, port, self.timeout)
        return tcp_connect_scan(ip, port, self.timeout, self.grab_banners)

    def run(self, callback=None) -> ScanResult:
        """
        Run the scan. Optional callback(port_result) is called for each result.
        Returns a ScanResult with all findings.
        """
        ip = resolve_host(self.host)
        result = ScanResult(host=self.host, ip=ip, scan_type=self.scan_type)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self._scan_port, ip, port): port
                for port in self.ports
            }
            for future in as_completed(futures):
                port_result = future.result()
                if port_result:
                    result.ports.append(port_result)
                    if callback:
                        callback(port_result)

        # Sort by port number
        result.ports.sort(key=lambda p: p.port)
        result.end_time = time.time()
        return result

    def stop(self):
        """Signal the scanner to stop gracefully."""
        self._stop_event.set()
