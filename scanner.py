"""
Core scanning engine for PortHawk.
Handles TCP connect, UDP, banner grabbing, and version detection.
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
    state: str = "unknown"
    service: str = ""
    banner: str = ""
    version: str = ""
    latency_ms: float = 0.0


@dataclass
class ScanResult:
    host: str
    ip: str
    scan_type: str
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0
    ports: list = field(default_factory=list)

    @property
    def open_ports(self):
        return [p for p in self.ports if p.state == "open"]

    @property
    def duration(self) -> float:
        return round(self.end_time - self.start_time, 2)


COMMON_SERVICES: dict = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if port in (80, 8080, 8000, 8443, 443):
                sock.sendall(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
            data = sock.recv(1024)
            banner = data.decode(errors="ignore").strip()
            for line in banner.splitlines():
                line = line.strip()
                if line:
                    return line[:120]
    except Exception:
        pass
    return ""


def tcp_connect_scan(ip, port, timeout=1.0, grab_banners=False, detect_version=False):
    start = time.monotonic()
    result = PortResult(port=port, service=COMMON_SERVICES.get(port, ""))
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            result.state = "open"
            result.latency_ms = round(latency, 2)
            if grab_banners:
                result.banner = grab_banner(ip, port, timeout)
            if detect_version:
                from .version import detect_version as dv
                result.version = dv(ip, port, timeout)
    except ConnectionRefusedError:
        result.state = "closed"
    except (socket.timeout, OSError):
        result.state = "filtered"
    return result


def udp_scan(ip: str, port: int, timeout: float = 2.0) -> PortResult:
    result = PortResult(port=port, service=COMMON_SERVICES.get(port, ""))
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(b"\x00" * 8, (ip, port))
        sock.recvfrom(1024)
        result.state = "open"
    except socket.timeout:
        result.state = "open|filtered"
    except ConnectionRefusedError:
        result.state = "closed"
    except Exception:
        result.state = "filtered"
    finally:
        sock.close()
    return result


class Scanner:
    def __init__(self, host, ports, scan_type="tcp", threads=100,
                 timeout=1.0, grab_banners=False, detect_version=False):
        self.host = host
        self.ports = list(ports)
        self.scan_type = scan_type.lower()
        self.threads = min(threads, 500)
        self.timeout = timeout
        self.grab_banners = grab_banners
        self.detect_version = detect_version
        self._stop_event = threading.Event()

    def _scan_port(self, ip, port):
        if self._stop_event.is_set():
            return None
        if self.scan_type == "udp":
            return udp_scan(ip, port, self.timeout)
        return tcp_connect_scan(ip, port, self.timeout,
                                self.grab_banners, self.detect_version)

    def run(self, callback=None) -> ScanResult:
        ip = resolve_host(self.host)
