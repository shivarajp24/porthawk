import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from .utils import resolve_host

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
    def duration(self):
        return round(self.end_time - self.start_time, 2)

SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    3306:"MySQL",3389:"RDP",5432:"PostgreSQL",5900:"VNC",
    6379:"Redis",8080:"HTTP-Alt",8443:"HTTPS-Alt",27017:"MongoDB",
}

def grab_banner(ip, port, timeout=2.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            if port in (80,8080,443,8443):
                s.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
            data = s.recv(1024).decode(errors="ignore").strip()
            for line in data.splitlines():
                if line.strip():
                    return line.strip()[:100]
    except:
        pass
    return ""

def scan_port(ip, port, timeout, banners, ver):
    start = time.monotonic()
    r = PortResult(port=port, service=SERVICES.get(port,""))
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            r.latency_ms = round((time.monotonic()-start)*1000, 2)
            r.state = "open"
            if banners:
                r.banner = grab_banner(ip, port, timeout)
            if ver:
                try:
                    from .version import detect_version as dv
                    r.version = dv(ip, port, timeout)
                except:
                    pass
    except ConnectionRefusedError:
        r.state = "closed"
    except:
        r.state = "filtered"
    return r

class Scanner:
    def __init__(self, host, ports, scan_type="tcp", threads=100,
                 timeout=1.0, grab_banners=False, detect_version=False):
        self.host = host
        self.ports = list(ports)
        self.scan_type = scan_type
        self.threads = min(threads, 500)
        self.timeout = timeout
        self.grab_banners = grab_banners
        self.detect_version = detect_version
        self._stop = threading.Event()

    def run(self, callback=None):
        ip = resolve_host(self.host)
        result = ScanResult(host=self.host, ip=ip, scan_type=self.scan_type)
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(scan_port, ip, p, self.timeout,
                       self.grab_banners, self.detect_version): p
                       for p in self.ports}
            for f in as_completed(futures):
                pr = f.result()
                if pr:
                    result.ports.append(pr)
                    if callback:
                        callback(pr)
        result.ports.sort(key=lambda p: p.port)
        result.end_time = time.time()
        return result

    def stop(self):
        self._stop.set()
