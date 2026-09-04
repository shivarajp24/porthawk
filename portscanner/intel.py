"""
Network intelligence: DNS, Whois, Ping sweep, Traceroute, HTTP headers.
All pure Python — no external dependencies.
"""

import socket
import struct
import time
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── DNS ────────────────────────────────────────────────────────────────────

def dns_lookup(host: str) -> dict:
    """Forward + reverse DNS lookup."""
    result = {"host": host, "ips": [], "reverse": "", "error": ""}
    try:
        infos = socket.getaddrinfo(host, None)
        result["ips"] = list({i[4][0] for i in infos})
    except socket.gaierror as e:
        result["error"] = str(e)
        return result
    # Reverse lookup on first IP
    try:
        result["reverse"] = socket.gethostbyaddr(result["ips"][0])[0]
    except Exception:
        pass
    return result


def dns_records(host: str) -> dict:
    """
    Basic DNS — uses socket only (no dnspython needed).
    Returns A records and reverse PTR.
    """
    records = {"A": [], "PTR": ""}
    try:
        for info in socket.getaddrinfo(host, None, socket.AF_INET):
            ip = info[4][0]
            if ip not in records["A"]:
                records["A"].append(ip)
    except Exception:
        pass
    if records["A"]:
        try:
            records["PTR"] = socket.gethostbyaddr(records["A"][0])[0]
        except Exception:
            pass
    return records


# ─── WHOIS ──────────────────────────────────────────────────────────────────

WHOIS_PORT = 43
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "io":  "whois.nic.io",
    "in":  "whois.registry.in",
    "uk":  "whois.nic.uk",
    "de":  "whois.denic.de",
    "default": "whois.iana.org",
}

IP_WHOIS_SERVER = "whois.arin.net"


def whois_domain(domain: str, timeout: float = 5.0) -> str:
    """Query WHOIS for a domain name."""
    tld = domain.rsplit(".", 1)[-1].lower()
    server = WHOIS_SERVERS.get(tld, WHOIS_SERVERS["default"])
    return _whois_query(server, domain + "\r\n", timeout)


def whois_ip(ip: str, timeout: float = 5.0) -> str:
    """Query WHOIS for an IP address."""
    return _whois_query(IP_WHOIS_SERVER, "n + " + ip + "\r\n", timeout)


def _whois_query(server: str, query: str, timeout: float) -> str:
    try:
        with socket.create_connection((server, WHOIS_PORT), timeout=timeout) as sock:
            sock.sendall(query.encode())
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
            raw = b"".join(chunks).decode(errors="ignore")
            # Extract useful lines
            useful = []
            for line in raw.splitlines():
                line = line.strip()
                if line and not line.startswith("%") and not line.startswith("#"):
                    useful.append(line)
            return "\n".join(useful[:60])  # Limit output
    except Exception as e:
        return f"WHOIS error: {e}"


# ─── PING SWEEP ─────────────────────────────────────────────────────────────

def ping_host(ip: str, timeout: float = 1.0) -> bool:
    """
    TCP-based ping (connects to port 80 or 443).
    Works without root on Android/Termux.
    """
    for port in (80, 443, 22, 445):
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (ConnectionRefusedError):
            return True   # Port refused = host is up
        except Exception:
            continue
    return False


def ping_sweep(cidr_ips: list[str], threads: int = 50, timeout: float = 1.0) -> list[str]:
    """
    Ping sweep a list of IPs. Returns list of live hosts.
    """
    live = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(ping_host, ip, timeout): ip for ip in cidr_ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                if future.result():
                    live.append(ip)
            except Exception:
                pass
    return sorted(live)


# ─── TRACEROUTE ─────────────────────────────────────────────────────────────

def traceroute(host: str, max_hops: int = 20, timeout: float = 2.0) -> list[dict]:
    """
    TCP-based traceroute using increasing TTL.
    Works without raw sockets (no root needed).
    Returns list of hops with ip and latency.
    """
    try:
        dest_ip = socket.gethostbyname(host)
    except socket.gaierror as e:
        return [{"hop": 1, "ip": "?", "hostname": "", "latency_ms": 0, "error": str(e)}]

    hops = []
    for ttl in range(1, max_hops + 1):
        hop = {"hop": ttl, "ip": "?", "hostname": "", "latency_ms": 0}
        start = time.monotonic()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            try:
                sock.connect((dest_ip, 80))
                latency = (time.monotonic() - start) * 1000
                hop["ip"] = dest_ip
                hop["latency_ms"] = round(latency, 2)
                try:
                    hop["hostname"] = socket.gethostbyaddr(dest_ip)[0]
                except Exception:
                    pass
                hops.append(hop)
                sock.close()
                break
            except ConnectionRefusedError:
                latency = (time.monotonic() - start) * 1000
                hop["ip"] = dest_ip
                hop["latency_ms"] = round(latency, 2)
                hops.append(hop)
                sock.close()
                break
            except OSError:
                sock.close()
                hop["ip"] = "*"
                hops.append(hop)
        except Exception as e:
            hop["error"] = str(e)
            hops.append(hop)

        if hop["ip"] == dest_ip:
            break

    return hops


# ─── HTTP HEADERS ───────────────────────────────────────────────────────────

def fetch_http_headers(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """Fetch HTTP response headers from a web server."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    headers = {}
    status = ""
    error = ""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "PortHawk/1.0"},
            method="HEAD",
        )
        # Disable SSL verification
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            status = f"{resp.status} {resp.reason}"
            headers = dict(resp.headers)
    except urllib.error.HTTPError as e:
        status = f"{e.code} {e.reason}"
        headers = dict(e.headers) if e.headers else {}
    except Exception as e:
        error = str(e)
    return {"url": url, "status": status, "headers": headers, "error": error}


# ─── DEFAULT CREDENTIALS CHECK ──────────────────────────────────────────────

DEFAULT_CREDS: dict[int, list[tuple[str, str]]] = {
    21:    [("anonymous", ""), ("admin", "admin"), ("ftp", "ftp")],
    22:    [("root", "root"), ("admin", "admin"), ("admin", "password")],
    23:    [("admin", "admin"), ("root", "root"), ("user", "user")],
    3306: [("root", ""), ("root", "root"), ("admin", "admin")],
    6379: [("", ""), ("default", "")],
}


def check_default_creds(ip: str, port: int, timeout: float = 3.0) -> list[str]:
    """
    Check if common default credentials work.
    Returns list of working 'user:pass' strings.
    Note: Only does banner-based check for FTP/SSH; full auth needs paramiko.
    """
    working = []
    creds = DEFAULT_CREDS.get(port, [])
    if not creds:
        return working

    if port == 21:
        for user, pwd in creds:
            try:
                with socket.create_connection((ip, port), timeout=timeout) as sock:
                    sock.recv(1024)  # banner
                    sock.sendall(f"USER {user}\r\n".encode())
                    r1 = sock.recv(1024).decode(errors="ignore")
                    sock.sendall(f"PASS {pwd}\r\n".encode())
                    r2 = sock.recv(1024).decode(errors="ignore")
                    if r2.startswith("230"):
                        working.append(f"{user}:{pwd}")
            except Exception:
                pass

    return working
