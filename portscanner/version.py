"""
Version Detection — identifies service versions from banners and probes.
"""

import socket
import ssl
import re

# Version probe payloads per port
PROBES: dict[int, bytes] = {
    21:   b"",                                          # FTP — just read
    22:   b"",                                          # SSH — just read
    25:   b"EHLO porthawk\r\n",                         # SMTP
    80:   b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",  # HTTP
    110:  b"",                                          # POP3
    143:  b"",                                          # IMAP
    443:  b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n",  # HTTPS
    3306: b"\x00",                                      # MySQL handshake
    5432: b"\x00\x00\x00\x08\x04\xd2\x16/",            # PostgreSQL
    6379: b"*1\r\n$4\r\nINFO\r\n",                     # Redis
    27017: b"\x3a\x00\x00\x00\x03\x00\x00\x00\x00"
           b"\x00\x00\x00\xd4\x07\x00\x00\x00\x00"
           b"\x00\x00admin.$cmd\x00\x00\x00\x00\x00"
           b"\xff\xff\xff\xff\x13\x00\x00\x00\x10"
           b"isMaster\x00\x01\x00\x00\x00\x00",        # MongoDB
}

# Regex patterns to extract version strings
VERSION_PATTERNS: list[tuple[str, str]] = [
    # SSH
    (r"SSH-(\S+)", "SSH"),
    # HTTP Server header
    (r"[Ss]erver:\s*(.+?)[\r\n]", "HTTP Server"),
    # FTP
    (r"220[- ](.+?)[\r\n]", "FTP"),
    # SMTP
    (r"220[- ](.+?)[\r\n]", "SMTP"),
    # MySQL
    (r"[\x00-\x1f](.+?)\x00", "MySQL"),
    # Redis
    (r"redis_version:(\S+)", "Redis"),
    # Generic version
    (r"[Vv]ersion[:/\s]+(\d[\d.]+)", "Version"),
    # Apache/Nginx
    (r"(Apache|nginx|lighttpd|IIS)[/\s]+([\d.]+)", "Web"),
    # OpenSSH
    (r"OpenSSH[_/]([\d.p]+)", "OpenSSH"),
]


def detect_version(ip: str, port: int, timeout: float = 2.0) -> str:
    """
    Connect to port, send probe, parse response for version info.
    Returns version string or empty string.
    """
    raw = _get_banner_raw(ip, port, timeout)
    if not raw:
        return ""
    return _parse_version(raw, port)


def _get_banner_raw(ip: str, port: int, timeout: float) -> bytes:
    """Get raw bytes from port — uses SSL for 443/8443."""
    try:
        if port in (443, 8443):
            return _ssl_grab(ip, port, timeout)

        probe = PROBES.get(port, b"")
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            if probe:
                sock.sendall(probe)
            return sock.recv(2048)
    except Exception:
        return b""


def _ssl_grab(ip: str, port: int, timeout: float) -> bytes:
    """Grab banner over SSL/TLS."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as sock:
                probe = PROBES.get(port, b"HEAD / HTTP/1.1\r\nHost: target\r\n\r\n")
                sock.sendall(probe)
                return sock.recv(2048)
    except Exception:
        return b""


def _parse_version(data: bytes, port: int) -> str:
    """Try each regex pattern against decoded banner."""
    text = data.decode(errors="ignore")
    for pattern, label in VERSION_PATTERNS:
        m = re.search(pattern, text)
        if m:
            version = m.group(1).strip()[:80]
            # Clean up non-printable chars
            version = re.sub(r"[^\x20-\x7e]", "", version).strip()
            if version:
                return version
    # Fallback: return first printable line
    for line in text.splitlines():
        line = line.strip()
        clean = re.sub(r"[^\x20-\x7e]", "", line).strip()
        if len(clean) > 3:
            return clean[:80]
    return ""


def get_ssl_info(ip: str, port: int, timeout: float = 3.0) -> dict:
    """Get SSL/TLS certificate information."""
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((ip, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as sock:
                cert = sock.getpeercert(binary_form=False)
                cipher = sock.cipher()
                info["tls_version"] = sock.version()
                info["cipher"] = cipher[0] if cipher else ""
                if cert:
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer  = dict(x[0] for x in cert.get("issuer", []))
                    info["common_name"]   = subject.get("commonName", "")
                    info["issuer"]        = issuer.get("organizationName", "")
                    info["not_after"]     = cert.get("notAfter", "")
                    info["sans"]          = [
                        v for t, v in cert.get("subjectAltName", []) if t == "DNS"
                    ]
    except Exception:
        pass
    return info
