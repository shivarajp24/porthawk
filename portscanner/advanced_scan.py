"""
Advanced scanning: IP range, random order, service fingerprinting,
WAF detection, CDN detection, subdomain enumeration.
"""

import socket
import random
import re
import urllib.request
import urllib.error
import ssl
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── IP RANGE SCAN ──────────────────────────────────────────────────────────

def parse_ip_range(ip_range: str) -> list:
    """Parse 192.168.1.1-254 into list of IPs."""
    if "-" in ip_range:
        base, end = ip_range.rsplit(".", 1)
        start_end = end.split("-")
        if len(start_end) == 2:
            start, stop = int(start_end[0]), int(start_end[1])
            return [f"{base}.{i}" for i in range(start, stop + 1)]
    return [ip_range]


# ─── SERVICE FINGERPRINTING ─────────────────────────────────────────────────

FINGERPRINTS = {
    b"SSH":           "OpenSSH",
    b"220":           "FTP/SMTP",
    b"HTTP":          "HTTP Server",
    b"220 ProFTPD":   "ProFTPD",
    b"220 FileZilla": "FileZilla FTP",
    b"RFB":           "VNC",
    b"* OK":          "IMAP",
    b"+OK":           "POP3",
    b"AMQP":          "RabbitMQ",
    b"\xff\xfb":      "Telnet",
}

def fingerprint_service(ip: str, port: int, timeout: float = 2.0) -> str:
    """Deep service fingerprinting."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                banner = s.recv(1024)
            except Exception:
                banner = b""
            for sig, name in FINGERPRINTS.items():
                if sig in banner:
                    return name
            # HTTP probe
            try:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                resp = s.recv(1024)
                if b"HTTP" in resp:
                    server = re.search(rb"Server: (.+)", resp)
                    if server:
                        return server.group(1).decode(errors="ignore").strip()
                    return "HTTP Server"
            except Exception:
                pass
            if banner:
                return banner[:50].decode(errors="ignore").strip()
    except Exception:
        pass
    return ""


# ─── WAF DETECTION ──────────────────────────────────────────────────────────

WAF_SIGNATURES = {
    "Cloudflare":   ["cloudflare", "cf-ray", "__cfduid"],
    "AWS WAF":      ["awswaf", "x-amzn-requestid"],
    "Akamai":       ["akamai", "akamaighost"],
    "Sucuri":       ["sucuri", "x-sucuri-id"],
    "ModSecurity":  ["mod_security", "modsecurity"],
    "Wordfence":    ["wordfence"],
    "Imperva":      ["imperva", "incapsula", "visid_incap"],
    "Barracuda":    ["barracuda"],
    "F5 BIG-IP":    ["bigip", "f5"],
    "Nginx WAF":    ["naxsi"],
}

def detect_waf(host: str, port: int = 80, timeout: float = 5.0) -> str:
    """Detect Web Application Firewall."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/?<script>alert(1)</script>"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "PortHawk/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            headers_str = str(r.headers).lower()
            body = r.read(2048).decode(errors="ignore").lower()
            combined = headers_str + body
            for waf, sigs in WAF_SIGNATURES.items():
                if any(s in combined for s in sigs):
                    return waf
    except urllib.error.HTTPError as e:
        headers_str = str(e.headers).lower() if e.headers else ""
        for waf, sigs in WAF_SIGNATURES.items():
            if any(s in headers_str for s in sigs):
                return waf
    except Exception:
        pass
    return "None detected"


# ─── CDN DETECTION ──────────────────────────────────────────────────────────

CDN_SIGNATURES = {
    "Cloudflare":   ["cloudflare.com", "cf-ray"],
    "Akamai":       ["akamai", "akamaitech"],
    "Fastly":       ["fastly", "x-fastly"],
    "Amazon CloudFront": ["cloudfront.net", "x-amz-cf-id"],
    "Google CDN":   ["google", "x-goog"],
    "Azure CDN":    ["azure", "x-msedge"],
    "Sucuri":       ["sucuri.net"],
}

def detect_cdn(host: str, port: int = 80, timeout: float = 5.0) -> str:
    """Detect CDN provider."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "PortHawk/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            headers_str = str(r.headers).lower()
            for cdn, sigs in CDN_SIGNATURES.items():
                if any(s in headers_str for s in sigs):
                    return cdn
    except Exception:
        pass
    return "None detected"


# ─── SUBDOMAIN ENUMERATION ──────────────────────────────────────────────────

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "shop", "app", "portal", "vpn", "ssh", "smtp", "pop",
    "imap", "ns1", "ns2", "mx", "remote", "webmail", "cpanel",
    "dashboard", "manage", "git", "jenkins", "gitlab", "jira",
    "confluence", "docs", "cdn", "media", "static", "assets",
    "beta", "alpha", "demo", "backup", "secure", "login", "auth",
]

def enumerate_subdomains(domain: str, threads: int = 50, timeout: float = 2.0) -> list:
    """Enumerate common subdomains."""
    found = []

    def check(sub):
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            return {"subdomain": host, "ip": ip}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, sub): sub for sub in COMMON_SUBDOMAINS}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)

    return sorted(found, key=lambda x: x["subdomain"])


# ─── GEOIP ──────────────────────────────────────────────────────────────────

def geoip_lookup(ip: str, timeout: float = 5.0) -> dict:
    """GeoIP lookup using ip-api.com (free, no key needed)."""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as"
        req = urllib.request.Request(url, headers={"User-Agent": "PortHawk/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            import json
            data = json.loads(r.read())
            return {
                "country":  data.get("country", ""),
                "region":   data.get("regionName", ""),
                "city":     data.get("city", ""),
                "isp":      data.get("isp", ""),
                "org":      data.get("org", ""),
                "asn":      data.get("as", ""),
            }
    except Exception as e:
        return {"error": str(e)}


# ─── EMAIL HARVESTING ────────────────────────────────────────────────────────

def harvest_emails(host: str, port: int = 80, timeout: float = 5.0) -> list:
    """Find email addresses from web page source."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    emails = set()
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "PortHawk/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(65536).decode(errors="ignore")
            found = re.findall(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", body)
            emails.update(found)
    except Exception:
        pass
    return list(emails)
