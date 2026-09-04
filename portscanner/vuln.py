import socket
import ssl
import urllib.request
import urllib.error

# ─── HELPERS ────────────────────────────────────────────────────────────────

def _http_get(host, port, path="/", timeout=3.0):
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}{path}"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "PortHawk/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(4096).decode(errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}

def _tcp_send(ip, port, data, timeout=3.0):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(data)
            return s.recv(4096)
    except Exception:
        return b""

# ─── CHECKS ─────────────────────────────────────────────────────────────────

def check_ftp_anonymous(ip, port=21, timeout=3.0):
    """Check if FTP allows anonymous login."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.recv(1024)
            s.sendall(b"USER anonymous\r\n")
            r1 = s.recv(1024).decode(errors="ignore")
            s.sendall(b"PASS porthawk@test.com\r\n")
            r2 = s.recv(1024).decode(errors="ignore")
            if "230" in r2:
                return {"vuln": True, "detail": "FTP anonymous login ALLOWED"}
    except Exception:
        pass
    return {"vuln": False, "detail": "FTP anonymous login not allowed"}


def check_ssl_weak(ip, port=443, timeout=3.0):
    """Check for weak SSL versions (SSLv2, SSLv3, TLSv1.0)."""
    findings = []
    for proto_name, proto in [
        ("TLSv1.0", ssl.TLSVersion.TLSv1),
        ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ]:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.maximum_version = proto
            ctx.minimum_version = proto
            with socket.create_connection((ip, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw) as s:
                    findings.append(proto_name)
        except Exception:
            pass
    if findings:
        return {"vuln": True, "detail": f"Weak SSL supported: {', '.join(findings)}"}
    return {"vuln": False, "detail": "No weak SSL versions detected"}


def check_http_methods(host, port=80, timeout=3.0):
    """Check for dangerous HTTP methods (PUT, DELETE, TRACE)."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    dangerous = []
    for method in ["PUT", "DELETE", "TRACE", "CONNECT"]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method=method,
                                          headers={"User-Agent": "PortHawk/2.0"})
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                if r.status not in (405, 501):
                    dangerous.append(method)
        except urllib.error.HTTPError as e:
            if e.code not in (405, 501):
                dangerous.append(method)
        except Exception:
            pass
    if dangerous:
        return {"vuln": True, "detail": f"Dangerous HTTP methods allowed: {', '.join(dangerous)}"}
    return {"vuln": False, "detail": "No dangerous HTTP methods found"}


def check_admin_pages(host, port=80, timeout=3.0):
    """Check for common admin/login pages exposed."""
    paths = [
        "/admin", "/admin/", "/login", "/wp-admin/",
        "/phpmyadmin/", "/manager/html", "/administrator/",
        "/.env", "/config.php", "/backup/", "/shell.php",
    ]
    found = []
    for path in paths:
        code, _, _ = _http_get(host, port, path, timeout)
        if code in (200, 401, 403):
            found.append(f"{path} [{code}]")
    if found:
        return {"vuln": True, "detail": f"Exposed pages: {', '.join(found)}"}
    return {"vuln": False, "detail": "No sensitive pages found"}


def check_shellshock(host, port=80, timeout=3.0):
    """Check for Shellshock (CVE-2014-6271)."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/cgi-bin/test.cgi"
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={
            "User-Agent": "() { :;}; echo; echo SHELLSHOCK_VULNERABLE",
            "Referer": "() { :;}; echo; echo SHELLSHOCK_VULNERABLE",
        })
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(1024).decode(errors="ignore")
            if "SHELLSHOCK_VULNERABLE" in body:
                return {"vuln": True, "detail": "VULNERABLE to Shellshock CVE-2014-6271!"}
    except Exception:
        pass
    return {"vuln": False, "detail": "Not vulnerable to Shellshock"}


def check_heartbleed(ip, port=443, timeout=3.0):
    """Basic Heartbleed probe (CVE-2014-0160)."""
    # TLS heartbeat request
    hello = bytes.fromhex(
        "1603020041" "0100003d0303" +
        "00" * 32 +
        "00" "0002002f" "0100000f000f000d0000" +
        "0a6c6f63616c686f7374"
    )
    heartbeat = bytes.fromhex("180302000301ffff")
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(bytes.fromhex("160301007f010000"
                "7b03035eb2bde9b1b1b1b1b1b1b1b1"
                "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"
                "b1b100002cc02bc02fc00ac009c013c0"
                "14002f0035000a0100002e00000010000"
                "e00000b6578616d706c652e636f6d000d"
                "0006000401010201ff01000100"))
            s.recv(4096)
            s.sendall(bytes.fromhex("1803010003014000"))
            resp = s.recv(4096)
            if resp and resp[0] == 0x18:
                return {"vuln": True, "detail": "VULNERABLE to Heartbleed CVE-2014-0160!"}
    except Exception:
        pass
    return {"vuln": False, "detail": "Not vulnerable to Heartbleed"}


def check_open_redirect(host, port=80, timeout=3.0):
    """Check for open redirect vulnerability."""
    paths = [
        "/redirect?url=http://evil.com",
        "/go?to=http://evil.com",
        "/?next=http://evil.com",
        "/?url=http://evil.com",
        "/?redirect=http://evil.com",
    ]
    for path in paths:
        code, _, headers = _http_get(host, port, path, timeout)
        location = headers.get("Location", "")
        if "evil.com" in location:
            return {"vuln": True, "detail": f"Open redirect via {path}"}
    return {"vuln": False, "detail": "No open redirect found"}


def check_ssh_weak_algo(ip, port=22, timeout=3.0):
    """Check SSH banner for old/weak versions."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            banner = s.recv(256).decode(errors="ignore").strip()
            weak = []
            if "SSH-1" in banner:
                weak.append("SSHv1 (insecure)")
            for old in ["OpenSSH_4", "OpenSSH_5", "OpenSSH_6"]:
                if old in banner:
                    weak.append(f"Old version: {banner}")
                    break
            if weak:
                return {"vuln": True, "detail": f"Weak SSH: {', '.join(weak)}"}
            return {"vuln": False, "detail": f"SSH banner: {banner}"}
    except Exception:
        pass
    return {"vuln": False, "detail": "Could not connect to SSH"}


def check_smb_eternalblue(ip, port=445, timeout=3.0):
    """Basic EternalBlue probe (CVE-2017-0144) — checks SMB version."""
    negotiate = bytes.fromhex(
        "00000054ff534d4272000000001853c8"
        "000000000000000000000000ffffffff"
        "00000000002400024c414e4d414e312e"
        "300002574f524b47524f555000024c4d"
        "312e325830303200024c4d4e322e3132"
        "003302"
    )
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.sendall(negotiate)
            resp = s.recv(1024)
            if resp and len(resp) > 40:
                return {"vuln": True,
                        "detail": "SMB open — may be vulnerable to EternalBlue, run full check"}
    except Exception:
        pass
    return {"vuln": False, "detail": "SMB not accessible"}


# ─── RUNNER ─────────────────────────────────────────────────────────────────

def run_vuln_scan(host: str, ip: str, open_ports: list) -> list:
    """
    Run all relevant vulnerability checks based on open ports.
    Returns list of finding dicts: {name, port, vuln, detail}
    """
    findings = []
    port_nums = [p.port for p in open_ports]

    checks = {
        21:  [("FTP Anonymous Login",  check_ftp_anonymous)],
        22:  [("SSH Weak Version",     check_ssh_weak_algo)],
        80:  [
            ("HTTP Dangerous Methods", check_http_methods),
            ("Admin Pages Exposed",    check_admin_pages),
            ("Shellshock",             check_shellshock),
            ("Open Redirect",          check_open_redirect),
        ],
        443: [
            ("SSL Weak Version",       check_ssl_weak),
            ("Heartbleed",             check_heartbleed),
            ("HTTP Dangerous Methods", check_http_methods),
            ("Admin Pages Exposed",    check_admin_pages),
            ("Open Redirect",          check_open_redirect),
        ],
        445: [("EternalBlue SMB",      check_smb_eternalblue)],
        8080:[
            ("HTTP Dangerous Methods", check_http_methods),
            ("Admin Pages Exposed",    check_admin_pages),
        ],
        8443:[
            ("SSL Weak Version",       check_ssl_weak),
            ("HTTP Dangerous Methods", check_http_methods),
        ],
    }

    for port in port_nums:
        for name, fn in checks.get(port, []):
            try:
                result = fn(host if port in (80,443,8080,8443) else ip, port)
                findings.append({
                    "name": name,
                    "port": port,
                    "vuln": result["vuln"],
                    "detail": result["detail"],
                })
            except Exception as e:
                findings.append({
                    "name": name,
                    "port": port,
                    "vuln": False,
                    "detail": f"Error: {e}",
                })
    return findings
