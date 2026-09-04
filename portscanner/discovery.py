"""
Discovery module - HTTP title, robots.txt, DNS brute force, banners.
"""

import socket
import ssl
import urllib.request
import urllib.error
import re
from concurrent.futures import ThreadPoolExecutor, as_completed


# ─── HELPER ─────────────────────────────────────────────────────────────────

def _get(host, port, path="/", timeout=5.0):
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{host}:{port}{path}"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "PortHawk/2.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read(65536).decode(errors="ignore"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, "", {}
    except Exception:
        return 0, "", {}


# ─── HTTP TITLE ─────────────────────────────────────────────────────────────

def get_http_title(host, port=80, timeout=5.0) -> str:
    """Get webpage title."""
    _, body, _ = _get(host, port, "/", timeout)
    if body:
        m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()[:100]
    return ""


# ─── ROBOTS.TXT ─────────────────────────────────────────────────────────────

def get_robots(host, port=80, timeout=5.0) -> dict:
    """Fetch and parse robots.txt."""
    _, body, _ = _get(host, port, "/robots.txt", timeout)
    if not body:
        return {"found": False, "disallowed": [], "allowed": [], "sitemaps": []}

    disallowed = re.findall(r"Disallow:\s*(.+)", body, re.IGNORECASE)
    allowed    = re.findall(r"Allow:\s*(.+)", body, re.IGNORECASE)
    sitemaps   = re.findall(r"Sitemap:\s*(.+)", body, re.IGNORECASE)

    return {
        "found": True,
        "disallowed": [d.strip() for d in disallowed],
        "allowed":    [a.strip() for a in allowed],
        "sitemaps":   [s.strip() for s in sitemaps],
    }


# ─── DNS BRUTE FORCE ────────────────────────────────────────────────────────

DNS_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "shop", "app", "portal", "vpn", "ssh", "smtp", "pop",
    "imap", "ns1", "ns2", "mx", "remote", "webmail", "cpanel",
    "dashboard", "manage", "git", "jenkins", "gitlab", "jira",
    "confluence", "docs", "cdn", "media", "static", "assets",
    "beta", "alpha", "demo", "backup", "secure", "login", "auth",
    "db", "database", "mysql", "redis", "mongo", "elastic",
    "kibana", "grafana", "prometheus", "docker", "k8s", "prod",
    "internal", "intranet", "corp", "office", "network", "proxy",
    "gateway", "router", "switch", "firewall", "ids", "waf",
    "upload", "download", "files", "images", "video", "stream",
    "chat", "support", "help", "forum", "community", "wiki",
    "status", "monitor", "alert", "log", "audit", "report",
]

def dns_brute(domain: str, threads: int = 50, timeout: float = 2.0) -> list:
    """Brute force subdomains."""
    found = []

    def check(sub):
        host = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(host)
            return {"subdomain": host, "ip": ip}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(check, sub): sub for sub in DNS_WORDLIST}
        for f in as_completed(futures):
            r = f.result()
            if r:
                found.append(r)

    return sorted(found, key=lambda x: x["subdomain"])


# ─── SERVICE BANNER ─────────────────────────────────────────────────────────

def grab_all_banners(ip: str, open_ports: list, timeout: float = 2.0) -> dict:
    """Grab banners from all open ports."""
    banners = {}
    for p in open_ports:
        try:
            with socket.create_connection((ip, p.port), timeout=timeout) as s:
                s.settimeout(timeout)
                try:
                    data = s.recv(1024)
                    banner = data.decode(errors="ignore").strip()
                    if banner:
                        banners[p.port] = banner[:200]
                except Exception:
                    pass
        except Exception:
            pass
    return banners


# ─── HTTP PATHS ─────────────────────────────────────────────────────────────

INTERESTING_PATHS = [
    "/.git/HEAD", "/.env", "/config.php", "/wp-config.php",
    "/backup.zip", "/backup.sql", "/dump.sql", "/.htaccess",
    "/server-status", "/server-info", "/phpinfo.php",
    "/adminer.php", "/phpmyadmin/", "/admin/", "/administrator/",
    "/swagger.json", "/api/v1/", "/graphql", "/.well-known/",
    "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml",
]

def discover_paths(host, port=80, timeout=5.0) -> list:
    """Discover interesting files and directories."""
    found = []
    for path in INTERESTING_PATHS:
        code, body, _ = _get(host, port, path, timeout)
        if code in (200, 403, 301, 302):
            found.append({"path": path, "code": code, "size": len(body)})
    return found


# ─── TECHNOLOGY DETECTION ───────────────────────────────────────────────────

TECH_SIGNATURES = {
    "WordPress":   ["wp-content", "wp-includes", "WordPress"],
    "Joomla":      ["joomla", "/components/com_"],
    "Drupal":      ["drupal", "sites/default"],
    "Laravel":     ["laravel_session", "Laravel"],
    "Django":      ["csrfmiddlewaretoken", "Django"],
    "React":       ["react", "__react"],
    "Vue.js":      ["vue.js", "__vue__"],
    "Angular":     ["ng-version", "angular"],
    "jQuery":      ["jquery"],
    "Bootstrap":   ["bootstrap.min.css", "bootstrap.min.js"],
    "PHP":         ["php", ".php"],
    "ASP.NET":     ["__VIEWSTATE", "asp.net"],
    "Apache":      ["Apache"],
    "Nginx":       ["nginx"],
    "IIS":         ["Microsoft-IIS"],
    "Cloudflare":  ["cloudflare", "cf-ray"],
}

def detect_technologies(host, port=80, timeout=5.0) -> list:
    """Detect web technologies in use."""
    _, body, headers = _get(host, port, "/", timeout)
    combined = body.lower() + str(headers).lower()
    found = []
    for tech, sigs in TECH_SIGNATURES.items():
        if any(s.lower() in combined for s in sigs):
            found.append(tech)
    return found


# ─── RUNNER ─────────────────────────────────────────────────────────────────

def run_discovery(host: str, ip: str, open_ports: list) -> dict:
    """Run all discovery checks."""
    results = {}
    web_ports = [p.port for p in open_ports if p.port in (80,443,8080,8443,8000)]

    if web_ports:
        port = web_ports[0]
        print(f"      HTTP Title   : ", end="", flush=True)
        title = get_http_title(host, port)
        print(title or "—")
        results["title"] = title

        print(f"      Technologies : ", end="", flush=True)
        techs = detect_technologies(host, port)
        print(", ".join(techs) if techs else "—")
        results["technologies"] = techs

        print(f"      Robots.txt   : ", end="", flush=True)
        robots = get_robots(host, port)
        if robots["found"]:
            print(f"Found — {len(robots['disallowed'])} disallowed paths")
            for d in robots["disallowed"][:5]:
                print(f"                     Disallow: {d}")
        else:
            print("Not found")
        results["robots"] = robots

        print(f"      Interesting  : ", end="", flush=True)
        paths = discover_paths(host, port)
        if paths:
            print(f"{len(paths)} found")
            for p in paths[:5]:
                print(f"                     [{p['code']}] {p['path']}")
        else:
            print("Nothing found")
        results["paths"] = paths

    print(f"      Banners      : ", end="", flush=True)
    banners = grab_all_banners(ip, open_ports)
    print(f"{len(banners)} grabbed")
    for port, banner in banners.items():
        print(f"                     {port}: {banner[:60]}")
    results["banners"] = banners

    return results
