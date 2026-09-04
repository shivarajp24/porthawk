import argparse
import sys
from . import __version__
from .scanner import Scanner
from .utils import parse_ports, expand_cidr, is_valid_ip
from .output import colorize, BOLD, GREEN, CYAN, YELLOW, RED

BANNER = r"""
  ____            _   _   _                _    
 |  _ \ ___  _ __| |_| | | | __ ___      _| | __
 | |_) / _ \| '__| __| |_| |/ _` \ \ /\ / / |/ /
 |  __/ (_) | |  | |_|  _  | (_| |\ V  V /|   < 
 |_|   \___/|_|   \__|_| |_|\__,_| \_/\_/ |_|\_\
                        v2.0 — by shivarajp24
"""

def build_parser():
    parser = argparse.ArgumentParser(
        prog="porthawk",
        description="PortHawk v2.0 — Advanced Port Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  porthawk scanme.nmap.org
  porthawk scanme.nmap.org -p 1-1000 --banner --version
  porthawk scanme.nmap.org --vuln --web-vuln
  porthawk scanme.nmap.org --discover
  porthawk scanme.nmap.org --brute
  porthawk scanme.nmap.org --brute --wordlist-user users.txt --wordlist-pass pass.txt
  porthawk scanme.nmap.org --dns --whois --geoip --subdomains
  porthawk scanme.nmap.org --waf --cdn
  porthawk 192.168.1.1-254 --ping-sweep
  porthawk scanme.nmap.org --tor
  porthawk scanme.nmap.org --evasion sneaky
  porthawk scanme.nmap.org --vuln --telegram-token TOKEN --telegram-chat ID
  porthawk scanme.nmap.org -o report.html -f html
  porthawk scanme.nmap.org -o report.xml -f xml
  porthawk --plugins
        """
    )

    parser.add_argument("target", nargs="?")

    # Scan
    scan = parser.add_argument_group("Scan")
    scan.add_argument("-p", "--ports", default="common")
    scan.add_argument("-t", "--threads", type=int, default=100)
    scan.add_argument("--timeout", type=float, default=1.0)
    scan.add_argument("--scan-type", choices=["tcp","udp"], default="tcp", dest="scan_type")
    scan.add_argument("--banner", action="store_true")
    scan.add_argument("--version", action="store_true", dest="detect_version")
    scan.add_argument("--show-closed", action="store_true", dest="show_closed")
    scan.add_argument("--random", action="store_true", dest="random_ports")

    # Intel
    intel = parser.add_argument_group("Intelligence")
    intel.add_argument("--dns", action="store_true")
    intel.add_argument("--whois", action="store_true")
    intel.add_argument("--traceroute", action="store_true")
    intel.add_argument("--http-headers", action="store_true", dest="http_headers")
    intel.add_argument("--ssl", action="store_true")
    intel.add_argument("--geoip", action="store_true")
    intel.add_argument("--waf", action="store_true")
    intel.add_argument("--cdn", action="store_true")
    intel.add_argument("--subdomains", action="store_true")
    intel.add_argument("--emails", action="store_true")
    intel.add_argument("--ping-sweep", action="store_true", dest="ping_sweep")

    # Discovery
    disc = parser.add_argument_group("Discovery")
    disc.add_argument("--discover", action="store_true",
                      help="HTTP title, robots.txt, paths, technologies")

    # Vuln
    vuln = parser.add_argument_group("Vulnerability")
    vuln.add_argument("--vuln", action="store_true")
    vuln.add_argument("--web-vuln", action="store_true", dest="web_vuln")

    # Brute Force
    brute = parser.add_argument_group("Brute Force")
    brute.add_argument("--brute", action="store_true",
                       help="Brute force SSH, FTP, HTTP, MySQL, Redis")
    brute.add_argument("--wordlist-user", metavar="FILE", dest="wordlist_user",
                       help="Custom username wordlist file")
    brute.add_argument("--wordlist-pass", metavar="FILE", dest="wordlist_pass",
                       help="Custom password wordlist file")

    # Evasion
    evasion = parser.add_argument_group("Evasion")
    evasion.add_argument("--tor", action="store_true")
    evasion.add_argument("--proxy", metavar="HOST:PORT")
    evasion.add_argument("--evasion", choices=["normal","slow","sneaky","paranoid"],
                         default="normal")

    # Notify
    notify = parser.add_argument_group("Notifications")
    notify.add_argument("--telegram-token", metavar="TOKEN", dest="tg_token")
    notify.add_argument("--telegram-chat", metavar="ID", dest="tg_chat")
    notify.add_argument("--email-to", metavar="EMAIL", dest="email_to")
    notify.add_argument("--email-from", metavar="EMAIL", dest="email_from")
    notify.add_argument("--email-pass", metavar="PASS", dest="email_pass")
    notify.add_argument("--smtp-host", metavar="HOST", default="smtp.gmail.com", dest="smtp_host")
    notify.add_argument("--smtp-port", metavar="PORT", type=int, default=465, dest="smtp_port")

    # Plugins
    parser.add_argument("--plugins", action="store_true")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("-o", "--output", metavar="FILE")
    out.add_argument("-f", "--format",
                     choices=["text","json","csv","html","xml","pdf"],
                     default="text")

    return parser


def print_results(result):
    print(colorize(f"\n  {'PORT':<10} {'SERVICE':<14} {'VERSION / BANNER'}", BOLD))
    print("  " + "-" * 55)
    for p in result.open_ports:
        info = p.version or p.banner or ""
        print(f"  {colorize(str(p.port)+'/tcp', GREEN):<20} {p.service:<14} {info[:40]}")
    if not result.open_ports:
        print(colorize("  No open ports found.", YELLOW))
    print()
    print(f"  Open: {colorize(str(len(result.open_ports)), GREEN)}  "
          f"Scanned: {len(result.ports)}  Time: {result.duration}s\n")


def print_vuln_results(findings):
    if not findings:
        return
    print(colorize(f"\n  {'PORT':<8} {'CHECK':<25} {'RESULT'}", BOLD))
    print("  " + "-" * 60)
    for f in findings:
        status = colorize("VULNERABLE", RED) if f["vuln"] else colorize("Safe", GREEN)
        print(f"  {f['port']:<8} {f['name']:<25} {status}")
        print(f"  {'':<8} {colorize(f['detail'][:55], YELLOW)}")
    print()


def load_wordlist(path: str) -> list:
    try:
        with open(path) as f:
            return [l.strip() for l in f if l.strip()]
    except Exception:
        return []


def main():
    parser = build_parser()
    args = parser.parse_args()

    print(colorize(BANNER, BOLD))
    print(colorize("  Only scan systems you own or have permission to test.\n", YELLOW))

    if not args.target:
        parser.print_help()
        return

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    if args.random_ports:
        import random
        random.shuffle(ports)
        print(colorize("  [*] Port order randomized\n", CYAN))

    if "/" in args.target:
        targets = list(expand_cidr(args.target))
    elif "-" in args.target.split(".")[-1]:
        from .advanced_scan import parse_ip_range
        targets = parse_ip_range(args.target)
    else:
        targets = [args.target]

    if args.ping_sweep:
        from .intel import ping_sweep as ps
        print(colorize(f"  [*] Ping sweep {len(targets)} hosts...\n", CYAN))
        targets = ps(targets)
        print(colorize(f"  Live: {len(targets)} hosts", GREEN))
        for ip in targets:
            print(f"      {colorize(ip, GREEN)}")
        print()
        if not targets:
            return

    if args.tor:
        from .proxy import check_tor_running
        if check_tor_running():
            print(colorize("  [*] Tor active\n", CYAN))
        else:
            print(colorize("  [!] Tor not running on 9050\n", YELLOW))
            args.tor = False

    from .proxy import get_limiter, jitter_sleep
    limiter = get_limiter(args.evasion)
    if args.evasion != "normal":
        print(colorize(f"  [*] Evasion: {args.evasion}\n", CYAN))

    # Load custom wordlists
    custom_users = load_wordlist(args.wordlist_user) if args.wordlist_user else None
    custom_pass  = load_wordlist(args.wordlist_pass) if args.wordlist_pass else None

    for target in targets:
        print(f"  Scanning {colorize(target, GREEN)} — {len(ports)} ports [{args.scan_type.upper()}]\n")

        scanner = Scanner(
            host=target, ports=ports, scan_type=args.scan_type,
            threads=args.threads, timeout=args.timeout,
            grab_banners=args.banner, detect_version=args.detect_version,
        )
        try:
            result = scanner.run()
        except ValueError as e:
            print(f"  Error: {e}", file=sys.stderr)
            continue
        except KeyboardInterrupt:
            scanner.stop()
            print("\n  Scan interrupted.")
            sys.exit(0)

        print_results(result)
        extra = {}
        findings = []

        # GeoIP
        if args.geoip:
            from .advanced_scan import geoip_lookup
            print(colorize("  [*] GeoIP...", CYAN))
            geo = geoip_lookup(result.ip)
            if "error" not in geo:
                print(f"      Country : {geo.get('country','')}")
                print(f"      City    : {geo.get('city','')}")
                print(f"      ISP     : {geo.get('isp','')}")
                print(f"      ASN     : {geo.get('asn','')}\n")

        # DNS
        if args.dns:
            from .intel import dns_lookup
            print(colorize("  [*] DNS...", CYAN))
            d = dns_lookup(target)
            extra["dns"] = d
            print(f"      A  : {', '.join(d.get('ips',[]))}")
            print(f"      PTR: {d.get('reverse','') or '—'}\n")

        # WHOIS
        if args.whois:
            from .intel import whois_domain, whois_ip
            print(colorize("  [*] WHOIS...", CYAN))
            w = whois_ip(target) if is_valid_ip(target) else whois_domain(target)
            extra["whois"] = w
            for l in [x for x in w.splitlines() if x.strip()][:8]:
                print(f"      {l}")
            print()

        # Traceroute
        if args.traceroute:
            from .intel import traceroute
            print(colorize("  [*] Traceroute...", CYAN))
            hops = traceroute(target)
            extra["traceroute"] = hops
            for h in hops:
                print(f"      {h['hop']:>2}  {h['ip']:<18} {h.get('latency_ms',0)}ms")
            print()

        # HTTP Headers
        if args.http_headers:
            from .intel import fetch_http_headers
            for p in result.open_ports:
                if p.port in (80,443,8080,8443):
                    print(colorize(f"  [*] HTTP headers {p.port}...", CYAN))
                    h = fetch_http_headers(target, p.port)
                    extra["http_headers"] = h
                    print(f"      Status: {h.get('status','')}")
                    for k,v in list((h.get("headers") or {}).items())[:6]:
                        print(f"      {k}: {v}")
                    print()
                    break

        # SSL
        if args.ssl:
            from .version import get_ssl_info
            for p in result.open_ports:
                if p.port in (443,8443):
                    print(colorize(f"  [*] SSL {p.port}...", CYAN))
                    s = get_ssl_info(target, p.port)
                    extra["ssl"] = s
                    if s:
                        print(f"      CN     : {s.get('common_name','')}")
                        print(f"      Issuer : {s.get('issuer','')}")
                        print(f"      TLS    : {s.get('tls_version','')}")
                        print(f"      Expires: {s.get('not_after','')}")
                    print()
                    break

        # WAF
        if args.waf:
            from .advanced_scan import detect_waf
            for p in result.open_ports:
                if p.port in (80,443,8080,8443):
                    print(colorize("  [*] WAF detection...", CYAN))
                    waf = detect_waf(target, p.port)
                    print(f"      WAF: {colorize(waf, YELLOW)}\n")
                    break

        # CDN
        if args.cdn:
            from .advanced_scan import detect_cdn
            for p in result.open_ports:
                if p.port in (80,443,8080,8443):
                    print(colorize("  [*] CDN detection...", CYAN))
                    cdn = detect_cdn(target, p.port)
                    print(f"      CDN: {colorize(cdn, CYAN)}\n")
                    break

        # Subdomains
        if args.subdomains:
            from .advanced_scan import enumerate_subdomains
            print(colorize("  [*] Subdomains...", CYAN))
            subs = enumerate_subdomains(target)
            if subs:
                for s in subs:
                    print(f"      {colorize(s['subdomain'], GREEN)} → {s['ip']}")
            else:
                print("      None found")
            print()

        # Emails
        if args.emails:
            from .advanced_scan import harvest_emails
            for p in result.open_ports:
                if p.port in (80,443,8080,8443):
                    print(colorize("  [*] Email harvesting...", CYAN))
                    emails = harvest_emails(target, p.port)
                    if emails:
                        for e in emails:
                            print(f"      {colorize(e, CYAN)}")
                    else:
                        print("      None found")
                    print()
                    break

        # Discovery
        if args.discover:
            from .discovery import run_discovery
            print(colorize("  [*] Discovery scan...\n", CYAN))
            disc = run_discovery(target, result.ip, result.open_ports)
            extra["discovery"] = disc
            print()

        # Vuln
        if args.vuln:
            from .vuln import run_vuln_scan
            print(colorize("  [*] Vulnerability scan...\n", CYAN))
            v_findings = run_vuln_scan(target, result.ip, result.open_ports)
            print_vuln_results(v_findings)
            findings.extend(v_findings)

        # Web Vuln
        if args.web_vuln:
            from .web_vuln import run_web_vuln_scan
            print(colorize("  [*] Web vulnerability scan...\n", CYAN))
            w_findings = run_web_vuln_scan(target, result.open_ports)
            print_vuln_results(w_findings)
            findings.extend(w_findings)

        # Brute Force
        if args.brute:
            from .bruteforce import run_brute_force
            print(colorize("  [*] Brute force...\n", CYAN))
            bf = run_brute_force(target, result.ip, result.open_ports,
                                 custom_users, custom_pass)
            if bf:
                print(colorize(f"\n  [!] Credentials found:", RED))
                for c in bf:
                    print(colorize(
                        f"      {c['service']}:{c['port']} "
                        f"→ {c['username']}:{c['password']}", RED))
            print()

        # Plugins
        if args.plugins:
            from .proxy import PluginManager
            print(colorize("  [*] Running plugins...\n", CYAN))
            pm = PluginManager()
            pm.load()
            presults = pm.run_all(target, result.ip, result.open_ports)
            for r in presults:
                print(f"      [{r['plugin']}] {r['result']}")
            print()

        # Save output
        if args.output:
            if args.format == "html":
                from .report import generate_html_report
                content = generate_html_report(result, extra)
                with open(args.output, "w") as f:
                    f.write(content)
                print(colorize(f"  HTML → {args.output}", CYAN))
            elif args.format == "xml":
                from .notify import to_xml
                content = to_xml(result, findings)
                with open(args.output, "w") as f:
                    f.write(content)
                print(colorize(f"  XML → {args.output}", CYAN))
            elif args.format == "pdf":
                from .notify import to_pdf_html
                content = to_pdf_html(result, findings)
                path = args.output.replace(".pdf",".html")
                with open(path, "w") as f:
                    f.write(content)
                print(colorize(f"  PDF-ready → {path}", CYAN))
            elif args.format == "json":
                from .output import to_json
                with open(args.output, "w") as f:
                    f.write(to_json(result))
                print(colorize(f"  JSON → {args.output}", CYAN))
            elif args.format == "csv":
                from .output import to_csv
                with open(args.output, "w") as f:
                    f.write(to_csv(result))
                print(colorize(f"  CSV → {args.output}", CYAN))

        # Telegram
        if args.tg_token and args.tg_chat:
            from .notify import send_telegram, format_telegram_message
            print(colorize("  [*] Telegram alert...", CYAN))
            msg = format_telegram_message(result, findings)
            ok = send_telegram(args.tg_token, args.tg_chat, msg)
            print(colorize("  Sent!", GREEN) if ok else colorize("  Failed!", YELLOW))
            print()

        # Email
        if args.email_to and args.email_from and args.email_pass:
            from .notify import send_email, format_email_body
            print(colorize("  [*] Email alert...", CYAN))
            body = format_email_body(result, findings)
            ok = send_email(args.smtp_host, args.smtp_port,
                           args.email_from, args.email_pass,
                           args.email_to,
                           f"PortHawk Report — {target}", body)
            print(colorize("  Sent!", GREEN) if ok else colorize("  Failed!", YELLOW))
            print()

        jitter_sleep(args.evasion)

    print(colorize("  Scan complete. Stay ethical! 🦅\n", BOLD))

if __name__ == "__main__":
    main()
