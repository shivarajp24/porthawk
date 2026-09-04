import argparse
import sys
from . import __version__
from .scanner import Scanner
from .utils import parse_ports, expand_cidr
from .output import print_table, save_output, colorize, BOLD, GREEN, CYAN, YELLOW, RED

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
        description="PortHawk v2.0 — Fast port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  porthawk scanme.nmap.org
  porthawk scanme.nmap.org -p 1-1000 --banner
  porthawk scanme.nmap.org --version --dns --whois
  porthawk scanme.nmap.org --vuln
  porthawk 10.0.0.0/24 --ping-sweep
  porthawk scanme.nmap.org -o report.html -f html
        """
    )
    parser.add_argument("target")
    parser.add_argument("-p", "--ports", default="common")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.0)
    parser.add_argument("--scan-type", choices=["tcp","udp"], default="tcp", dest="scan_type")
    parser.add_argument("--banner", action="store_true")
    parser.add_argument("--version", action="store_true", dest="detect_version")
    parser.add_argument("--show-closed", action="store_true", dest="show_closed")
    parser.add_argument("--dns", action="store_true")
    parser.add_argument("--whois", action="store_true")
    parser.add_argument("--traceroute", action="store_true")
    parser.add_argument("--http-headers", action="store_true", dest="http_headers")
    parser.add_argument("--ssl", action="store_true")
    parser.add_argument("--ping-sweep", action="store_true", dest="ping_sweep")
    parser.add_argument("--vuln", action="store_true", help="Run vulnerability scan")
    parser.add_argument("-o", "--output", metavar="FILE")
    parser.add_argument("-f", "--format", choices=["text","json","csv","html"], default="text")
    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()
    print(colorize(BANNER, BOLD))
    print(colorize("  Only scan systems you own or have permission to test.\n", YELLOW))
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))
    targets = list(expand_cidr(args.target)) if "/" in args.target else [args.target]

    if args.ping_sweep:
        from .intel import ping_sweep as ps
        print(colorize(f"  [*] Ping sweep {len(targets)} hosts...\n", CYAN))
        targets = ps(targets)
        print(colorize(f"  Live hosts: {len(targets)}\n", GREEN))
        for ip in targets:
            print(f"      {colorize(ip, GREEN)}")
        print()
        if not targets:
            return

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

        # Print results
        print(colorize(f"  {'PORT':<8} {'SERVICE':<14} {'VERSION / BANNER'}", BOLD))
        print("  " + "-" * 50)
        for p in result.open_ports:
            info = p.version or p.banner or ""
            print(f"  {colorize(str(p.port)+'/tcp', GREEN):<20} {p.service:<14} {info[:50]}")
        if not result.open_ports:
            print(colorize("  No open ports found.", YELLOW))
        print()
        print(f"  Open: {colorize(str(len(result.open_ports)), GREEN)}  |  Scanned: {len(result.ports)}  |  Time: {result.duration}s")
        print()

        # Intel modules
        extra = {}
        if args.dns:
            from .intel import dns_lookup
            print(colorize("  [*] DNS lookup...", CYAN))
            d = dns_lookup(target)
            extra["dns"] = d
            print(f"      A  : {', '.join(d.get('ips', []))}")
            print(f"      PTR: {d.get('reverse','') or '—'}\n")

        if args.whois:
            from .intel import whois_domain, whois_ip
            from .utils import is_valid_ip
            print(colorize("  [*] WHOIS...", CYAN))
            w = whois_ip(target) if is_valid_ip(target) else whois_domain(target)
            extra["whois"] = w
            for l in [x for x in w.splitlines() if x.strip()][:8]:
                print(f"      {l}")
            print()

        if args.traceroute:
            from .intel import traceroute
            print(colorize("  [*] Traceroute...", CYAN))
            hops = traceroute(target)
            extra["traceroute"] = hops
            for h in hops:
                print(f"      {h['hop']:>2}  {h['ip']:<18} {h.get('latency_ms',0)}ms")
            print()

        if args.http_headers:
            from .intel import fetch_http_headers
            for p in result.open_ports:
                if p.port in (80,443,8080,8443):
                    print(colorize(f"  [*] HTTP headers port {p.port}...", CYAN))
                    h = fetch_http_headers(target, p.port)
                    extra["http_headers"] = h
                    print(f"      Status: {h.get('status','')}")
                    for k,v in list((h.get("headers") or {}).items())[:6]:
                        print(f"      {k}: {v}")
                    print()
                    break

        if args.ssl:
            from .version import get_ssl_info
            for p in result.open_ports:
                if p.port in (443,8443):
                    print(colorize(f"  [*] SSL info port {p.port}...", CYAN))
                    s = get_ssl_info(target, p.port)
                    extra["ssl"] = s
                    if s:
                        print(f"      CN     : {s.get('common_name','')}")
                        print(f"      Issuer : {s.get('issuer','')}")
                        print(f"      TLS    : {s.get('tls_version','')}")
                        print(f"      Expires: {s.get('not_after','')}")
                    print()
                    break

        # Vulnerability scan
        if args.vuln:
            from .vuln import run_vuln_scan
            print(colorize("  [*] Running vulnerability scan...\n", CYAN))
            findings = run_vuln_scan(target, result.ip, result.open_ports)
            if findings:
                print(colorize(f"  {'PORT':<8} {'CHECK':<28} {'RESULT'}", BOLD))
                print("  " + "-" * 60)
                for f in findings:
                    if f["vuln"]:
                        status = colorize("VULNERABLE", RED)
                    else:
                        status = colorize("Safe", GREEN)
                    print(f"  {f['port']:<8} {f['name']:<28} {status}")
                    print(f"           {colorize(f['detail'], YELLOW)}")
                print()
            else:
                print(colorize("  No vulnerabilities checked (no relevant ports open).\n", YELLOW))

        # Save output
        if args.output:
            if args.format == "html":
                from .report import generate_html_report
                content = generate_html_report(result, extra)
                with open(args.output, "w") as f:
                    f.write(content)
                print(colorize(f"  HTML saved → {args.output}", CYAN))
            else:
                save_output(result, args.output, args.format)

    print(colorize("  Scan complete. Stay ethical! 🦅\n", BOLD))

if __name__ == "__main__":
    main()
