"""PortHawk CLI v2.0"""

import argparse
import sys
from . import __version__
from .scanner import Scanner
from .utils import parse_ports, expand_cidr
from .output import print_table, save_output, colorize, BOLD, GREEN, CYAN, YELLOW

BANNER = r"""
  ____            _   _   _                _    
 |  _ \ ___  _ __| |_| | | | __ ___      _| | __
 | |_) / _ \| '__| __| |_| |/ _` \ \ /\ / / |/ /
 |  __/ (_) | |  | |_|  _  | (_| |\ V  V /|   < 
 |_|   \___/|_|   \__|_| |_|\__,_| \_/\_/ |_|\_\
                        v2.0 — by shivarajp24
"""

def build_parser():
    parser = argparse.ArgumentParser(prog="porthawk",
        description="PortHawk v2.0 — Fast multi-threaded port scanner")
    parser.add_argument("target")
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("-p", "--ports", default="common")
    scan.add_argument("-t", "--threads", type=int, default=100)
    scan.add_argument("--timeout", type=float, default=1.0)
    scan.add_argument("--scan-type", choices=["tcp","udp"], default="tcp", dest="scan_type")
    scan.add_argument("--banner", action="store_true")
    scan.add_argument("--version", action="store_true", dest="detect_version")
    scan.add_argument("--show-closed", action="store_true", dest="show_closed")
    intel = parser.add_argument_group("Intelligence Options")
    intel.add_argument("--dns", action="store_true")
    intel.add_argument("--whois", action="store_true")
    intel.add_argument("--traceroute", action="store_true")
    intel.add_argument("--http-headers", action="store_true", dest="http_headers")
    intel.add_argument("--ssl", action="store_true")
    intel.add_argument("--ping-sweep", action="store_true", dest="ping_sweep")
    intel.add_argument("--default-creds", action="store_true", dest="default_creds")
    out = parser.add_argument_group("Output Options")
    out.add_argument("-o", "--output", metavar="FILE")
    out.add_argument("-f", "--format", choices=["text","json","csv","html"], default="text")
    out.add_argument("--no-color", action="store_true", dest="no_color")
    return parser

def run_intel(args, target, scan_result=None):
    from .intel import dns_lookup, whois_domain, whois_ip, traceroute, fetch_http_headers, check_default_creds
    from .version import get_ssl_info
    from .utils import is_valid_ip
    extra = {}
    if args.dns:
        print(colorize("  [*] DNS lookup...", CYAN))
        extra["dns"] = dns_lookup(target)
        d = extra["dns"]
        print(f"      A  : {', '.join(d.get('ips', []))}")
        print(f"      PTR: {d.get('reverse','') or '—'}\n")
    if args.whois:
        print(colorize("  [*] WHOIS lookup...", CYAN))
        w = whois_ip(target) if is_valid_ip(target) else whois_domain(target)
        extra["whois"] = w
        for l in [x for x in w.splitlines() if x.strip()][:10]:
            print(f"      {l}")
        print()
    if args.traceroute:
        print(colorize("  [*] Traceroute...", CYAN))
        hops = traceroute(target)
        extra["traceroute"] = hops
        for h in hops:
            print(f"      {h['hop']:>2}  {h['ip']:<18} {h.get('latency_ms',0)}ms")
        print()
    if args.http_headers and scan_result:
        for p in scan_result.open_ports:
            if p.port in (80, 443, 8080, 8443):
                print(colorize(f"  [*] HTTP headers port {p.port}...", CYAN))
                h = fetch_http_headers(target, p.port)
                extra["http_headers"] = h
                print(f"      Status: {h.get('status','')}")
                for k, v in list((h.get("headers") or {}).items())[:8]:
                    print(f"      {k}: {v}")
                print()
                break
    if args.ssl and scan_result:
        for p in scan_result.open_ports:
            if p.port in (443, 8443):
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
    if args.default_creds and scan_result:
        print(colorize("  [*] Checking default creds...", CYAN))
        for p in scan_result.open_ports:
            found = check_default_creds(target, p.port)
            if found:
                print(colorize(f"      [!] {p.port} WORKS: {', '.join(found)}", YELLOW))
        print()
    return extra

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
        print(colorize(f"  Live: {len(targets)} hosts\n", GREEN))
        for ip in targets:
            print(f"      {colorize(ip, GREEN)}")
        print()
        if not targets:
            return
    for target in targets:
        print(f"  Scanning {colorize(target, GREEN)} — {len(ports)} ports [{args.scan_type.upper()}]\n")
        def on_result(p):
            if p.state == "open":
                info = p.version or p.banner
                print(f"  {colorize('OPEN', GREEN)}  {p.port:<6}  {p.service:<14}  {info[:50]}")
        scanner = Scanner(host=target, ports=ports, scan_type=args.scan_type,
                          threads=args.threads, timeout=args.timeout,
                          grab_banners=args.banner, detect_version=args.detect_version)
        try:
            result = scanner.run(callback=on_result)
        except ValueError as e:
            print(f"  Error: {e}", file=sys.stderr)
            continue
        except KeyboardInterrupt:
            scanner.stop()
            print("\n  Scan interrupted.")
            sys.exit(0)
        print_table(result, show_closed=args.show_closed)
        extra = run_intel(args, target, result)
        if args.output:
            if args.format == "html":
                from .report import generate_html_report
                content = generate_html_report(result, extra)
                with open(args.output, "w") as f:
                    f.write(content)
                print(colorize(f"  HTML saved → {args.output}", CYAN))
            else:
                save_output(result, args.output, args.format)
    print(colorize("\n  Scan complete. Stay ethical! 🦅\n", BOLD))

if __name__ == "__main__":
    main()
