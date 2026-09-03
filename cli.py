"""
Command-line interface for PortHawk.

Examples:
  porthawk scanme.nmap.org
  porthawk 192.168.1.1 -p 22,80,443
  porthawk 10.0.0.1 -p 1-1000 --threads 200 --banner
  porthawk 10.0.0.0/24 -p common --output report.json --format json
  porthawk 192.168.1.1 -p all --scan-type udp
"""

import argparse
import sys
import time

from . import __version__
from .scanner import Scanner
from .utils import parse_ports, expand_cidr, is_valid_ip, resolve_host
from .output import print_table, save_output, colorize, BOLD, GREEN, RESET

BANNER = r"""
  ____            _   _   _                _    
 |  _ \ ___  _ __| |_| | | | __ ___      _| | __
 | |_) / _ \| '__| __| |_| |/ _` \ \ /\ / / |/ /
 |  __/ (_) | |  | |_|  _  | (_| |\ V  V /|   < 
 |_|   \___/|_|   \__|_| |_|\__,_| \_/\_/ |_|\_\
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="porthawk",
        description="PortHawk — Fast multi-threaded port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("target", help="IP address, hostname, or CIDR (e.g. 10.0.0.0/24)")
    parser.add_argument(
        "-p", "--ports",
        default="common",
        metavar="PORTS",
        help="Ports to scan: '80', '20-25', '22,80,443', 'common', 'all' (default: common)",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int, default=100,
        metavar="N",
        help="Number of concurrent threads (default: 100, max: 500)",
    )
    parser.add_argument(
        "--timeout",
        type=float, default=1.0,
        metavar="SEC",
        help="Socket timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--scan-type",
        choices=["tcp", "udp"],
        default="tcp",
        dest="scan_type",
        help="Scan type: tcp or udp (default: tcp)",
    )
    parser.add_argument(
        "--banner",
        action="store_true",
        help="Attempt banner grabbing on open TCP ports",
    )
    parser.add_argument(
        "--show-closed",
        action="store_true",
        dest="show_closed",
        help="Also display closed/filtered ports in output",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Save results to a file",
    )
    parser.add_argument(
        "-f", "--format",
        choices=["text", "json", "csv"],
        default="text",
        help="Output file format: text, json, csv (default: text)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        dest="no_color",
        help="Disable colored output",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"PortHawk {__version__}",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Print banner
    print(colorize(BANNER, BOLD))
    print(f"  PortHawk v{__version__} — Use responsibly on networks you own or have permission to scan.\n")

    # Parse ports
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        parser.error(str(e))

    # Expand CIDR or single host
    if "/" in args.target:
        try:
            targets = list(expand_cidr(args.target))
        except ValueError as e:
            parser.error(str(e))
    else:
        targets = [args.target]

    # Scan each target
    for target in targets:
        print(f"  Scanning {colorize(target, GREEN)} — {len(ports)} ports via {args.scan_type.upper()} ...\n")

        scanned = [0]

        def on_result(port_result):
            scanned[0] += 1
            if port_result.state == "open":
                banner = f"  [{port_result.banner}]" if port_result.banner else ""
                print(
                    f"\r  {colorize('OPEN', GREEN)}  {port_result.port:<6}"
                    f"  {port_result.service:<14}{banner}"
                )

        scanner = Scanner(
            host=target,
            ports=ports,
            scan_type=args.scan_type,
            threads=args.threads,
            timeout=args.timeout,
            grab_banners=args.banner,
        )

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

        if args.output:
            save_output(result, args.output, args.format)


if __name__ == "__main__":
    main()
