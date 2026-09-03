"""
Output formatters: pretty table (terminal), JSON, CSV.
"""

import csv
import json
import sys
from io import StringIO

from .scanner import ScanResult, PortResult

# ANSI colors
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

STATE_COLOR = {
    "open":         GREEN,
    "closed":       RED,
    "filtered":     YELLOW,
    "open|filtered": YELLOW,
}

NO_COLOR = "--no-color" in sys.argv or not sys.stdout.isatty()


def colorize(text: str, color: str) -> str:
    if NO_COLOR:
        return text
    return f"{color}{text}{RESET}"


def print_summary(result: ScanResult) -> None:
    """Print scan header and summary."""
    print()
    print(colorize("=" * 58, BOLD))
    print(colorize("  PortHawk — Scan Report", BOLD))
    print(colorize("=" * 58, BOLD))
    print(f"  Target  : {result.host} ({result.ip})")
    print(f"  Type    : {result.scan_type.upper()}")
    print(f"  Ports   : {len(result.ports)} scanned")
    print(f"  Open    : {colorize(str(len(result.open_ports)), GREEN)}")
    print(f"  Duration: {result.duration}s")
    print(colorize("=" * 58, BOLD))
    print()


def print_table(result: ScanResult, show_closed: bool = False) -> None:
    """Print results as a formatted table."""
    print_summary(result)

    header = f"  {'PORT':<8} {'STATE':<14} {'SERVICE':<14} {'LATENCY':>8}   {'BANNER'}"
    print(colorize(header, BOLD))
    print("  " + "-" * 56)

    for p in result.ports:
        if not show_closed and p.state != "open":
            continue
        color = STATE_COLOR.get(p.state, RESET)
        state_str = colorize(f"{p.state:<12}", color)
        banner_short = (p.banner[:40] + "…") if len(p.banner) > 40 else p.banner
        latency = f"{p.latency_ms:.1f}ms" if p.latency_ms else "—"
        print(
            f"  {p.port:<8} {state_str}  {p.service:<14} {latency:>8}   {banner_short}"
        )

    if not result.open_ports:
        print(colorize("  No open ports found.", YELLOW))
    print()


def to_json(result: ScanResult, indent: int = 2) -> str:
    """Serialize ScanResult to a JSON string."""
    data = {
        "host": result.host,
        "ip": result.ip,
        "scan_type": result.scan_type,
        "duration_seconds": result.duration,
        "ports_scanned": len(result.ports),
        "open_count": len(result.open_ports),
        "results": [
            {
                "port": p.port,
                "state": p.state,
                "service": p.service,
                "latency_ms": p.latency_ms,
                "banner": p.banner,
            }
            for p in result.ports
        ],
    }
    return json.dumps(data, indent=indent)


def to_csv(result: ScanResult) -> str:
    """Serialize ScanResult to a CSV string."""
    buf = StringIO()
    writer = csv.DictWriter(
        buf, fieldnames=["port", "state", "service", "latency_ms", "banner"]
    )
    writer.writeheader()
    for p in result.ports:
        writer.writerow({
            "port": p.port,
            "state": p.state,
            "service": p.service,
            "latency_ms": p.latency_ms,
            "banner": p.banner,
        })
    return buf.getvalue()


def save_output(result: ScanResult, path: str, fmt: str) -> None:
    """Save scan results to a file in the specified format."""
    if fmt == "json":
        content = to_json(result)
    elif fmt == "csv":
        content = to_csv(result)
    else:
        # Plain text table
        old_stdout = sys.stdout
        sys.stdout = buf = StringIO()
        print_table(result, show_closed=True)
        sys.stdout = old_stdout
        content = buf.getvalue()

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(colorize(f"  Results saved → {path}", CYAN))
