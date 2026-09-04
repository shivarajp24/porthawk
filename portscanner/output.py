import csv
import json
import sys
from io import StringIO

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

STATE_COLOR = {
    "open": GREEN,
    "closed": RED,
    "filtered": YELLOW,
    "open|filtered": YELLOW,
}

def colorize(text, color):
    return f"{color}{text}{RESET}"

def print_summary(result):
    if result is None:
        return
    print()
    print(colorize("=" * 60, BOLD))
    print(colorize("  PortHawk v2.0 — Scan Report", BOLD))
    print(colorize("=" * 60, BOLD))
    print(f"  Target  : {result.host} ({result.ip})")
    print(f"  Type    : {result.scan_type.upper()}")
    print(f"  Ports   : {len(result.ports)} scanned")
    print(f"  Open    : {colorize(str(len(result.open_ports)), GREEN)}")
    print(f"  Duration: {result.duration}s")
    print(colorize("=" * 60, BOLD))
    print()

def print_table(result, show_closed=False):
    if result is None:
        return
    print_summary(result)
    header = f"  {'PORT':<8} {'STATE':<14} {'SERVICE':<14} {'LATENCY':>8}   {'VERSION / BANNER'}"
    print(colorize(header, BOLD))
    print("  " + "-" * 64)
    for p in result.ports:
        if not show_closed and p.state != "open":
            continue
        color = STATE_COLOR.get(p.state, RESET)
        state_str = colorize(f"{p.state:<12}", color)
        info = p.version or p.banner
        info_short = (info[:45] + "...") if len(info) > 45 else info
        latency = f"{p.latency_ms:.1f}ms" if p.latency_ms else "-"
        print(f"  {p.port:<8} {state_str}  {p.service:<14} {latency:>8}   {info_short}")
    if not result.open_ports:
        print(colorize("  No open ports found.", YELLOW))
    print()

def to_json(result, indent=2):
    data = {
        "host": result.host,
        "ip": result.ip,
        "scan_type": result.scan_type,
        "duration_seconds": result.duration,
        "open_count": len(result.open_ports),
        "results": [
            {"port": p.port, "state": p.state, "service": p.service,
             "version": p.version, "latency_ms": p.latency_ms, "banner": p.banner}
            for p in result.ports
        ],
    }
    return json.dumps(data, indent=indent)

def to_csv(result):
    buf = StringIO()
    writer = csv.DictWriter(buf, fieldnames=["port","state","service","version","latency_ms","banner"])
    writer.writeheader()
    for p in result.ports:
        writer.writerow({"port": p.port, "state": p.state, "service": p.service,
                         "version": p.version, "latency_ms": p.latency_ms, "banner": p.banner})
    return buf.getvalue()

def save_output(result, path, fmt):
    if fmt == "json":
        content = to_json(result)
    elif fmt == "csv":
        content = to_csv(result)
    else:
        content = ""
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(colorize(f"  Results saved to {path}", CYAN))
