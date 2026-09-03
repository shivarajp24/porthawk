# PortHawk 🦅

A fast, multi-threaded port scanner written in pure Python — no dependencies required.

```
  ____            _   _   _                _    
 |  _ \ ___  _ __| |_| | | | __ ___      _| | __
 | |_) / _ \| '__| __| |_| |/ _` \ \ /\ / / |/ /
 |  __/ (_) | |  | |_|  _  | (_| |\ V  V /|   < 
 |_|   \___/|_|   \__|_| |_|\__,_| \_/\_/ |_|\_\
```

> ⚠️ **Legal Notice:** Only scan systems you own or have explicit written permission to test. Unauthorized port scanning may violate laws (Computer Fraud and Abuse Act, IT Act, etc.) in your jurisdiction.

---

## Features

- **TCP & UDP scanning** — connect scan (no root needed) and UDP probing
- **Banner grabbing** — identify services running on open ports
- **CIDR support** — scan entire subnets (e.g. `10.0.0.0/24`)
- **Flexible port specs** — ranges, lists, named sets (`common`, `all`)
- **Multi-threaded** — up to 500 concurrent threads
- **Multiple output formats** — colored terminal table, JSON, CSV
- **Zero dependencies** — pure Python standard library only

---

## Installation

### From PyPI (once published)
```bash
pip install porthawk
```

### From source
```bash
git clone https://github.com/yourusername/porthawk.git
cd porthawk
pip install -e .
```

### Run without installing
```bash
python -m portscanner.cli <target>
```

---

## Usage

### Basic scan (top common ports)
```bash
porthawk scanme.nmap.org
```

### Specific ports
```bash
porthawk 192.168.1.1 -p 22,80,443,8080
```

### Port range with banner grabbing
```bash
porthawk 10.0.0.1 -p 1-1000 --banner
```

### Full scan with more threads
```bash
porthawk 192.168.1.1 -p all --threads 300 --timeout 0.5
```

### Scan an entire subnet
```bash
porthawk 192.168.1.0/24 -p common
```

### UDP scan
```bash
porthawk 192.168.1.1 -p 53,67,68,69,123,161 --scan-type udp
```

### Save results to JSON
```bash
porthawk 192.168.1.1 -p common --output results.json --format json
```

### Save results to CSV
```bash
porthawk 192.168.1.1 -p 1-1000 --output results.csv --format csv
```

---

## CLI Reference

```
usage: porthawk [-h] [-p PORTS] [-t N] [--timeout SEC]
                [--scan-type {tcp,udp}] [--banner] [--show-closed]
                [-o FILE] [-f {text,json,csv}] [--no-color] [-v]
                target

positional arguments:
  target                IP, hostname, or CIDR block

options:
  -p, --ports PORTS     Ports: '80', '20-25', '22,80,443', 'common', 'all'
                        (default: common)
  -t, --threads N       Concurrent threads (default: 100, max: 500)
  --timeout SEC         Socket timeout in seconds (default: 1.0)
  --scan-type {tcp,udp} tcp or udp (default: tcp)
  --banner              Grab service banners from open ports
  --show-closed         Also show closed/filtered ports
  -o, --output FILE     Save results to file
  -f, --format FORMAT   Output format: text, json, csv (default: text)
  --no-color            Disable colored output
  -v, --version         Show version and exit
```

---

## Using as a Python Library

```python
from portscanner import Scanner, parse_ports

ports = parse_ports("22,80,443,8000-8090")

scanner = Scanner(
    host="192.168.1.1",
    ports=ports,
    scan_type="tcp",
    threads=150,
    timeout=1.0,
    grab_banners=True,
)

result = scanner.run()

print(f"Scanned {result.host} in {result.duration}s")
for port in result.open_ports:
    print(f"  {port.port}/tcp  {port.service}  {port.banner}")
```

### Scan a CIDR with callback
```python
from portscanner import Scanner, parse_ports, expand_cidr

ports = parse_ports("22,80,443")

for ip in expand_cidr("192.168.1.0/24"):
    scanner = Scanner(host=ip, ports=ports, threads=50)
    result = scanner.run(callback=lambda r: print(r) if r.state == "open" else None)
```

---

## Sample Output

```
  PORT     STATE          SERVICE        LATENCY   BANNER
  -------------------------------------------------------
  22       open           SSH              4.2ms   SSH-2.0-OpenSSH_8.9p1
  80       open           HTTP             2.1ms   HTTP/1.1 200 OK
  443      open           HTTPS            3.8ms   HTTP/1.1 200 OK
  8080     open           HTTP-Alt         2.9ms

  4 open port(s) found on scanme.nmap.org in 3.41s
```

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Project Structure

```
porthawk/
├── portscanner/
│   ├── __init__.py      # Public API
│   ├── scanner.py       # Core scan engine (TCP, UDP, banner)
│   ├── utils.py         # Port parsing, CIDR expansion, host resolution
│   ├── output.py        # Table, JSON, CSV formatters
│   └── cli.py           # argparse CLI entry point
├── tests/
│   ├── test_scanner.py
│   └── test_utils.py
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Comparison with Nmap

| Feature              | PortHawk        | Nmap            |
|----------------------|-----------------|-----------------|
| Language             | Python (pure)   | C               |
| Root required (TCP)  | No              | No (connect)    |
| Root required (SYN)  | —               | Yes             |
| OS fingerprinting    | No              | Yes             |
| Script engine (NSE)  | No              | Yes             |
| Banner grabbing      | Basic           | Advanced        |
| Dependencies         | None            | libpcap         |
| Install              | `pip install`   | System package  |
| Output formats       | Table/JSON/CSV  | Many            |

PortHawk is lighter and easier to embed in Python scripts; Nmap is more feature-complete for professional pentesting.

---

## Contributing

Pull requests welcome! Please open an issue first for major changes.

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Run tests: `pytest tests/ -v`
4. Submit a PR

---

## License

MIT — see [LICENSE](LICENSE).
