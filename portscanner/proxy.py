"""
Proxy and Tor support for anonymous scanning.
Rate limiting for IDS evasion.
"""

import socket
import time
import random
import threading


# ─── PROXY SUPPORT ──────────────────────────────────────────────────────────

class ProxyScanner:
    """
    SOCKS5 proxy scanner.
    Works with Tor (127.0.0.1:9050) or any SOCKS5 proxy.
    """

    def __init__(self, proxy_host: str, proxy_port: int):
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

    def connect(self, target_ip: str, target_port: int, timeout: float = 5.0):
        """Connect via SOCKS5 proxy."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((self.proxy_host, self.proxy_port))

        # SOCKS5 handshake
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        if resp != b"\x05\x00":
            sock.close()
            raise ConnectionError("SOCKS5 auth failed")

        # Connect request
        host_bytes = target_ip.encode()
        sock.sendall(
            b"\x05\x01\x00\x03" +
            bytes([len(host_bytes)]) +
            host_bytes +
            target_port.to_bytes(2, "big")
        )
        resp = sock.recv(10)
        if resp[1] != 0:
            sock.close()
            raise ConnectionError(f"SOCKS5 connect failed: {resp[1]}")
        return sock

    def scan_port(self, ip: str, port: int, timeout: float = 3.0) -> str:
        """Scan a port via proxy. Returns 'open', 'closed', or 'filtered'."""
        try:
            sock = self.connect(ip, port, timeout)
            sock.close()
            return "open"
        except ConnectionError:
            return "closed"
        except Exception:
            return "filtered"


def tor_scanner() -> ProxyScanner:
    """Create scanner using Tor (must be running on 9050)."""
    return ProxyScanner("127.0.0.1", 9050)


def check_tor_running() -> bool:
    """Check if Tor is running on default port."""
    try:
        with socket.create_connection(("127.0.0.1", 9050), timeout=2):
            return True
    except Exception:
        return False


# ─── RATE LIMITING ──────────────────────────────────────────────────────────

class RateLimiter:
    """
    Token bucket rate limiter for IDS evasion.
    Controls how many packets/connections per second.
    """

    def __init__(self, rate: float = 10.0, burst: int = 20):
        """
        rate  = max connections per second
        burst = max burst size
        """
        self.rate = rate
        self.burst = burst
        self._tokens = burst
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def acquire(self):
        """Wait until a token is available."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.burst, self._tokens + elapsed * self.rate)
            self._last = now

            if self._tokens >= 1:
                self._tokens -= 1
                return
            # Need to wait
            wait = (1 - self._tokens) / self.rate

        time.sleep(wait)
        with self._lock:
            self._tokens = max(0, self._tokens - 1)


# ─── EVASION MODES ──────────────────────────────────────────────────────────

EVASION_PROFILES = {
    "normal":   {"rate": 100, "burst": 200, "jitter": 0},
    "slow":     {"rate": 5,   "burst": 10,  "jitter": 0.5},
    "sneaky":   {"rate": 1,   "burst": 2,   "jitter": 2.0},
    "paranoid": {"rate": 0.2, "burst": 1,   "jitter": 5.0},
}

def get_limiter(profile: str = "normal") -> RateLimiter:
    """Get rate limiter for evasion profile."""
    p = EVASION_PROFILES.get(profile, EVASION_PROFILES["normal"])
    return RateLimiter(rate=p["rate"], burst=p["burst"])

def jitter_sleep(profile: str = "normal"):
    """Add random delay for evasion."""
    p = EVASION_PROFILES.get(profile, EVASION_PROFILES["normal"])
    if p["jitter"] > 0:
        time.sleep(random.uniform(0, p["jitter"]))


# ─── PLUGIN SYSTEM ──────────────────────────────────────────────────────────

import importlib
import os

class PluginManager:
    """
    Simple plugin system — load custom Python scripts from plugins/ folder.
    Each plugin must have a run(host, ip, open_ports) function.
    """

    def __init__(self, plugin_dir: str = None):
        if plugin_dir is None:
            plugin_dir = os.path.join(os.path.dirname(__file__), "..", "plugins")
        self.plugin_dir = os.path.abspath(plugin_dir)
        self.plugins = []

    def load(self):
        """Load all .py files from plugins directory."""
        if not os.path.exists(self.plugin_dir):
            os.makedirs(self.plugin_dir, exist_ok=True)
            self._create_example_plugin()
            return

        for fname in os.listdir(self.plugin_dir):
            if fname.endswith(".py") and not fname.startswith("_"):
                path = os.path.join(self.plugin_dir, fname)
                try:
                    spec = importlib.util.spec_from_file_location(fname[:-3], path)
                    mod = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(mod)
                    if hasattr(mod, "run"):
                        self.plugins.append((fname[:-3], mod))
                        print(f"  [+] Plugin loaded: {fname}")
                except Exception as e:
                    print(f"  [!] Plugin error {fname}: {e}")

    def run_all(self, host: str, ip: str, open_ports: list) -> list:
        """Run all loaded plugins."""
        results = []
        for name, mod in self.plugins:
            try:
                result = mod.run(host, ip, open_ports)
                if result:
                    results.append({"plugin": name, "result": result})
            except Exception as e:
                results.append({"plugin": name, "result": f"Error: {e}"})
        return results

    def _create_example_plugin(self):
        """Create an example plugin file."""
        example = '''"""
Example PortHawk Plugin.
Copy this file, rename it, and modify the run() function.
"""

def run(host: str, ip: str, open_ports: list) -> str:
    """
    host       = target hostname
    ip         = resolved IP
    open_ports = list of PortResult objects
    Returns a string result or None.
    """
    port_nums = [p.port for p in open_ports]
    return f"Example plugin: found {len(open_ports)} open ports: {port_nums}"
'''
        path = os.path.join(self.plugin_dir, "example_plugin.py")
        with open(path, "w") as f:
            f.write(example)
        print(f"  [+] Example plugin created at: {path}")
