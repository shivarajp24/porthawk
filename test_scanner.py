"""Tests for scanner engine (uses localhost for real socket tests)."""

import socket
import threading
import pytest
from portscanner.scanner import tcp_connect_scan, Scanner, ScanResult


def start_echo_server(port: int) -> threading.Thread:
    """Start a minimal TCP server on localhost for testing."""
    def serve():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", port))
            s.listen(1)
            s.settimeout(3)
            try:
                conn, _ = s.accept()
                conn.close()
            except Exception:
                pass
    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


class TestTcpConnectScan:
    def test_open_port(self):
        """A real listening socket should report as open."""
        port = 19876
        start_echo_server(port)
        import time; time.sleep(0.1)
        result = tcp_connect_scan("127.0.0.1", port, timeout=2.0)
        assert result.state == "open"
        assert result.latency_ms > 0

    def test_closed_port(self):
        """A port with nothing listening should be closed."""
        result = tcp_connect_scan("127.0.0.1", 19999, timeout=1.0)
        assert result.state == "closed"


class TestScanner:
    def test_scan_result_type(self):
        scanner = Scanner("127.0.0.1", [19999, 19998], threads=2, timeout=0.5)
        result = scanner.run()
        assert isinstance(result, ScanResult)
        assert result.ip == "127.0.0.1"
        assert len(result.ports) == 2

    def test_open_ports_property(self):
        port = 19875
        start_echo_server(port)
        import time; time.sleep(0.1)
        scanner = Scanner("127.0.0.1", [port, 19874], threads=2, timeout=2.0)
        result = scanner.run()
        open_ports = result.open_ports
        assert any(p.port == port for p in open_ports)

    def test_duration_recorded(self):
        scanner = Scanner("127.0.0.1", [19990], threads=1, timeout=0.5)
        result = scanner.run()
        assert result.duration >= 0
