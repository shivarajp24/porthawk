"""PortHawk — A fast, multi-threaded port scanner."""

__version__ = "2.0.0"
__author__ = "shivarajp24"

from .scanner import Scanner, ScanResult, PortResult
from .utils import parse_ports, expand_cidr, resolve_host

__all__ = [
    "Scanner", "ScanResult", "PortResult",
    "parse_ports", "expand_cidr", "resolve_host",
]
