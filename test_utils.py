"""Tests for utility functions."""

import pytest
from portscanner.utils import parse_ports, expand_cidr, is_valid_ip


class TestParsePorts:
    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_port_range(self):
        assert parse_ports("20-23") == [20, 21, 22, 23]

    def test_comma_list(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_mixed(self):
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_common_keyword(self):
        result = parse_ports("common")
        assert 80 in result
        assert 443 in result
        assert len(result) > 50

    def test_all_keyword(self):
        result = parse_ports("all")
        assert len(result) == 65535
        assert result[0] == 1
        assert result[-1] == 65535

    def test_invalid_port_number(self):
        with pytest.raises(ValueError):
            parse_ports("99999")

    def test_invalid_string(self):
        with pytest.raises(ValueError):
            parse_ports("abc")

    def test_deduplication(self):
        result = parse_ports("80,80,80")
        assert result.count(80) == 1


class TestExpandCidr:
    def test_small_network(self):
        ips = list(expand_cidr("192.168.1.0/30"))
        assert "192.168.1.1" in ips
        assert "192.168.1.2" in ips
        assert len(ips) == 2

    def test_invalid_cidr(self):
        with pytest.raises(ValueError):
            list(expand_cidr("not-a-cidr"))


class TestIsValidIp:
    def test_valid_ipv4(self):
        assert is_valid_ip("192.168.1.1") is True

    def test_valid_ipv6(self):
        assert is_valid_ip("::1") is True

    def test_invalid(self):
        assert is_valid_ip("not-an-ip") is False
        assert is_valid_ip("999.999.999.999") is False
