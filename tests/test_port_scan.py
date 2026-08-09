"""Port scanner behavior tests."""

import socket

import pytest

from modules.port_scan import PortScanner


def test_extracts_bracketed_ipv6_host_and_explicit_port():
    scanner = PortScanner("https://[::1]:8443/path", threads=2)

    assert scanner.target == "::1"
    assert scanner.url_port == 8443


def test_rejects_url_without_hostname():
    with pytest.raises(ValueError, match="主机名"):
        PortScanner("http://")


def test_scan_returns_open_ports_in_sorted_order():
    listeners = []
    try:
        for _ in range(2):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", 0))
            sock.listen(1)
            listeners.append(sock)

        open_ports = sorted(sock.getsockname()[1] for sock in listeners)
        scanner = PortScanner("http://127.0.0.1", threads=2, timeout=0.2)

        assert scanner.scan(reversed(open_ports)) == open_ports
    finally:
        for sock in listeners:
            sock.close()


def test_scan_rejects_invalid_ports():
    scanner = PortScanner("http://127.0.0.1", threads=1)

    with pytest.raises(ValueError, match="1 到 65535"):
        scanner.scan([0, 80])
