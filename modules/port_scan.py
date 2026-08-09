"""Concurrent TCP connect port scanner."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor
from typing import Iterable, List, Optional
from urllib.parse import urlsplit


class PortScanner:
    """Scan TCP ports on the host contained in a URL."""

    def __init__(self, url: str, threads: int = 20, timeout: float = 0.5):
        parsed = urlsplit(url if "://" in url else "http://" + url)
        if not parsed.hostname:
            raise ValueError("目标 URL 中缺少有效主机名")
        if threads < 1:
            raise ValueError("线程数必须大于 0")
        if timeout <= 0:
            raise ValueError("超时时间必须大于 0")

        self.target = parsed.hostname
        try:
            self.url_port: Optional[int] = parsed.port
        except ValueError as exc:
            raise ValueError("目标 URL 中的端口无效") from exc
        self.threads = threads
        self.timeout = timeout

    def scan(self, ports: Iterable[int] = range(1, 1025)) -> List[int]:
        """Return sorted TCP ports that accepted a connection."""
        port_list = sorted(set(ports))
        if any(
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 1 <= port <= 65535
            for port in port_list
        ):
            raise ValueError("端口必须是 1 到 65535 之间的整数")

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            states = executor.map(self._check_port, port_list)
        return [port for port, is_open in zip(port_list, states) if is_open]

    def _check_port(self, port: int) -> bool:
        try:
            with socket.create_connection((self.target, port), timeout=self.timeout):
                return True
        except (OSError, socket.timeout):
            return False
