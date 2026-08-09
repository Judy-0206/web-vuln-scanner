"""Concurrent web content discovery with soft-404 filtering."""

from __future__ import annotations

import difflib
import re
import secrets
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Union
from urllib.parse import urljoin, urlsplit

import requests

USER_AGENT = "web-vuln-scanner/1.0 (+authorized-security-testing)"
_INTERESTING_STATUSES = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403}


class DirScanner:
    """Discover web paths from a wordlist without following redirects."""

    def __init__(
        self,
        url: str,
        threads: int = 20,
        timeout: float = 5.0,
        verify_tls: bool = True,
    ):
        parsed = urlsplit(url if "://" in url else "http://" + url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("目标必须是有效的 HTTP 或 HTTPS URL")
        if threads < 1:
            raise ValueError("线程数必须大于 0")
        self.base_url = (
            url.rstrip("/")
            if "://" in url
            else ("http://" + url).rstrip("/")
        )
        self.threads = threads
        self.timeout = timeout
        self.verify_tls = verify_tls

    def scan(self, wordlist: Union[str, Path]) -> List[Dict[str, object]]:
        paths = self._load_paths(Path(wordlist))
        if not paths:
            return []

        baseline = self._request("/__wvs_not_found_" + secrets.token_hex(8))
        baseline_signature = self._signature(baseline) if baseline is not None else None

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(
                lambda path: self._check_path(path, baseline_signature), paths
            )
        findings = [result for result in results if result is not None]
        return sorted(findings, key=lambda item: str(item["path"]))

    @staticmethod
    def _load_paths(path: Path) -> List[str]:
        if not path.is_file():
            raise FileNotFoundError("目录字典不存在: {0}".format(path))
        unique = set()
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            value = raw_line.strip()
            if not value or value.startswith("#"):
                continue
            unique.add("/" + value.lstrip("/"))
        return sorted(unique)

    def _check_path(
        self, path: str, baseline: Optional[Tuple[int, str]]
    ) -> Optional[Dict[str, object]]:
        response = self._request(path)
        if response is None or response.status_code not in _INTERESTING_STATUSES:
            return None
        if baseline is not None and self._looks_like_soft_404(response, baseline):
            return None
        return {
            "path": path,
            "url": urljoin(self.base_url + "/", path.lstrip("/")),
            "status": response.status_code,
            "length": len(response.content),
            "redirect": response.headers.get("Location"),
        }

    def _request(self, path: str) -> Optional[requests.Response]:
        url = urljoin(self.base_url + "/", path.lstrip("/"))
        try:
            return requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=self.timeout,
                allow_redirects=False,
                verify=self.verify_tls,
            )
        except requests.RequestException:
            return None

    @classmethod
    def _looks_like_soft_404(
        cls, response: requests.Response, baseline: Tuple[int, str]
    ) -> bool:
        baseline_status, baseline_body = baseline
        if response.status_code != baseline_status:
            return False
        body = cls._normalize_body(response.text)
        if not body and not baseline_body:
            return True
        return difflib.SequenceMatcher(None, body, baseline_body).ratio() >= 0.90

    @classmethod
    def _signature(cls, response: requests.Response) -> Tuple[int, str]:
        return response.status_code, cls._normalize_body(response.text)

    @staticmethod
    def _normalize_body(body: str) -> str:
        body = re.sub(r"/__wvs_not_found_[0-9a-f]+", "/<path>", body)
        body = re.sub(r"/soft-[A-Za-z0-9._~-]+", "/<path>", body)
        body = re.sub(r"[0-9a-f]{16,}", "<token>", body, flags=re.IGNORECASE)
        return " ".join(body.split())[:20000]
