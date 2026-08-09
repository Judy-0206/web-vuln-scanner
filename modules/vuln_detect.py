"""Safe, differential checks for web vulnerability classes.

Supported probes: reflected XSS, error-based SQLi, command injection
(error/echo), path traversal (file-content evidence), server-side template
injection (evaluation evidence), and open redirect (Location evidence).
All payloads are non-destructive.
"""

from __future__ import annotations

import html
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup

USER_AGENT = "web-vuln-scanner/1.0 (+authorized-security-testing)"
# Pages that change session/state or expose server info instead of taking
# user input. Browsing them during a scan can log the scanner out (login/logout),
# reset databases (setup), or change target config (security).
NON_TARGET_PAGES = {
    "login.php",
    "logout.php",
    "setup.php",
    "security.php",
    "install.php",
    "phpinfo.php",
}

ALLOWED_KINDS = {"XSS", "SQLI", "CMDI", "TRAVERSAL", "SSTI", "REDIRECT"}

SQL_ERROR_MARKERS = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch_",
    "mysqli_fetch_",
    "sqlstate[",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-01756",
    "postgresql query failed",
    "sqlite3::sqlexception",
)

CMDI_ERROR_MARKERS = (
    "sh: ",
    "/bin/sh:",
    "command not found",
    "which: no ",
    "not recognized as an internal or external command",
)

# Command output evidence: `;id` / `||id` / backtick-id invoke `id`; its
# stdout ("uid=...") is strong proof of command execution (input echo is not).
CMDI_OUTPUT_MARKERS = ("uid=", "gid=", "groups=")
CMDI_ID_INVOCATIONS = (";id", "||id", "`id`", "&id", "|id")

TRAVERSAL_MARKERS = (
    "root:x:0:0:",
    "[fonts]",
    "[extensions]",
    "boot.ini",
    "for 16-bit app support",
)

# payload -> expected evaluated output (evaluation proves template execution).
# Expected values are long/unique (10 digits) so random page content such as
# tokens or counters cannot collide with them.
SSTI_EVALUATIONS = {
    "{{99999*99999}}": "9999800001",
    "${99999*99999}": "9999800001",
    "<%= 99999*99999 %>": "9999800001",
}

# Regexes used to find endpoint-looking strings inside JavaScript source.
JS_ENDPOINT_PATTERNS = (
    re.compile(r"""fetch\(\s*["']([^"']+)["']"""),
    re.compile(r"""\$\.[a-z]+\(\s*["']([^"']+)["']"""),
    re.compile(r"""url:\s*["']([^"']+)["']"""),
    re.compile(r"""["']((?:/|\.{1,2}/)[^"']*?(?:\.php|\.jsp|\.aspx|/api/)[^"']*)["']"""),
)

MAX_PAGES = 60


class VulnDetector:
    """Probe discovered parameters with non-destructive differential payloads."""

    def __init__(
        self,
        url: str,
        threads: int = 10,
        timeout: float = 5.0,
        verify_tls: bool = True,
        cookie: str = "",
        user_agent: str = USER_AGENT,
    ):
        parsed = urlsplit(url if "://" in url else "http://" + url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("目标必须是有效的 HTTP 或 HTTPS URL")
        if threads < 1:
            raise ValueError("线程数必须大于 0")
        self.base_url = url if "://" in url else "http://" + url
        self.threads = threads
        self.timeout = timeout
        self.verify_tls = verify_tls
        self.cookie = cookie.strip()
        self.user_agent = user_agent
        self.total_requests = 0
        self.failed_requests = 0

    def scan(self, payload_file: Union[str, Path]) -> List[Dict[str, object]]:
        payloads = self._load_payloads(Path(payload_file))
        jobs = []
        discovered_targets = self._discover_targets()
        for method, target_url, params, probe_indexes, baseline in discovered_targets:
            jobs.extend(
                (
                    kind,
                    payload,
                    index,
                    params[index][0],
                    params,
                    baseline,
                    target_url,
                    method,
                )
                for kind, payload in payloads
                for index in probe_indexes
            )
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            results = executor.map(self._run_probe, jobs)
        findings = [item for item in results if item is not None]
        return sorted(
            findings,
            key=lambda item: (str(item["type"]), str(item["parameter"])),
        )

    def _discover_targets(
        self,
    ) -> List[
        Tuple[str, str, List[Tuple[str, str]], List[int], requests.Response]
    ]:
        start_response = self._request(self.base_url)
        if start_response is None:
            return []

        origin = urlsplit(self.base_url)
        scope_path = origin.path
        if not scope_path.endswith("/"):
            scope_path = scope_path.rsplit("/", 1)[0] + "/"

        pages: List[Tuple[str, requests.Response]] = []
        queue = [self.base_url]
        visited = set()
        while queue and len(pages) < MAX_PAGES:
            url = queue.pop(0)
            if url in visited:
                continue
            visited.add(url)
            response = (
                start_response if url == self.base_url else self._request(url)
            )
            if response is None:
                continue
            pages.append((url, response))
            if "html" not in response.headers.get("Content-Type", "").lower():
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            for candidate in self._page_candidates(soup, url, origin, scope_path):
                if candidate not in visited and len(queue) + len(visited) < MAX_PAGES:
                    queue.append(candidate)

        targets = []
        seen = set()
        for page_url, response in pages:
            query_params = parse_qsl(
                urlsplit(page_url).query, keep_blank_values=True
            )
            if query_params:
                key = ("GET", page_url, tuple(query_params))
                if key not in seen:
                    seen.add(key)
                    targets.append(
                        (
                            "GET",
                            page_url,
                            query_params,
                            list(range(len(query_params))),
                            response,
                        )
                    )
            if "html" not in response.headers.get("Content-Type", "").lower():
                continue
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                action = form.get("action") or page_url
                target = requests.compat.urljoin(page_url, action)
                parsed = urlsplit(target)
                outside_origin = parsed.netloc != origin.netloc
                outside_path = not parsed.path.startswith(scope_path)
                page_name = parsed.path.rsplit("/", 1)[-1]
                if outside_origin or outside_path or page_name in NON_TARGET_PAGES:
                    continue
                method = (form.get("method") or "GET").upper()
                if method not in {"GET", "POST"}:
                    continue
                params, probe_indexes = self._form_parameters(form)
                if not probe_indexes:
                    continue
                target = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
                key = (method, target, tuple(params))
                if key in seen:
                    continue
                seen.add(key)
                baseline = self._request(method, target, params)
                if baseline is not None:
                    targets.append((method, target, params, probe_indexes, baseline))
        return targets

    def _page_candidates(
        self,
        soup,
        page_url: str,
        origin,
        scope_path: str,
    ) -> List[str]:
        candidates = []
        for anchor in soup.find_all("a", href=True):
            candidate = self._normalize_candidate(
                requests.compat.urljoin(page_url, anchor["href"]),
                origin,
                scope_path,
            )
            if candidate:
                candidates.append(candidate)
        script_sources = []
        for script in soup.find_all("script", src=True):
            script_sources.append(
                requests.compat.urljoin(page_url, script["src"])
            )
        for script in soup.find_all("script"):
            if script.string:
                script_sources.extend(
                    self._extract_js_endpoints(script.string, origin, scope_path)
                )
        for source in script_sources:
            normalized = self._normalize_candidate(source, origin, scope_path)
            if not normalized:
                continue
            js_response = self._request(normalized)
            if js_response is None:
                continue
            js_candidates = self._extract_js_endpoints(
                js_response.text, origin, scope_path
            )
            candidates.extend(
                c for c in js_candidates if c not in candidates
            )
        return list(dict.fromkeys(candidates))

    def _normalize_candidate(
        self, url: str, origin, scope_path: str
    ) -> Optional[str]:
        parsed = urlsplit(url)
        page_name = parsed.path.rsplit("/", 1)[-1]
        if (
            parsed.scheme in {"http", "https"}
            and parsed.netloc == origin.netloc
            and parsed.path.startswith(scope_path)
            and page_name not in NON_TARGET_PAGES
        ):
            return urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, parsed.query, "")
            )
        return None

    def _extract_js_endpoints(
        self, js_text: str, origin, scope_path: str
    ) -> List[str]:
        found = []
        for pattern in JS_ENDPOINT_PATTERNS:
            for match in pattern.findall(js_text):
                value = match.strip()
                if not value or value.startswith(("http://", "https://", "//")):
                    continue
                normalized = self._normalize_candidate(
                    requests.compat.urljoin(self.base_url, value), origin, scope_path
                )
                if normalized and normalized not in found:
                    found.append(normalized)
        return found

    @staticmethod
    def _form_parameters(form) -> Tuple[List[Tuple[str, str]], List[int]]:
        params: List[Tuple[str, str]] = []
        probe_indexes = []
        for field in form.find_all(["input", "select", "textarea"]):
            name = field.get("name")
            if not name or field.has_attr("disabled"):
                continue
            field_type = (field.get("type") or "text").lower()
            if field.name == "select":
                option = field.find("option", selected=True) or field.find("option")
                value = option.get("value", option.text) if option else ""
            elif field.name == "textarea":
                value = field.text or ""
            else:
                value = field.get("value", "")
            params.append((name, value))
            if field_type not in {"submit", "button", "reset", "image", "file"}:
                probe_indexes.append(len(params) - 1)
        return params, probe_indexes

    @staticmethod
    def _load_payloads(path: Path) -> List[Tuple[str, str]]:
        if not path.is_file():
            raise FileNotFoundError("Payload 文件不存在: {0}".format(path))
        payloads: List[Tuple[str, str]] = []
        for line_number, raw_line in enumerate(
            path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "|" not in line:
                raise ValueError(
                    "Payload 第 {0} 行格式错误，应为 TYPE|PAYLOAD".format(line_number)
                )
            kind, payload = line.split("|", 1)
            kind = kind.strip().upper()
            if kind not in ALLOWED_KINDS or not payload:
                raise ValueError("Payload 第 {0} 行类型或内容无效".format(line_number))
            payloads.append((kind, payload))
        return payloads

    def _run_probe(
        self,
        job: Tuple[
            str,
            str,
            int,
            str,
            Sequence[Tuple[str, str]],
            requests.Response,
            str,
            str,
        ],
    ) -> Optional[Dict[str, object]]:
        kind, payload, index, parameter, params, baseline, target_url, method = job
        test_params = list(params)
        test_params[index] = (parameter, payload)
        if method == "GET":
            parsed = urlsplit(target_url)
            test_url = urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path or "/",
                    urlencode(test_params),
                    "",
                )
            )
        else:
            test_url = target_url
        response = self._request(method, test_url, test_params)
        if response is None:
            return None

        if kind == "XSS":
            return self._check_xss(
                parameter, payload, test_url, response, baseline, method, test_params
            )
        if kind == "SQLI":
            return self._check_sqli(
                parameter, payload, test_url, response, baseline, method, test_params
            )
        if kind == "CMDI":
            return self._check_cmdi(
                parameter, payload, test_url, response, baseline, method, test_params
            )
        if kind == "TRAVERSAL":
            return self._check_traversal(
                parameter, payload, test_url, response, baseline, method, test_params
            )
        if kind == "SSTI":
            return self._check_ssti(
                parameter, payload, test_url, response, baseline, method, test_params
            )
        return self._check_redirect(
            parameter, payload, test_url, response, method, test_params
        )

    def _check_xss(
        self,
        parameter: str,
        payload: str,
        test_url: str,
        response: requests.Response,
        baseline: requests.Response,
        method: str,
        test_params: Sequence[Tuple[str, str]],
    ) -> Optional[Dict[str, object]]:
        if payload not in response.text or payload in baseline.text:
            return None
        escaped = html.escape(payload, quote=True)
        if escaped != payload and escaped in response.text:
            return None
        if self._sql_markers(response.text):
            return None
        return self._finding(
            "Reflected XSS",
            "medium",
            parameter,
            payload,
            test_url,
            response,
            payload,
            method,
            test_params,
        )

    def _check_sqli(
        self,
        parameter: str,
        payload: str,
        test_url: str,
        response: requests.Response,
        baseline: requests.Response,
        method: str,
        test_params: Sequence[Tuple[str, str]],
    ) -> Optional[Dict[str, object]]:
        baseline_markers = self._sql_markers(baseline.text)
        response_markers = self._sql_markers(response.text)
        new_markers = sorted(response_markers - baseline_markers)
        evidence = new_markers[0] if new_markers else None
        if not evidence:
            # Some PHP apps die() silently on query failure (display_errors
            # off, die(mysqli_connect_error())). The only visible signal is
            # the page output being truncated mid-document. This can also be
            # caused by eval()/XML parse errors, so report it as a generic
            # injection-triggered truncation instead of claiming SQLi.
            baseline_closed = baseline.text.rstrip().endswith("</html>")
            response_closed = response.text.rstrip().endswith("</html>")
            truncated = (
                baseline_closed
                and not response_closed
                and len(response.text) < len(baseline.text) * 0.95
            )
            if truncated:
                return self._finding(
                    "PHP Output Truncation (suspected injection)",
                    "high",
                    parameter,
                    payload,
                    test_url,
                    response,
                    "页面输出截断（PHP 静默终止）",
                    method,
                    test_params,
                )
        if not evidence:
            return None
        return self._finding(
            "Error-based SQL Injection",
            "high",
            parameter,
            payload,
            test_url,
            response,
            evidence,
            method,
            test_params,
        )

    def _check_cmdi(
        self,
        parameter: str,
        payload: str,
        test_url: str,
        response: requests.Response,
        baseline: requests.Response,
        method: str,
        test_params: Sequence[Tuple[str, str]],
    ) -> Optional[Dict[str, object]]:
        if self._sql_markers(response.text):
            return None
        lowered = response.text.lower()
        baseline_lowered = baseline.text.lower()
        new_markers = [
            marker
            for marker in CMDI_ERROR_MARKERS
            if marker in lowered and marker not in baseline_lowered
        ]
        evidence = None
        if new_markers:
            # "sh: " / "command not found" also appear in static docs and help
            # pages. Only trust them when the payload marker word (wvscmdi)
            # appears next to them AND the raw payload is not echoed back.
            marker_word = re.search(r"(wvs[a-z0-9]+)", payload)
            trusted = (
                marker_word
                and marker_word.group(1) in response.text
                and payload not in response.text
            )
            if trusted:
                evidence = new_markers[0]
        elif any(kind in payload for kind in CMDI_ID_INVOCATIONS):
            for marker in CMDI_OUTPUT_MARKERS:
                if marker in response.text and marker not in baseline.text:
                    evidence = marker
                    break
        if not evidence:
            echo_match = re.search(
                r"echo[^a-zA-Z0-9]+(wvs[a-zA-Z0-9]+)", payload
            )
            if echo_match:
                token = echo_match.group(1)
                echoed = (
                    token in response.text
                    and token not in baseline.text
                    and payload not in response.text
                )
                if echoed:
                    evidence = token
        if not evidence:
            return None
        return self._finding(
            "Command Injection",
            "high",
            parameter,
            payload,
            test_url,
            response,
            evidence,
            method,
            test_params,
        )

    def _check_traversal(
        self,
        parameter: str,
        payload: str,
        test_url: str,
        response: requests.Response,
        baseline: requests.Response,
        method: str,
        test_params: Sequence[Tuple[str, str]],
    ) -> Optional[Dict[str, object]]:
        if self._sql_markers(response.text):
            return None
        lowered = response.text.lower()
        baseline_lowered = baseline.text.lower()
        new_markers = [
            marker
            for marker in TRAVERSAL_MARKERS
            if marker in lowered and marker not in baseline_lowered
        ]
        if not new_markers:
            return None
        return self._finding(
            "Path Traversal",
            "high",
            parameter,
            payload,
            test_url,
            response,
            new_markers[0],
            method,
            test_params,
        )

    def _check_ssti(
        self,
        parameter: str,
        payload: str,
        test_url: str,
        response: requests.Response,
        baseline: requests.Response,
        method: str,
        test_params: Sequence[Tuple[str, str]],
    ) -> Optional[Dict[str, object]]:
        expected = SSTI_EVALUATIONS.get(payload)
        if not expected:
            return None
        if payload in response.text:
            return None
        if expected not in response.text or expected in baseline.text:
            return None
        return self._finding(
            "Server-Side Template Injection",
            "high",
            parameter,
            payload,
            test_url,
            response,
            expected,
            method,
            test_params,
        )

    def _check_redirect(
        self,
        parameter: str,
        payload: str,
        test_url: str,
        response: requests.Response,
        method: str,
        test_params: Sequence[Tuple[str, str]],
    ) -> Optional[Dict[str, object]]:
        location = response.headers.get("Location", "")
        if not location:
            return None
        if payload not in location and "evil.invalid" not in location:
            return None
        return self._finding(
            "Open Redirect",
            "low",
            parameter,
            payload,
            test_url,
            response,
            location,
            method,
            test_params,
        )

    @staticmethod
    def _sql_markers(body: str) -> set:
        lowered = body.lower()
        return {marker for marker in SQL_ERROR_MARKERS if marker in lowered}

    def _request(
        self,
        method: str,
        url: Optional[str] = None,
        params: Optional[Sequence[Tuple[str, str]]] = None,
    ) -> Optional[requests.Response]:
        if url is None:
            url = method
            method = "GET"
        headers = {"User-Agent": self.user_agent, "Connection": "close"}
        if self.cookie:
            headers["Cookie"] = self.cookie
        kwargs = {
            "headers": headers,
            "timeout": self.timeout,
            "allow_redirects": False,
            "verify": self.verify_tls,
        }
        if method == "POST":
            kwargs["data"] = params or []
        for attempt in range(2):
            self.total_requests += 1
            try:
                return requests.request(method, url, **kwargs)
            except requests.RequestException:
                self.failed_requests += 1
        return None

    def _finding(
        self,
        vuln_type: str,
        severity: str,
        parameter: str,
        payload: str,
        url: str,
        response: requests.Response,
        evidence: str,
        method: str = "GET",
        params: Optional[Sequence[Tuple[str, str]]] = None,
    ) -> Dict[str, object]:
        request_target = urlsplit(url)
        path = request_target.path or "/"
        if request_target.query:
            path += "?" + request_target.query
        host = request_target.hostname or ""
        if request_target.port is not None:
            host = "{0}:{1}".format(host, request_target.port)
        body = urlencode(params or []) if method == "POST" else ""
        raw_request = (
            "{0} {1} HTTP/1.1\r\n"
            "Host: {2}\r\n"
            "User-Agent: {3}\r\n"
            "Accept: */*\r\n"
        ).format(method, path, host, self.user_agent)
        if self.cookie:
            raw_request += "Cookie: {0}\r\n".format(self.cookie)
        if method == "POST":
            raw_request += (
                "Content-Type: application/x-www-form-urlencoded\r\n"
                "Content-Length: {0}\r\n"
            ).format(len(body.encode()))
        raw_request += "Connection: close\r\n\r\n" + body
        raw_response = "HTTP/1.1 {0} {1}\r\n".format(
            response.status_code, response.reason
        )
        location = response.headers.get("Location")
        if location:
            raw_response += "Location: {0}\r\n".format(location)
        body = response.text[:2000]
        if evidence and evidence not in body:
            marker_index = response.text.find(evidence)
            if marker_index >= 0:
                window = response.text[
                    max(0, marker_index - 120) : marker_index + 200
                ]
                body += "\r\n...[证据上下文]\r\n{0}".format(window)
        raw_response += "Content-Length: {0}\r\n\r\n{1}".format(
            len(response.content), body
        )
        return {
            "type": vuln_type,
            "severity": severity,
            "url": url,
            "method": method,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence,
            "raw_request": raw_request,
            "raw_response": raw_response,
            "request": {
                "method": method,
                "url": url,
                "headers": {"User-Agent": self.user_agent},
                "body": body,
            },
            "response": {
                "status": response.status_code,
                "length": len(response.content),
                "evidence": evidence,
            },
        }
