"""Vulnerability detector behavior tests."""

import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.parse import parse_qs, urlsplit

from modules.vuln_detect import VulnDetector


class VulnerableTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        value = params.get("q", [""])[0]

        if parsed.path == "/reflect":
            body = ("result=" + value).encode()
        elif parsed.path == "/escaped":
            body = ("result=" + html.escape(value)).encode()
        elif parsed.path == "/sql" and "'" in value:
            body = b"You have an error in your SQL syntax near quote"
        elif parsed.path == "/always-error":
            body = b"You have an error in your SQL syntax from maintenance"
        elif parsed.path == "/links":
            body = (
                b'<a href="/reflect?q=seed">search</a>'
                b'<a href="https://outside.invalid/?q=seed">outside</a>'
            )
        elif parsed.path == "/vuln/sqli/" and "id" in params:
            body = (
                b"You have an error in your SQL syntax near quote"
                if "'" in params["id"][0]
                else b"ok"
            )
        elif parsed.path == "/pikachu-like":
            body = b'<a href="/xss-form">xss</a><a href="/post-form">sqli</a>'
        elif parsed.path == "/js-page":
            body = (
                b'<script src="/app.js"></script>'
                b'<a href="/level2">next</a>'
            )
        elif parsed.path == "/app.js":
            body = (
                b'fetch("/api/users?id=1");'
                b'$.get("/api/items?page=2");'
            )
        elif parsed.path == "/api/users" and "id" in params:
            body = ("user=" + params["id"][0]).encode()
        elif parsed.path == "/api/users":
            body = b'[{"id":1}]'
        elif parsed.path == "/api/items" and "page" in params:
            body = ("items=" + params["page"][0]).encode()
        elif parsed.path == "/api/items":
            body = b'[{"page":2}]'
        elif parsed.path == "/level2":
            body = b'<a href="/reflect?q=seed">deep</a>'
        elif parsed.path == "/dvwa-like":
            body = (
                b'<a href="/vuln/sqli/">sqli</a>'
                b'<a href="/logout.php">logout</a>'
                b'<a href="/setup.php">setup</a>'
            )
        elif parsed.path == "/vuln/sqli/":
            body = (
                b'<form method="get">'
                b'<select name="id"><option value="1">1</option></select>'
                b'<input name="Submit" value="Submit" type="submit">'
                b"</form>"
            )
        elif parsed.path == "/logout.php":
            body = b"logged out"
        elif parsed.path == "/xss-form" and "message" in params:
            body = ("result=" + params["message"][0]).encode()
        elif parsed.path == "/xss-form":
            body = (
                b'<form method="get">'
                b'<input name="message" type="text">'
                b'<input name="submit" value="submit" type="submit">'
                b"</form>"
            )
        elif parsed.path == "/post-form":
            body = (
                b'<form method="post">'
                b'<select name="id"><option value="1">one</option></select>'
                b'<input name="submit" value="query" type="submit">'
                b"</form>"
            )
        elif parsed.path == "/sql-error-reflect":
            body = (
                ("<pre>You have an error in your SQL syntax near '{0}'</pre>").format(
                    value
                )
            ).encode()
        elif parsed.path == "/cmdi" and "ip" in params:
            body = (
                b"sh: wvscmdi: not found"
                if "wvscmdi" in params["ip"][0]
                else b"ok"
            )
        elif parsed.path == "/cmdi-echo" and "ip" in params:
            body = (
                b"uid=0(root) gid=0(root) groups=0(root)"
                if "wvscmdi" in params["ip"][0]
                else b"ok"
            )
        elif parsed.path == "/traversal" and "file" in params:
            body = (
                b"root:x:0:0:root:/root:/bin/bash"
                if "etc/passwd" in params["file"][0]
                else b"not found"
            )
        elif parsed.path == "/ssti" and "name" in params:
            value = params["name"][0]
            if value == "{{99999*99999}}":
                body = b"hello 9999800001"
            else:
                body = ("hello {0}".format(value)).encode()
        elif parsed.path == "/cmdi-echo-token" and "ip" in params:
            body = (
                b"ping failed\nwvscmdiok"
                if "wvscmdi" in params["ip"][0]
                else b"ping ok"
            )
        elif parsed.path == "/cmdi-static" and "ip" in params:
            body = (
                b"<pre>sh: command not found example</pre>"
                if "wvscmdi" in params["ip"][0]
                else b"ok"
            )
        elif parsed.path == "/cmdi-sqlerr" and "ip" in params:
            body = (
                (
                    "You have an error in your SQL syntax near '{0}'"
                ).format(params["ip"][0])
            ).encode()
        elif parsed.path == "/sql-truncate" and "q" in params:
            if "'" in params["q"][0]:
                body = b"<html><body>cut off"
            else:
                body = b"<html><body>ok</body></html>"
        elif parsed.path == "/redirect" and "url" in params:
            if "evil.invalid" in params["url"][0]:
                self.send_response(302)
                self.send_header("Location", params["url"][0])
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            body = b"ok"
        else:
            body = b"ok"

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        params = parse_qs(self.rfile.read(length).decode(), keep_blank_values=True)
        value = params.get("id", [""])[0]
        if self.path == "/post-form" and "'" in value:
            body = b"You have an error in your SQL syntax near quote"
            status = 500
        else:
            body = b"ok"
            status = 200
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableTestHandler)
    Thread(target=server.serve_forever, daemon=True).start()
    return server


def write_payloads(tmp_path):
    payloads = tmp_path / "payloads.txt"
    payloads.write_text(
        "# XSS\nXSS|<svg onload=alert(1)>\n"
        "# SQLi\nSQLI|'\n"
        "# CMDI\nCMDI|wvscmdi||id\nCMDI|wvscmdi||echo wvscmdiok\n"
        "# TRAVERSAL\nTRAVERSAL|../../../../../../etc/passwd\n"
        "# SSTI\nSSTI|{{99999*99999}}\n"
        "# REDIRECT\nREDIRECT|//evil.invalid/x\n",
        encoding="utf-8",
    )
    return payloads


def test_detects_raw_xss_reflection_with_parameter_preservation(tmp_path):
    server = start_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/reflect?keep=1&q=seed"
        detector = VulnDetector(url, threads=2, timeout=1)
        findings = detector.scan(write_payloads(tmp_path))

        xss = next(item for item in findings if item["type"] == "Reflected XSS")
        assert xss["parameter"] == "q"
        assert "keep=1" in xss["url"]
        assert xss["evidence"] == "<svg onload=alert(1)>"
        assert xss["request"]["method"] == "GET"
        assert xss["raw_request"].startswith("GET /reflect?")
        assert "Host: 127.0.0.1:" in xss["raw_request"]
        assert "User-Agent: web-vuln-scanner/1.0" in xss["raw_request"]
        assert xss["raw_response"].startswith("HTTP/1.1 200")
        assert "result=<svg onload=alert(1)>" in xss["raw_response"]
    finally:
        server.shutdown()
        server.server_close()


def test_does_not_report_html_escaped_reflection(tmp_path):
    server = start_server()
    try:
        url = f"http://127.0.0.1:{server.server_port}/escaped?q=seed"
        detector = VulnDetector(url, threads=2, timeout=1)
        assert detector.scan(write_payloads(tmp_path)) == []
    finally:
        server.shutdown()
        server.server_close()


def test_sql_error_requires_injected_response_delta(tmp_path):
    server = start_server()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        vulnerable = VulnDetector(base + "/sql?q=1", timeout=1)
        noisy = VulnDetector(base + "/always-error?q=1", timeout=1)
        findings = vulnerable.scan(write_payloads(tmp_path))
        assert any(item["type"] == "Error-based SQL Injection" for item in findings)
        assert noisy.scan(write_payloads(tmp_path)) == []
    finally:
        server.shutdown()
        server.server_close()


def test_without_query_parameters_returns_no_findings(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/reflect", timeout=1
        )
        assert detector.scan(write_payloads(tmp_path)) == []
    finally:
        server.shutdown()
        server.server_close()


def test_discovers_same_origin_parameterized_links_on_start_page(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/links", timeout=1
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert any(
            item["type"] == "Reflected XSS" and "/reflect?" in item["url"]
            for item in findings
        )
        assert all("outside.invalid" not in item["url"] for item in findings)
    finally:
        server.shutdown()
        server.server_close()


def test_does_not_touch_login_logout_setup_or_security_pages(tmp_path):
    visited = []
    original_do_GET = VulnerableTestHandler.do_GET

    def do_GET_with_tracking(self):
        visited.append(self.path)
        original_do_GET(self)

    VulnerableTestHandler.do_GET = do_GET_with_tracking
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/dvwa-like",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert findings, "expected the sqli form to be probed"
        assert all("/logout.php" not in path for path in visited)
        assert all("/setup.php" not in path for path in visited)
        assert any("/vuln/sqli/" in path for path in visited)
    finally:
        server.shutdown()
        server.server_close()
        VulnerableTestHandler.do_GET = original_do_GET


def test_xss_not_reported_when_reflection_comes_from_sql_error_message(
    tmp_path,
):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/sql-error-reflect?q=seed",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert not any(item["type"] == "Reflected XSS" for item in findings)
    finally:
        server.shutdown()
        server.server_close()


def test_discovers_api_endpoints_from_javascript_files(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/js-page", timeout=1
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert any(
            item["parameter"] == "id" and "/api/users" in item["url"]
            for item in findings
        )
        assert any(
            item["parameter"] == "page" and "/api/items" in item["url"]
            for item in findings
        )
    finally:
        server.shutdown()
        server.server_close()


def test_crawls_one_level_deep_from_links(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/js-page", timeout=1
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert any("/reflect?" in item["url"] for item in findings)
    finally:
        server.shutdown()
        server.server_close()


def test_detects_command_injection_error_and_echo(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/cmdi?ip=8.8.8.8",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        cmdi = next(item for item in findings if item["type"] == "Command Injection")
        assert cmdi["parameter"] == "ip"
        assert cmdi["severity"] == "high"
        assert cmdi["evidence"] == "sh: "

        echo_detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/cmdi-echo?ip=8.8.8.8",
            timeout=1,
        )
        echo_findings = echo_detector.scan(write_payloads(tmp_path))
        echo_cmdi = next(
            item for item in echo_findings if item["type"] == "Command Injection"
        )
        assert echo_cmdi["evidence"] == "uid="
    finally:
        server.shutdown()
        server.server_close()


def test_detects_path_traversal_with_passwd_evidence(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/traversal?file=1.txt",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        trav = next(
            item for item in findings if item["type"] == "Path Traversal"
        )
        assert trav["evidence"] == "root:x:0:0:"
    finally:
        server.shutdown()
        server.server_close()


def test_detects_ssti_evaluation(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/ssti?name=world", timeout=1
        )
        findings = detector.scan(write_payloads(tmp_path))
        ssti = next(
            item
            for item in findings
            if item["type"] == "Server-Side Template Injection"
        )
        assert ssti["evidence"] == "9999800001"
    finally:
        server.shutdown()
        server.server_close()


def test_detects_open_redirect(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/redirect?url=ok",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        redir = next(item for item in findings if item["type"] == "Open Redirect")
        assert redir["severity"] == "low"
        assert "evil.invalid" in redir["raw_response"]
    finally:
        server.shutdown()
        server.server_close()


def test_detects_command_injection_via_echo_token(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/cmdi-echo-token?ip=8.8.8.8",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        cmdi = next(item for item in findings if item["type"] == "Command Injection")
        assert cmdi["evidence"] == "wvscmdiok"
    finally:
        server.shutdown()
        server.server_close()


def test_cmdi_not_reported_when_error_marker_is_static_page_text(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/cmdi-static?ip=8.8.8.8",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert not any(item["type"] == "Command Injection" for item in findings)
    finally:
        server.shutdown()
        server.server_close()


def test_sqli_reported_when_injection_truncates_page_output(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/sql-truncate?q=1",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        trunc = next(
            item
            for item in findings
            if item["type"] == "PHP Output Truncation (suspected injection)"
        )
        assert "截断" in trunc["evidence"]
    finally:
        server.shutdown()
        server.server_close()


def test_cmdi_not_reported_when_token_comes_from_sql_error_message(
    tmp_path,
):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/cmdi-sqlerr?ip=8.8.8.8",
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert not any(item["type"] == "Command Injection" for item in findings)
    finally:
        server.shutdown()
        server.server_close()


def test_sends_cookie_header_on_every_request(tmp_path):
    received = []
    original_do_GET = VulnerableTestHandler.do_GET

    def do_GET_with_capture(self):
        received.append(self.headers.get("Cookie"))
        original_do_GET(self)

    VulnerableTestHandler.do_GET = do_GET_with_capture
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/reflect?q=seed",
            timeout=1,
            cookie="PHPSESSID=abc123; security=low",
        )
        findings = detector.scan(write_payloads(tmp_path))
        assert findings, "expected at least one probe request to the server"
        assert received, "no requests captured"
        assert all("PHPSESSID=abc123" in value for value in received if value)
        assert all("security=low" in value for value in received if value)
    finally:
        server.shutdown()
        server.server_close()
        VulnerableTestHandler.do_GET = original_do_GET


def test_crawls_same_origin_links_and_tests_get_and_post_forms(tmp_path):
    server = start_server()
    try:
        detector = VulnDetector(
            f"http://127.0.0.1:{server.server_port}/pikachu-like",
            threads=2,
            timeout=1,
        )
        findings = detector.scan(write_payloads(tmp_path))

        assert any(
            item["type"] == "Reflected XSS"
            and item["method"] == "GET"
            and item["parameter"] == "message"
            for item in findings
        )
        assert any(
            item["type"] == "Error-based SQL Injection"
            and item["method"] == "POST"
            and item["parameter"] == "id"
            for item in findings
        )
        post_finding = next(item for item in findings if item["method"] == "POST")
        assert post_finding["raw_request"].startswith("POST /post-form HTTP/1.1")
        assert "Content-Type: application/x-www-form-urlencoded" in post_finding[
            "raw_request"
        ]
        assert "id=%27" in post_finding["raw_request"]
    finally:
        server.shutdown()
        server.server_close()
