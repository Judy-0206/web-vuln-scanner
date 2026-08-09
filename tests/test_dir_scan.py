"""Directory scanner behavior tests."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from modules.dir_scan import DirScanner


class DirectoryTestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/admin":
            self.send_response(200)
            body = b"admin panel"
        elif self.path == "/login":
            self.send_response(302)
            self.send_header("Location", "/signin")
            body = b""
        elif self.path == "/forbidden":
            self.send_response(403)
            body = b"forbidden"
        elif self.path.startswith("/soft-") or self.path.startswith(
            "/__wvs_not_found_"
        ):
            self.send_response(200)
            body = ("Not found: " + self.path).encode()
        else:
            self.send_response(404)
            body = b"missing"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def start_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), DirectoryTestHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def test_scan_finds_interesting_statuses_and_filters_404(tmp_path):
    server = start_server()
    try:
        wordlist = tmp_path / "dirs.txt"
        wordlist.write_text(
            "# comment\n/admin\nlogin\nforbidden\nmissing\nadmin\n",
            encoding="utf-8",
        )
        scanner = DirScanner(
            f"http://127.0.0.1:{server.server_port}", threads=3, timeout=1
        )

        findings = scanner.scan(wordlist)

        assert [(item["path"], item["status"]) for item in findings] == [
            ("/admin", 200),
            ("/forbidden", 403),
            ("/login", 302),
        ]
        assert findings[0]["url"].endswith("/admin")
    finally:
        server.shutdown()
        server.server_close()


def test_scan_filters_dynamic_soft_404_pages(tmp_path):
    server = start_server()
    try:
        wordlist = tmp_path / "dirs.txt"
        wordlist.write_text("soft-one\nsoft-two\n", encoding="utf-8")
        scanner = DirScanner(
            f"http://127.0.0.1:{server.server_port}", threads=2, timeout=1
        )

        assert scanner.scan(wordlist) == []
    finally:
        server.shutdown()
        server.server_close()


def test_missing_wordlist_raises_clear_error(tmp_path):
    scanner = DirScanner("http://127.0.0.1")

    try:
        scanner.scan(tmp_path / "missing.txt")
    except FileNotFoundError as exc:
        assert "目录字典不存在" in str(exc)
    else:
        raise AssertionError("expected FileNotFoundError")
