"""Local vulnerable fixture used for tests and manual demos."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query, keep_blank_values=True)
        value = params.get("q", [""])[0]
        if parsed.path == "/":
            body = (
                b'<a href="/reflect?q=seed">xss demo</a>'
                b'<a href="/sql?q=seed">sqli demo</a>'
                b'<a href="/rce?ip=8.8.8.8">cmdi demo</a>'
                b'<a href="/download?file=a.txt">traversal demo</a>'
                b'<a href="/redirect?url=ok">redirect demo</a>'
                b'<a href="/ssti?name=world">ssti demo</a>'
            )
            status = 200
        elif parsed.path == "/reflect":
            status = 200
            body = ("result=" + value).encode("utf-8")
        elif parsed.path == "/admin":
            status = 200
            body = b"admin panel"
        elif parsed.path == "/sql" and "'" in value:
            status = 500
            body = b"You have an error in your SQL syntax near quote"
        elif parsed.path == "/sql":
            status = 200
            body = b"query ok"
        elif parsed.path == "/rce":
            ip = params.get("ip", [""])[0]
            if "wvscmdi" in ip:
                status = 200
                body = b"sh: wvscmdi: not found"
            else:
                status = 200
                body = b"ping ok"
        elif parsed.path == "/download":
            filename = params.get("file", [""])[0]
            if "etc/passwd" in filename:
                status = 200
                body = b"root:x:0:0:root:/root:/bin/bash"
            else:
                status = 200
                body = b"file not found"
        elif parsed.path == "/redirect":
            url = params.get("url", [""])[0]
            if "evil.invalid" in url:
                self.send_response(302)
                self.send_header("Location", url)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            status = 200
            body = b"ok"
        elif parsed.path == "/ssti":
            name = params.get("name", [""])[0]
            status = 200
            body = (
                b"hello 9999800001"
                if name == "{{99999*99999}}"
                else ("hello " + name).encode("utf-8")
            )
        else:
            status = 404
            body = b"missing"

        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        pass


def main():
    parser = argparse.ArgumentParser(description="web-vuln-scanner 本地演示靶场")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    print("Demo target: http://127.0.0.1:{0}/".format(args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
