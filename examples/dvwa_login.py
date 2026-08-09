"""Log into a DVWA instance, optionally set the security level, print cookies.

Usage:
    python examples/dvwa_login.py http://127.0.0.1/dvwa/ admin password [level]

level 可选值:
    low / medium / high / impossible   登录后把安全等级设为指定值
    keep                                不修改安全等级，保持 DVWA 当前设置（默认）

Then pass the printed cookie to the scanner:
    python scanner.py -u http://127.0.0.1/dvwa/ --vuln-only \\
        --cookie 'PHPSESSID=...; security=low' \\
        --user-agent 'web-vuln-scanner-login-helper' \\
        --threads 1 \\
        -o reports/dvwa.md
"""
from __future__ import annotations

import http.cookiejar
import re
import sys
import time
import urllib.parse
import urllib.request

TOKEN_RE = re.compile(r"name=['\"]user_token['\"] value=['\"]([0-9a-f]{32})['\"]")
LEVELS = {"low", "medium", "high", "impossible", "keep"}


def _token(html: str) -> str:
    match = TOKEN_RE.search(html)
    if not match:
        raise RuntimeError("无法在页面中找到 user_token")
    return match.group(1)


def login(
    base: str, username: str, password: str, user_agent: str
) -> tuple[urllib.request.OpenerDirector, http.cookiejar.CookieJar]:
    cookie_jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cookie_jar)
    )
    opener.addheaders = [("User-Agent", user_agent)]

    def fetch(path: str, data: bytes | None = None) -> str:
        return opener.open(base + path, data=data, timeout=10).read().decode(
            "utf-8", "replace"
        )

    html = fetch("login.php")
    post = urllib.parse.urlencode(
        {
            "username": username,
            "password": password,
            "user_token": _token(html),
            "Login": "Login",
        }
    ).encode()
    index_html = fetch("login.php", post)
    if "vulnerabilities" not in index_html:
        raise RuntimeError("登录失败，请检查账号密码")
    return opener, cookie_jar


def _set_level(
    opener: urllib.request.OpenerDirector,
    base: str,
    cookie_jar: http.cookiejar.CookieJar,
    level: str,
) -> None:
    def fetch(path: str, data: bytes | None = None) -> str:
        return opener.open(base + path, data=data, timeout=10).read().decode(
            "utf-8", "replace"
        )

    for attempt in range(3):
        sec_html = fetch("security.php")
        post = urllib.parse.urlencode(
            {
                "security": level,
                "seclev_submit": "Submit",
                "user_token": _token(sec_html),
            }
        ).encode()
        fetch("security.php", post)
        cookies = {c.name: c.value for c in cookie_jar}
        if cookies.get("security") == level:
            return
        time.sleep(0.5)
    raise RuntimeError("无法将 DVWA security level 设为 {0}".format(level))


def login_and_set_level(
    base: str,
    username: str,
    password: str,
    user_agent: str,
    level: str = "keep",
) -> str:
    opener, cookie_jar = login(base, username, password, user_agent)
    if level != "keep":
        _set_level(opener, base, cookie_jar, level)
    return "; ".join(
        "{0}={1}".format(c.name, c.value) for c in cookie_jar
    )


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    base = sys.argv[1].rstrip("/") + "/"
    username = sys.argv[2]
    password = sys.argv[3]
    level = sys.argv[4] if len(sys.argv) > 4 else "keep"
    if level not in LEVELS:
        print("无效的安全等级: {0}，可选 {1}".format(level, sorted(LEVELS)))
        return 2
    user_agent = "web-vuln-scanner-login-helper"
    print(login_and_set_level(base, username, password, user_agent, level))
    return 0


if __name__ == "__main__":
    sys.exit(main())
