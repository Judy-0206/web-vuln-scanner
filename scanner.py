#!/usr/bin/env python3
"""web-vuln-scanner command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence
from urllib.parse import urlsplit, urlunsplit

from modules.dir_scan import DirScanner
from modules.port_scan import PortScanner
from modules.report import render_chinese_markdown
from modules.vuln_detect import VulnDetector

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_DIR_WORDLIST = PROJECT_ROOT / "wordlists" / "dirs.txt"
DEFAULT_PAYLOAD_FILE = PROJECT_ROOT / "wordlists" / "payloads.txt"
DEFAULT_REPORT = PROJECT_ROOT / "examples" / "output.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="授权场景使用的轻量级 Web 漏洞扫描器",
        epilog=(
            "示例: python scanner.py -u http://127.0.0.1:8000 "
            "--vuln-only"
        ),
    )
    parser.add_argument("-u", "--url", required=True, help="目标 HTTP(S) URL")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--port-only", action="store_true", help="仅执行端口扫描")
    modes.add_argument("--dir-only", action="store_true", help="仅执行目录扫描")
    modes.add_argument("--vuln-only", action="store_true", help="仅执行漏洞检测")
    parser.add_argument(
        "-o", "--output", default=str(DEFAULT_REPORT), help="JSON 报告输出路径"
    )
    parser.add_argument(
        "--report-format",
        choices=("json", "zh-md"),
        help="报告格式；默认根据输出扩展名判断，.md 为中文 Markdown",
    )
    parser.add_argument("--threads", type=int, default=10, help="并发线程数")
    parser.add_argument("--timeout", type=float, default=3.0, help="连接超时秒数")
    parser.add_argument(
        "--ports", default="1-1024", help="端口列表/范围，如 80,443,8000-8100"
    )
    parser.add_argument("--wordlist", help="目录扫描字典路径")
    parser.add_argument("--payloads", help="漏洞探针文件路径")
    parser.add_argument(
        "--insecure", action="store_true", help="关闭 HTTPS 证书校验（不推荐）"
    )
    parser.add_argument(
        "--cookie",
        help="登录会话 Cookie，如 PHPSESSID=abc; security=low",
    )
    parser.add_argument(
        "--user-agent",
        default="web-vuln-scanner/1.0 (+authorized-security-testing)",
        help="自定义 User-Agent",
    )
    return parser


def parse_ports(spec: str) -> List[int]:
    if not spec or not spec.strip():
        raise ValueError("端口范围不能为空")
    ports = set()
    try:
        for token in spec.split(","):
            token = token.strip()
            if not token:
                raise ValueError
            if "-" in token:
                start_text, end_text = token.split("-", 1)
                start, end = int(start_text), int(end_text)
                if start > end:
                    raise ValueError
                ports.update(range(start, end + 1))
            else:
                ports.add(int(token))
    except (TypeError, ValueError) as exc:
        raise ValueError("端口格式无效: {0}".format(spec)) from exc
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("端口必须位于 1 到 65535")
    return sorted(ports)


def normalize_url(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    parsed = urlsplit(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("目标必须是有效的 HTTP 或 HTTPS URL")
    return urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path or "", parsed.query, "")
    )


def run_scan(args: argparse.Namespace) -> Dict[str, object]:
    target = normalize_url(args.url)
    if args.threads < 1:
        raise ValueError("线程数必须大于 0")
    if args.timeout <= 0:
        raise ValueError("超时时间必须大于 0")

    result: Dict[str, object] = {
        "target": target,
        "scan_time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "ports": [],
        "directories": [],
        "vulnerabilities": [],
    }
    errors: List[str] = []
    result["errors"] = errors

    if not args.dir_only and not args.vuln_only:
        try:
            ports = parse_ports(args.ports)
            result["ports"] = PortScanner(
                target, threads=args.threads, timeout=args.timeout
            ).scan(ports)
        except (OSError, ValueError) as exc:
            errors.append("端口扫描: {0}".format(exc))

    if not args.port_only and not args.vuln_only:
        wordlist = Path(args.wordlist) if args.wordlist else DEFAULT_DIR_WORDLIST
        try:
            result["directories"] = DirScanner(
                target,
                threads=args.threads,
                timeout=args.timeout,
                verify_tls=not args.insecure,
            ).scan(wordlist)
        except (OSError, ValueError) as exc:
            errors.append("目录扫描: {0}".format(exc))

    if not args.port_only and not args.dir_only:
        payloads = Path(args.payloads) if args.payloads else DEFAULT_PAYLOAD_FILE
        try:
            detector = VulnDetector(
                target,
                threads=args.threads,
                timeout=args.timeout,
                verify_tls=not args.insecure,
                cookie=args.cookie or "",
                user_agent=args.user_agent,
            )
            result["vulnerabilities"] = detector.scan(payloads)
            if getattr(detector, "failed_requests", 0):
                errors.append(
                    "漏洞检测: {0}/{1} 请求失败，疑似目标过载或会话失效；"
                    "可尝试 --threads 1".format(
                        detector.failed_requests, detector.total_requests
                    )
                )
        except (OSError, ValueError) as exc:
            errors.append("漏洞检测: {0}".format(exc))

    output = Path(args.output).expanduser()
    output.parent.mkdir(parents=True, exist_ok=True)
    report_format = getattr(args, "report_format", None)
    if report_format is None:
        is_markdown = output.suffix.lower() in {".md", ".markdown"}
        report_format = "zh-md" if is_markdown else "json"
    if report_format == "zh-md":
        content = render_chinese_markdown(result)
    else:
        content = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    output.write_text(content, encoding="utf-8")
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        result = run_scan(args)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
        return 2

    print("[+] 目标: {0}".format(result["target"]))
    print("[+] 开放端口: {0}".format(len(result["ports"])))
    print("[+] 目录发现: {0}".format(len(result["directories"])))
    print("[+] 漏洞发现: {0}".format(len(result["vulnerabilities"])))
    if result["errors"]:
        for error in result["errors"]:
            print("[!] {0}".format(error), file=sys.stderr)
    print("[+] 报告: {0}".format(Path(args.output).expanduser().resolve()))
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    sys.exit(main())
