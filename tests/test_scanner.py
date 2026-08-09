"""CLI and report behavior tests."""

import json
from argparse import Namespace
from pathlib import Path

import pytest

import scanner


def make_args(tmp_path, **overrides):
    values = {
        "url": "example.test",
        "port_only": False,
        "dir_only": False,
        "vuln_only": False,
        "output": str(tmp_path / "nested" / "report.json"),
        "threads": 4,
        "timeout": 1.0,
        "ports": "80,443,8000-8001",
        "wordlist": None,
        "payloads": None,
        "insecure": False,
        "cookie": None,
        "user_agent": "web-vuln-scanner/1.0 (+authorized-security-testing)",
        "report_format": None,
    }
    values.update(overrides)
    return Namespace(**values)


def test_parse_ports_supports_ranges_and_deduplicates():
    assert scanner.parse_ports("443,80,8000-8002,443") == [80, 443, 8000, 8001, 8002]


@pytest.mark.parametrize("value", ["", "abc", "80-", "0", "65536", "90-80"])
def test_parse_ports_rejects_invalid_specs(value):
    with pytest.raises(ValueError):
        scanner.parse_ports(value)


def test_parser_rejects_multiple_only_modes():
    parser = scanner.build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args(["-u", "example.test", "--port-only", "--dir-only"])


def test_run_scan_uses_selected_mode_and_creates_report_parent(tmp_path, monkeypatch):
    calls = []

    class FakePortScanner:
        def __init__(self, url, threads, timeout):
            calls.append((url, threads, timeout))

        def scan(self, ports):
            calls.append(tuple(ports))
            return [80]

    monkeypatch.setattr(scanner, "PortScanner", FakePortScanner)
    args = make_args(tmp_path, port_only=True)

    result = scanner.run_scan(args)

    assert result["target"] == "http://example.test"
    assert result["ports"] == [80]
    assert result["directories"] == []
    assert result["vulnerabilities"] == []
    assert Path(args.output).is_file()
    saved = json.loads(Path(args.output).read_text(encoding="utf-8"))
    assert saved == result
    assert calls[-1] == (80, 443, 8000, 8001)


def test_wordlist_defaults_are_resolved_from_project_not_cwd(
    tmp_path, monkeypatch
):
    observed = {}

    class FakeDirScanner:
        def __init__(self, *_args, **_kwargs):
            pass

        def scan(self, wordlist):
            observed["wordlist"] = Path(wordlist)
            return []

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(scanner, "DirScanner", FakeDirScanner)
    args = make_args(tmp_path, dir_only=True)

    scanner.run_scan(args)

    assert observed["wordlist"] == scanner.PROJECT_ROOT / "wordlists" / "dirs.txt"


def test_run_scan_writes_chinese_markdown_report_by_extension(tmp_path, monkeypatch):
    class FakeVulnDetector:
        def __init__(self, *_args, **_kwargs):
            pass

        def scan(self, _payloads):
            return [
                {
                    "type": "Error-based SQL Injection",
                    "severity": "high",
                    "url": "http://example.test/search?id=%27",
                    "method": "GET",
                    "parameter": "id",
                    "payload": "'",
                    "evidence": "you have an error in your sql syntax",
                    "raw_request": (
                        "GET /search?id=%27 HTTP/1.1\r\n"
                        "Host: example.test\r\n\r\n"
                    ),
                    "raw_response": (
                        "HTTP/1.1 500 Internal Server Error\r\n\r\n"
                        "SQL syntax error"
                    ),
                }
            ]

    monkeypatch.setattr(scanner, "VulnDetector", FakeVulnDetector)
    output = tmp_path / "reports" / "中文扫描报告.md"
    args = make_args(tmp_path, vuln_only=True, output=str(output))

    scanner.run_scan(args)

    report = output.read_text(encoding="utf-8")
    assert "# Web 漏洞扫描报告" in report
    assert "## 一、扫描摘要" in report
    assert "错误型 SQL 注入" in report
    assert "严重性：**高危**" in report
    assert "### 原始 HTTP 请求" in report
    assert "GET /search?id=%27 HTTP/1.1" in report
    assert "### 原始 HTTP 响应" in report
    assert "SQL syntax error" in report


def test_report_format_can_force_chinese_markdown_for_non_md_path(
    tmp_path, monkeypatch
):
    class FakePortScanner:
        def __init__(self, *_args, **_kwargs):
            pass

        def scan(self, _ports):
            return [80]

    monkeypatch.setattr(scanner, "PortScanner", FakePortScanner)
    output = tmp_path / "report.txt"
    args = make_args(
        tmp_path,
        port_only=True,
        output=str(output),
        report_format="zh-md",
    )

    scanner.run_scan(args)

    assert output.read_text(encoding="utf-8").startswith("# Web 漏洞扫描报告")
