"""Chinese Markdown report rendering."""

from __future__ import annotations

from typing import Dict, List

VULNERABILITY_NAMES = {
    "Error-based SQL Injection": "错误型 SQL 注入",
    "Reflected XSS": "反射型跨站脚本（XSS）",
    "Command Injection": "命令注入",
    "Path Traversal": "路径穿越（任意文件读取）",
    "Server-Side Template Injection": "服务端模板注入（SSTI）",
    "Open Redirect": "开放重定向",
    "PHP Output Truncation (suspected injection)": "PHP 输出截断（疑似注入）",
}
SEVERITY_NAMES = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def render_chinese_markdown(result: Dict[str, object]) -> str:
    """Render scanner results as a Chinese Markdown report."""
    ports = _as_list(result.get("ports"))
    directories = _as_list(result.get("directories"))
    vulnerabilities = _as_list(result.get("vulnerabilities"))
    errors = _as_list(result.get("errors"))

    lines = [
        "# Web 漏洞扫描报告",
        "",
        "## 一、扫描摘要",
        "",
        "| 项目 | 结果 |",
        "|---|---|",
        "| 目标地址 | `{0}` |".format(_escape_table(result.get("target", ""))),
        "| 扫描时间（UTC） | `{0}` |".format(
            _escape_table(result.get("scan_time", ""))
        ),
        "| 开放端口 | {0} |".format(len(ports)),
        "| 发现目录 | {0} |".format(len(directories)),
        "| 漏洞发现 | {0} |".format(len(vulnerabilities)),
        "| 扫描错误 | {0} |".format(len(errors)),
        "",
        "## 二、资产与攻击面",
        "",
        "### 开放端口",
        "",
    ]
    if ports:
        lines.append(", ".join("`{0}`".format(port) for port in ports))
    else:
        lines.append("未发现开放端口，或本次未执行端口扫描。")

    lines.extend(["", "### Web 目录", ""])
    if directories:
        lines.extend(
            [
                "| 路径 | 状态码 | 响应长度 | 重定向 |",
                "|---|---:|---:|---|",
            ]
        )
        for item in directories:
            if not isinstance(item, dict):
                continue
            redirect = item.get("redirect") or "-"
            lines.append(
                "| `{0}` | {1} | {2} | `{3}` |".format(
                    _escape_table(item.get("path", item.get("url", ""))),
                    item.get("status", "-"),
                    item.get("length", "-"),
                    _escape_table(redirect),
                )
            )
    else:
        lines.append("未发现目录，或本次未执行目录扫描。")

    lines.extend(["", "## 三、漏洞发现", ""])
    if vulnerabilities:
        for index, item in enumerate(vulnerabilities, start=1):
            if isinstance(item, dict):
                lines.extend(_render_vulnerability(index, item))
    else:
        lines.append("本次扫描未产生已确认的漏洞检测结果。")

    lines.extend(["", "## 四、扫描异常", ""])
    if errors:
        lines.extend("- {0}".format(error) for error in errors)
    else:
        lines.append("无。")

    lines.extend(
        [
            "",
            "## 五、检测边界",
            "",
            "- 本报告只记录扫描器实际收到的响应，不代表目标不存在其他漏洞。",
            "- XSS 检测结果表示探针未经 HTML 编码即被反射；"
            "是否可执行仍取决于浏览器上下文。",
            "- SQL 注入检测仅覆盖注入后新增数据库错误特征的场景。",
            "- 仅可对本人资产、合法靶场或已明确授权的目标使用。",
            "",
        ]
    )
    return "\n".join(lines)


def _render_vulnerability(index: int, item: Dict[str, object]) -> List[str]:
    vuln_type = str(item.get("type", "未知漏洞"))
    name = VULNERABILITY_NAMES.get(vuln_type, vuln_type)
    severity = SEVERITY_NAMES.get(
        str(item.get("severity", "info")).lower(),
        str(item.get("severity", "未知")),
    )
    lines = [
        "### {0}. {1}".format(index, name),
        "",
        "- 严重性：**{0}**".format(severity),
        "- 请求方法：`{0}`".format(item.get("method", "GET")),
        "- 漏洞地址：`{0}`".format(item.get("url", "")),
        "- 影响参数：`{0}`".format(item.get("parameter", "-")),
        "- 使用载荷：`{0}`".format(_escape_inline_code(item.get("payload", ""))),
        "- 响应证据：`{0}`".format(_escape_inline_code(item.get("evidence", ""))),
        "",
        "### 原始 HTTP 请求",
        "",
        "```http",
        str(item.get("raw_request", "未记录")).rstrip(),
        "```",
        "",
        "### 原始 HTTP 响应",
        "",
        "```http",
        str(item.get("raw_response", "未记录")).rstrip(),
        "```",
        "",
    ]
    return lines


def _as_list(value: object) -> List[object]:
    return value if isinstance(value, list) else []


def _escape_table(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _escape_inline_code(value: object) -> str:
    return str(value).replace("`", "\\`").replace("\r", "").replace("\n", " ")
