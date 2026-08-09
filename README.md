# Web-Vuln-Scanner 🔍

一个面向学习和 GitHub 项目展示的 Python 3 命令行 Web 漏洞扫描器。它实现了 TCP 端口探测、Web 目录发现，以及针对现有 GET 参数的反射型 XSS / 错误型 SQL 注入差分检测，并输出结构化 JSON 证据。

> **仅限本人资产、靶场或已获得明确授权的目标。** 使用者应自行确认测试范围、速率和适用法律。

## 功能

- **多线程 TCP 端口扫描**：支持单端口、逗号列表和范围。
- **目录扫描**：识别 2xx、重定向、401/403，并通过随机不存在路径基线过滤软 404。
- **六类漏洞检测**：反射型 XSS、错误型 SQL 注入、命令注入（错误/命令输出特征）、路径穿越（文件内容特征）、SSTI（求值回显）、开放重定向（Location 证据）。
- **输入点自动发现**：入口页同源链接递归爬取（最多 60 页）、GET/POST 表单参数、JavaScript 文件中提取的 API 端点（`fetch`/`$.get`/`/api/` 路径）。
- **JSON 报告/md 报告**：保存目标、UTC 扫描时间、开放端口、目录详情、漏洞结构化证据、可复现 raw HTTP 请求/响应和模块错误。
- **安全默认值**：不跟随重定向、不修改数据、不执行外联 payload，TLS 默认校验。

## 环境

- Python 3.8+
- requests
- beautifulsoup4
- pytest（开发测试）

`argparse` 是 Python 标准库，不需要单独安装。

## 安装

```bash
git clone https://github.com/Judy-0206/web-vuln-scanner.git
cd web-vuln-scanner
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

开发环境：

```bash
python -m pip install -r requirements-dev.txt
pytest -q
```

## 使用

### 全扫描

```bash
python scanner.py -u 'http://127.0.0.1:8000/search?q=test'
```

### 只扫描端口

```bash
python scanner.py -u http://127.0.0.1 --port-only --ports 22,80,443,8000-8100
```

### 只扫描目录

```bash
python scanner.py -u http://127.0.0.1:8000 --dir-only \
  --wordlist wordlists/dirs.txt --threads 20
```

### 只检测漏洞

```bash
python scanner.py -u 'http://127.0.0.1:8000/search?q=test' \
  --vuln-only --payloads wordlists/payloads.txt \
  -o reports/vulnerabilities.json
```

### 输出中文版报告

输出文件使用 `.md` 扩展名时，会自动生成中文 Markdown 报告：

```bash
python scanner.py -u 'http://127.0.0.1:8000/search?q=test' \
  -o reports/中文扫描报告.md
```

也可以通过参数强制指定格式：

```bash
python scanner.py -u http://127.0.0.1:8000/ \
  --report-format zh-md -o reports/report.txt
```

中文版报告包含扫描摘要、开放端口、目录、按发现逐条列出的中文漏洞名和严重性，以及可复现的 raw HTTP 请求/响应。JSON 格式仍保持兼容。

首页没有查询参数时，漏洞模块会解析入口页中的同源链接（最多 100 个），提取各页面的 GET/POST 表单并检测命名参数。它不会跨域爬取，也不会提交上传字段。

### 自签名 HTTPS

```bash
python scanner.py -u 'https://127.0.0.1:8443/?q=test' --vuln-only --insecure
```

仅在已确认目标使用自签名证书时使用 `--insecure`。

### 扫描需要登录的目标（DVWA 等）

DVWA 未登录时所有页面都重定向到 login.php，扫描前需要先登录并把会话 Cookie 传给扫描器。仓库提供了 DVWA 登录辅助脚本（自动处理 user_token 并降到 low 安全级别）：

```bash
python examples/dvwa_login.py http://192.168.157.140:8888/dvwa/ admin 123456
# 输出: PHPSESSID=xxx; security=low
```

`dvwa_login.py` 的第四个参数用于选择安全等级：`low` / `medium` / `high` / `impossible` / `keep`（默认 `keep`，保持 DVWA 当前设置不变）。例如以 medium 等级扫描：

```bash
python examples/dvwa_login.py http://192.168.157.140:8888/dvwa/ admin 123456 medium
# 输出: PHPSESSID=xxx; security=medium

python scanner.py -u http://192.168.157.140:8888/dvwa/ --vuln-only \
  --cookie 'PHPSESSID=xxx; security=low' \
  --user-agent 'web-vuln-scanner-login-helper' \
  --threads 1 \
  -o reports/dvwa.md
```

注意：

- `--user-agent` 必须与登录时使用的保持一致，否则部分应用会判定会话失效。
- 会话型 PHP 应用（DVWA、Pikachu 等）建议 `--threads 1`：此类应用会串行加锁处理同一会话的并发请求，并发过高会导致大量请求超时并静默漏报；扫描器发现大量请求失败时也会在报告中提示。
- 扫描器会自动跳过 `login.php`、`logout.php`、`setup.php`、`security.php` 等会话/配置类页面，避免扫描过程中把自己登出或修改目标配置。

## CLI 参数

| 参数 | 作用 |
|---|---|
| `-u, --url` | 必填，目标 HTTP(S) URL |
| `--port-only` | 仅端口扫描 |
| `--dir-only` | 仅目录扫描 |
| `--vuln-only` | 仅漏洞检测 |
| `--ports` | 端口规格，默认 `1-1024` |
| `--wordlist` | 自定义目录字典 |
| `--payloads` | 自定义漏洞探针文件 |
| `--threads` | 并发数，默认 20 |
| `--timeout` | 单请求/连接超时秒数，默认 3 |
| `--insecure` | 关闭 TLS 证书校验 |
| `--cookie` | 登录会话 Cookie，如 `PHPSESSID=abc; security=low` |
| `--user-agent` | 自定义 User-Agent，登录态目标需与登录时一致 |
| `-o, --output` | 报告输出路径；`.md` 自动生成中文版 Markdown |
| `--report-format` | 强制指定 `json` 或 `zh-md` |

三个 `--*-only` 参数互斥。没有指定时执行全部模块。

## Payload 文件格式

每行使用 `TYPE|PAYLOAD`，支持 `XSS`、`SQLI`、`CMDI`、`TRAVERSAL`、`SSTI`、`REDIRECT`；空行和 `#` 注释会被忽略。

```text
XSS|<wvs-xss-probe>
SQLI|'
CMDI|wvscmdi;id
TRAVERSAL|../../../../../../etc/passwd
SSTI|{{7*7}}
REDIRECT|//evil.invalid/x
```

## 报告结构

```json
{
  "target": "http://127.0.0.1:8000/search?q=test",
  "scan_time": "2026-08-08T12:34:56+00:00",
  "ports": [8000],
  "directories": [],
  "vulnerabilities": [
    {
      "type": "Reflected XSS",
      "severity": "medium",
      "parameter": "q",
      "payload": "<wvs-xss-probe>",
      "raw_request": "GET /search?q=%3Cwvs-xss-probe%3E HTTP/1.1\r\nHost: 127.0.0.1:8000\r\nUser-Agent: web-vuln-scanner/1.0 (+authorized-security-testing)\r\nAccept: */*\r\nConnection: close\r\n\r\n",
      "raw_response": "HTTP/1.1 200 OK\r\nContent-Length: 31\r\n\r\nresult=<wvs-xss-probe>",
      "request": {
        "method": "GET",
        "url": "http://127.0.0.1:8000/search?q=%3Cwvs-xss-probe%3E",
        "headers": {
          "User-Agent": "web-vuln-scanner/1.0 (+authorized-security-testing)"
        }
      },
      "response": {
        "status": 200,
        "length": 31,
        "evidence": "<wvs-xss-probe>"
      }
    }
  ],
  "errors": []
}
```

报告保存失败属于 CLI 致命错误；单个扫描模块失败会写入 `errors`，同时保留其他模块结果。

## 项目结构

```text
web-vuln-scanner/
├── scanner.py
├── modules/
│   ├── port_scan.py
│   ├── dir_scan.py
│   ├── vuln_detect.py
│   └── report.py
├── wordlists/
│   ├── ports.txt
│   ├── dirs.txt
│   └── payloads.txt
├── examples/output.json
├── tests/
├── requirements.txt
├── requirements-dev.txt
└── LICENSE
```

## 检测边界

这个 MVP 不声称替代专业扫描器：

- XSS 结果证明的是**危险字符原样反射**，不是浏览器上下文中的完整可执行性证明。
- SQL 注入仅覆盖错误回显型特征，不覆盖布尔盲注、时间盲注和二阶注入。
- 命令注入/路径穿越/SSTI 均为**特征证据型**检测（命令错误、文件内容、求值结果），无回显的盲注型场景不覆盖。
- 漏洞检测覆盖 GET 参数及无需认证的 GET/POST 表单，不处理登录流程、不上传文件、不进行破坏性利用。
- 目录结果代表可达状态，不等同于漏洞。

## 测试

测试使用本机临时 HTTP/TCP 服务，不依赖公网：

```bash
pytest -q
python -m compileall -q scanner.py modules tests
```

也可以启动仓库自带的本地演示靶场，完整验证端口、目录与漏洞模块：

```bash
python examples/demo_server.py --port 8000
# 另开终端
python scanner.py -u http://127.0.0.1:8000/ --ports 8000 \
  -o examples/demo-output.json
```

## 许可证

MIT，见 [LICENSE](LICENSE)。