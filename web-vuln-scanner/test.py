#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Professional Web Vuln Scanner (Terminal-first)
- Safer SSTI (baseline + multi-payload confirm)
- Smarter SQLi heuristic (errors + diff)
- Reflected XSS probe
- LFI traversal checks
- CORS misconfig detection
- TRACE method test
- Exposure quick checks: .env, .git, phpinfo.php
- Auto HTTP/HTTPS selection, color output, Markdown report
NOTE: Use only on systems you own or have explicit permission to test.
"""

import argparse
import http.client
import re
import sys
import textwrap
from urllib.parse import urlparse

import requests
import urllib3
from colorama import Fore, Style, init

# ---------- Setup ----------
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

R = Fore.RED
G = Fore.GREEN
Y = Fore.YELLOW
C = Fore.CYAN
B = Fore.BLUE
N = Style.RESET_ALL

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) VulnScanner/1.0"

COMMON_PARAMS = ["id", "q", "s", "search", "name", "input", "user", "message", "page", "path", "file", "template"]

SQLI_ERROR_RE = re.compile(
    r"(sql syntax|mysql|sqlstate|odbc|unterminated|ORA-\d+|PG::|psql:|sqlite|MySQL server|ODBC Driver|JDBC)",
    re.I,
)

PASSWD_RE = re.compile(r"root:.*:0:0:", re.I)

def banner():
    print(f"""{B}
╔══════════════════════════════════════════════════════╗
║           Professional Web Vuln Scanner              ║
╠══════════════════════════════════════════════════════╣
║  For authorized security testing only.               ║
╚══════════════════════════════════════════════════════╝
{N}""")

def format_line(tag, status, detail=""):
    if status == "FOUND" or status == "CONFIRMED":
        color = R
        symbol = "✗"
    elif status == "POSSIBLE":
        color = Y
        symbol = "!"
    elif status == "ERROR":
        color = Y
        symbol = "!"
    else:
        color = G
        symbol = "✓"
    out = f"{color}[{symbol}] {tag}: {status}{N}"
    if detail:
        out += f"\n    {detail.strip()}"
    return out

# ---------- HTTP helpers ----------
def try_both_protocols(host_or_url, timeout):
    """Accepts domain/IP or full URL. Returns working base URL or None."""
    candidate = host_or_url.strip()
    if candidate.startswith("http://") or candidate.startswith("https://"):
        try:
            requests.get(candidate, timeout=timeout, verify=False, headers={"User-Agent": UA}, allow_redirects=True)
            return candidate.rstrip("/")
        except Exception:
            return None
    for scheme in ("https://", "http://"):
        url = (scheme + candidate).rstrip("/")
        try:
            requests.get(url, timeout=timeout, verify=False, headers={"User-Agent": UA}, allow_redirects=True)
            return url
        except Exception:
            continue
    return None

def fetch(url, method="GET", params=None, data=None, headers=None, timeout=8):
    H = {"User-Agent": UA}
    if headers:
        H.update(headers)
    try:
        if method.upper() == "POST":
            # Prefer JSON when dict provided
            if isinstance(data, dict):
                return requests.post(url, json=data, headers=H, timeout=timeout, verify=False, allow_redirects=True)
            return requests.post(url, data=data, headers=H, timeout=timeout, verify=False, allow_redirects=True)
        return requests.get(url, params=params, headers=H, timeout=timeout, verify=False, allow_redirects=True)
    except requests.exceptions.RequestException:
        return None

def take_snippet(text, needle, span=120):
    try:
        i = text.lower().find(needle.lower())
        if i == -1:
            return text[:min(len(text), span)]
        start = max(0, i - 60)
        end = min(len(text), i + len(needle) + 60)
        return text[start:end].replace("\n", " ")
    except Exception:
        return text[:min(len(text or ""), span)]

# ---------- Checks ----------
def check_sql_injection(base_url, timeout):
    """Heuristic: baseline diff + error patterns across common param names and payloads."""
    payloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "1'--", "1') or ('1'='1"]
    evidences = []
    for p in COMMON_PARAMS:
        # Baseline with sane value
        r0 = fetch(base_url, params={p: "1"}, timeout=timeout)
        if not r0 or r0.status_code >= 500:
            continue
        base_len = len(r0.text)

        for inj in payloads:
            r = fetch(base_url, params={p: inj}, timeout=timeout)
            if not r:
                continue
            t = r.text or ""
            if SQLI_ERROR_RE.search(t):
                evidences.append((p, inj, "DB error", take_snippet(t, "sql")))
                continue
            # Significant DOM/body length change can be a weak signal
            if base_len and abs(len(t) - base_len) / max(base_len, 1) > 0.30:
                evidences.append((p, inj, "response length diff >30%", ""))
    if evidences:
        details = "\n    ".join(
            f"param={p} | payload={inj} | evidence={ev} | snippet={snip}".strip()
            for (p, inj, ev, snip) in evidences[:5]
        )
        # We keep this as POSSIBLE unless a clear DB error is seen
        level = "POSSIBLE"
        if any(ev[2] == "DB error" for ev in evidences):
            level = "POSSIBLE"  # still refrain from CONFIRMED without data exfil
        return format_line("SQL Injection", level, details)
    return format_line("SQL Injection", "NOT FOUND")

def check_ssti(base_url, timeout):
    """Baseline + multi payload confirm across common param names."""
    tests = {"{{7*7}}": "49", "{{9*9}}": "81"}
    for p in COMMON_PARAMS:
        base = fetch(base_url, params={p: "test"}, timeout=timeout)
        if not base:
            continue
        base_text = base.text or ""
        confirmed = []
        reflected = []
        for payload, expect in tests.items():
            r = fetch(base_url, params={p: payload}, timeout=timeout)
            if not r:
                continue
            body = r.text or ""
            if expect in body and expect not in base_text:
                confirmed.append((p, payload, expect))
            elif payload in body and payload not in base_text:
                reflected.append((p, payload))
        if confirmed:
            details = "\n    ".join(f"param={pp} | payload={pl} → saw '{ex}'" for (pp, pl, ex) in confirmed)
            return format_line("SSTI (Server-Side Template Injection)", "CONFIRMED", details)
        if reflected:
            details = "\n    ".join(f"param={pp} | payload echoed={pl}" for (pp, pl) in reflected[:3])
            # Only POSSIBLE; needs manual confirm
            return format_line("SSTI (Server-Side Template Injection)", "POSSIBLE", details)
    return format_line("SSTI (Server-Side Template Injection)", "NOT FOUND")

def check_xss_reflected(base_url, timeout):
    """Simple reflected XSS probe (unencoded reflection)."""
    probes = [
        ('"><img src=x onerror=alert(1)>xss123', "xss123"),
        ("<script>alert(1)</script>", "<script>alert(1)</script>"),
    ]
    for p in COMMON_PARAMS:
        for payload, token in probes:
            r = fetch(base_url, params={p: payload}, timeout=timeout)
            if not r:
                continue
            body = r.text or ""
            # If token appears unencoded and surrounding tags are present, flag possible
            if token in body and ("<script" in body or "<img" in body):
                snippet = take_snippet(body, token)
                return format_line("Reflected XSS", "POSSIBLE", f"param={p} | token={token} | snippet={snippet}")
    return format_line("Reflected XSS", "NOT FOUND")

def check_lfi(base_url, timeout):
    paths = ["../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd"]
    for p in ["file", "path", "page", "template"]:
        for pl in paths:
            r = fetch(base_url, params={p: pl}, timeout=timeout)
            if not r:
                continue
            body = r.text or ""
            if PASSWD_RE.search(body):
                return format_line("LFI (Local File Inclusion)", "CONFIRMED", f"param={p} | payload={pl}")
    return format_line("LFI (Local File Inclusion)", "NOT FOUND")

def check_rfi(base_url, timeout):
    """Very weak heuristic: if remote content is included verbatim (e.g., Example Domain)."""
    ext_url = "http://example.com/"
    for p in ["file", "path", "page", "template", "url", "u"]:
        r = fetch(base_url, params={p: ext_url}, timeout=timeout)
        if not r:
            continue
        body = r.text or ""
        # 'Example Domain' is the title of example.com - indicates server fetched & included it
        if "Example Domain" in body:
            return format_line("RFI (Remote File Inclusion)", "POSSIBLE", f"param={p} | payload={ext_url}")
    return format_line("RFI (Remote File Inclusion)", "NOT FOUND")

def check_exposed_files(base_url, timeout):
    findings = []
    for path, tag, pattern in [
        ("/.env", ".env exposed", re.compile(r"(DB_PASSWORD|SECRET|AWS_|KEY|TOKEN)", re.I)),
        ("/.git/HEAD", ".git exposed", re.compile(r"refs/heads/", re.I)),
        ("/phpinfo.php", "phpinfo exposed", re.compile(r"phpinfo\(\)", re.I)),
    ]:
        r = fetch(base_url + path, timeout=timeout)
        if r and r.status_code == 200 and r.text:
            if pattern.search(r.text):
                findings.append((tag, "CONFIRMED", path))
            else:
                # For .git/HEAD, even 200 is strong signal
                if path == "/.git/HEAD":
                    findings.append((tag, "POSSIBLE", path))
    if findings:
        detail = "\n    ".join(f"{t} → {lvl} at {p}" for (t, lvl, p) in findings)
        status = "CONFIRMED" if any(lvl == "CONFIRMED" for _, lvl, _ in findings) else "POSSIBLE"
        return format_line("Sensitive Files Exposure", status, detail)
    return format_line("Sensitive Files Exposure", "NOT FOUND")

# ---- CORS & TRACE (integrated from your code, improved) ----
def check_cors(base_url, timeout):
    origins_to_test = [
        "https://evil.example",
        "null",
        "https://subdomain.example.com",
    ]
    try:
        for origin in origins_to_test:
            r = fetch(
                base_url,
                headers={"Origin": origin, "User-Agent": UA},
                timeout=timeout,
            )
            if not r:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin")
            acac = r.headers.get("Access-Control-Allow-Credentials", "")
            if acao:
                # Credentials + reflected origin (not *)
                if acao == origin and acac.lower() == "true":
                    return format_line("CORS Misconfiguration", "FOUND", f"(Origin echoed with credentials: {origin})")
                # Wildcard with credentials is blocked by browsers, but wildcard alone may still be risky for public APIs
                if acao in ("*", origin):
                    return format_line("CORS Misconfiguration", "POSSIBLE", f"(ACAO={acao}, Origin={origin}, Creds={acac})")
        return format_line("CORS Misconfiguration", "NOT FOUND")
    except Exception as e:
        return format_line("CORS Check", "ERROR", str(e))

def check_trace(base_url, timeout):
    try:
        pu = urlparse(base_url)
        host = pu.netloc
        port = pu.port or (443 if pu.scheme == "https" else 80)
        conn_cls = http.client.HTTPSConnection if pu.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(host, port, timeout=timeout)
        conn.request("TRACE", "/", headers={"User-Agent": UA})
        res = conn.getresponse()
        body = res.read() or b""
        if res.status == 200 and b"TRACE" in body.upper():
            return format_line("TRACE Method Enabled", "FOUND")
        return format_line("TRACE Method Enabled", "NOT FOUND")
    except Exception as e:
        return format_line("TRACE Method Enabled", "ERROR", str(e))

# ---------- Runner & Report ----------
def run_all(base_url, timeout):
    results = []

    results.append(check_sql_injection(base_url, timeout))
    results.append(check_ssti(base_url, timeout))
    results.append(check_xss_reflected(base_url, timeout))
    results.append(check_lfi(base_url, timeout))
    results.append(check_rfi(base_url, timeout))
    results.append(check_exposed_files(base_url, timeout))
    results.append(check_cors(base_url, timeout))
    results.append(check_trace(base_url, timeout))

    return results

def write_report(path, target, results):
    md = []
    md.append(f"# Scan Report\n")
    md.append(f"**Target:** `{target}`  ")
    md.append("")
    for line in results:
        # Convert colored terminal line to plain markdown with sections
        # Extract tag, status, and detail
        plain = re.sub(r"\x1b\[[0-9;]*m", "", line)  # strip ANSI
        # "[✓] Tag: STATUS\n    details"
        first, *rest = plain.split("\n", 1)
        md.append(f"## {first}")
        if rest:
            md.append("```")
            md.append(rest[0].replace("    ", ""))
            md.append("```")
        md.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(md))

def main():
    parser = argparse.ArgumentParser(
        description="Professional Web Vuln Scanner (authorized testing only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Examples:
              python3 pro_vuln_scanner.py target.com
              python3 pro_vuln_scanner.py https://target.com --timeout 12 --report report.md
        """),
    )
    parser.add_argument("target", help="Domain/IP or full URL (e.g., example.com or https://example.com)")
    parser.add_argument("--timeout", type=int, default=8, help="Request timeout (seconds)")
    parser.add_argument("--report", default="report.md", help="Markdown report output path")
    args = parser.parse_args()

    banner()

    base_url = try_both_protocols(args.target, args.timeout)
    if not base_url:
        print(f"{R}[✗] Could not connect over HTTP or HTTPS: {args.target}{N}")
        sys.exit(2)

    print(f"{C}[+] Scanning: {base_url} (timeout={args.timeout}s){N}\n")

    results = run_all(base_url, args.timeout)
    for line in results:
        print(line)

    write_report(args.report, base_url, results)
    print(f"\n{C}[✔] Report saved to {args.report}{N}")

if __name__ == "__main__":
    main()
