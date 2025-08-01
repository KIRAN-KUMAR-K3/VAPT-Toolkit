import requests
import http.client
from urllib.parse import urlparse
from colorama import Fore, Style, init
import urllib3

# Disable SSL warnings for self-signed certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

def format_result(tag, status, detail=""):
    if status == "FOUND":
        return f"{Fore.RED}[✗] {tag}: {status}{Style.RESET_ALL} {detail}"
    elif status == "NOT FOUND":
        return f"{Fore.GREEN}[✓] {tag}: {status}{Style.RESET_ALL}"
    else:
        return f"{Fore.YELLOW}[!] {tag}: {status}{Style.RESET_ALL} {detail}"

def normalize_url(user_input):
    if not user_input.startswith("http"):
        return f"http://{user_input.strip()}"
    return user_input.strip()

def check_cors(target_url):
    origins_to_test = [
        "https://evil.com",
        "null",
        "https://subdomain.example.com"
    ]
    try:
        for origin in origins_to_test:
            headers = {
                "Origin": origin,
                "User-Agent": "Mozilla/5.0"
            }
            resp = requests.get(
                target_url,
                headers=headers,
                timeout=5,
                allow_redirects=True,
                verify=False  # Ignore SSL cert errors
            )
            acao = resp.headers.get("Access-Control-Allow-Origin")
            acac = resp.headers.get("Access-Control-Allow-Credentials")

            if acao and (acao == "*" or acao == origin):
                if acac and acac.lower() == "true" and acao != "*":
                    return format_result("CORS Misconfiguration", "FOUND", f"(Origin: {origin}, Credentials: True)")
                else:
                    return format_result("CORS Misconfiguration", "FOUND", f"(Origin: {origin})")
        return format_result("CORS Misconfiguration", "NOT FOUND")
    except Exception as e:
        return format_result("CORS Check", "ERROR", str(e))

def check_trace(target_url):
    try:
        parsed_url = urlparse(target_url)
        host = parsed_url.netloc
        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

        conn_class = http.client.HTTPSConnection if parsed_url.scheme == "https" else http.client.HTTPConnection
        conn = conn_class(host, port, timeout=5)
        conn.request("TRACE", "/", headers={"User-Agent": "Mozilla/5.0"})
        res = conn.getresponse()
        body = res.read()

        if res.status == 200 and b"TRACE" in body:
            return format_result("TRACE Method", "FOUND")
        else:
            return format_result("TRACE Method", "NOT FOUND")
    except Exception as e:
        return format_result("TRACE Method", "ERROR", str(e))

def try_both_protocols(domain_or_ip):
    urls = [f"http://{domain_or_ip}", f"https://{domain_or_ip}"]
    for url in urls:
        try:
            requests.get(url, timeout=3, verify=False)
            return url  # return working URL
        except:
            continue
    return None

def main():
    print(f"{Fore.CYAN}--- VAPT CORS & TRACE SCANNER ---{Style.RESET_ALL}")
    user_input = input("Enter Website URL or IP (e.g., 10.0.84.4 or example.com): ").strip()
    
    # Determine working scheme
    normalized_input = user_input.replace("http://", "").replace("https://", "").strip("/")
    working_url = try_both_protocols(normalized_input)

    if not working_url:
        print(f"{Fore.RED}[✗] Could not connect to {user_input} using HTTP or HTTPS.{Style.RESET_ALL}")
        return

    print(f"\n[INFO] Scanning {working_url}...\n")
    cors_result = check_cors(working_url)
    trace_result = check_trace(working_url)

    print(cors_result)
    print(trace_result)

    # Save report
    with open("report.txt", "w") as f:
        f.write(f"Scan Result for: {working_url}\n")
        f.write(cors_result + "\n")
        f.write(trace_result + "\n")

    print(f"\n{Fore.CYAN}[✔] Report saved to report.txt{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
