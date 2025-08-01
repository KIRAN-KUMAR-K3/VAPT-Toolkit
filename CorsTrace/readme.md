<h1 align="center">🛡️ CorsTrace</h1>
<p align="center">
  <b>An Automated CORS and HTTP TRACE Vulnerability Scanner</b><br>
  <i>Part of the <a href="https://github.com/KIRAN-KUMAR-K3/VAPT-Toolkit">VAPT-Toolkit</a> by Kiran Kumar K</i>
</p>

---

## ⚙️ What is CorsTrace?

**CorsTrace** is a simple and effective VAPT automation tool that checks:
- 🔍 CORS Misconfigurations
- 🔍 TRACE Method Vulnerability

Just paste a domain or IP address, and it automatically detects HTTP/HTTPS, fetches headers, and reports vulnerabilities.

---

## 🚀 Features

✅ Detects CORS misconfigurations using multiple origin tests  
✅ Detects if HTTP TRACE method is enabled  
✅ Supports both HTTP and HTTPS  
✅ Ignores SSL certificate issues (for self-signed certs)  
✅ Saves results to `report.txt`  
✅ Works on both domains and IP addresses  
✅ Color-coded terminal output  

---

## 🛠️ Installation

1. **Clone the Repository**
```bash
git clone https://github.com/KIRAN-KUMAR-K3/VAPT-Toolkit.git
cd VAPT-Toolkit/CorsTrace
````

2. **Install Requirements**

```bash
pip install -r requirements.txt
```

---

## ▶️ Usage

```bash
python3 main.py
```

Enter domain or IP (with or without protocol):

```
example.com
10.0.84.4
https://vulnerable.site
```

Example Output:

```
[INFO] Scanning https://target-site.com...

[✗] CORS Misconfiguration: FOUND (Origin: https://evil.com)
[✓] TRACE Method: NOT FOUND

[✔] Report saved to report.txt
```

---

## 📂 Output

All results are also saved to:

```
report.txt
```

---

## 📸 Optional Screenshot (Add if available)

![CorsTrace Demo](screenshot.png)

> To add: Take a screenshot of your terminal and name it `screenshot.png`, place it in the same folder.

---

## 👨‍💻 Author

**Kiran Kumar K**
GitHub: [@KIRAN-KUMAR-K3](https://github.com/KIRAN-KUMAR-K3)
LinkedIn: [linkedin.com/in/kiran-kumar-k3](https://linkedin.com/in/kiran-kumar-k3)

---

## ⭐ Star This Repo

If you found this tool helpful, please ⭐ star the repo to support development!
