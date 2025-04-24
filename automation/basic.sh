#!/bin/bash

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
   echo "❌ This script must be run as root!" 
   exit 1
fi

# Ask for target IP or domain
read -p "Enter target IP or domain: " TARGET
read -p "Enter directory name for results: " REPORT_DIR

# Create directory
mkdir -p "$REPORT_DIR" && cd "$REPORT_DIR"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")

echo "[*] Starting scan on $TARGET"
echo "[*] Results will be saved in $(pwd)"

# 1. Nmap Scan (Top 1000 ports for speed)
echo "[*] Running Nmap scan (Top 1000 ports)..."
nmap -sS -sV -O --script=default,vuln -T4 "$TARGET" -oN nmap_scan.txt

# 2. Nikto Scan
echo "[*] Running Nikto scan..."
if command -v nikto &> /dev/null; then
    nikto -h "https://$TARGET" -Tuning x -ssl -C all -o nikto_scan.txt
else
    echo "❌ Nikto not installed. Skipping."
fi

# 3. Nuclei Scan
echo "[*] Running Nuclei scan..."
if command -v nuclei &> /dev/null; then
    nuclei -u "https://$TARGET" -o nuclei_scan.txt
else
    echo "❌ Nuclei not installed. Skipping."
fi

# 4. Generate Markdown Report
echo "[*] Creating markdown report..."
cat <<EOF > report.md
### 🔍 Penetration Testing Report
**Target:** $TARGET  
**Date:** $(date)

## ✅ Nmap Scan Results
$(grep "open" nmap_scan.txt)

## 🌐 Nikto Scan
$(grep "OSVDB" nikto_scan.txt 2>/dev/null)

## ⚠️ Nuclei Scan
$(cat nuclei_scan.txt 2>/dev/null)
EOF

# 5. Convert to PDF
if command -v pandoc &> /dev/null; then
    echo "[*] Generating PDF..."
    pandoc report.md -o report_$TIMESTAMP.pdf
else
    echo "❌ Pandoc not installed. Skipping PDF generation."
fi

echo "✅ Done! Check the results in: $(pwd)"
ls -lah
