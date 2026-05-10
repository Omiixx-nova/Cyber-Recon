# 🔍 CyberRecon Web Suite v4.0

> Bug Bounty & Cybersecurity Toolkit — Real Data, Real Results

Built by Omiixx | Parrot OS | Python + Flask + JavaScript

---

## 🚀 What is CyberRecon?

CyberRecon is a browser-based cybersecurity 
reconnaissance toolkit designed for:

🕵️ Ethical Hackers
🐛 Bug Bounty Hunters  
🔐 Cybersecurity Enthusiasts
🎓 Students learning Penetration Testing

It combines a Python Flask backend with a 
hacker-themed frontend to perform real 
reconnaissance tasks.

---

## ⚡ Features — 8 Real Tools

🔍 Subdomain Scanner
→ Finds real subdomains using DNS resolution
→ Shows IP of each subdomain found

🗂️ Directory Fuzzer  
→ Probes paths against target URL
→ Shows 200 OK / 403 Forbidden / 404

🛡️ Header Analyzer
→ Checks all HTTP security headers
→ Flags missing/critical headers
→ Gives security grade A/B/C/F

🌐 IP Lookup
→ Real location, ISP, timezone
→ Coordinates + Google Maps link
→ Works on any IP address

📋 WHOIS Lookup
→ Domain registrar info
→ Creation + expiry dates
→ Nameservers

🔒 SSL Certificate Checker
→ Valid/Expired status
→ Days remaining
→ Issuer + Cipher suite

🔌 Port Scanner
→ Checks open/closed ports
→ Shows service names (SSH, FTP, MySQL)
→ Quick scan preset available

🌍 DNS Lookup
→ A, AAAA, MX, CNAME, TXT, NS, SOA records
→ Complete DNS reconnaissance

🔐 Hash + URL Tools
→ SHA-1, SHA-256, SHA-384, SHA-512
→ URL Encode/Decode
→ Base64 Encode/Decode

---

## 🛠️ How to Run Locally

### Requirements:
- Python 3.x
- Parrot OS / Kali Linux / Any Linux
- Browser (Firefox recommended)

### Step 1 — Clone Repository:
git clone https://github.com/Omiixx-nova/cyberrecon-suite.git
cd cyberrecon-suite

### Step 2 — Create Virtual Environment:
python3 -m venv ~/cyberrecon-env
source ~/cyberrecon-env/bin/activate

### Step 3 — Install Dependencies:
pip install -r requirements.txt

### Step 4 — Start Backend:
python app.py

### Step 5 — Open Frontend:
Open index.html in your browser
Backend status will show ONLINE at top

---

## 📁 Project Structure

cyberrecon-suite/
├── index.html         → Frontend (browser UI)
├── app.py             → Flask backend (8 endpoints)
├── requirements.txt   → Python dependencies
└── README.md          → This file

---

## 🔌 API Endpoints

POST /api/subdomain-scan  → { "domain": "example.com" }
POST /api/dir-fuzz        → { "url": "...", "paths": [...] }
POST /api/headers         → { "url": "https://example.com" }
POST /api/ip-lookup       → { "ip": "8.8.8.8" }
POST /api/whois           → { "domain": "example.com" }
POST /api/ssl-check       → { "domain": "example.com" }
POST /api/port-scan       → { "host": "...", "ports": [...] }
POST /api/dns-lookup      → { "domain": "example.com" }

---

## ⚠️ Disclaimer

This tool is for EDUCATIONAL purposes only.
Only test on domains/IPs you OWN or have 
PERMISSION to test.
Unauthorized scanning is ILLEGAL.
The developer is not responsible for misuse.

---

## 👤 Author

Omiixx
GitHub  → https://github.com/Omiixx-nova
Focus   → Cybersecurity | Bug Bounty | Ethical Hacking
OS      → Parrot OS

---

## 📅 Version History

v1.0 → Basic demo tools
v2.0 → Matrix UI + Dark theme + Tabs
v3.0 → Hash generator + URL tools + IP lookup
v4.0 → Real Flask backend + 8 live endpoints

---

⭐ Star this repo if you found it useful!
