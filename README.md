# Kira Scan

Kira Scan is a Python-based OSINT and vulnerability scanner that leverages the Tor network for anonymous reconnaissance. It performs domain lookups, WHOIS queries, subdomain discovery, port scanning (via Nmap), tech fingerprinting, and CVE analysis through the NIST NVD API.

> ✨ Designed for privacy-focused security researchers and analysts.

---

## ⚙️ Features

- 🔍 Domain & Subdomain scanning
- 🌐 WHOIS & DNS resolution
- 💥 Port scanning (TCP connect scan)
- 📅 CVE detection via NIST API (CPE-matched when possible)
- 🛎️ Email scraping
- 🕵️ Tor-based anonymity
- ⌛ Async I/O + threading for performance
- ⚖️ CVE filter by minimum year (default: 2015)

---

## ⚡ Requirements

- Python 3.10+
- Tor (daemon running on localhost)
- Optional: `torsocks` for fallback IP resolution

Install dependencies:

```bash
pip install -r requirements.txt
```

**`requirements.txt`**:
```txt
aiohttp
requests
beautifulsoup4
python-whois
tqdm
python-nmap
dnspython
asyncio
stem
```

---

## ▶️ How to Run

```bash
python kira_scan.py
```

Choose one of the following:
```
1. Full Scan (Domain + Subdomains + Nmap + CVE + Tech)
2. Show IP (Tor + Real)
3. Exit
```

You will be prompted to:
- Enter a target domain
- Optionally set a minimum CVE year filter

---

## ⚠️ Known Limitations

- **Tor latency** can cause timeouts or incomplete data
- Some subdomain scans via `crt.sh` may fail under Tor routing
- Nmap TCP connect scans are slower than SYN scans (used for portability)
- NIST API rate limits apply (60 RPM with key, 10 RPM without)
- Fingerprinting is based on headers only (no JS execution)

> ⚡ **This is a work in progress**. Some instability is expected due to anonymous network routing and external API behavior.

---

## 🚫 Disclaimer

Kira Scan is for **educational and ethical research** only. Use responsibly and lawfully.

---

MIT License
Copyright (c) 2025
