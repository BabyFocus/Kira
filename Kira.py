# Kira Scan — Python OSINT & CVE Scanner via TOR
HEADER = r"""
 _  _____ ____      _
| |/ /_ _|  _ \    / \
| ' / | || |_) |  / _ \
| . \ | ||  _ <  / ___ \
|_|\_\___|_| \_\/_/   \_\
"""
import socket
import requests
import re
import time
import subprocess
import json
import os
import whois
import nmap
import asyncio
import aiohttp
import threading
import logging
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
from tqdm import tqdm
import shutil
import dns.resolver

class QuietFilter(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        return not msg.startswith("Error while closing connector") \
            and not msg.startswith("Error fetching JSON") \
            and not msg.startswith("ERROR:root")

logging.basicConfig(level=logging.ERROR)
logging.getLogger().addFilter(QuietFilter())

TOR_SOCKS_PROXY = "socks5h://127.0.0.1:9050"
HEADERS = {"User-Agent": "Mozilla/5.0"}
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_THREADS = 5
MIN_YEAR = 2015  # Default CVE filter year

def is_torsocks_available():
    return shutil.which("torsocks") is not None

def check_tor_ip():
    # Prefer torsocks curl for reliability
    if is_torsocks_available():
        try:
            result = subprocess.check_output(["torsocks", "curl", "-s", "https://check.torproject.org"], timeout=10).decode()
            m = re.search(r"Your IP address appears to be: ([\\d\\.]+)", result)
            if m:
                return m.group(1)
        except:
            pass
    try:
        r = requests.get("https://check.torproject.org", proxies={"http": TOR_SOCKS_PROXY, "https": TOR_SOCKS_PROXY}, timeout=10)
        m = re.search(r"Your IP address appears to be: ([\\d\\.]+)", r.text)
        if m:
            return m.group(1)
    except:
        pass
    return None

async def fetch_json(session, url, params=None):
    try:
        async with session.get(url, params=params, timeout=10) as response:
            return await response.json()
    except Exception as e:
        return {}

async def query_cves_async(service, cpe=None, min_year=2015):
    async with aiohttp.ClientSession() as session:
        try:
            params = {"keywordSearch": cpe or service, "resultsPerPage": 10}
            data = await fetch_json(session, NVD_API_BASE, params)
            results = []
            for cve in data.get('vulnerabilities', []):
                year = int(cve['cve']['id'].split("-")[1])
                if year >= min_year:
                    desc = cve['cve']['descriptions'][0]['value'][:80]
                    results.append(f"{cve['cve']['id']}: {desc}...")
            return results or [f"ℹ️ No relevant CVEs found for {cpe or service}"]
        except Exception:
            return ["❌ CVE lookup failed"]

def get_ip(domain):
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 4
        answer = resolver.resolve(domain, 'A')
        return answer[0].to_text()
    except:
        try:
            return socket.gethostbyname(domain)
        except:
            return None

def whois_lookup(domain):
    print("***** WHOIS Start *****")
    try:
        info = whois.whois(domain)
        lines = str(info).splitlines()
        filtered = [line for line in lines if not line.strip().startswith("%") and line.strip()]
        return "\n".join(filtered)
    except Exception as e:
        return f"❌ WHOIS lookup failed: {e}"

async def fingerprint_async(domain):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"http://{domain}", headers=HEADERS, timeout=10) as r:
                text = await r.text()
                soup = BeautifulSoup(text, "html.parser")
                server = r.headers.get("Server", "N/A")
                powered = r.headers.get("X-Powered-By", "N/A")
                return r.status, server, powered, soup
    except:
        return None, "❌", "❌", None

def search_emails(soup):
    if not soup:
        return []
    return re.findall(r"[\w\.-]+@[\w\.-]+", soup.get_text())

def scan_ports(ip):
    nm = nmap.PortScanner()
    nm.scan(ip, arguments="-sT -T4 -Pn -F")
    if ip in nm.all_hosts():
        return nm[ip]
    return {}

def extract_cpe(service_data):
    try:
        for key in service_data.keys():
            if key.startswith('cpe'):
                return service_data[key]
        return None
    except:
        return None

async def scan_services(ip, services, min_year=2015):
    for proto in services.all_protocols():
        for port in services[proto].keys():
            data = services[proto][port]
            name = data.get("name", "unknown")
            cpe = extract_cpe(data)
            print(f"  📦 CVE check for {name} (port {port})")
            cves = await query_cves_async(name, cpe, min_year=min_year)
            for cve in cves:
                print("   -", cve)

async def subdomain_tasks(sub, ip, min_year=2015):
    print(f"\n📂 {sub} — {f'🌐 {ip}' if ip else '❌ Skipped (DNS failed)'}")
    if not ip:
        return
    print("\n🔍 WHOIS:")
    print(whois_lookup(sub))
    print("\n🦬 Fingerprinting site tech and metadata...")
    status, server, powered, soup = await fingerprint_async(sub)
    print(f"  🌐 HTTP status: {status if status else '❌'}")
    print(f"  🔱 Server: {server}\n  ⚙️ X-Powered-By: {powered}")
    print("\n📨 Searching for emails...")
    for email in search_emails(soup):
        print("  📧", email)
    print(f"\n🎯 Nmap scan for: {sub}")
    ports = scan_ports(ip)
    await scan_services(ip, ports, min_year=min_year)

if __name__ == "__main__":
    print("\n===== 🌐 Domain Scanner via TOR =====")
    print("1. Full Scan (Domain + Subdomains + Nmap + CVE + Tech)")
    print("2. Show IP (Tor + Real)")
    print("3. Exit")

    choice = input("Select an option (1/2/3): ")

    if choice == "1":
        domain = input("\nEnter domain: ")

        year_input = input("\nMinimum CVE year to include (default 2015): ")
        min_year = int(year_input.strip()) if year_input.strip().isdigit() else MIN_YEAR

        ip = get_ip(domain)
        print(f"\n🔎 Starting full scan for {domain}")
        print("🌐 IP:", ip)
        print("\n🔍 WHOIS:\n", whois_lookup(domain))
        print("\n🦬 Fingerprinting site tech and metadata...")
        status, server, powered, soup = asyncio.run(fingerprint_async(domain))
        print(f"  🌐 HTTP status: {status if status else '❌'}")
        print(f"  🔱 Server: {server}\n  ⚙️ X-Powered-By: {powered}")
        print("\n📨 Emails:")
        for email in search_emails(soup):
            print("  📧", email)

        print("\n🎯 Nmap scan for:", domain)
        ports = scan_ports(ip)
        asyncio.run(scan_services(ip, ports, min_year=min_year))

        print("\n📍 Passive subdomain scan...")
        try:
            r = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", headers=HEADERS, timeout=10)
            subdomains = sorted(set(entry['name_value'] for entry in r.json()))
            print(f"✅ Found {len(subdomains)} subdomains.")

            async def run_all_subdomain_tasks():
                tasks = []
                for sub in tqdm(subdomains, desc="🔎 Scanning Subdomains"):
                    ip_sub = get_ip(sub)
                    tasks.append(subdomain_tasks(sub, ip_sub, min_year=min_year))
                await asyncio.gather(*tasks)

            asyncio.run(run_all_subdomain_tasks())

        except Exception as e:
            print(f"❌ Failed to fetch subdomains: {e}")

    elif choice == "2":
        tor_ip = check_tor_ip()
        print("🕵️ Tor IP:", tor_ip if tor_ip else "❌ Failed via Tor")
        try:
            real_ip = requests.get("https://api.ipify.org", timeout=10).text
            print("🌐 Real IP:", real_ip)
        except:
            print("🌐 Real IP: ❌ Failed via direct connection")

    else:
        print("Exiting...")
