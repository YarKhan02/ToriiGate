from mitmproxy import http

import requests

SUSPICIOUS_SITES_FILE = "suspicious_sites.txt"

suspicious_sites = set()

def fetch_suspicious_sites(url="https://urlhaus.abuse.ch/downloads/text/"):
    global suspicious_sites
    try:
        response = requests.get(url, proxies={"http": None, "https": None})
        response.raise_for_status()

        for line in response.text.splitlines():
            if not line.startswith("#") and line.strip():
                suspicious_sites.add(line.strip())

        print("[*] Successfully fetched suspicious sites.")
    except requests.RequestException as e:
        print(f"[!] Error fetching suspicious sites: {e}")

fetch_suspicious_sites()

def save_suspicious_url(url):
    with open(SUSPICIOUS_SITES_FILE, "a") as f:
        f.write(url + "\n")

def request(flow: http.HTTPFlow):
    url = flow.request.url
    print(f"Captured URL: {url}")
    
    if url in suspicious_sites:
        print(f"[ALERT] Suspicious URL detected: {url}")
        save_suspicious_url(url)
