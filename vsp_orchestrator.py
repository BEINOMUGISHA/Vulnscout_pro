import time
import random
import sys
from datetime import datetime

# ANSI Colors
CLR_RESET = "\033[0m"
CLR_PRIMARY = "\033[38;5;39m"
CLR_CRITICAL = "\033[38;5;196m"
CLR_HIGH = "\033[38;5;208m"
CLR_WARN = "\033[38;5;214m"
CLR_INFO = "\033[38;5;40m"
CLR_MODULE = "\033[38;5;244m"
CLR_TAG = "\033[38;5;250m"
CLR_DIM = "\033[38;5;240m"
CLR_NEON = "\033[38;5;190m"

def get_timestamp():
    return datetime.now().strftime("%H:%M:%S")

def log(module, tag, message, color=CLR_RESET):
    ts = f"{CLR_DIM}[{get_timestamp()}]{CLR_RESET}"
    mod = f"{CLR_MODULE}[{module:7}]{CLR_RESET}"
    tlabel = f"[{tag:7}]"
    print(f"{ts} {mod} {tlabel} {color}{message}{CLR_RESET}")

def print_banner():
    banner = f"""
{CLR_PRIMARY}
 ██▒   █▓ █▒ █▓ ██▓      ███▄    █   ██████  ▄████▄   ▒█████   █    ██ ▄▄▄█████▓
▓██░   █▒▓██▒█▒▓██▒      ██ ▀█   █ ▒██    ▒ ▒██▀ ▀█  ▒██▒  ██▒ ██  ▓██▒▓  ██▒ ▓▒
 ▓██  █▒░▒██ █░▒██░      ▓██  ▀█ ██▒░ ▓██▄   ▒▓█    ▄ ▒██░  ██▒▓██  ▒██░▒ ▓██░ ▒░
  ▒██ █░░░██ █ ▒██░      ▓██▒  ▐▌██▒  ▒   ██▒▒▓▓▄ ▄██▒▒██   ██░▓▓█  ░██░░ ▓██▓ ░ 
   ▒▀█░  ░██▒█░░██████▒  ▒██░   ▓██░▒██████▒▒▒ ▓███▀ ░░ ████▓▒░▒▒█████▓   ▒██▒ ░ 
   ░ ▐░  ░▒▒▒ ░░ ▒░▓  ░  ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▒░▒░ ░▒▓▒ ▒ ▒   ▒ ░░   
   ░ ░░  ░░▒ ░ ░ ░ ▒  ░  ░ ░░   ░ ▒░░ ░▒  ░ ░  ░  ▒     ░ ▒ ▒░ ░░▒░ ░ ░     ░    
     ░░   ░░     ░ ░        ░   ░ ░ ░  ░  ░  ░          ░ ░ ▒   ░░░ ░ ░   ░      
      ░    ░       ░  ░           ░       ░  ░ ░          ░ ░     ░                
     ░                                       ░                                    
{CLR_RESET}
>> scan_orchestrator pipeline [production-cli]
>> target: https://api.fintech-demo.local
--------------------------------------------------------------------------------
"""
    print(banner)

def run_mission():
    print_banner()
    
    # Phase 1: Initializing
    log("SYSTEM", "BOOT", "Initializing Neural Link to core cluster...", CLR_PRIMARY)
    time.sleep(0.8)
    log("ORCH", "INFO", "Allocating worker pool: 50 active threads", CLR_INFO)
    time.sleep(0.5)
    log("ORCH", "INFO", "Target identified: api.fintech-demo.local (10.0.4.152)", CLR_INFO)
    time.sleep(0.3)
    log("WAF", "WARN", "Fingerprinting: Imunify360 + Cloudflare detected.", CLR_WARN)
    time.sleep(1)

    # Phase 2: Crawling
    log("CRAWL", "SPAWN", "Injecting multi-threaded spider pool...", CLR_NEON)
    paths = [
        "/api/v1/auth", "/admin/login", "/config/v2/webhooks", "/api/v1/users",
        "/ussd/callback", "/graphql", "/payments", "/profile/edit"
    ]
    for i in range(10):
        path = random.choice(paths)
        log("CRAWL", "DISC", f"Found node: {path} (200 OK)", CLR_DIM)
        time.sleep(0.2)
    log("ORCH", "INFO", "Asset perimeter mapping complete: 42 nodes discovered.", CLR_INFO)
    time.sleep(0.8)

    # Phase 3: Detecting
    log("DETECT", "START", "Initiating Tactical Payload Delivery...", CLR_WARN)
    payloads = [
        ("SQLI", "' OR '1'='1", "/api/v1/auth", "password"),
        ("XSS", "<script>alert(1)</script>", "/profile/edit", "name"),
        ("SSRF", "http://169.254.169.254/", "/config/v2/webhooks", "url"),
        ("IDOR", "user_id=1", "/api/v1/users/774", "id")
    ]
    
    for i in range(20):
        p_type, p_val, p_target, p_param = random.choice(payloads)
        log("DETECT", "FIRE", f"Sending {p_type} payload to {p_target} [{p_param}]", CLR_DIM)
        time.sleep(0.15)
        if i == 5:
            log("DETECT", "ANOM", "Anomaly detected in HTTP/1.1 response header (500 Internal Server Error)", CLR_WARN)
    
    # Hits
    time.sleep(1)
    log("VALID", "HIT", "!! CRITICAL ALERT: SQL INJECTION CONFIRMED !!", CLR_CRITICAL)
    log("VALID", "HIT", "Location: /api/v1/auth [password]", CLR_CRITICAL)
    log("VALID", "HIT", "Evidence: Database schema leak detected in response body.", CLR_CRITICAL)
    
    time.sleep(0.8)
    log("VALID", "HIT", "!! HIGH ALERT: SSRF CONFIRMED ON CLOUD METADATA !!", CLR_HIGH)
    log("VALID", "HIT", "Location: /config/v2/webhooks [url]", CLR_HIGH)

    # Finalizing
    time.sleep(1)
    log("SCORE", "INFO", "Calculating mission risk score (CVSS v3.1)...", CLR_INFO)
    time.sleep(0.5)
    log("ORCH", "INFO", "Scan complete. Discovered 1 CRITICAL, 1 HIGH findings.", CLR_INFO)
    
    print(f"\n{CLR_CRITICAL}MISSION COMPLETE.{CLR_RESET}\n")

if __name__ == "__main__":
    try:
        run_mission()
    except KeyboardInterrupt:
        print("\n[!] Mission aborted by operator.")
        sys.exit(0)
