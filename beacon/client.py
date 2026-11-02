import argparse
import time
import random
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def run_beacon(target_url, mode, interval, min_int, max_int, jitter, duration):
    print(f"[*] Starting beacon to {target_url}")
    print(f"[*] Mode: {mode}")
    
    start_time = time.time()
    count = 0
    
    while True:
        if duration > 0 and (time.time() - start_time) > duration:
            print("[*] Duration reached. Stopping beacon.")
            break
            
        try:
            # Vary payload size randomly and simulate evasion logic
            path = f"/{random.randint(1000, 9999)}"
            # Some evasion logic might hit different paths or add random padded headers
            headers = {"User-Agent": "Mozilla/5.0", "X-Padding": "A" * random.randint(10, 100)}
            response = requests.get(target_url + path, headers=headers, verify=False, timeout=3)
            print(f"[+] Sent beacon {count} - Status: {response.status_code}")
        except Exception as e:
            print(f"[-] Failed to reach {target_url}: {e}")
            
        count += 1
        
        # Calculate next sleep
        if mode == 'fixed':
            sleep_time = interval
        elif mode == 'random':
            sleep_time = random.uniform(min_int, max_int)
        elif mode == 'evasion':
            # very wide random interval with occasional large jitter
            sleep_time = random.uniform(min_int, max_int)
            
        if jitter > 0:
            jitter_val = random.uniform(-jitter, jitter)
            sleep_time = max(0.1, sleep_time + jitter_val)
            
        print(f"[*] Sleeping for {sleep_time:.2f} seconds...")
        time.sleep(sleep_time)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Beacon Simulation Client")
    parser.add_argument('--url', default='http://127.0.0.1:8080', help="C2 Server URL")
    parser.add_argument('--mode', choices=['fixed', 'random', 'evasion'], default='fixed', help="Beaconing mode")
    parser.add_argument('--interval', type=float, default=5.0, help="Fixed interval (seconds)")
    parser.add_argument('--min', type=float, default=5.0, dest='min_int', help="Minimum interval for random mode")
    parser.add_argument('--max', type=float, default=15.0, dest='max_int', help="Maximum interval for random mode")
    parser.add_argument('--jitter', type=float, default=0.0, help="Jitter in seconds")
    parser.add_argument('--duration', type=int, default=0, help="Stop after duration (seconds). 0 = infinite")
    
    args = parser.parse_args()
    
    if args.mode == 'evasion':
        args.min_int = 5.0
        args.max_int = 60.0
        args.jitter = 2.0
        
    try:
        run_beacon(args.url, args.mode, args.interval, args.min_int, args.max_int, args.jitter, args.duration)
    except KeyboardInterrupt:
        print("\n[*] Beacon stopped by user.")
        sys.exit(0)
