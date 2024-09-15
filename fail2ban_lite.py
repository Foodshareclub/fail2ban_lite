import re
import time
import subprocess
import logging
from collections import defaultdict
import os
import threading
import sys

# Configuration
MAX_ATTEMPTS = 3
BAN_TIME = 300  # Ban duration in seconds (5 minutes)

# Ensure the logs directory exists
os.makedirs('/app/logs', exist_ok=True)

# Set up logging
logging.basicConfig(filename='/app/logs/fail2ban_lite.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Dictionary to keep track of banned IPs and their ban end times
banned_ips = {}

def tail_journal():
    cmd = ["journalctl", "-f", "-n", "0"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True) as process:
        while True:
            line = process.stdout.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)

def is_ip_banned(ip_address):
    return ip_address in banned_ips and time.time() < banned_ips[ip_address]

def ban_ip(ip_address):
    if not is_ip_banned(ip_address):
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            ban_end_time = time.time() + BAN_TIME
            banned_ips[ip_address] = ban_end_time
            logging.info("Banned IP: %s", ip_address)
            # Schedule unban
            threading.Timer(BAN_TIME, unban_ip, args=[ip_address]).start()
        except subprocess.CalledProcessError as e:
            logging.error("Failed to ban IP %s: %s", ip_address, e)
    else:
        logging.info("IP %s is already banned. Skipping.", ip_address)

def unban_ip(ip_address):
    if ip_address in banned_ips:
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
            del banned_ips[ip_address]
            logging.info("Unbanned IP: %s", ip_address)
        except subprocess.CalledProcessError as e:
            logging.error("Failed to unban IP %s: %s", ip_address, e)

def list_banned_ips():
    try:
        result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, check=True)
        banned = []
        for line in result.stdout.splitlines():
            if "DROP" in line:
                parts = line.split()
                if len(parts) >= 4 and parts[3].count('.') == 3:  # Simple check for IPv4 format
                    ip_address = parts[3]
                    banned.append(ip_address)
        logging.info("Currently banned IPs: %s", banned)
        return banned
    except subprocess.CalledProcessError as e:
        logging.error("Failed to list banned IPs: %s", e)
        return []

def load_existing_bans():
    banned = list_banned_ips()
    current_time = time.time()
    for ip_address in banned:
        banned_ips[ip_address] = current_time + BAN_TIME
    logging.info("Loaded %d existing bans from iptables", len(banned))

def main():
    logging.info("Fail2Ban Lite started")
    load_existing_bans()
    failed_attempts = defaultdict(int)

    try:
        for line in tail_journal():
            match = re.search(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", line)
            if not match:
                match = re.search(r"Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)", line)
            
            if match:
                ip_address = match.group(1)
                if not is_ip_banned(ip_address):
                    failed_attempts[ip_address] += 1
                    logging.info("Potential failed attempt from IP: %s (Count: %d)", ip_address, failed_attempts[ip_address])
                    logging.info("Full log line: %s", line)
                    
                    if failed_attempts[ip_address] >= MAX_ATTEMPTS:
                        ban_ip(ip_address)
                        failed_attempts[ip_address] = 0
                else:
                    logging.info("Blocked attempt from banned IP: %s", ip_address)

            # Periodically list banned IPs (every 5 minutes)
            if int(time.time()) % 300 == 0:
                list_banned_ips()

    except Exception as e:
        logging.error("An unexpected error occurred: %s", str(e))
    finally:
        logging.info("Fail2Ban Lite stopped")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--list-banned":
        banned_list = list_banned_ips()
        if banned_list:
            print("Currently banned IPs:")
            for ip_address in banned_list:
                print(ip_address)
        else:
            print("No IPs are currently banned.")
    else:
        main()
