import re
import time
import subprocess
import logging
from collections import defaultdict
import os
import threading
import sys
import argparse
from ipaddress import ip_address, ip_network

# Configuration
MAX_ATTEMPTS = 3
BAN_TIME = 31536000  # Ban duration in seconds (1 year)
LOG_FILE = '/app/logs/fail2ban_lite.log'
WHITELIST_FILE = '/app/config/whitelist.txt'

# Ensure the logs and config directories exist
os.makedirs('/app/logs', exist_ok=True)
os.makedirs('/app/config', exist_ok=True)

# Set up logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Dictionary to keep track of banned IPs and their ban end times
banned_ips = {}

# Load whitelist
def load_whitelist():
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        whitelist.add(ip_network(line))
                    except ValueError:
                        logging.warning(f"Invalid IP or network in whitelist: {line}")
    return whitelist

whitelist = load_whitelist()

def tail_journal():
    cmd = ["journalctl", "-f", "-n", "0"]
    with subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True) as process:
        while True:
            line = process.stdout.readline()
            if line:
                yield line.strip()
            else:
                time.sleep(0.1)

def is_ip_banned(ip):
    return ip in banned_ips and time.time() < banned_ips[ip]

def is_ip_whitelisted(ip):
    return any(ip_address(ip) in network for network in whitelist)

def ban_ip(ip):
    if not is_ip_banned(ip) and not is_ip_whitelisted(ip):
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            ban_end_time = time.time() + BAN_TIME
            banned_ips[ip] = ban_end_time
            logging.info("Banned IP: %s for 1 year", ip)
            # Schedule unban
            threading.Timer(BAN_TIME, unban_ip, args=[ip]).start()
        except subprocess.CalledProcessError as e:
            logging.error("Failed to ban IP %s: %s", ip, e)
    elif is_ip_whitelisted(ip):
        logging.info("IP %s is whitelisted. Skipping ban.", ip)
    else:
        logging.info("IP %s is already banned. Skipping.", ip)

def unban_ip(ip):
    if ip in banned_ips:
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del banned_ips[ip]
            logging.info("Unbanned IP: %s", ip)
        except subprocess.CalledProcessError as e:
            logging.error("Failed to unban IP %s: %s", ip, e)

def list_banned_ips():
    try:
        result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, check=True)
        banned = []
        for line in result.stdout.splitlines():
            if "DROP" in line:
                parts = line.split()
                if len(parts) >= 4 and parts[3].count('.') == 3:  # Simple check for IPv4 format
                    banned.append(parts[3])
        logging.info("Currently banned IPs: %s", banned)
        return banned
    except subprocess.CalledProcessError as e:
        logging.error("Failed to list banned IPs: %s", e)
        return []

def load_existing_bans():
    banned = list_banned_ips()
    current_time = time.time()
    for ip in banned:
        banned_ips[ip] = current_time + BAN_TIME
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
                ip = match.group(1)
                if not is_ip_banned(ip):
                    if not is_ip_whitelisted(ip):
                        failed_attempts[ip] += 1
                        logging.info("Potential failed attempt from IP: %s (Count: %d)", ip, failed_attempts[ip])
                        logging.info("Full log line: %s", line)
                        
                        if failed_attempts[ip] >= MAX_ATTEMPTS:
                            ban_ip(ip)
                            failed_attempts[ip] = 0
                    else:
                        logging.info("Whitelisted IP attempt: %s", ip)
                else:
                    logging.info("Blocked attempt from banned IP: %s", ip)

            # Periodically list banned IPs (every 5 minutes)
            if int(time.time()) % 300 == 0:
                list_banned_ips()

    except Exception as e:
        logging.error("An unexpected error occurred: %s", str(e))
    finally:
        logging.info("Fail2Ban Lite stopped")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fail2Ban Lite")
    parser.add_argument("--list-banned", action="store_true", help="List currently banned IPs")
    parser.add_argument("--unban", metavar="IP", help="Unban a specific IP address")
    args = parser.parse_args()

    if args.list_banned:
        banned_list = list_banned_ips()
        if banned_list:
            print("Currently banned IPs:")
            for ip in banned_list:
                print(ip)
        else:
            print("No IPs are currently banned.")
    elif args.unban:
        unban_ip(args.unban)
        print(f"Unbanned IP: {args.unban}")
    else:
        main()
