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
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True)
    while True:
        line = process.stdout.readline()
        if line:
            yield line.strip()
        else:
            time.sleep(0.1)

def is_ip_banned(ip):
    return ip in banned_ips and time.time() < banned_ips[ip]

def ban_ip(ip):
    if not is_ip_banned(ip):
        try:
            subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            ban_end_time = time.time() + BAN_TIME
            banned_ips[ip] = ban_end_time
            logging.info(f"Banned IP: {ip}")
            # Schedule unban
            threading.Timer(BAN_TIME, unban_ip, args=[ip]).start()
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to ban IP {ip}: {e}")
    else:
        logging.info(f"IP {ip} is already banned. Skipping.")

def unban_ip(ip):
    if ip in banned_ips:
        try:
            subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            del banned_ips[ip]
            logging.info(f"Unbanned IP: {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to unban IP {ip}: {e}")

def list_banned_ips():
    try:
        result = subprocess.run(["iptables", "-L", "INPUT", "-n"], capture_output=True, text=True, check=True)
        banned = []
        for line in result.stdout.splitlines():
            if "DROP" in line:
                parts = line.split()
                if len(parts) >= 4 and parts[3].count('.') == 3:  # Simple check for IPv4 format
                    ip = parts[3]
                    banned.append(ip)
        logging.info(f"Currently banned IPs: {banned}")
        return banned
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to list banned IPs: {e}")
        return []

def load_existing_bans():
    banned = list_banned_ips()
    current_time = time.time()
    for ip in banned:
        banned_ips[ip] = current_time + BAN_TIME
    logging.info(f"Loaded {len(banned)} existing bans from iptables")

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
                    failed_attempts[ip] += 1
                    logging.info(f"Potential failed attempt from IP: {ip} (Count: {failed_attempts[ip]})")
                    logging.info(f"Full log line: {line}")
                    
                    if failed_attempts[ip] >= MAX_ATTEMPTS:
                        ban_ip(ip)
                        failed_attempts[ip] = 0
                else:
                    logging.info(f"Blocked attempt from banned IP: {ip}")

            # Periodically list banned IPs (every 5 minutes)
            if int(time.time()) % 300 == 0:
                list_banned_ips()

    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
    finally:
        logging.info("Fail2Ban Lite stopped")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--list-banned":
        banned_list = list_banned_ips()
        if banned_list:
            print("Currently banned IPs:")
            for ip in banned_list:
                print(ip)
        else:
            print("No IPs are currently banned.")
    else:
        main()
