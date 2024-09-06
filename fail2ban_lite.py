import re
import time
import subprocess
import logging
from collections import defaultdict
import os
import threading

# Configuration
MAX_ATTEMPTS = 3
BAN_TIME = 300  # Ban duration in seconds (5 minutes)

# Ensure the logs directory exists
os.makedirs('/app/logs', exist_ok=True)

# Set up logging
logging.basicConfig(filename='/app/logs/fail2ban_lite.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Set to keep track of banned IPs
banned_ips = set()

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
    try:
        subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"], check=True, stderr=subprocess.DEVNULL)
        return True
    except subprocess.CalledProcessError:
        return False

def ban_ip(ip):
    if ip in banned_ips or is_ip_banned(ip):
        logging.info(f"IP {ip} is already banned. Skipping.")
        return

    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        banned_ips.add(ip)
        logging.info(f"Banned IP: {ip}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to ban IP {ip}: {e}")

def unban_ip(ip):
    if ip not in banned_ips and not is_ip_banned(ip):
        logging.info(f"IP {ip} is not banned. Skipping.")
        return

    try:
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
        banned_ips.discard(ip)
        logging.info(f"Unbanned IP: {ip}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to unban IP {ip}: {e}")

def main():
    logging.info("Fail2Ban Lite started")
    failed_attempts = defaultdict(int)

    try:
        for line in tail_journal():
            match = re.search(r"Failed password.*from (\d+\.\d+\.\d+\.\d+)", line)
            if not match:
                match = re.search(r"Invalid user \w+ from (\d+\.\d+\.\d+\.\d+)", line)
            
            if match:
                ip = match.group(1)
                failed_attempts[ip] += 1
                logging.info(f"Potential failed attempt from IP: {ip} (Count: {failed_attempts[ip]})")
                logging.info(f"Full log line: {line}")
                
                if failed_attempts[ip] >= MAX_ATTEMPTS:
                    ban_ip(ip)
                    # Schedule unban
                    threading.Timer(BAN_TIME, unban_ip, args=[ip]).start()
                    failed_attempts[ip] = 0

    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
    finally:
        logging.info("Fail2Ban Lite stopped")

if __name__ == "__main__":
    main()
