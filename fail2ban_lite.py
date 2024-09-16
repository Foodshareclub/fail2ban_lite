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
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import signal
from logging.handlers import RotatingFileHandler
from flask import Flask

# Load environment variables from .env file
load_dotenv()

# Configuration
MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))
BAN_TIME = int(os.getenv('BAN_TIME', 31536000))  # Ban duration in seconds (1 year)
LOG_FILE = os.getenv('LOG_FILE', '/app/logs/fail2ban_lite.log')
WHITELIST_FILE = os.getenv('WHITELIST_FILE', '/app/config/whitelist.txt')
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
JOURNAL_CMD = os.getenv('JOURNAL_CMD', 'journalctl -f -n 0').split()
EMAIL_ENABLED = os.getenv('EMAIL_ENABLED', 'false').lower() == 'true'
EMAIL_NOTIFICATIONS_ENABLED = os.getenv('EMAIL_NOTIFICATIONS_ENABLED', 'false').lower() == 'true'
EMAIL_HOST = os.getenv('EMAIL_HOST', 'localhost')
EMAIL_PORT = int(os.getenv('EMAIL_PORT', 25))
EMAIL_USER = os.getenv('EMAIL_USER', '')
EMAIL_PASS = os.getenv('EMAIL_PASS', '')
EMAIL_FROM = os.getenv('EMAIL_FROM', 'fail2ban@example.com')
EMAIL_TO = os.getenv('EMAIL_TO', 'admin@example.com')

# Ensure the logs and config directories exist
os.makedirs('/app/logs', exist_ok=True)
os.makedirs('/app/config', exist_ok=True)

# Set up logging with rotation
handler = RotatingFileHandler(LOG_FILE, maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
logger.addHandler(handler)

# Dictionary to keep track of banned IPs and their ban end times
banned_ips = {}

# Load whitelist
def load_whitelist():
    whitelist = set()
    if os.path.exists(WHITELIST_FILE):
        with open(WHITELIST_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        whitelist.add(ip_network(line))
                    except ValueError:
                        logging.warning("Invalid IP or network in whitelist: %s", line)
    return whitelist

whitelist = load_whitelist()

def tail_journal():
    with subprocess.Popen(JOURNAL_CMD, stdout=subprocess.PIPE, universal_newlines=True) as process:
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
            logging.info("Banned IP: %s for %d seconds", ip, BAN_TIME)
            send_email("IP Banned", f"The IP {ip} has been banned for {BAN_TIME} seconds.")
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
            send_email("IP Unbanned", f"The IP {ip} has been unbanned.")
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

def reload_config(signum, frame):
    global MAX_ATTEMPTS, BAN_TIME, LOG_LEVEL, whitelist
    load_dotenv()
    MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', 3))
    BAN_TIME = int(os.getenv('BAN_TIME', 31536000))
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    logging.getLogger().setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    whitelist = load_whitelist()
    logging.info("Configuration reloaded")

signal.signal(signal.SIGHUP, reload_config)

def send_email(subject, body):
    if not EMAIL_ENABLED or not EMAIL_NOTIFICATIONS_ENABLED:
        return
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))
    try:
        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            if EMAIL_USER and EMAIL_PASS:
                server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_FROM, EMAIL_TO, msg.as_string())
        logging.info("Sent email notification to %s", EMAIL_TO)
    except Exception as e:
        logging.error("Failed to send email: %s", e)

app = Flask(__name__)

@app.route('/health')
def health():
    return "OK", 200

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

    threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8082)).start()  # Changed port to 8082

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
