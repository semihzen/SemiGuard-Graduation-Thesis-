import os
import time
import smtplib
import logging
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv
import subprocess
import ipaddress
load_dotenv()
SENDER_EMAIL = "saldiritespit@gmail.com"
RECEIVER_EMAIL = "semihzenqin@gmail.com"
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
INTERFACE = "ens33"

LOG_FILE = os.path.expanduser("/home/semih/Desktop/log/arp_spoof_log.txt")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def send_email_alert(ip, real_mac, fake_mac):
    subject = " ARP Spoofing Detected!"
    body = f"""
A spoofed MAC address has been detected for the following IP:

 IP Address: {ip}
 Real MAC: {real_mac}
 Fake MAC: {fake_mac}

The fake MAC has been removed from the ARP table.
"""
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL

    try:
        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print(" Alert email has been sent.", flush=True)
        logging.info(f"Alert email sent: IP={ip}")
    except Exception as e:
        print(f" Failed to send email: {e}", flush=True)
        logging.error(f"Failed to send email: {e}")

def log_attack(ip, real_mac, fake_mac):
    alert = (
        f"ARP Spoofing DETECTED:\n"
        f"IP: {ip}\n"
        f"Real MAC: {real_mac}\n"
        f"Fake MAC: {fake_mac}\n"
    )
    logging.info(alert)

def get_arp_table():
    arp_table = {}
    with os.popen("ip neigh") as output:
        for line in output:
            parts = line.strip().split()
            if len(parts) >= 6:
                ip = parts[0]
                mac = parts[4].lower()
                state = parts[5]
                arp_table[ip] = (mac, state)
    return arp_table

def scan_network(interface):
    print("Starting network scan...", flush=True)
    logging.info("Network scan started.")

    ip_info = None
    with os.popen(f"ip -o -f inet addr show {interface}") as f:
        for line in f:
            if line.strip():
                ip_info = line.strip().split()
                break

    if not ip_info:
        print(f" Failed to get IP info for interface {interface}!", flush=True)
        logging.error(f"Failed to get IP info for interface {interface}!")
        return {}

    ip_with_prefix = ip_info[3]
    network = ipaddress.ip_network(ip_with_prefix, strict=False)

    for ip in network.hosts():
        ip_str = str(ip)
        subprocess.Popen(['ping', '-c', '1', '-W', '1', ip_str],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)

    time.sleep(3)

    arp_table = get_arp_table()
    print(f" Network scan complete, {len(arp_table)} devices found.", flush=True)
    logging.info(f"Network scan complete, {len(arp_table)} devices found.")
    return arp_table

def detect_arp_spoof(reference_arp, interface_name):
    print("Monitoring ARP table for spoofing...", flush=True)
    logging.info("ARP table monitoring started.")
    while True:
        current_arp = get_arp_table()
        for ip, (real_mac, _) in reference_arp.items():
            if ip in current_arp:
                current_mac, _ = current_arp[ip]
                if current_mac != real_mac:
                    alert_msg = (
                        f"ARP Spoofing Detected!\n"
                        f"IP: {ip}\nReal MAC: {real_mac}\nFake MAC: {current_mac}"
                    )
                    print(alert_msg, flush=True)
                    logging.warning(alert_msg)

                    del_command = f"ip neigh del {ip} dev {interface_name}"
                    result = os.system(del_command)
                    if result == 0:
                        print(f" Spoofed entry removed from ARP table: {ip}", flush=True)
                        logging.info(f"Spoofed entry removed from ARP table: {ip}")
                    else:
                        print(f" Failed to delete ARP entry: {del_command}", flush=True)
                        logging.error(f"Failed to delete ARP entry: {del_command}")

                    send_email_alert(ip, real_mac, current_mac)
                    log_attack(ip, real_mac, current_mac)

        time.sleep(5)

if __name__ == "__main__":
    reference_arp = scan_network(INTERFACE)
    if not reference_arp:
        print(" Failed to create reference ARP table. Exiting.", flush=True)
        logging.error("Failed to create reference ARP table. Exiting.")
        exit(1)

    print(" Initial ARP table captured as reference:", flush=True)
    logging.info("Initial ARP table captured as reference.")
    for ip, (mac, state) in reference_arp.items():
        print(f" Reference: {ip} -> {mac} (State: {state})", flush=True)
        logging.info(f"Reference: {ip} -> {mac} (State: {state})")

    print(" Reference ARP table saved. Starting monitoring...\n", flush=True)
    logging.info("Reference ARP table saved. Starting monitoring...")
    detect_arp_spoof(reference_arp, INTERFACE)
