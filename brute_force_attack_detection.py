import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, TCP, IP
import smtplib
from email.mime.text import MIMEText
import os

# Configuration
POST_THRESHOLD = 20
TCP_SYN_THRESHOLD = 30
INTERVAL = 10

SENDER_EMAIL = "saldiritespit@gmail.com"
RECEIVER_EMAIL = "semihzenqin@gmail.com"
EMAIL_PASSWORD = "cahrgcjnksrbojdm"

post_counter = defaultdict(list)
tcp_syn_counter = defaultdict(list)

# Log dosyası ayarı
log_dir = "/home/semih/Desktop/log"
os.makedirs(log_dir, exist_ok=True)
log_file_path = os.path.join(log_dir, "bruteforce_log.txt")

def log_to_file(message):
    try:
        with open(log_file_path, "a") as log_file:
            log_file.write(message + "\n")
    except Exception as e:
        print(f"Log error: {e}", flush=True)

def send_email(subject, body):
    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL

        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(f"Email sent: {subject}", flush=True)
    except Exception as e:
        print(f"Failed to send email: {e}", flush=True)

def monitor_http_posts():
    print("HTTP POST monitoring started...", flush=True)

    while True:
        cmd = f"tshark -Y 'http.request.method == \"POST\"' -T fields -e ip.src -a duration:{INTERVAL}"
        try:
            result = subprocess.check_output(cmd, shell=True, text=True).strip().split('\n')
        except subprocess.CalledProcessError:
            continue

        now = time.time()
        for ip in result:
            if ip:
                post_counter[ip].append(now)

        for ip, times in list(post_counter.items()):
            post_counter[ip] = [t for t in times if now - t <= INTERVAL]
            if len(post_counter[ip]) > POST_THRESHOLD:
                msg = f"[{datetime.now()}] {ip} sent {len(post_counter[ip])} POST requests (suspicious activity)"
                print("ALERT: " + msg, flush=True)
                send_email("ALERT: BruteForce|Potential HTTP POST Attack", msg)
                log_to_file("HTTP POST ALERT: " + msg)
                post_counter[ip] = []

        time.sleep(INTERVAL)

def monitor_tcp_syn(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        if packet[TCP].flags == "S":
            src_ip = packet[IP].src
            now = time.time()
            tcp_syn_counter[src_ip].append(now)

def process_tcp_syn():
    print("TCP connection analysis started...", flush=True)

    while True:
        now = time.time()
        for ip, times in list(tcp_syn_counter.items()):
            tcp_syn_counter[ip] = [t for t in times if now - t <= INTERVAL]
            if len(tcp_syn_counter[ip]) > TCP_SYN_THRESHOLD:
                msg = f"[{datetime.now()}] {ip} initiated {len(tcp_syn_counter[ip])} TCP connections (suspicious activity)"
                print("ALERT: " + msg, flush=True)
                send_email("ALERT: High TCP Connection Rate", msg)
                log_to_file("TCP SYN ALERT: " + msg)
                tcp_syn_counter[ip] = []

        time.sleep(INTERVAL)

def start_sniffing():
    sniff(filter="tcp", prn=monitor_tcp_syn, store=0)

def main():
    print("Brute-force attack detection started...", flush=True)

    threading.Thread(target=start_sniffing, daemon=True).start()
    threading.Thread(target=process_tcp_syn, daemon=True).start()
    threading.Thread(target=monitor_http_posts, daemon=True).start()

    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
