import logging
from scapy.all import sniff, TCP, IP
from datetime import datetime
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import Counter

SENDER_EMAIL = "saldiritespit@gmail.com"
RECEIVER_EMAIL = "semihzenqin@gmail.com"
EMAIL_PASSWORD = "cahrgcjnksrbojdm"
INTERFACE = "ens33"

LOG_DIR = "/home/semih/Desktop/log"
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)
LOG_FILE = os.path.join(LOG_DIR, "ddos_detection.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

def send_email(subject, body):
    try:
        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = RECEIVER_EMAIL
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, EMAIL_PASSWORD)
        server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        server.quit()
        print(f"📧 Email sent: {subject}", flush=True)
    except Exception as e:
        print(f"❌ Failed to send email: {e}", flush=True)

THRESHOLD = 100
INTERVAL = 10
ip_list = []

def packet_handler(pkt):
    if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
        if pkt.haslayer(IP):
            src_ip = pkt[IP].src
            ip_list.append(src_ip)

def monitor():
    global ip_list
    print("🛡️ DDOS detection system started...", flush=True)
    while True:
        ip_list = []
        sniff(filter="tcp", prn=packet_handler, timeout=INTERVAL, iface=INTERFACE, store=False)
        total_syn = len(ip_list)
        if total_syn > THRESHOLD:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            ip_counter = Counter(ip_list)
            top_attackers = ip_counter.most_common(5)
            
            ip_report = "\n".join([f"{ip} => {count} SYN" for ip, count in top_attackers])
            message = (
                f"🔥 [{timestamp}] POTENTIAL DDOS ATTACK DETECTED!\n"
                f"Total SYN packets: {total_syn}\n"
                f"Top source IPs:\n{ip_report}"
            )
            print(message, flush=True)
            logging.info(message)
            send_email("🔥 DDOS DETECTED", message)

if __name__ == "__main__":
    monitor()
