from scapy.all import sniff, IP, ICMP
import time
from collections import defaultdict
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
load_dotenv()
THRESHOLD = 50
LOG_PATH = "/home/semih/Desktop/log/icmp_attack_log.txt"
SENDER_EMAIL = "saldiritespit@gmail.com"
RECEIVER_EMAIL = "semihzenqin@gmail.com"
EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD")
EMAIL_COOLDOWN = 300

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

icmp_counter = defaultdict(int)
last_email_time = defaultdict(float)
start_time = time.time()

def send_email(alert_message):
    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL
    msg['To'] = RECEIVER_EMAIL
    msg['Subject'] = 'ICMP Attack Detected'

    msg.attach(MIMEText(alert_message, 'plain'))

    try:
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, EMAIL_PASSWORD)
            server.sendmail(SENDER_EMAIL, RECEIVER_EMAIL, msg.as_string())
        print(" Warning email sent!", flush=True)
    except Exception as e:
        print(f" Failed to send email: {e}", flush=True)
        logging.error(f" Failed to send email: {e}")

def detect_icmp_attack(packet):
    global start_time, icmp_counter

    if packet.haslayer(ICMP):
        current_time = time.time()
        source_ip = packet[IP].src
        icmp_counter[source_ip] += 1

        if current_time - start_time >= 1:
            for ip, count in icmp_counter.items():
                if count >= THRESHOLD:
                    alert = f"ICMP attack detected! {count} pings received from {ip} within 1 second."
                    print(alert, flush=True)
                    logging.info(alert)

                    if current_time - last_email_time[ip] >= EMAIL_COOLDOWN:
                        send_email(alert)
                        last_email_time[ip] = current_time
                    else:
                        print(f" Email cooldown not expired for {ip}.", flush=True)

            icmp_counter = defaultdict(int)
            start_time = current_time

print(" ICMP attack detection started...", flush=True)

sniff(prn=detect_icmp_attack, filter="icmp", store=0, iface="ens33")
