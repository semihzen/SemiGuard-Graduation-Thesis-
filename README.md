
# SemiGuard: Lightweight Desktop-Based Intrusion Detection System
SemiGuard is a Python-based intrusion detection system (IDS) developed as part of a graduation thesis project. Designed to run on a desktop Ubuntu environment, it aims to detect and mitigate common network attacks in real time using packet analysis and signature-based detection methods. ### You can access detailed information through the Report.pdf file included in the repository.

## Features

Real-time detection of:
ARP Spoofing
ICMP Flooding
TCP SYN Flood (DDoS)
Brute-force Login Attempts
Email alerts for each detected attack
Auto-mitigation (e.g., ARP table correction)
GUI interface developed using PyQt5
Log generation for each attack type

## Technologies Used

Python 3
PyQt5 (GUI)
Scapy (Packet Analysis)
BeautifulSoup & Requests (Brute-force Detection)
GNS3 (Network Simulation)
DVWA (Brute-force Simulation)


