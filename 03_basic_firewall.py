import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

# Read IPs from a file
def read_ip_file(filename):
    with open(filename, "r") as file:
        ips = [line.strip() for line in file]
    return set(ips)

# Check for Nimda worm signature
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False

# Log events to a file
def log_event(message):
    log_folder = "logs"
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
    
    with open(log_file, "a") as file:
        file.write(f"{message}\n")

def packet_callback(packet):
    src_ip = packet[IP].src
