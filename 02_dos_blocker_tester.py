import sys
import time
from scapy.all import Ether, IP, UDP, sendp

TARGET_IP = "192.168.1.X"  # Replace with the target IP address
INTERFACE = "eth0"  # Replace with your network interface

def send_packets(target_ip, interface):
    packet = Ether() / IP(dst=target_ip) / UDP()
    start_time = time.time()