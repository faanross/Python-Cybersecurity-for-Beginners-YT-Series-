import sys
import time
from scapy.all import Ether, IP, UDP, sendp

TARGET_IP = "192.168.1.X"  # Replace with the target IP address
INTERFACE = "eth0"  # Replace with your network interface

def send_packets(target_ip, interface):
    packet = Ether() / IP(dst=target_ip) / UDP()
    start_time = time.time()

    while True:
        sendp(packet, iface=interface)
        current_time = time.time()
        time_interval = current_time - start_time

        if time_interval >= 1:
            break

if __name__ == "__main__":
    if sys.version_info[0] < 3:
        print("This script requires Python 3.")
        sys.exit(1)