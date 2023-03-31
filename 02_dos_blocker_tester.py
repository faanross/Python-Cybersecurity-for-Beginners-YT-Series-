import sys
import time
from scapy.all import Ether, IP, UDP, sendp

TARGET_IP = "192.168.1.X"  # Replace with the target IP address
INTERFACE = "eth0"  # Replace with your network interface