import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP

THRESHOLD = 100

def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1