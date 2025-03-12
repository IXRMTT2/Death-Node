from scapy.all import *
from scapy.all import Dot11, sniff
import time 
from detect import detect_anomalies
import numpy as np

packet_count = []

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        packet_count.append([len(pkt)])
        if len(packet_count) >= 10:
            detect_anomalies(np.array(packet_count))

        print(f"[+] Detected Packet: {len(pkt)}")
        
        mac = pkt.addr2
        with open("logs/threats.log", "a") as log:
            log.write(f"{time.ctime()} - Detected Packet from {mac}\n")
        print(f"[+] Detected Suspicious Packet from {mac}")

sniff(iface="wlan0", prn=packet_handler, store=0)