from scapy.all import *
import time 

def packet_handler(pkt):
    if pkt.haslayer(Dot11):
        mac = pkt.addr2
        with open("logs/threats.log", "a") as log:
            log.write(f"{time.ctime()} - Detected Packet from {mac}\n")
        print(f"[+] Detected Suspicious Packet from {mac}")

sniff(iface="wlan0", prn=packet_handler, store=0)