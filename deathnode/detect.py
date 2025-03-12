from sklearn.ensemble import IsolationForest
import numpy as np
import time
from countermeasures import block_mac, deauth

def detect_anomalies(packet_count):
    model = IsolationForest(contamination=0.1)
    model.fit(packet_count)
    predictions = model.predict(packet_count)

    for i, pred in enumerate(predictions):
        if pred == -1: 
            alert_user(i, packet_count[i])

def alert_user(index, data):
    print("[IMPORTANT] Possible Threat Detected")
    print(f"Suspicious Activity Detected at index {index}: {data}")
    print("Options: (1) Block | (2) Deauth | (3) Ignore")

    action = input ("Choose Action: ")
    if action == "1":
        mac = input("Enter MAC Address to Block: ")
        block_mac(mac)
    elif action == "2":
        mac = input("Enter MAC Address to Write in the Death Node: ")
        gateway_mac = input("Enter Gateway MAC Address: ")
        deauth(mac, gateway_mac)
    elif action == "3":
        print("[INFO] Ignoring the Threat")
    else:
        print("[ERROR] Invalid Choice")

