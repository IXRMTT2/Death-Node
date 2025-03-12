import os
import threading
from sniff import packet_handler
from detect import alert_user
from countermeasures import block_mac, deauth

def show_menu():
    print("1. Start Sniffing")
    print("2. View Threat Log")
    print("3. Manual Block")
    print("4. Manual Deauth")
    print("5. Exit")

def view_log():
    with open("logs/threats.log", "r") as log:
        print(log.read())

def main():
    while True:
        show_menu()
        choice = input("Enter Choice: ")
        if choice == "1":
            print("[+] Starting Sniffing Thread")
            thread = threading.Thread(target=packet_handler, daemon=True)
            thread.start()
        elif choice == "2":
            view_log()
        elif choice == "3":
            mac = input("Enter MAC Address to Block: ")
            block_mac(mac)
        elif choice == "4":
            mac = input("Enter MAC Address to Write in the Death Node: ")
            deauth(mac)
        elif choice == "5":
            print("Closing the DeathNode")
            break
        else:
            print("Invalid Choice")
if __name__ == "__main__":
    main()

