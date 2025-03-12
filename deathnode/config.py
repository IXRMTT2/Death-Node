NETWORK_INTERFACE = "wlan0"

ANOMALY_THRESHOLD = 0.1

LOG_FILE = "logs/deathnode.log"

DEAUTH_COUNT = 50000
DEAUTH_INTERVAL = 0.1

AUTO_BAN = False # Change if you want the AI to automatically block devices (not recommended)

TRUSTED_MACS = [ # Put whitelisted MAC addresses in here
    "00:00:00:00:00:00"
    "AA:AA:AA:AA:AA:AA"
]