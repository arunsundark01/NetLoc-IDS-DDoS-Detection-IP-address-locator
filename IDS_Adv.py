from collections import defaultdict
from scapy.all import sniff, IP
import time
import threading
import socket
import requests
from datetime import datetime
from pushbullet import Pushbullet

# Your machine's local IP
MY_IP = socket.gethostbyname(socket.gethostname())

# Track packet counts and alert flags per source IP
source_ip_count = defaultdict(int)
source_ip_alerted = defaultdict(bool)
dos_threshold = 10  # Threshold of packets per second from one source
LOG_FILE = "DDos_Monitor.log"
API_KEY = "Your_IpInfo_Key"

def log(msg):
    try:
        # Open the log file and write the message with proper encoding (UTF-8)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"[{timestamp}] {msg}\n")
        print(f"[{timestamp}] {msg}")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def get_ip_info(ip):
    try:
        # Use ipinfo.io API to get details about the IP
        url = f'https://ipinfo.io/{ip}/json?token={API_KEY}'
        response = requests.get(url)
        data = response.json()

        # Extract relevant information
        ip_info = {
            "IP": ip,
            "Hostname": socket.gethostbyaddr(ip)[0] if socket.gethostbyaddr(ip) else "N/A",
            "Location": data.get('city', 'Unknown') + ", " + data.get('region', 'Unknown') + ", " + data.get('country', 'Unknown'),
            "Org": data.get('org', 'Unknown'),
            "City": data.get('city', 'Unknown'),
            "Country": data.get('country', 'Unknown'),
            "Domain": data.get('hostname', 'Unknown')
        }

        return ip_info
    except Exception as e:
        log(f"Error retrieving IP info: {e}")
        return {"IP": ip, "Error": "Unable to retrieve info"}

def notification(msg, body):
    try:
        pb = Pushbullet("YOUR_Pushbullet_Key")  # Replace with your token
        push = pb.push_note(msg, body)
        log("Pushbullet alert sent.")
    except Exception as e:
        log(f"Failed to send Pushbullet alert: {e}")

# Function to detect incoming DDoS attacks
def detect_ddos_attack(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst

        if ip_dst == MY_IP:
            source_ip_count[ip_src] += 1

            # Alert only once per second per attacker
            # Store current count in a variable
            current_count = source_ip_count[ip_src]

            if current_count > dos_threshold and not source_ip_alerted[ip_src]:
                msg = (f"Potential DDoS attack detected: {ip_src} → {ip_dst} with packet count = {current_count}")
                body = ("Alert!! A malicious hacker or a web server is trying to congest the network traffic in your ip address with packets more than defined in threshold")
                ip_info = get_ip_info(ip_src)
                log(msg)
                log(f"Attacking IP Info: {ip_info}")
                notification(msg, body)
                print(f"Potential DDoS attack detected: {ip_src} → {ip_dst} with packet count = {current_count}")
                print(f"Attacking IP Info: {ip_info}")
                source_ip_alerted[ip_src] = True


# Reset counts and alerts every second
def reset_packet_counts():
    global source_ip_count, source_ip_alerted
    while True:
        time.sleep(3)
        source_ip_count.clear()
        source_ip_alerted.clear()

# Start reset thread
reset_thread = threading.Thread(target=reset_packet_counts)
reset_thread.daemon = True
reset_thread.start()

# Start sniffing
print(f"Monitoring for DDoS attacks targeting {MY_IP}...")
sniff(prn=detect_ddos_attack, store=0)