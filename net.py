import sys
import socket
import csv
import json
import time
from scapy.all import ARP, Ether, srp, sniff
from scapy.layers.inet import IP, TCP, UDP
from collections import defaultdict
import pandas as pd

# Function to scan the network using ARP requests
def arp_scan(network):
    print(f"Scanning network: {network}...")

    # Create ARP request packet
    arp_request = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address
    packet = ether / arp_request

    # Send and receive packets
    result = srp(packet, timeout=3, verbose=False)[0]

    # Parse the results
    devices = []
    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'hostname': resolve_hostname(received.psrc),
            'upload': 0,  # Initialize upload traffic
            'download': 0  # Initialize download traffic
        })

    return devices

# Function to resolve hostname from IP address
def resolve_hostname(ip):
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except socket.herror:
        return "Unknown"

# Function to process packets and track traffic
def process_packet(packet, traffic_data):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Check if the source or destination IP is in the local network
        if src_ip in traffic_data:
            traffic_data[src_ip]['upload'] += len(packet)
        if dst_ip in traffic_data:
            traffic_data[dst_ip]['download'] += len(packet)

# Function to start real-time packet sniffing
def start_realtime_sniffing(devices, interval=10):
    print("Starting real-time packet sniffing...")
    traffic_data = {device['ip']: device for device in devices}

    def periodic_display():
        while True:
            time.sleep(interval)
            display_top_devices(list(traffic_data.values()))
            save_to_json(list(traffic_data.values()))
            save_to_csv(list(traffic_data.values()))

    # Start a separate thread for periodic display and saving
    import threading
    display_thread = threading.Thread(target=periodic_display, daemon=True)
    display_thread.start()

    # Start sniffing packets
    sniff(filter="ip", prn=lambda pkt: process_packet(pkt, traffic_data), store=False)

# Function to save results to a JSON file
def save_to_json(devices, filename="network_traffic.json"):
    with open(filename, 'w') as f:
        json.dump(devices, f, indent=4)
    print(f"Results saved to {filename}")

# Function to save results to a CSV file
def save_to_csv(devices, filename="network_traffic.csv"):
    fieldnames = ['ip', 'mac', 'hostname', 'upload', 'download']
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for device in devices:
            writer.writerow(device)
    print(f"Results saved to {filename}")

# Function to display top upload/download devices
def display_top_devices(devices, top_n=5):
    df = pd.DataFrame(devices)
    print("\nTop Devices by Upload Traffic:")
    print(df.nlargest(top_n, 'upload')[['ip', 'mac', 'hostname', 'upload']])
    print("\nTop Devices by Download Traffic:")
    print(df.nlargest(top_n, 'download')[['ip', 'mac', 'hostname', 'download']])

# Main function
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network_realtime_monitor.py <network>")
        print("Example: python network_realtime_monitor.py 192.168.1.0/24")
        sys.exit(1)

    network = sys.argv[1]

    # Perform ARP scan to discover devices
    print("Starting ARP scan...")
    devices = arp_scan(network)
    print(f"Found {len(devices)} devices on the network.")

    # Start real-time packet sniffing
    print("Starting real-time network traffic monitoring...")
    try:
        start_realtime_sniffing(devices, interval=10)  # Update every 10 seconds
    except KeyboardInterrupt:
        print("\nMonitoring stopped.")