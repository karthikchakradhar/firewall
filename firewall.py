from scapy.all import *
import time
import threading

# Firewall configuration
BLOCKED_IPS = {}  # Dictionary to store blocked IPs and their expiry time
ALLOWED_PORTS = [80, 443]  # Allowed ports (HTTP and HTTPS)
LOG_FILE = "firewall_log.txt"  # Log file for firewall activity

# Function to block an IP address
def block_ip(ip, duration=60):
    """
    Block an IP address for a specified duration (in seconds).
    """
    if ip not in BLOCKED_IPS:
        BLOCKED_IPS[ip] = time.time() + duration
        print(f"Blocked IP: {ip} for {duration} seconds")
        log_activity(f"Blocked IP: {ip} for {duration} seconds")

# Function to unblock an IP address
def unblock_ip(ip):
    """
    Unblock an IP address.
    """
    if ip in BLOCKED_IPS:
        del BLOCKED_IPS[ip]
        print(f"Unblocked IP: {ip}")
        log_activity(f"Unblocked IP: {ip}")

# Function to check and unblock expired IPs
def unblock_expired_ips():
    """
    Periodically check and unblock IPs whose block duration has expired.
    """
    while True:
        current_time = time.time()
        for ip in list(BLOCKED_IPS.keys()):
            if BLOCKED_IPS[ip] < current_time:
                unblock_ip(ip)
        time.sleep(10)  # Check every 10 seconds

# Function to log firewall activity
def log_activity(message):
    """
    Log firewall activity to a file.
    """
    with open(LOG_FILE, "a") as log:
        log.write(f"{time.ctime()}: {message}\n")

# Function to send a "Try Harder" message to intruders
def send_message_to_intruder(ip):
    """
    Send a "Try Harder" message to the intruder's IP.
    """
    try:
        send(IP(dst=ip)/ICMP()/"Try Harder!", verbose=0)
        print(f"Sent 'Try Harder' message to {ip}")
        log_activity(f"Sent 'Try Harder' message to {ip}")
    except Exception as e:
        print(f"Failed to send message to {ip}: {e}")

# Packet processing function
def packet_callback(packet):
    """
    Process each packet and apply firewall rules.
    """
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        # Rule 1: Block packets from blocked IPs
        if src_ip in BLOCKED_IPS:
            print(f"Blocked packet from {src_ip} to {dst_ip}")
            log_activity(f"Blocked packet from {src_ip} to {dst_ip}")
            send_message_to_intruder(src_ip)  # Send a message to the intruder
            return  # Drop the packet

        # Rule 2: Allow traffic only on specific ports (TCP only)
        if TCP in packet:
            dst_port = packet[TCP].dport
            if dst_port not in ALLOWED_PORTS:
                print(f"Blocked packet to port {dst_port} from {src_ip}")
                log_activity(f"Blocked packet to port {dst_port} from {src_ip}")
                block_ip(src_ip, duration=60)  # Block the IP for 60 seconds
                return  # Drop the packet

        # If the packet passes all rules, allow it`~`
        print(f"Allowed packet from {src_ip} to {dst_ip}")
        log_activity(f"Allowed packet from {src_ip} to {dst_ip}")

# Start the firewall
def start_firewall():
    """
    Start the firewall and begin sniffing network traffic.
    """
    print("Starting firewall...")
    log_activity("Firewall started")
    try:
        # Start a thread to unblock expired IPs
        threading.Thread(target=unblock_expired_ips, daemon=True).start()

        # Sniff network traffic and apply the packet_callback function
        sniff(prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("Firewall stopped.")
        log_activity("Firewall stopped")

# Main entry point
if __name__ == "__main__":
    start_firewall()