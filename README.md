# firewall
Below is an **enhanced Python firewall script** that includes the following features:

1. **Block and Unblock IPs**: Functions to dynamically block and unblock IP addresses.
2. **Handling Packets**: Inspect and filter packets based on rules.
3. **Checking Logs**: Log blocked and allowed packets to a file.
4. **Unblock Expired IPs**: Automatically unblock IPs after a specified time.
5. **Message Intruders**: Send a "Try Harder" message to intruders.

---

### **Step-by-Step Implementation**

---

### **Step 1: Install Required Libraries**
Install `scapy` for packet manipulation and `threading` for handling IP unblocking:
```bash
pip install scapy
```

---

### **Step 2: Write the Python Script**
download the firewall.py

---

### **Step 3: Run the Script**
1. Save the script to a file, e.g., `firewall.py`.
2. Run the script with administrative privileges:
   ```bash
   sudo python3 firewall.py
   ```

---

### **Step 4: Test the Firewall**
1. Send traffic to the machine running the script.
2. Observe the output in the terminal and the log file (`firewall_log.txt`).
3. Test blocking and unblocking IPs dynamically.

---

### **Key Features**
1. **Block and Unblock IPs**:
   - Use `block_ip(ip, duration)` to block an IP for a specified duration.
   - Use `unblock_ip(ip)` to unblock an IP manually.
2. **Handle Packets**:
   - Inspect packets and apply rules (blocked IPs, allowed ports).
3. **Check Logs**:
   - All firewall activity is logged to `firewall_log.txt`.
4. **Unblock Expired IPs**:
   - IPs are automatically unblocked after the specified duration.
5. **Message Intruders**:
   - Send a "Try Harder" message to intruders using ICMP packets.

---

### **Example Log File (`firewall_log.txt`)**
```
Wed Oct 18 12:00:00 2023: Firewall started
Wed Oct 18 12:00:05 2023: Blocked IP: 192.168.1.100 for 60 seconds
Wed Oct 18 12:00:05 2023: Sent 'Try Harder' message to 192.168.1.100
Wed Oct 18 12:00:10 2023: Allowed packet from 192.168.1.101 to 192.168.1.1
Wed Oct 18 12:01:05 2023: Unblocked IP: 192.168.1.100
```

---

### **Customization**
- Modify `ALLOWED_PORTS` to allow additional ports.
- Adjust the block duration in `block_ip()`.
- Enhance the "Try Harder" message or use a different protocol (e.g., TCP).

