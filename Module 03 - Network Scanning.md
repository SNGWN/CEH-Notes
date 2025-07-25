## TCP vs UDP
	- TCP and UDP (Transmission Control Protocol and User Datagram Protocol) are communications protocol that facilitate the exchange of message (in form of Packets) between computer devices in a network. These protocols decide how packet will reach the destination. 65535
		TCP								UDP
	- Connection Oriented Protocol					- Connection Less protocol
	- Provides Error checking					- No Error Checking Mechanism
	- Guarantees Delivery of Data					- No Guarantees of Data Delivery
	- Slower and less efficient for fast transmission		- Faster Transmission
	- All Packets follow the same path				- Packets can follow any path to reach destination
	- Automimic Retransmission possible  				- Retransmission is not possible in case of Packets loss
---------------------------------------------------
## TCP Flags:
	- SYN : Sync flag is used to Initiate 3 way handshake between hosts.
	- ACK : Acknowledgment flag is used to acknowledge the successful receipt of a packet.
	- FIN : The Finished flag means there is no more data from the sender.  1GB --> 50000 --> 1,2,3,4,5,6,.........50000 (FIN)
	- URG : The Urgent flag is used to notify the receiver to process the urgent packets before processing all other packets.
	- PSH : The Push flag is somewhat similar to the URG flag and tells the receiver to process these packets as they are received instead of buffering them.
	- RST : Reset a Connection
---------------------------------------------------
## TCP 3 Way Handshake:
	_____________________________________________
	|    Client	|   Direction 	|   Server  |
	|:-------------:|:-------------:|:---------:|
	|    SYN    	| ---->     	|           |
	|		|     	  <----	|  SYN+ACK  |
	|    ACK 	| ---->     	|           |


## OSI Model
	_________________________________________________________________________________________________________
	| Layer ||       Name         ||		Description			||  Example protocols	|	
	|:-----:||:------------------:||:----------------------------------------------:||:--------------------:|
	|   7   || Application layer  || Human Computer Interaction Layer.		|| 	HTTP, SNMP	|
	|   6   || Presentation layer || Ensure Data Usability Format		    	||	MIME, ASCII	|
	|   5   || Session layer      || Maintain Con. and control Ports and Session	||	SOCKS, NetBIOS 	|
	|   4   || Transport layer    || Data Transmission by TCP or UDP		||	TCP, UDP       	|
	|   3   || Network layer      || Decide Physical Path for Transmission		||   	IP, ICMP      	|
	|   2   || Data link layer    || Read MAC Address from data packet		||	MAC, ARP	|
	|   1   || Physical layer     || Physical connection				||	Ethernet, Wi-Fi	|

## TCP/IP Model
	__________________________________________________
	| Layer |       Name         | Example protocols |
	|:-----:|:------------------:|:-----------------:|
	|   4   | Application layer  |    HTTP, SNMP     |
	|   3   | Transport layer    |    TCP, UDP       |
	|   2   | Internet layer     |    IP, ICMP       |
	|   1   | Link layer         |    ARP, MAC       |
---------------------------------------------------------------------------------------------------------------
# Practical Part
------------------
## Main Objectives
	k1. Scan live host
	k2. Open Ports and Running Services
	k3. OS and Architecture info
	k4. Security Implemented (Firewall, IDS, IPS) Detection and evasion

## k1. Live hosts
	arp-scan --local
	nmap -sn <network>/<cidr>					-sn specify NO-Port Ping Scan
	ping <ip>
	netdiscover -r <network address>/<cidr>
--------------------------------------------------------------------------
## Nmap Port Scan Status
	Open - If No response is received by Nmap, it means Port is Open for connection.
	Closed - If response is received by nmap with RST or SYN flag, it means ports are closed.
	Filtered - May be some kind of firewall is implemented on client side.
	Open/Filtered - Nmap is confused, either port is open or filtered.
	Closed/Filtered - Nmap is confused, either port is closed or filtered
--------------------------------------------------------------------------
## k2. Open Ports and Running Services Scan
	Nmap
		nmap <ip>				Simple Port Scan
		nmap -v <ip>				Port Scan with increase verbosity. (-vv is more powerful)
		nmap <ip> <ip> <ip>			Scan Multiple host in single go
		nmap <1.1.1.2-200>			Scan IP Range from 2 to 200
		nmap <network>/cidr			Scan Entire Subnet
		nmap -p 1-65535 <ip>			-p specify Port Numbers to scan.
		nmap -p U:<port>,T:<port> <ip>		Scan specified TCP and UDP ports. use "" for all.
		nmap -sU <ip>				Scan 1000 Common UDP Ports
		nmap -T<0-5> <ip>			-T specify intensity of scan to time taken by scan. 5 is fastest and 0 is slowest. Default Speed is 3(-T3).
		nmap -sT <ip>				TCP Connect Scan
		nmap -iL list.txt			Scan ip written in list.txt file (Separate IP by Space, Tab or New Line). --exclude file list.txt (to exclude ip from search)
		nmap -A <ip>				Aggressive Scan (it use -O -sC --traceroute -sV) options
		nmap -O <ip>				-O is used for OS Detection
		nmap -sC <ip>				-sC is used to run Default NSE Scripts  --- --script
		nmap -sV <ip>				-sv is used for Service Version Detection
		nmap -6 <ip>				IPv6 Scan
		nmap -sS <ip>				Sync Scan/Ping. Helpful in case where ICMP pings are blocked.
		nmap -sA <ip>				ACK Scan/Ping. Helpful in case where ICMP pings are blocked. Null Scan
		nmap --scanflags SYNACKFIN <ip>		We can set flags using --scanflags option.
		nmap -Pn <ip>				Don't Ping Scan (When Firewall block Ping Packets)
		nmap -sR <ip>				Scan for RPC (Remote Procedure Call) Service
	Hping3
		hping3 --icmp <ip> --verbose		Ping Scan in Verbose
		hping3 --scan <ports> <ip>		Scan for Open Ports on IP (--ack, --syn, --fin, --urg)
		hping3 --udp <ip> --verbose		UDP port Scan in Verbose

--------------------------------------------------------------------------
## k3. Security Implemented (Firewall, IDS, IPS) Detection and evasion
	nmap -f <ip>				-f will fragment packets in 8-byte packets. Helpful when attempting to evade some older or improperly configured firewall or we can specify packet fragment size using --mtu <size>" option. Size should be multiple of 8
	nmap -D RND:<val> <ip>			-D Decoy option is used to mask an Nmap scan by using one or more decoys. Decoy is used to hide identity. RND is Number of Decoy Address to be used. We can also specify Addresses by our own. as nmap -D decoy1,decoy2,decoy3,etc <ip>
	nmap -sX <ip>				Nmap XMas Scan (if Firewall is enable you get (all thousand ports are closed/filtered), if Firewall is disable you get (Closed). Xmas Scan use PSH+URG+FIN flag or All flag for packets and create abnormal situation for client for which client either respond with RST Flag or some relevant info.
--------------------------------------------------------------------------
## We can also use Zenmap
--------------------------------------------------------------------------

# Advanced Network Scanning Techniques and Payloads

## Stealth and Evasion Techniques
```bash
# Advanced Nmap Evasion
nmap -sS -f -D RND:10 --randomize-hosts --spoof-mac 0 target  # Stealth SYN scan with fragmentation and decoys
nmap -sA -T1 --scan-delay 5s target                           # ACK scan with slow timing
nmap --script-timeout 30s --host-timeout 300s target         # Custom timeouts

# Custom TCP Flags
nmap --scanflags SYNFINPSH target                             # Custom flag combination
hping3 -S -p 80 -c 1 target                                  # Custom SYN packet
hping3 -A -p 80 -c 1 target                                  # Custom ACK packet
```

**Documentation**: Advanced evasion techniques to bypass firewalls and IDS/IPS systems.
**Limitations**: May be detected by modern security systems; some techniques are noisy.

## Service Version Detection and OS Fingerprinting
```bash
# Aggressive Service Detection
nmap -sV --version-intensity 9 target                        # Maximum version detection
nmap -O --osscan-guess target                                # OS detection with guessing
nmap -A --script vuln target                                 # Aggressive scan with vulnerability scripts

# Banner Grabbing
nc -nv target 21                                            # Manual FTP banner grab
nc -nv target 22                                            # SSH banner grab
curl -I http://target                                       # HTTP header grab
telnet target 25                                            # SMTP banner grab
```

**Documentation**: Detailed service enumeration and OS identification for vulnerability assessment.
**Limitations**: Aggressive scans are easily detected; may trigger security alerts.

## NSE (Nmap Scripting Engine) Advanced Usage
```bash
# Vulnerability Discovery Scripts
nmap --script vuln target                                   # All vulnerability scripts
nmap --script smb-vuln-* target                            # SMB vulnerability scripts
nmap --script http-vuln-* target                           # HTTP vulnerability scripts
nmap --script ssl-* target                                 # SSL/TLS scripts

# Brute Force Scripts
nmap --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt target
nmap --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt target
nmap --script http-brute --script-args userdb=users.txt,passdb=pass.txt target

# Information Gathering Scripts
nmap --script dns-brute target                             # DNS brute force
nmap --script smb-enum-shares target                       # SMB share enumeration
nmap --script http-enum target                             # HTTP directory enumeration
```

**Documentation**: Leverages NSE for automated vulnerability detection and service enumeration.
**Limitations**: Scripts may be outdated; some may cause service disruption.

## UDP Scanning and Service Discovery
```bash
# Comprehensive UDP Scanning
nmap -sU --top-ports 1000 target                           # Top 1000 UDP ports
nmap -sU -p 53,67,68,69,123,161,162,500,514,1434 target   # Common UDP services
unicornscan -mU target                                     # Alternative UDP scanner

# SNMP Enumeration
snmpwalk -c public -v1 target                              # SNMP walk with public community
snmpcheck -t target                                        # SNMP security check
onesixtyone -c community.txt target                        # SNMP community brute force
```

**Documentation**: Identifies UDP services which are often overlooked in security assessments.
**Limitations**: UDP scanning is slower and less reliable than TCP; may produce false positives.

## Masscan - High-Speed Port Scanning
```bash
# Mass Port Scanning
masscan -p1-65535 target --rate=1000                       # Full port range scan
masscan -p80,443,8080,8443 0.0.0.0/0 --rate=10000        # Internet-wide scan (use responsibly)
masscan -p22 192.168.1.0/24 --rate=1000 --banners        # SSH service discovery with banners

# Masscan with Nmap Follow-up
masscan -p1-65535 target --rate=1000 -oG masscan.out
nmap -sV -iL masscan_targets.txt                           # Version detection on discovered ports
```

**Documentation**: Ultra-fast port scanning for large networks and internet-wide reconnaissance.
**Limitations**: High-speed scans may overwhelm targets; requires careful rate limiting.

## Network Discovery and Host Enumeration
```bash
# ARP Scanning (Local Network)
arp-scan -l                                                # Local network ARP scan
arp-scan 192.168.1.0/24                                  # Specific subnet ARP scan
netdiscover -r 192.168.1.0/24 -P                         # Passive network discovery

# ICMP Scanning Variations
nmap -sn -PE target                                       # ICMP Echo ping
nmap -sn -PP target                                       # ICMP Timestamp ping
nmap -sn -PM target                                       # ICMP Address Mask ping
fping -a -g 192.168.1.0/24                               # Fast ping sweep
```

**Documentation**: Discovers live hosts using various network protocols and techniques.
**Limitations**: ICMP may be blocked by firewalls; ARP scanning limited to local subnet.

## IPv6 Scanning Techniques
```bash
# IPv6 Discovery and Scanning
nmap -6 target_ipv6                                       # Basic IPv6 scan
nmap -6 -sS target_ipv6                                   # IPv6 SYN scan
alive6 eth0                                               # IPv6 alive scan
thc-ipv6 -i eth0                                         # THC IPv6 toolkit

# IPv6 Address Generation
atk6-address6 target_prefix                               # Generate IPv6 addresses
atk6-detect-new-ip6 eth0                                  # Detect new IPv6 addresses
```

**Documentation**: Scans IPv6 networks which are often less monitored than IPv4.
**Limitations**: IPv6 scanning requires different techniques; address space is much larger.

## Firewall and IDS Evasion Advanced Techniques
```bash
# Source Port Manipulation
nmap -g 53 target                                         # Source port 53 (DNS)
nmap -g 88 target                                         # Source port 88 (Kerberos)
hping3 -S -p 80 -s 53 target                            # Custom source port with hping3

# IP ID and Sequence Manipulation
nmap -sI zombie_host target                               # IDLE scan using zombie host
nmap --ip-options "L 192.168.1.1,192.168.1.2" target    # Loose source routing

# MTU and Fragmentation
nmap -f --mtu 24 target                                   # Custom MTU fragmentation
nmap --send-ip target                                     # Raw IP packets
```

**Documentation**: Advanced evasion techniques to bypass network security controls.
**Limitations**: Modern firewalls may detect these techniques; some may require root privileges.

# Network Scanning Automation Scripts

## Bash Script for Comprehensive Network Scan
```bash
#!/bin/bash
# comprehensive_scan.sh - Automated network reconnaissance

TARGET=$1
LOGDIR="scan_results_$(date +%Y%m%d_%H%M%S)"

mkdir -p $LOGDIR

# Host discovery
echo "[+] Performing host discovery..."
nmap -sn $TARGET > $LOGDIR/host_discovery.txt

# Port scanning
echo "[+] Performing port scan..."
nmap -sS -T4 $TARGET > $LOGDIR/port_scan.txt

# Service detection
echo "[+] Performing service detection..."
nmap -sV $TARGET > $LOGDIR/service_detection.txt

# Vulnerability scanning
echo "[+] Performing vulnerability scan..."
nmap --script vuln $TARGET > $LOGDIR/vulnerability_scan.txt

echo "[+] Scan complete. Results saved in $LOGDIR/"
```

**Documentation**: Automated scanning workflow for comprehensive network assessment.
**Limitations**: May trigger security alerts; requires careful timing in production environments.

# Reference URLs and Research Papers:
- Nmap Official Documentation: https://nmap.org/book/
- NIST SP 800-115 Network Security Testing: https://csrc.nist.gov/publications/detail/sp/800-115/final
- Fyodor's Original Nmap Paper: https://nmap.org/misc/nmap_doc.html
- Research Paper: "Network Scanning Techniques and Defense" - https://ieeexplore.ieee.org/document/8444985
- SANS Network Security Monitoring: https://www.sans.org/reading-room/whitepapers/detection/
- RFC 793 - TCP Protocol: https://tools.ietf.org/html/rfc793
- IPv6 Security Research: https://www.ipv6security.org/
- Masscan Documentation: https://github.com/robertdavidgraham/masscan
