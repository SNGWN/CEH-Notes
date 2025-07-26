# Module 03 - Network Scanning

## Learning Objectives

- Understand network protocol fundamentals (TCP/UDP, OSI/TCP-IP models)
- Master network discovery and host enumeration techniques
- Learn comprehensive port scanning methodologies
- Develop skills in service version detection and OS fingerprinting
- Understand firewall and IDS evasion techniques
- Explore advanced scanning tools and automation strategies
- Master Nmap Scripting Engine (NSE) for vulnerability detection

---

## Network Protocol Fundamentals

### TCP vs UDP Comparison

**TCP (Transmission Control Protocol)** and **UDP (User Datagram Protocol)** are core transport layer protocols that define how data packets are transmitted across networks.

| Characteristic | TCP | UDP |
|:---------------|:----|:----|
| **Connection Type** | Connection-oriented protocol | Connectionless protocol |
| **Reliability** | Provides error checking and correction | No error checking mechanism |
| **Data Delivery** | Guarantees delivery of data | No guarantees of data delivery |
| **Transmission Speed** | Slower due to overhead | Faster transmission |
| **Packet Routing** | All packets follow the same path | Packets can follow any path |
| **Retransmission** | Automatic retransmission possible | No retransmission capability |
| **Use Cases** | Web browsing, email, file transfer | Streaming, gaming, DNS queries |

### TCP Control Flags

#### Core TCP Flags
- **SYN (Synchronize)**: Initiates three-way handshake between hosts
- **ACK (Acknowledgment)**: Acknowledges successful packet receipt
- **FIN (Finished)**: Indicates no more data from sender
- **RST (Reset)**: Immediately terminates connection
- **PSH (Push)**: Forces immediate processing of buffered data
- **URG (Urgent)**: Indicates urgent data that should be processed immediately

#### TCP Three-Way Handshake

```
┌─────────────┐                    ┌─────────────┐
│   Client    │                    │   Server    │
└─────────────┘                    └─────────────┘
       │                                  │
       │ 1. SYN (seq=x)                  │
       │ ──────────────────────────────► │
       │                                  │
       │ 2. SYN-ACK (seq=y, ack=x+1)    │
       │ ◄────────────────────────────── │
       │                                  │
       │ 3. ACK (seq=x+1, ack=y+1)      │
       │ ──────────────────────────────► │
       │                                  │
       │    [Connection Established]      │
```

**Security Implications**:
- **SYN flood attacks**: Overwhelming server with SYN requests
- **Connection hijacking**: Exploiting sequence number prediction
- **Port scanning detection**: Analyzing handshake responses

---

## Network Models and Architecture

### OSI (Open Systems Interconnection) Model

| Layer | Name | Description | Example Protocols |
|:-----:|:-----|:------------|:------------------|
| **7** | Application | Human-computer interaction interface | HTTP, HTTPS, FTP, SMTP, DNS |
| **6** | Presentation | Data formatting, encryption, compression | TLS/SSL, JPEG, PNG, ASCII |
| **5** | Session | Session management and control | NetBIOS, RPC, SQL sessions |
| **4** | Transport | Reliable data transmission | TCP, UDP, SCTP |
| **3** | Network | Routing and logical addressing | IP, ICMP, OSPF, BGP |
| **2** | Data Link | Node-to-node data transfer | Ethernet, Wi-Fi, ARP |
| **1** | Physical | Physical transmission medium | Cables, radio waves, fiber optic |

### TCP/IP Model

| Layer | Name | Description | Example Protocols |
|:-----:|:-----|:------------|:------------------|
| **4** | Application | Application-level protocols | HTTP, HTTPS, FTP, SSH, Telnet |
| **3** | Transport | Host-to-host communication | TCP, UDP |
| **2** | Internet | Internetworking and routing | IP, ICMP, ARP |
| **1** | Link | Network interface and hardware | Ethernet, Wi-Fi, PPP |

**Security Considerations**:
- **Layer-specific attacks**: Each layer presents unique vulnerabilities
- **Protocol analysis**: Understanding protocols aids in vulnerability assessment
- **Defense in depth**: Security controls at multiple layers

---

## Network Scanning Fundamentals

### Core Scanning Objectives

#### 🎯 Primary Goals
1. **Live host discovery**: Identify active systems on the network
2. **Port enumeration**: Discover open ports and running services
3. **Service identification**: Determine service versions and configurations
4. **Operating system detection**: Fingerprint target system architecture
5. **Security posture assessment**: Identify firewalls, IDS/IPS systems

#### 📊 Scanning Methodology
1. **Reconnaissance**: Gather target information and network topology
2. **Discovery**: Identify live hosts and network ranges
3. **Enumeration**: Discover ports, services, and system details
4. **Vulnerability assessment**: Identify potential security weaknesses
5. **Documentation**: Record findings for analysis and reporting

---

## Host Discovery Techniques

### 🔍 Network Discovery Methods

#### ARP-Based Discovery (Local Network)
```bash
# ARP scanning for local subnet discovery
arp-scan --local                            # Scan local network segment
arp-scan 192.168.1.0/24                    # Specific subnet ARP scan
arp-scan -I eth0 192.168.1.0/24            # Interface-specific scan
netdiscover -r 192.168.1.0/24              # Active network discovery
netdiscover -r 192.168.1.0/24 -P           # Passive network discovery
```

**Advantages**: Fast, reliable for local networks, bypasses IP-level filtering
**Limitations**: Only works on local subnet, may trigger ARP monitoring

#### ICMP-Based Discovery
```bash
# ICMP ping sweeps
nmap -sn 192.168.1.0/24                    # No port scan ping sweep
nmap -sn -PE 192.168.1.0/24                # ICMP Echo ping
nmap -sn -PP 192.168.1.0/24                # ICMP Timestamp ping  
nmap -sn -PM 192.168.1.0/24                # ICMP Address Mask ping
fping -a -g 192.168.1.0/24                 # Fast ping alternative
```

**Advantages**: Quick host identification, standard network diagnostic
**Limitations**: Often blocked by firewalls, may not reflect actual host status

#### TCP/UDP-Based Discovery
```bash
# TCP SYN discovery
nmap -sn -PS22,80,443 192.168.1.0/24       # TCP SYN ping to specific ports
nmap -sn -PA80,443 192.168.1.0/24          # TCP ACK ping

# UDP discovery
nmap -sn -PU53,67,123 192.168.1.0/24       # UDP ping to specific ports
```

**Advantages**: Bypasses ICMP filtering, targets specific services
**Limitations**: May trigger security alerts, slower than ICMP

---

## Port Scanning Techniques

### 🔍 Nmap Port Scan Types

#### TCP Connect Scanning
```bash
# TCP Connect scans (complete three-way handshake)
nmap -sT target                             # Basic TCP connect scan
nmap -sT -p 1-65535 target                 # Full port range scan
nmap -sT -p- target                        # All 65535 ports
nmap -sT --top-ports 1000 target           # Top 1000 most common ports
```

**Characteristics**: 
- **Stealth level**: Low (creates full connections)
- **Accuracy**: High (definitive open/closed status)
- **Speed**: Slower due to full handshake
- **Detection**: Easily logged and detected

#### SYN Stealth Scanning
```bash
# SYN stealth scans (half-open scanning)
nmap -sS target                             # Basic SYN scan
nmap -sS -T4 target                        # Faster timing template
nmap -sS -p 80,443,22,21,25 target         # Specific port list
nmap -sS --scan-delay 1s target            # Custom delay between probes
```

**Characteristics**:
- **Stealth level**: Higher (no full connection established)
- **Accuracy**: High for determining port state
- **Speed**: Fast (no connection teardown)
- **Detection**: More difficult to detect than TCP connect

#### Advanced Scan Types
```bash
# Specialized scan techniques
nmap -sA target                             # ACK scan (firewall detection)
nmap -sW target                             # Window scan (OS detection)
nmap -sM target                             # Maimon scan (FIN/ACK)
nmap -sN target                             # Null scan (no flags set)
nmap -sF target                             # FIN scan (FIN flag only)
nmap -sX target                             # Xmas scan (FIN+PSH+URG flags)
```

**Use Cases**:
- **ACK scans**: Firewall rule testing and bypass
- **FIN/NULL/Xmas scans**: Evasion of simple packet filters
- **Window scans**: Operating system fingerprinting

### 📊 Port State Interpretation

#### Nmap Port States
- **Open**: Service actively listening and accepting connections
- **Closed**: Port accessible but no service listening
- **Filtered**: Packet filtered by firewall, no response received
- **Unfiltered**: Port accessible but unknown if open or closed
- **Open|Filtered**: Cannot determine if open or filtered
- **Closed|Filtered**: Cannot determine if closed or filtered

---

## Service Detection and Version Enumeration

### 🔍 Service Version Detection

#### Basic Service Enumeration
```bash
# Service version detection
nmap -sV target                             # Basic service version scan
nmap -sV --version-intensity 0 target      # Light version detection
nmap -sV --version-intensity 9 target      # Aggressive version detection
nmap -sV --version-all target              # Try all probes
```

#### Advanced Service Analysis
```bash
# Comprehensive service analysis
nmap -A target                              # Aggressive scan (OS+Version+Scripts+Traceroute)
nmap -sC -sV target                        # Default scripts with version detection
nmap -O target                             # Operating system detection
nmap -sV -O --osscan-guess target          # OS detection with guessing
```

### 🎯 Banner Grabbing Techniques

#### Manual Banner Grabbing
```bash
# Direct service interaction
nc -nv target 21                           # FTP banner grabbing
nc -nv target 22                           # SSH version information
nc -nv target 25                           # SMTP service banner
nc -nv target 80                           # HTTP server information
telnet target 110                          # POP3 service banner

# HTTP-specific banner grabbing
curl -I http://target                      # HTTP headers only
wget --server-response --spider http://target # Server response headers
```

#### Automated Banner Grabbing
```bash
# Nmap banner grabbing scripts
nmap --script banner target                # Generic banner grabbing
nmap --script http-headers target          # HTTP header enumeration
nmap --script smtp-commands target         # SMTP command enumeration
nmap --script ssh2-enum-algos target       # SSH algorithm enumeration
```

---

## Operating System Detection

### 🖥️ OS Fingerprinting Techniques

#### Active OS Fingerprinting
```bash
# Nmap OS detection
nmap -O target                             # Basic OS detection
nmap -O --osscan-limit target              # Limit to promising targets
nmap -O --osscan-guess target              # Aggressive OS guessing
nmap -O --max-os-tries 2 target            # Limit OS detection attempts
```

#### OS Detection Methods
- **TCP ISN analysis**: Initial sequence number patterns
- **TCP options analysis**: Window size, option order patterns
- **ICMP analysis**: Response patterns and error handling
- **UDP analysis**: Closed port response behavior

#### Passive OS Fingerprinting
```bash
# p0f passive OS fingerprinting
p0f -i eth0 -p                             # Passive analysis of traffic
p0f -f /etc/p0f/p0f.fp -r capture.pcap    # Analysis of packet capture

# Alternative passive tools
ettercap -T -M arp:remote target           # Passive scanning with ettercap
```

**Advantages**: Completely passive, no packets sent to target
**Limitations**: Requires network traffic analysis, less detailed information

---

## UDP Scanning Methodology

### 📡 UDP Service Discovery

#### Comprehensive UDP Scanning
```bash
# UDP port scanning
nmap -sU target                            # Top 1000 UDP ports
nmap -sU --top-ports 100 target           # Top 100 UDP ports
nmap -sU -p 53,67,68,69,123,161,162 target # Common UDP services
nmap -sU -sV target                        # UDP scan with version detection
```

#### Common UDP Services
- **Port 53**: DNS (Domain Name System)
- **Port 67/68**: DHCP (Dynamic Host Configuration Protocol)
- **Port 69**: TFTP (Trivial File Transfer Protocol)
- **Port 123**: NTP (Network Time Protocol)
- **Port 161/162**: SNMP (Simple Network Management Protocol)
- **Port 500**: IKE (Internet Key Exchange)
- **Port 514**: Syslog
- **Port 1434**: MS SQL Server Browser

#### UDP Scanning Challenges
- **Reliability issues**: UDP is connectionless, responses not guaranteed
- **False positives**: Firewalls may drop packets silently
- **Speed limitations**: Slower than TCP scanning due to rate limiting

---

## Nmap Scripting Engine (NSE)

### 🔧 NSE Categories and Usage

#### Vulnerability Detection Scripts
```bash
# Comprehensive vulnerability scanning
nmap --script vuln target                  # All vulnerability scripts
nmap --script vuln,safe target             # Safe vulnerability scripts only
nmap --script smb-vuln-* target            # SMB-specific vulnerabilities
nmap --script http-vuln-* target           # HTTP vulnerability scripts
nmap --script ssl-* target                 # SSL/TLS security scripts
```

#### Service Enumeration Scripts
```bash
# Service-specific enumeration
nmap --script smb-enum-* target            # SMB enumeration scripts
nmap --script dns-* target                 # DNS enumeration scripts
nmap --script http-enum target             # HTTP directory enumeration
nmap --script ftp-* target                 # FTP service scripts
nmap --script ssh-* target                 # SSH enumeration scripts
```

#### Brute Force Scripts
```bash
# Authentication brute forcing
nmap --script ssh-brute --script-args userdb=users.txt,passdb=pass.txt target
nmap --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt target
nmap --script http-brute --script-args userdb=users.txt,passdb=pass.txt target
nmap --script smb-brute --script-args userdb=users.txt,passdb=pass.txt target
```

#### Custom Script Parameters
```bash
# Script argument customization
nmap --script http-enum --script-args http-enum.basepath='/admin/' target
nmap --script smb-enum-shares --script-args smbdomain=WORKGROUP target
nmap --script ssl-cert --script-args ssl-cert.timeout=5s target
```

---

## Advanced Scanning Techniques

### 🥷 Stealth and Evasion Methods

#### Timing and Performance Tuning
```bash
# Timing templates (0-5, slowest to fastest)
nmap -T0 target                            # Paranoid timing (5+ minutes between probes)
nmap -T1 target                            # Sneaky timing (15 seconds between probes)
nmap -T2 target                            # Polite timing (0.4 seconds between probes)
nmap -T3 target                            # Normal timing (default)
nmap -T4 target                            # Aggressive timing
nmap -T5 target                            # Insane timing (fastest)

# Custom timing controls
nmap --min-rate 100 target                 # Minimum packet rate
nmap --max-rate 1000 target                # Maximum packet rate
nmap --scan-delay 2s target                # Delay between probes
nmap --max-retries 2 target                # Maximum probe retries
```

#### Packet Fragmentation
```bash
# Fragmentation techniques
nmap -f target                             # Fragment packets into 8-byte chunks
nmap -ff target                            # Fragment into 16-byte chunks
nmap --mtu 24 target                       # Custom MTU size (multiple of 8)
nmap --data-length 25 target               # Append random data to packets
```

#### Source Address Manipulation
```bash
# Decoy scanning
nmap -D RND:10 target                      # 10 random decoy addresses
nmap -D decoy1,decoy2,decoy3 target        # Specific decoy addresses
nmap -D RND:5,ME target                    # 5 decoys plus real address

# Source port manipulation
nmap -g 53 target                          # Source port 53 (DNS)
nmap -g 88 target                          # Source port 88 (Kerberos)
nmap --source-port 53 target               # Alternative syntax

# IDLE/Zombie scanning
nmap -sI zombie_host target                # IDLE scan using zombie host
```

#### Advanced Evasion Techniques
```bash
# Firewall and IDS evasion
nmap -f -D RND:10 --randomize-hosts target # Multiple evasion techniques
nmap --spoof-mac 0 target                  # Random MAC address spoofing
nmap --spoof-mac Dell target               # Vendor-specific MAC spoofing
nmap --ip-options "L 192.168.1.1" target  # Loose source routing
nmap --ttl 64 target                       # Custom TTL value
```

---

## High-Speed Scanning with Masscan

### ⚡ Masscan Configuration and Usage

#### Basic Masscan Operations
```bash
# High-speed port scanning
masscan -p1-65535 target --rate=1000       # Full port range at 1000 pps
masscan -p80,443,8080,8443 target --rate=10000 # Specific ports at high speed
masscan --top-ports 100 target --rate=5000 # Top 100 ports scan

# Output formatting
masscan -p1-65535 target --rate=1000 -oG masscan.out # Grepable output
masscan -p1-65535 target --rate=1000 -oJ masscan.json # JSON output
masscan -p1-65535 target --rate=1000 -oX masscan.xml # XML output
```

#### Masscan with Nmap Integration
```bash
# Two-stage scanning approach
# Stage 1: Fast port discovery with masscan
masscan -p1-65535 target --rate=5000 -oG discovered_ports.txt

# Stage 2: Detailed analysis with nmap
nmap -sV -sC -iL discovered_ports.txt -p $(cat discovered_ports.txt | grep "Host:" | cut -d' ' -f5 | cut -d'/' -f1 | sort -u | tr '\n' ',' | sed 's/,$//')
```

### 🌐 Large-Scale Network Scanning

#### Internet-Wide Scanning Considerations
```bash
# Responsible internet scanning
masscan -p80,443 0.0.0.0/0 --rate=1000 --excludefile exclude.txt
# Note: Always include exclude files for critical infrastructure

# Network range scanning
masscan -p22,80,443 10.0.0.0/8 --rate=10000 --randomize-hosts
masscan -p1-1000 192.168.0.0/16 --rate=5000 --wait=5
```

**Ethical Considerations**:
- **Rate limiting**: Avoid overwhelming target networks
- **Exclude lists**: Respect network operator preferences
- **Legal compliance**: Ensure proper authorization for scanning
- **Responsible disclosure**: Report critical vulnerabilities appropriately

---

## IPv6 Scanning Strategies

### 🌏 IPv6 Network Discovery

#### IPv6 Address Discovery
```bash
# IPv6 host discovery
nmap -6 target_ipv6                        # Basic IPv6 scan
nmap -6 -sn 2001:db8::/32                  # IPv6 ping sweep
alive6 eth0                                # IPv6 alive host detection

# IPv6 address enumeration
atk6-address6 2001:db8::1                  # Generate potential addresses
atk6-detect-new-ip6 eth0                   # Detect new IPv6 addresses
```

#### IPv6 Scanning Challenges
- **Address space size**: 128-bit addresses create enormous search space
- **Address allocation patterns**: Understanding common IPv6 addressing schemes
- **Reduced toolset**: Fewer tools support comprehensive IPv6 scanning
- **Security assumptions**: IPv6 networks often have weaker security controls

---

## Automation and Scripting

### 🤖 Automated Scanning Workflows

#### Comprehensive Scanning Script
```bash
#!/bin/bash
# network_scanner.sh - Automated network reconnaissance

TARGET=$1
OUTPUT_DIR="scan_$(date +%Y%m%d_%H%M%S)"
THREADS=50

if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target_network>"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
echo "[*] Starting comprehensive network scan of $TARGET"
echo "[*] Results will be saved in $OUTPUT_DIR"

# Phase 1: Host Discovery
echo "[+] Phase 1: Host Discovery"
nmap -sn "$TARGET" | grep "Nmap scan report" | awk '{print $5}' > "$OUTPUT_DIR/live_hosts.txt"
host_count=$(wc -l < "$OUTPUT_DIR/live_hosts.txt")
echo "[+] Discovered $host_count live hosts"

# Phase 2: Port Scanning
echo "[+] Phase 2: Port Scanning"
nmap -sS -T4 -iL "$OUTPUT_DIR/live_hosts.txt" -oN "$OUTPUT_DIR/port_scan.nmap" \
     -oG "$OUTPUT_DIR/port_scan.gnmap" -oX "$OUTPUT_DIR/port_scan.xml"

# Phase 3: Service Detection
echo "[+] Phase 3: Service Detection"
nmap -sV -sC -iL "$OUTPUT_DIR/live_hosts.txt" -oN "$OUTPUT_DIR/service_scan.nmap" \
     -oX "$OUTPUT_DIR/service_scan.xml"

# Phase 4: Vulnerability Assessment
echo "[+] Phase 4: Vulnerability Assessment"
nmap --script vuln -iL "$OUTPUT_DIR/live_hosts.txt" -oN "$OUTPUT_DIR/vuln_scan.nmap"

# Phase 5: OS Detection
echo "[+] Phase 5: OS Detection"
nmap -O --osscan-guess -iL "$OUTPUT_DIR/live_hosts.txt" -oN "$OUTPUT_DIR/os_detection.nmap"

echo "[+] Scan completed. Results available in $OUTPUT_DIR"
```

#### Parallel Scanning with GNU Parallel
```bash
# Parallel host scanning
parallel -j 10 nmap -sS -T4 {} :::: live_hosts.txt

# Parallel service detection
parallel -j 5 nmap -sV -p {} target ::: $(cat open_ports.txt)
```

---

## Network Scanning Defense and Detection

### 🛡️ Defensive Measures

#### Scan Detection Techniques
- **Connection monitoring**: Tracking rapid connection attempts
- **Port knock detection**: Identifying systematic port probing
- **Timing analysis**: Detecting non-human scanning patterns
- **Honeypots**: Deploying decoy services to detect scanning

#### Countermeasures Implementation
```bash
# Iptables rate limiting
iptables -A INPUT -p tcp --dport 22 -m limit --limit 3/min -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j DROP

# Port knocking implementation
iptables -A INPUT -p tcp --dport 22 -m recent --update --seconds 60 --name SSH --rsource -j DROP
iptables -A INPUT -p tcp --dport 22 -m recent --set --name SSH --rsource -j ACCEPT
```

---

## Additional Resources

### 📚 Essential Reading
- **[Nmap Official Documentation](https://nmap.org/book/)** - Comprehensive Nmap reference guide
- **[NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)** - Network Security Testing guidelines
- **[RFC 793 - TCP Protocol](https://tools.ietf.org/html/rfc793)** - TCP specification and behavior

### 🔬 Research Papers and Case Studies
- **["Network Scanning Techniques and Defense"](https://ieeexplore.ieee.org/document/8444985)** - Academic analysis of scanning methods
- **[SANS Network Security Monitoring](https://www.sans.org/reading-room/whitepapers/detection/)** - Detection and response strategies
- **[IPv6 Security Research](https://www.ipv6security.org/)** - IPv6-specific security considerations

### 🛠️ Professional Tools and Resources
- **[Masscan Documentation](https://github.com/robertdavidgraham/masscan)** - High-speed port scanner
- **Nmap Scripting Engine**: Custom script development
- **Zmap Project**: Internet-wide scanning tools
- **NMAP Front-ends**: Zenmap, NmapFE, WebMap

---

*Last Updated: January 2024 | CEH v12 Compatible*
