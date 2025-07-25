# Module 04 - Enumeration

## Overview
Enumeration is the process of extracting detailed information about identified services, shares, and users on target systems. Unlike scanning which identifies open ports and services, enumeration involves actively connecting to systems and performing queries to gather specific information that can be used for attacking a system.

## Learning Objectives
- Understand the enumeration process and its importance in penetration testing
- Learn various enumeration techniques for different services
- Master enumeration tools and their practical applications
- Identify countermeasures against enumeration attacks
- Develop comprehensive enumeration methodologies

---

## What is Enumeration?

Enumeration is an intrusive process where an attacker establishes an active connection to the target and performs directed queries to gain more information about the target. It occurs after port scanning and involves:

- **Active information gathering** from identified services
- **Detailed service fingerprinting** beyond basic port scanning
- **User account discovery** and validation
- **Share and resource enumeration**
- **Network topology mapping**
- **Operating system and application version detection**

### Enumeration vs Scanning
| Scanning | Enumeration |
|----------|-------------|
| Passive information gathering | Active information gathering |
| Identifies open ports | Extracts detailed service information |
| Minimal target interaction | Direct connection to services |
| Stealth-focused | More intrusive and detectable |

---

## Types of Enumeration

### 1. NetBIOS Enumeration
NetBIOS (Network Basic Input/Output System) allows applications to communicate over a local area network.

**Default Ports:**
- **137/UDP** - NetBIOS Name Service
- **138/UDP** - NetBIOS Datagram Service  
- **139/TCP** - NetBIOS Session Service

**Information Gathered:**
- Computer names and workgroup information
- Shared resources and folders
- User accounts and groups
- System uptime and OS version

**Tools and Techniques:**
```bash
# NetBIOS enumeration with nmap
nmap -sU -p 137 --script nbstat target-ip

# NetBIOS name lookup
nbtscan target-ip

# Enumerate NetBIOS shares
smbclient -L //target-ip -N

# Net command enumeration (Windows)
net view \\target-ip
net use \\target-ip\ipc$ "" /user:""
```

### 2. SNMP Enumeration
Simple Network Management Protocol (SNMP) is used for collecting and organizing information about managed devices on IP networks.

**Default Ports:**
- **161/UDP** - SNMP Agent
- **162/UDP** - SNMP Trap

**Common Community Strings:**
- public (read-only)
- private (read-write)
- admin, administrator
- cisco, router
- manager, security

**Enumeration Techniques:**
```bash
# SNMP enumeration with snmpwalk
snmpwalk -c public -v1 target-ip

# Enumerate system information
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.1

# Enumerate network interfaces
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.2.2.1.2

# Enumerate running processes
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.25.4.2.1.2

# Enumerate installed software
snmpwalk -c public -v1 target-ip 1.3.6.1.2.1.25.6.3.1.2

# SNMP brute force community strings
onesixtyone -c community.txt target-ip

# SNMP enumeration script
snmp-check target-ip -c public
```

### 3. LDAP Enumeration
Lightweight Directory Access Protocol (LDAP) is used for accessing and maintaining distributed directory information services.

**Default Ports:**
- **389/TCP** - LDAP
- **636/TCP** - LDAPS (SSL)
- **3268/TCP** - Global Catalog
- **3269/TCP** - Global Catalog SSL

**Enumeration Techniques:**
```bash
# LDAP enumeration with ldapsearch
ldapsearch -x -h target-ip -p 389 -s base

# Anonymous bind enumeration
ldapsearch -x -h target-ip -p 389 -s sub -b "dc=domain,dc=com"

# Enumerate domain users
ldapsearch -x -h target-ip -p 389 -s sub -b "dc=domain,dc=com" "(objectclass=user)"

# Enumerate domain groups
ldapsearch -x -h target-ip -p 389 -s sub -b "dc=domain,dc=com" "(objectclass=group)"

# LDAP enumeration with nmap
nmap -p 389 --script ldap-rootdse target-ip
nmap -p 389 --script ldap-search target-ip
```

### 4. NTP Enumeration
Network Time Protocol (NTP) is used for clock synchronization between computer systems.

**Default Port:**
- **123/UDP** - NTP

**Enumeration Techniques:**
```bash
# NTP enumeration with ntpq
ntpq -c readlist target-ip
ntpq -c peers target-ip

# NTP version enumeration
ntpdate -q target-ip

# NTP enumeration with nmap
nmap -sU -p 123 --script ntp-info target-ip
nmap -sU -p 123 --script ntp-monlist target-ip
```

### 5. SMTP Enumeration
Simple Mail Transfer Protocol (SMTP) is used for email transmission.

**Default Ports:**
- **25/TCP** - SMTP
- **465/TCP** - SMTPS
- **587/TCP** - SMTP Submission

**Enumeration Commands:**
```bash
# SMTP user enumeration with VRFY
telnet target-ip 25
HELO attacker.com
VRFY root
VRFY admin
VRFY user

# SMTP user enumeration with EXPN
EXPN root
EXPN admin

# SMTP user enumeration with RCPT TO
MAIL FROM: attacker@example.com
RCPT TO: root@target.com

# Automated SMTP enumeration
smtp-user-enum -M VRFY -u users.txt -t target-ip
smtp-user-enum -M EXPN -u users.txt -t target-ip
smtp-user-enum -M RCPT -u users.txt -t target-ip

# SMTP enumeration with nmap
nmap -p 25 --script smtp-commands target-ip
nmap -p 25 --script smtp-enum-users target-ip
```

### 6. DNS Enumeration
Domain Name System (DNS) enumeration involves gathering information about DNS servers and domain records.

**Default Port:**
- **53/TCP/UDP** - DNS

**Enumeration Techniques:**
```bash
# DNS zone transfer
dig axfr @target-ip domain.com
host -l domain.com target-ip

# DNS record enumeration
dig any domain.com @target-ip
nslookup
> set type=any
> domain.com

# DNS brute force subdomain enumeration
dnsrecon -d domain.com -t brt
fierce -dns domain.com

# DNS enumeration with nmap
nmap -p 53 --script dns-zone-transfer target-ip
nmap -p 53 --script dns-brute domain.com
```

### 7. RPC Enumeration
Remote Procedure Call (RPC) allows programs to execute procedures on remote systems.

**Default Port:**
- **135/TCP** - RPC Endpoint Mapper (Windows)
- **111/TCP** - RPC Portmapper (Unix/Linux)

**Enumeration Techniques:**
```bash
# RPC enumeration with rpcinfo
rpcinfo -p target-ip

# RPC endpoint enumeration (Windows)
rpcinfo -T tcp target-ip

# RPC enumeration with nmap
nmap -p 135 --script rpc-grind target-ip
nmap -p 111 --script rpc-grind target-ip

# Windows RPC enumeration
rpcclient -U "" -N target-ip
```

### 8. FTP Enumeration
File Transfer Protocol (FTP) enumeration focuses on gathering information about FTP services.

**Default Ports:**
- **20/TCP** - FTP Data
- **21/TCP** - FTP Control

**Enumeration Techniques:**
```bash
# FTP banner grabbing
telnet target-ip 21
nc target-ip 21

# Anonymous FTP access
ftp target-ip
# Username: anonymous
# Password: (blank or email)

# FTP enumeration with nmap
nmap -p 21 --script ftp-anon target-ip
nmap -p 21 --script ftp-bounce target-ip

# FTP brute force
hydra -L users.txt -P passwords.txt target-ip ftp
```

### 9. SSH Enumeration
Secure Shell (SSH) enumeration involves gathering information about SSH services.

**Default Port:**
- **22/TCP** - SSH

**Enumeration Techniques:**
```bash
# SSH banner grabbing
telnet target-ip 22
nc target-ip 22

# SSH version enumeration
ssh -V target-ip

# SSH enumeration with nmap
nmap -p 22 --script ssh-hostkey target-ip
nmap -p 22 --script ssh-auth-methods target-ip

# SSH user enumeration
ssh-keyscan target-ip
```

---

## Advanced Enumeration Techniques

### Windows Active Directory Enumeration

**PowerShell Commands:**
```powershell
# Domain information
Get-ADDomain
Get-ADForest

# User enumeration
Get-ADUser -Filter * -Properties *
Get-ADUser -Identity "username" -Properties *

# Group enumeration
Get-ADGroup -Filter *
Get-ADGroupMember "Domain Admins"

# Computer enumeration
Get-ADComputer -Filter *
Get-ADComputer -Identity "computername" -Properties *

# Trust enumeration
Get-ADTrust -Filter *

# GPO enumeration
Get-GPO -All
```

**Native Windows Commands:**
```cmd
# Domain and user information
net user /domain
net user username /domain
net group /domain
net group "Domain Admins" /domain

# Share enumeration
net share
net view \\computername

# Service enumeration
sc query
tasklist /svc

# Registry enumeration
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

### Linux System Enumeration

**User and Group Information:**
```bash
# User enumeration
cat /etc/passwd
cat /etc/shadow
getent passwd

# Group enumeration
cat /etc/group
groups
id

# Logged in users
who
w
last
```

**Service and Process Enumeration:**
```bash
# Running processes
ps aux
ps -ef
top
htop

# Network connections
netstat -tulpn
ss -tulpn
lsof -i

# Scheduled tasks
crontab -l
cat /etc/crontab
ls -la /etc/cron*

# Installed packages
dpkg -l (Debian/Ubuntu)
rpm -qa (Red Hat/CentOS)
```

---

## Enumeration Tools

### Comprehensive Enumeration Tools

#### enum4linux
```bash
# Complete SMB enumeration
enum4linux -a target-ip

# Specific enumeration types
enum4linux -U target-ip  # Users
enum4linux -S target-ip  # Shares
enum4linux -G target-ip  # Groups
enum4linux -P target-ip  # Password policy
```

#### SMBMap
```bash
# SMB share enumeration
smbmap -H target-ip
smbmap -H target-ip -u username -p password

# Recursive share enumeration
smbmap -H target-ip -R

# Upload/download files
smbmap -H target-ip -u username -p password --upload '/path/local/file.txt' 'C$\file.txt'
smbmap -H target-ip -u username -p password --download 'C$\file.txt'
```

#### rpcclient
```bash
# Connect to RPC
rpcclient -U "" -N target-ip

# Enumerate users
enumdomusers
queryuser 0x1f4

# Enumerate groups
enumdomgroups
querygroup 0x201

# Enumerate domains
enumdomains

# Get domain info
querydominfo
```

#### BloodHound
```bash
# Data collection with SharpHound
.\SharpHound.exe -c all

# Data collection with Python
bloodhound-python -u username -p password -ns target-ip -d domain.com -c all

# Start BloodHound
neo4j console
bloodhound
```

#### LinEnum
```bash
# Linux enumeration script
chmod +x LinEnum.sh
./LinEnum.sh

# Thorough enumeration
./LinEnum.sh -t
```

---

## Automated Enumeration Scripts

### Custom Enumeration Script
```bash
#!/bin/bash
# Basic enumeration script

TARGET=$1
if [ -z "$TARGET" ]; then
    echo "Usage: $0 <target-ip>"
    exit 1
fi

echo "Starting enumeration of $TARGET"

# Port scan
echo "=== Port Scan ==="
nmap -sS -sV -O $TARGET

# SMB enumeration
echo "=== SMB Enumeration ==="
enum4linux -a $TARGET

# SNMP enumeration
echo "=== SNMP Enumeration ==="
onesixtyone $TARGET public private

# DNS enumeration
echo "=== DNS Enumeration ==="
dig any @$TARGET

# Web enumeration
echo "=== Web Enumeration ==="
nikto -h $TARGET

echo "Enumeration complete!"
```

### Python Enumeration Script
```python
#!/usr/bin/env python3
import socket
import subprocess
import sys

def banner_grab(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        return banner
    except:
        return None

def enumerate_target(target_ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995]
    
    print(f"Enumerating {target_ip}")
    
    for port in common_ports:
        banner = banner_grab(target_ip, port)
        if banner:
            print(f"Port {port}: {banner}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 enum.py <target-ip>")
        sys.exit(1)
    
    enumerate_target(sys.argv[1])
```

---

## Countermeasures

### Network Level Protection
- **Firewall Rules** - Block unnecessary ports and services
- **Network Segmentation** - Isolate critical systems
- **VPN Access** - Require VPN for administrative access
- **Port Security** - Disable unused network ports

### Service Hardening
- **Disable Unnecessary Services** - Remove or disable unused services
- **Change Default Configurations** - Modify default settings and ports
- **Strong Authentication** - Implement strong passwords and MFA
- **Access Controls** - Limit user privileges and access

### SNMP Security
- **SNMPv3** - Use SNMPv3 with authentication and encryption
- **Custom Community Strings** - Avoid default community strings
- **Access Control Lists** - Restrict SNMP access by IP
- **Disable SNMP** - Disable if not required

### SMB/NetBIOS Security
- **Disable SMBv1** - Use SMBv2/SMBv3 only
- **Null Session Protection** - Prevent anonymous connections
- **Share Permissions** - Properly configure share and NTFS permissions
- **Network Authentication** - Require authentication for share access

### LDAP Security
- **Bind Authentication** - Disable anonymous binds
- **SSL/TLS Encryption** - Use LDAPS for encrypted communication
- **Access Controls** - Implement proper directory permissions
- **Query Limitations** - Limit query scope and results

---

## Detection and Monitoring

### Log Analysis
Monitor logs for enumeration activities:
- **Multiple failed authentication attempts**
- **Unusual LDAP queries**
- **Excessive DNS requests**
- **SMB null session attempts**
- **SNMP community string brute forcing**

### Network Monitoring
- **IDS/IPS Signatures** - Deploy rules for enumeration detection
- **Network Traffic Analysis** - Monitor for suspicious patterns
- **Honeypots** - Deploy decoy services to detect enumeration
- **Baseline Monitoring** - Establish normal network behavior

### Security Tools
- **Splunk** - Log aggregation and analysis
- **ELK Stack** - Elasticsearch, Logstash, Kibana
- **OSSEC** - Host-based intrusion detection
- **Snort** - Network intrusion detection

---

## Latest Enumeration Techniques (2024)

### Cloud Service Enumeration
```bash
# AWS enumeration
aws sts get-caller-identity
aws iam list-users
aws ec2 describe-instances

# Azure enumeration
az account show
az ad user list
az vm list

# Google Cloud enumeration
gcloud auth list
gcloud projects list
gcloud compute instances list
```

### Container Enumeration
```bash
# Docker enumeration
docker ps
docker images
docker network ls

# Kubernetes enumeration
kubectl get pods
kubectl get services
kubectl get nodes
kubectl describe pod <pod-name>
```

### API Enumeration
```bash
# REST API enumeration
curl -X GET "https://api.target.com/v1/users"
curl -X OPTIONS "https://api.target.com/v1/"

# GraphQL enumeration
curl -X POST "https://api.target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}'
```

---

## Practical Exercises

### Exercise 1: SMB Enumeration Lab
1. Set up Windows target machine
2. Configure SMB shares with various permissions
3. Use enum4linux and smbclient to enumerate shares
4. Document findings and access levels

### Exercise 2: SNMP Enumeration Challenge
1. Configure SNMP on target system
2. Use different community strings
3. Extract system information, processes, and network data
4. Create comprehensive system profile

### Exercise 3: Active Directory Enumeration
1. Set up AD environment with multiple users and groups
2. Use BloodHound for attack path analysis
3. Enumerate trust relationships and privileges
4. Document potential attack vectors

---

## References and Further Reading

### Official Documentation
- [NIST SP 800-115: Technical Guide to Information Security Testing](https://csrc.nist.gov/publications/detail/sp/800-115/final)
- [RFC 1157: Simple Network Management Protocol (SNMP)](https://tools.ietf.org/html/rfc1157)
- [RFC 4511: Lightweight Directory Access Protocol (LDAP)](https://tools.ietf.org/html/rfc4511)

### Security Resources
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [SANS Penetration Testing Resources](https://www.sans.org/white-papers/)
- [Penetration Testing Execution Standard](http://www.pentest-standard.org/)

### Tool Documentation
- [Nmap Scripting Engine](https://nmap.org/book/nse.html)
- [enum4linux Documentation](https://labs.portcullis.co.uk/tools/enum4linux/)
- [BloodHound Documentation](https://bloodhound.readthedocs.io/)

---

*This content is provided for educational purposes only. All enumeration techniques should be used only in authorized testing environments with proper permissions.*