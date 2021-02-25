# Web Server
Web Servers are the programs that are used for hosting services.
Web Servers are deployed on a separate web server hardware or installed on a host as a program.
It delivers content over **Hyper Text Transfer Protocol** (HTTP).
Web Servers support different types of application extensions whereas all of the support **Hypertext Markup Language** (HTML).

# Web Server Security Issue
Web server vulnerabilities:
  - Improper permission of file directories
  - Default configurations
  - Enabling unnecessary services
  - Lack of security
  - Bugs
  - Misconfigured SSL certificate - Drown Attack
  - Enabled debugging

# Open Source Web Servers
  - Apache HTTP Server
  - Nginx
  - Apache Tomcat

# Web Server Attacks
  # DoS/DDoS
  # DNS Server Hijacking

# Directory Traversal Attacks
  Attacker using trials and error method to access restricted directories to reveal sensitive information.

# Man-in-the-Middle / Sniffing Attacks
  # Phishing Attacks
  # Website Defacement
    After a successful intrusion, attacker alters and modify the content of the website.
  # Webserver Misconfiguration
    Attacker looks for misconfigurations and vulnerabilities to exploit.
  # Web Cache Poisoning Attack
    The attacker wipe the actual cache of the webserver and sending crafted request to store fake entries.

# Web Application Attacks
  - Cookie Tampering
  - DoS
  - SQL Injection
  - Session Hijacking
  - Cross-Site Request Forgery (CSRF)
  - Cross-Site Scripting (XSS)
  - Buffer Overflow

# Attack Methodology
  # Information Gathering
    Collecting information from internet.
  # robots.txt
    Attacker extract information about internal files.
  # Web Server Footprinting
    Results the server name, type, OS, applications, etc.

# Mirroring a website
  Download the website, to inspect offline, without any interaction to the target.
Tool:
  - httrack
  - Wget - wget --mirror

# Vulnerability Scanning
  Automated tool to inspect website and detect vulnerabilities.
  These tools perform deep inspection of scripts, open ports, banners, etc.
Tools:
  - owasp-zap
  - openvas
  - Nessus
  - Qualys
  - Crash Test
  - burpsuite Pro

# Hacking Web Passwords
  Extract passwords to gain authorized access to the system.
  Password may be get from social engineering, tampering the communication, etc.

# Countermeasures
  - Place web server in a secure zone (behind firewall, IDS, IPS, DMZ)
  - Detect potential changes (hashing, script to detect change)
  - Disable insecure and unnecessary ports
  - Using port 443 (HTTPS) over port 80 (HTTP)
  - Encrypted traffic
  - Software update
  - Disable default account

# Patch Management
**Patch Management** is an automated process to detect missing security patches, find out solutions, download patch, test the patch in an isolated environment then deploy the patch onto the systems.
