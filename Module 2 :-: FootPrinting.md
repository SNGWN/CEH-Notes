# Footprinting & Reconnaissance
	Collecting info regarding internal and external security architecture. Foot printing and Recon help attacker to reduce focus area and bring closer to the target. Collect information about a target network.
	- Active Footprinting : Collect info with Direct interaction
	- Passive Footprinting : Collect info without direct interaction
		Methods:
			Web App Footprinting
				- Public Emails - Email Addresses available on Webpages.
				- WHOIS - WHOIS give us info about Domain like when registered, expiry, owner, etc.
				- IP Geolocation - Geolocation of Server and Organization.
				- Wayback URLs - Analyse changes made in web app over time, collect all API endpoints, directories, comments from JS file and HTML files. Check Archive.org for this.
				- Technology - Check what different frameworks, languages, there versions are used in constructing web app. Use tools such as Wappalyzer, Built-with, etc
				- Directory - Perform dictionary check on web app for directories exposed by application through tools such as dirb, gobuster, etc.
			DNS Footprinting
				- A - Server IPv4 Address
				- AAAA - Server IPv6 Address
				- MX - Mail Server used for handling Emails for that domain.
				- TTL - Time to Live (After how many hops packet will be discarded)
				- CNAME - Provides additional names or aliases for the address record
			Social Engineering
				- Eavesdropping - process of intercepting unauthorized communication to gather information.
				- Shoulder Surfing - Secretly observing the target to gather sensitive information like passwords, personal identification information, account information etc.
				- Dumpster Diving:  This is a process of collecting sensitive information by. looking into the trash/bin.
--------------------------------------------------------------------------------------------------
# K1). User Recon Techniques
	- UserRecon - (Tool) - https://github.com/issamelferkh/userrecon.git
			git clone https://github.com/issamelferkh/userrecon.git
			- This tool search for username on 75 different Social media sites.
			- ./userrecon 				- Enter Name
	- sherlock - Simmilar to user recon
			python3 sherlock <name>
	- theHarvester - theHarvester <domain> --source <source>
	- Job Sites - (LinkedIn, indeed, monster.com, etc.)
	- Social Searcher
		- This Website search for user name on different Social media Platform. User Search is not limited to 1 search per website.

----------------------------------------------------------------
# K2). Google Dorks & Google Hacking Database (GHDB)
	- Intitle : Matches Given String to Page Title. (intitle:Owasp top 10)
	- InText : Matches Given String with string in Text. (intitle:How to become a Hacker")
	- Site : Limit the search to a specific site only. (site:drive.google.com)
	- Inurl : Matches Given String with string in URL. (inurl:twitter.com)
	- Filetype : Matches File Type with Search Query. (filetype:pdf)
	- Exploit DB https://Exploit-db.com/google-hacking-database

----------------------------------------------------------------
# K3). Domain Recon Technique
	- website-informer - IP Address, Owner Email, Sub Domains, DNS, Registrar
	- whois.domaintools.com - IP Address, Sub Domains, DNS, Registrar, other sited registered on same Server(If Any).
	- Shodan - Shodan is a Device Search Engine. Shodan search for devices accessible through internet.
		- Search for Devices running that services
		- Search for Devices connected to that organization
		- search for Devices based on location
		- search for open devices like Camera, Printer, Router, IOT Devices, TVs, etc
	- Builtwith.com / Wappalyzer
		- This website tell us about Technology used to build website. like Google Analytics, Chatbots, Programming Languages, E-Commerce Technology, etc.
	- DnsDumpster.com
		- Provide Information about Domain Name
	- DnsTwister - https://dnstwister.report/
		- This website show domain with similar name which are registered or available.
	- Dirb - Directory Buster
	- Sublist3r - Identify subdomains

----------------------------------------------------------------
# K4). Tools can be used for Footprinting
		- Maltego - Maltego is a GUI based tool which search for all Connections of Domain with Server, other Websites, MX Servers and other domains connected to these mail servers or other domains hosted on same server.
		- Gobuster - Analyse application DNS, Directory, GCP, etc
		- Burp Suite - GUI framework to perform all kind of SAST/DAST scan on web apps including information gathering.
----------------------------------------------------------------
# K5). Information collected
		- Organization Information - Phone Numbers, Employee Details, Email Addresses, Physical Location, etc
		- Relation with other companies - Other Organizations Client working with.
		- Network Information - Different Networks, Running Services, Domains, Mail Server, etc.
		- System Information - OS, Architecture, etc

----------------------------------------------------------------
# K6). Practical Footprinting Payloads and Techniques

## WHOIS Information Gathering
```bash
# Basic WHOIS queries
whois example.com                    # Domain registration info
whois -h whois.arin.net 192.168.1.1 # IP WHOIS lookup
dig example.com                      # DNS information
nslookup example.com                 # DNS lookup
```

**Documentation**: Retrieves domain registration details, IP ownership, and DNS records.
**Limitations**: Some WHOIS servers may rate-limit queries; privacy protection may hide details.

## DNS Enumeration and Zone Transfer
```bash
# DNS Record Enumeration
dig @8.8.8.8 example.com ANY         # All DNS records
dig @8.8.8.8 example.com MX          # Mail server records
dig @8.8.8.8 example.com NS          # Name servers
dig @8.8.8.8 example.com TXT         # TXT records

# Zone Transfer Attempt
dig @ns1.example.com example.com AXFR # Zone transfer attempt
dnsrecon -d example.com -t axfr       # Automated zone transfer
```

**Documentation**: Enumerates DNS records and attempts zone transfers to gather subdomain information.
**Limitations**: Zone transfers are usually restricted; requires proper DNS server configuration.

## Subdomain Enumeration
```bash
# Sublist3r - Subdomain discovery
sublist3r -d example.com -v           # Verbose subdomain enumeration
sublist3r -d example.com -b           # Use brute force

# Amass - Advanced subdomain enumeration
amass enum -d example.com             # Basic enumeration
amass enum -brute -d example.com      # Brute force mode

# Manual subdomain brute force
for sub in www mail ftp admin test; do
    nslookup $sub.example.com
done
```

**Documentation**: Discovers subdomains using passive and active techniques.
**Limitations**: Passive methods may miss subdomains; brute force can be time-consuming.

## Google Dorking Advanced Techniques
```
# File Discovery
site:example.com filetype:pdf          # Find PDF files
site:example.com filetype:doc          # Find DOC files
site:example.com filetype:xlsx         # Find Excel files

# Login Pages and Admin Panels
site:example.com inurl:login           # Find login pages
site:example.com inurl:admin           # Find admin panels
site:example.com intitle:"index of"    # Directory listings

# Error Pages and Debug Info
site:example.com "sql syntax near"     # SQL errors
site:example.com "Warning: mysql"     # MySQL warnings
site:example.com "error in your SQL"  # SQL error messages

# Email and Contact Information
site:example.com "@example.com"       # Email addresses
site:example.com "contact" filetype:txt # Contact files
```

**Documentation**: Uses Google search operators to find sensitive information and exposed files.
**Limitations**: Results depend on Google's indexing; sensitive info may not be indexed.

## OSINT Social Media Enumeration
```bash
# theHarvester - Email and subdomain harvesting
theHarvester -d example.com -l 500 -b all  # Search all sources
theHarvester -d example.com -b linkedin    # LinkedIn specific
theHarvester -d example.com -b twitter     # Twitter specific

# Sherlock - Username enumeration across platforms
python3 sherlock.py target_username       # Search across platforms

# Holehe - Email enumeration across platforms
holehe example@domain.com                  # Check email registration
```

**Documentation**: Gathers emails, usernames, and social media presence for target organization.
**Limitations**: Rate limiting on APIs; some platforms may block automated requests.

## Website Technology Fingerprinting
```bash
# Whatweb - Technology identification
whatweb example.com                       # Basic scan
whatweb -v example.com                    # Verbose output
whatweb -a 3 example.com                  # Aggressive scan

# Wappalyzer CLI
wappalyzer example.com                    # Technology stack

# Nikto - Web vulnerability scanner
nikto -h example.com                      # Basic scan
nikto -h example.com -p 80,443           # Specific ports
```

**Documentation**: Identifies web technologies, frameworks, and potential vulnerabilities.
**Limitations**: May trigger security alerts; some technologies may be hidden or obfuscated.

## Network Range Discovery
```bash
# ASN Lookup and IP Range Discovery
whois -h whois.radb.net -- '-i origin AS15169'  # Google ASN ranges
amass intel -org "Target Organization"           # Organization ASN discovery

# Shodan Queries for Organization
shodan search "org:\"Target Organization\""     # Organization assets
shodan search "ssl:\"example.com\""             # SSL certificate search
shodan search "hostname:\"example.com\""        # Hostname search
```

**Documentation**: Discovers IP ranges and internet-facing assets belonging to target organization.
**Limitations**: Requires Shodan API key; some assets may not be indexed.

# Reference URLs and Research Papers:
- OWASP Testing Guide - Information Gathering: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/
- NIST SP 800-115 Technical Guide to Information Security Testing: https://csrc.nist.gov/publications/detail/sp/800-115/final
- SANS Institute - Footprinting and Reconnaissance: https://www.sans.org/reading-room/whitepapers/testing/
- Research Paper: "Footprinting Techniques and Tools" - https://www.ijsr.net/archive/v4i4/SUB152673.pdf
- Passive DNS Analysis: https://www.farsightsecurity.com/technical-whitepapers/
- OSINT Framework: https://osintframework.com/
