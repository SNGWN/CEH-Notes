# Module 02 - Footprinting and Reconnaissance

## Learning Objectives

- Master passive and active footprinting methodologies
- Understand web application reconnaissance techniques
- Learn DNS enumeration and zone transfer attacks
- Develop OSINT (Open Source Intelligence) skills
- Explore social engineering information gathering
- Master advanced Google dorking techniques
- Understand network range and infrastructure discovery

---

## Footprinting Fundamentals

### What is Footprinting?

**Footprinting** is the systematic process of collecting information about target systems, networks, and organizations to identify potential attack vectors and reduce the attack surface scope. It represents the first phase of the ethical hacking methodology and forms the foundation for all subsequent security testing activities.

### Core Objectives

- **Reduce attack surface**: Focus efforts on viable targets and entry points
- **Identify security perimeter**: Map external-facing systems and services  
- **Gather intelligence**: Collect organizational, technical, and personnel information
- **Plan attack strategy**: Develop targeted approach based on discovered information

---

## Footprinting Methodologies

### 🔍 Passive Footprinting

**Information gathering** without direct interaction with target systems, minimizing detection risk.

#### Characteristics
- **No direct target contact**: Information gathered from third-party sources
- **Stealth approach**: Minimal detection risk and forensic evidence
- **Publicly available data**: Relies on open source intelligence (OSINT)
- **Legal compliance**: Generally permissible as uses public information

#### Key Sources
- **Search engines**: Google, Bing, DuckDuckGo advanced queries
- **Social media platforms**: LinkedIn, Twitter, Facebook, Instagram
- **Public databases**: WHOIS, DNS records, certificate transparency
- **Archive services**: Wayback Machine, cached content
- **Professional networks**: Company websites, press releases, job postings

### 🎯 Active Footprinting

**Direct interaction** with target systems to gather detailed technical information.

#### Characteristics
- **Direct system interaction**: Scanning, probing, and service enumeration
- **Higher information quality**: Detailed technical specifications
- **Detection risk**: May trigger security alerts and logging
- **Legal considerations**: Requires explicit authorization

#### Key Techniques
- **Network scanning**: Port scans, service detection, OS fingerprinting
- **DNS enumeration**: Zone transfers, subdomain brute forcing
- **Social engineering**: Phone calls, emails, physical reconnaissance
- **Website interaction**: Technology fingerprinting, directory enumeration

---

## Web Application Footprinting

### 📧 Email Address Discovery

#### Techniques and Sources
- **Website parsing**: Contact pages, staff directories, privacy policies
- **WHOIS records**: Administrative and technical contacts
- **Social media**: Professional profiles and public posts
- **Code repositories**: GitHub, GitLab commit histories
- **Job postings**: Contact information in recruitment listings

#### Email Pattern Analysis
```bash
# Common email patterns for organizations
firstname.lastname@company.com
first.last@company.com  
f.lastname@company.com
firstname@company.com
flastname@company.com
```

### 🌐 WHOIS Intelligence Gathering

**WHOIS databases** provide comprehensive domain registration and ownership information.

#### Key Information Retrieved
- **Registrar details**: Domain registration service provider
- **Registration dates**: Creation, expiration, and last updated
- **Contact information**: Administrative, technical, and billing contacts
- **Name servers**: Authoritative DNS servers for the domain
- **IP ranges**: Associated network blocks and ASN information

#### Privacy Considerations
- **WHOIS privacy protection**: May obscure actual ownership details
- **GDPR compliance**: European domains may have limited public information
- **Corporate vs personal**: Business domains typically provide more detail

### 📍 IP Geolocation Analysis

#### Information Sources
- **Geographic location**: Country, region, city coordinates
- **ISP information**: Internet service provider and organization
- **ASN details**: Autonomous system number and network blocks
- **Infrastructure mapping**: Data center and hosting provider identification

#### Limitations and Accuracy
- **VPN and proxy services**: May show incorrect geographic location
- **CDN networks**: Content delivery networks can obscure true server location
- **IP reputation**: Historical usage and security incident associations

### 📱 Technology Stack Identification

#### Web Technology Fingerprinting
- **Server technologies**: Web servers (Apache, Nginx, IIS)
- **Programming languages**: PHP, Python, Java, .NET
- **Frameworks**: React, Angular, Django, Laravel
- **Content management**: WordPress, Drupal, Joomla
- **Analytics and tracking**: Google Analytics, social media pixels

#### Tools and Techniques
- **Browser extensions**: Wappalyzer, BuiltWith, WhatRuns
- **Command-line tools**: whatweb, WebTechNOTIce
- **Response header analysis**: Server headers, X-Powered-By headers
- **Source code analysis**: JavaScript libraries, CSS frameworks

### 🔄 Historical Analysis (Wayback Machine)

#### Archived Content Discovery
- **Website evolution**: Changes in design, content, and functionality
- **Exposed directories**: Previously accessible paths and endpoints
- **API documentation**: Historical API endpoints and parameters
- **Code comments**: Developer comments in HTML and JavaScript
- **Technology changes**: Evolution of technology stack over time

#### Strategic Value
- **Vulnerability windows**: Historical software versions with known CVEs
- **Design patterns**: Understanding of development practices
- **Content migration**: Identifying moved or deprecated functionality

---

## DNS Footprinting and Enumeration

### DNS Record Types and Intelligence Value

#### 🅰️ A Records (IPv4 Addresses)
- **Primary use**: Maps domain names to IPv4 addresses
- **Intelligence value**: Reveals server infrastructure and hosting providers
- **Security implications**: Direct access points for targeted attacks

#### 🅰️ AAAA Records (IPv6 Addresses)  
- **Primary use**: Maps domain names to IPv6 addresses
- **Intelligence value**: Modern infrastructure and dual-stack configurations
- **Security implications**: Often overlooked in security configurations

#### 📮 MX Records (Mail Servers)
- **Primary use**: Specifies mail servers for email delivery
- **Intelligence value**: Email infrastructure and third-party services
- **Security implications**: Email security posture and phishing targets

#### ⏱️ TTL (Time to Live)
- **Primary use**: Caching duration for DNS records
- **Intelligence value**: Infrastructure change frequency and practices
- **Security implications**: DNS cache poisoning and hijacking opportunities

#### 🔗 CNAME Records (Aliases)
- **Primary use**: Domain name aliases and redirections
- **Intelligence value**: Service relationships and infrastructure mapping
- **Security implications**: Subdomain takeover vulnerabilities

#### 📝 TXT Records (Text Information)
- **Primary use**: Domain verification and policy specification
- **Intelligence value**: Third-party services, SPF, DKIM, DMARC policies
- **Security implications**: Email security posture and service enumeration

### Zone Transfer Attacks

#### Understanding DNS Zone Transfers
**Zone transfers** allow secondary DNS servers to replicate complete DNS zone data from primary servers.

#### AXFR (Full Zone Transfer)
```bash
# Attempting zone transfer
dig @ns1.target.com target.com AXFR
dnsrecon -d target.com -t axfr
fierce -dns target.com
```

#### Security Implications
- **Complete subdomain enumeration**: Full internal DNS structure exposure
- **Infrastructure mapping**: Internal network topology revelation
- **Service discovery**: Hidden services and development environments

---

## Social Engineering Information Gathering

### 👂 Eavesdropping Techniques

#### Physical Eavesdropping
- **Workplace monitoring**: Overhearing conversations in public spaces
- **Phone conversations**: Public areas, elevators, transportation
- **Meeting rooms**: Conference calls and strategy discussions
- **Technical discussions**: IT support calls and troubleshooting

#### Digital Eavesdropping
- **Network traffic**: Unencrypted communications monitoring
- **VoIP communications**: Internet-based phone call interception
- **Video conferences**: Unsecured meeting platforms
- **Instant messaging**: Corporate chat platforms and tools

### 👀 Shoulder Surfing

#### Target Information Types
- **Passwords and PINs**: Authentication credential observation
- **Screen content**: Sensitive documents and communications
- **Access codes**: Physical security systems and badges
- **Personal information**: Social security numbers, addresses

#### High-Risk Locations
- **Airport lounges**: Business travelers using laptops
- **Coffee shops**: Public WiFi and workspace areas
- **Public transportation**: Mobile device usage
- **Office buildings**: Shared workspaces and elevators

### 🗑️ Dumpster Diving (Physical OSINT)

#### Target Materials
- **Financial documents**: Bank statements, invoices, contracts
- **Technical documentation**: Network diagrams, user manuals
- **Personnel information**: Employee directories, organizational charts
- **Security materials**: Passwords written on paper, access cards

#### Legal and Ethical Considerations
- **Property laws**: Trash ownership and trespassing regulations
- **Privacy expectations**: Personal vs. corporate information
- **Professional boundaries**: Ethical hacking scope limitations

---

## OSINT Tools and Techniques

### 👤 User Reconnaissance Tools

#### UserRecon Framework
```bash
# Installation and Usage
git clone https://github.com/issamelferkh/userrecon.git
cd userrecon
./userrecon.sh

# Features
# - Searches across 75+ social media platforms
# - Automated username enumeration
# - Results aggregation and reporting
```

**Use Cases**: Social media presence mapping, username correlation across platforms
**Limitations**: Rate limiting on platforms, privacy settings may hide profiles

#### Sherlock - Username Intelligence
```bash
# Installation
pip3 install sherlock-project

# Usage Examples
sherlock target_username                    # Search across all supported sites
sherlock target_username --timeout 10      # Custom timeout settings
sherlock target_username --print-found     # Only display found accounts
sherlock target_username --csv             # Export results to CSV
```

**Capabilities**: 300+ platform support, concurrent searching, detailed reporting
**Considerations**: Some platforms may require API keys for full functionality

#### theHarvester - Email and Domain Intelligence
```bash
# Domain-based email harvesting
theHarvester -d target.com -b all -l 500   # Search all sources
theHarvester -d target.com -b google       # Google-specific search
theHarvester -d target.com -b linkedin     # LinkedIn employee enumeration
theHarvester -d target.com -b dnsdumpster  # DNS subdomain discovery

# Export options
theHarvester -d target.com -b all -f output.html  # HTML report
theHarvester -d target.com -b all -f output.xml   # XML format
```

**Intelligence Gathering**: Emails, subdomains, hosts, employee names
**Advanced Features**: Shodan integration, virtual host detection, DNS enumeration

### 💼 Professional Network Analysis

#### LinkedIn Intelligence Gathering
- **Employee enumeration**: Current and former staff identification
- **Organizational structure**: Department mapping and hierarchy
- **Technology insights**: Skills, certifications, and tool usage
- **Contact information**: Professional email patterns and phone numbers
- **Business relationships**: Partners, clients, and vendor connections

#### Job Board Analysis
- **Technology stack requirements**: Required skills and tools
- **Infrastructure insights**: System requirements and environments
- **Security posture**: Security-related job postings and requirements
- **Organizational growth**: Expansion areas and strategic initiatives
- **Contact patterns**: HR and technical contact information

---

## Google Dorking and Advanced Search

### 🔍 Google Search Operators

#### Content-Specific Operators
```bash
# Title and content searches
intitle:"login page" site:target.com        # Find login pages
intext:"password reset" site:target.com     # Find password reset functionality  
inurl:admin site:target.com                 # Administrative interfaces
inanchor:"contact us" site:target.com       # Link anchor text search
```

#### File Type Discovery
```bash
# Document and file enumeration
filetype:pdf site:target.com               # PDF documents
filetype:doc site:target.com               # Word documents
filetype:xlsx site:target.com              # Excel spreadsheets
filetype:pptx site:target.com              # PowerPoint presentations
filetype:txt site:target.com               # Text files
```

#### Sensitive Information Discovery
```bash
# Configuration and error pages
"Index of /" site:target.com               # Directory listings
"error in your SQL syntax" site:target.com # SQL error messages
"Warning: mysql_" site:target.com          # MySQL warnings
"ORA-" site:target.com                     # Oracle database errors
```

#### Advanced Combination Queries
```bash
# Complex search patterns
site:target.com (inurl:admin OR inurl:administrator OR inurl:panel)
site:target.com filetype:pdf (password OR confidential OR internal)
site:target.com "powered by" (inurl:login OR inurl:admin)
```

### 🗃️ Google Hacking Database (GHDB)

#### Categories and Applications
- **Footholds**: Initial access points and entry vectors
- **Web server detection**: Technology and version identification
- **Error messages**: System configuration and database information
- **Network or vulnerability data**: Infrastructure and security weaknesses
- **Files containing passwords**: Credential and authentication data
- **Sensitive online shopping info**: E-commerce and payment data

#### GHDB Resources
- **[Exploit-DB GHDB](https://www.exploit-db.com/google-hacking-database)**
- **Community contributions**: Crowdsourced dork discovery
- **Regular updates**: New techniques and query patterns

---

## Domain and Infrastructure Analysis

### 🌐 Domain Intelligence Platforms

#### Website-Informer
**Comprehensive domain analysis** providing technical and business intelligence.

**Key Information**:
- **IP address and hosting**: Server location and provider details
- **DNS configuration**: Name servers and record information
- **Subdomains**: Associated subdomain discovery
- **Technology stack**: Server software and applications
- **Contact information**: Administrative and technical contacts

#### DomainTools
**Professional-grade domain intelligence** with historical and predictive analytics.

**Advanced Features**:
- **WHOIS history**: Historical ownership and configuration changes
- **DNS history**: Previous DNS configurations and changes
- **IP neighborhood**: Other domains on same infrastructure
- **Risk assessment**: Domain reputation and threat intelligence
- **API access**: Programmatic intelligence gathering

#### DNSDumpster
**Visual DNS reconnaissance** with interactive network mapping.

**Capabilities**:
- **DNS enumeration**: Comprehensive DNS record discovery
- **Visual mapping**: Graphical representation of infrastructure
- **Subdomain discovery**: Active and passive subdomain enumeration
- **Network topology**: Infrastructure relationship visualization

### 🔍 Shodan - The Internet Search Engine

#### Core Search Capabilities
```bash
# Organization-based searches
org:"Target Organization"                   # Organization assets
net:"192.168.1.0/24"                      # Network range scanning
country:"US" city:"New York"               # Geographic filtering
```

#### Service and Technology Discovery
```bash
# Service-specific searches
port:22 country:"US"                       # SSH services by country
apache version:"2.4" country:"DE"         # Specific Apache versions
"default password" port:23                 # Telnet with default creds
ssl:"target.com"                          # SSL certificate search
```

#### IoT and Device Discovery
```bash
# Device-specific searches
"Server: webcam"                          # Web cameras
"HP LaserJet" port:9100                   # Network printers
"Schneider Electric" port:502             # Industrial control systems
title:"DVR" country:"US"                  # Digital video recorders
```

**Professional Features**: API access, monitoring alerts, vulnerability tracking
**Security Considerations**: Responsible disclosure, legal compliance, ethical usage

### 🏗️ Technology Stack Analysis

#### BuiltWith Intelligence
- **Technology detection**: Comprehensive framework and tool identification
- **Historical analysis**: Technology adoption and migration patterns
- **Market intelligence**: Competitor technology comparison
- **Lead generation**: Business development opportunities

#### Wappalyzer
- **Browser integration**: Real-time technology detection
- **API access**: Programmatic technology identification
- **Technology categories**: Detailed classification and versioning
- **Competitive analysis**: Market share and adoption trends

---

## Subdomain Discovery and Enumeration

### 🔍 Automated Subdomain Discovery

#### Sublist3r - Comprehensive Enumeration
```bash
# Basic subdomain enumeration
sublist3r -d target.com                    # Standard enumeration
sublist3r -d target.com -v                 # Verbose output
sublist3r -d target.com -b                 # Enable brute force
sublist3r -d target.com -p 80,443          # Specific port testing

# Output and reporting
sublist3r -d target.com -o subdomains.txt  # Save results to file
```

**Search Engines Used**: Google, Yahoo, Bing, Baidu, Ask, Netcraft, DNSdumpster
**Advanced Features**: Brute force integration, port scanning, output formatting

#### Amass - Advanced Asset Discovery
```bash
# Passive enumeration
amass enum -d target.com                   # Basic enumeration
amass enum -d target.com -src             # Show data sources
amass enum -d target.com -ip              # Include IP addresses

# Active enumeration  
amass enum -active -d target.com           # Active reconnaissance
amass enum -brute -d target.com            # Brute force subdomains
amass enum -d target.com -config config.ini # Custom configuration
```

**Data Sources**: 55+ different information sources
**Advanced Capabilities**: DNS zone walking, certificate transparency, reverse DNS

### 🔄 DNS Recon and Zone Analysis

#### DNSRecon Framework
```bash
# Standard domain enumeration
dnsrecon -d target.com                     # Basic enumeration
dnsrecon -d target.com -t std              # Standard record types
dnsrecon -d target.com -t axfr             # Zone transfer attempt
dnsrecon -d target.com -t brt              # Brute force subdomains

# Advanced techniques
dnsrecon -d target.com -r 192.168.1.0/24   # Reverse DNS lookup
dnsrecon -d target.com -t srv              # SRV record enumeration
```

**Enumeration Types**: Standard, zone transfer, brute force, reverse lookup, cache snooping
**Output Formats**: Standard, XML, CSV, JSON for integration

---

## Additional Resources

### 📚 Essential Reading
- **[OWASP Testing Guide - Information Gathering](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/)** - Comprehensive web application reconnaissance
- **[NIST SP 800-115](https://csrc.nist.gov/publications/detail/sp/800-115/final)** - Technical Guide to Information Security Testing
- **[SANS Reading Room](https://www.sans.org/reading-room/whitepapers/testing/)** - Footprinting and reconnaissance research

### 🔬 Research Papers and Case Studies
- **["Footprinting Techniques and Tools"](https://www.ijsr.net/archive/v4i4/SUB152673.pdf)** - Academic analysis of reconnaissance methods
- **[Passive DNS Analysis](https://www.farsightsecurity.com/technical-whitepapers/)** - DNS intelligence gathering techniques
- **[OSINT Framework](https://osintframework.com/)** - Comprehensive tool and technique repository

### 🛠️ Professional Tools and Platforms
- **Commercial OSINT**: Maltego, Recorded Future, ThreatConnect
- **DNS Intelligence**: SecurityTrails, DomainTools, PassiveTotal
- **Social Media**: Social Searcher, Hootsuite Insights, Brandwatch
- **Search Platforms**: Shodan, Binary Edge, Zoomeye

---

*Last Updated: January 2024 | CEH v12 Compatible*
