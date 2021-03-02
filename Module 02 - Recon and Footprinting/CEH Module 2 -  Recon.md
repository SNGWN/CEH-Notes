# Footprinting & Reconnaissance
	Collecting info regarding internal and external security architecture. Foot printing and Recon help attacker to reduce focus area and bring closer to the target. Collect information about a target network.
	- Active Footprinting : Collect info with Direct interaction
	- Passive Footprinting : Collect info without direct interaction
		Methods:
			- Public Emails - Email Addresses available on Webpages.
			- WHOIS - WHOIS give us info about Domain like when registered, expiry, owner, etc.
			- IP Geolocation - Geolocation of Server and Organization
			**DNS Footprinting**
				- Server IP - Server IP Address
				- MX - Mail Server used for handling Emails for that domain.
				- TTL - Time to Live (After how many hops packet will be discarded)
				- CNAME - Provides additional names or aliases for the address record
			**Social Engineering**
				- Eavesdropping - process of intercepting unauthorized communication to gather information.
				- Shoulder Surfing - Secretly observing the target to gather sensitive information like passwords, personal identification information, account information etc.
				- Dumpster Diving:  This is a process of collecting sensitive information by. looking into the trash/bin.
--------------------------------------------------------------------------------------------------
# K1). User Recon Techniques
		- **UserRecon** - (Tool) - https://github.com/issamelferkh/userrecon.git
				git clone https://github.com/issamelferkh/userrecon.git
				- This tool search for username on 75 different Social media sites.
				- ./userrecon 				- Enter Name
		- **sherlock** - Simmilar to user recon
				python3 sherlock <name>
		- **theHarvester** - theHarvester <domain> --source <source>
		- **Job Sites** - (LinkedIn, indeed, monster.com, etc.)
		- **Social Searcher**
			- This Website search for user name on different Social media Platform. User Search is not limited to 1 search per website.

----------------------------------------------------------------
# K2). Google Dorks & Google Hacking Database (GHDB)
			- **Intitle** : Matches Given String to Page Title. (intitle:Owasp top 10)
			- **InText** : Matches Given String with string in Text. (intitle:How to become a Hacker")
			- **Site** : Limit the search to a specific site only. (site:drive.google.com)
			- **Inurl** : Matches Given String with string in URL. (inurl:twitter.com)
			- **Filetype** : Matches File Type with Search Query. (filetype:pdf)
			- **Exploit DB** https://Exploit-db.com/google-hacking-database

----------------------------------------------------------------
#	K3). Domain Recon Technique
		**website-informer** - IP Address, Owner Email, Sub Domains, DNS, Registrar
		**whois.domaintools.com** - IP Address, Sub Domains, DNS, Registrar, other sited registered on same Server(If Any).
		**Shodan** - Shodan is a Device Search Engine. Shodan search for devices accessible through internet.
			- Search for Devices running that services
			- Search for Devices connected to that organization
			- search for Devices based on location
			- search for open devices like Camera, Printer, Router, IOT Devices, TVs, etc
		**Builtwith.com / Wappalyzer**
			- This website tell us about Technology used to build website. like Google Analytics, Chatbots, Programming Languages, E-Commerce Technology, etc.
		**DnsDumpster.com**
			- Provide Information about Domain Name
		**DnsTwister** - https://dnstwister.report/
			- This website show domain with similar name which are registered or available.
		**Dirb** - Directory Buster
		**Sublist3r** - Identify subdomains

----------------------------------------------------------------
#	K4). Tools can be used for Footprinting
		- **Maltego** - Maltego is a GUI based tool which search for all Connections of Domain with Server, other Websites, MX Servers and other domains connected to these mail servers or other domains hosted on same server.
----------------------------------------------------------------
#	K5). Information collected
		- Organization Information - Phone Numbers, Employee Details, Email Addresses, Physical Location, etc
		- Relation with other companies - Other Organizations Client working with.
		- Network Information - Different Networks, Running Services, Domains, Mail Server, etc.
		- System Information - OS, Architecture, etc
