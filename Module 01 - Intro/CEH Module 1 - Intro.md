 # K1). Information Security Triangle or CIA Trait and Non-Repudiation
		- **Confidentiality**
			- Confidentiality Ensures that Information is only accessible by right person i.e. only Authorized person can see the information. Protection from unauthorized access. Confidentiality is ensured by implementing Authentication Checks (User Name and Password), Captcha (Mitigate Brute-force and prevent from Bots), etc. Confidential info should be stored in private offline storage and keep in a safe place, or encrypt data if possible.
			- Popular attacks affecting confidentiality : Data Breaches, Card Skimming, Keylogging, Phishing, Dumpster Diving, etc.
		- **Integrity**
			- Integrity Ensures that Information can only tempered by Authorized by person or it should not be tempered by unauthorized person. Info. either in rest or transit should not be tempered. Integrity is ensured by Encryption, double-triple Encoding, Hashing, salted hashing, MAC (Message Authentication Code), or we can say with the help of Cryptography.
			- Popular Attacks affecting Integrity : MITM, Packet sniffing, etc
		- **Availability**
		 	- Availability ensures that Info. is only available to the right person at the right time, i.e. whenever the info. is requested it should be available.
			- Popular Attacks Affecting Availability : DOS, DDOS, etc.
		-  diation**
		 	- Non-Repudiation ensures that Person A or Person B can't deny for action performed or happened on there side. For Example, suppose Person A send Money to Person B, so person B can't say money was never received. Like we have proof (Bank Statement, Account Balance Increment, Balance Deduction on Person A's side).
		- FireEye Data Breach --> https://malicious.life/episode/episode-101/

# K2). Different Hackers**
		**White Hat/Ethical Hackers** --> Bug Hunters, Penetration testers, Hacking with legal contracts.
		**Black Hat** --> Cyber Terrorists, Suicide Hackers, hacking with bad intensions.
		**Grey Hat** --> Sometime work for offenses and sometime for defences.
		**Script Kiddies** --> New in the field of Cyber Security, Use Past Exploits, use open pre-developed scripts to perform tasks.
		**State Sponsored Hackers** --> Hired by Government to gain Top Secrets of other countries.

# K3). Types of Penetration Testing
		**White Box Testing** --> You will get the complete details about system from client like Network access, login ID-Password, etc.
		**Black Box Testing** --> You have to enumerate as much as possible by your own.
		**Grey Box Testing** --> You will get only little details like network access.

# K4). Teams in Penetration Testing**
		**Red Team** --> Perform like an Hacker and try to hack into Computer Systems, physical Security, Network Security, etc
		**Blue Team** --> Act as a Defender, and implement necessary security checks to ensure System Security. Also react on Red team's Actions/Attacks. Blue team also work as Incident Response team.

# K5). Few Terms used in Hacking
		**Vulnerability** - Know Security Flaw which can be used to compromise CIA trait.
		**Payload** - This is the Malicious Script, used to perform malicious activity.
		**Exploit** - Exploit is the combination of Vulnerability and Payload.
		**Zero Day** - These are Vulnerabilities unknown to developer or not previously disclosed in public.
		**Deep Web & Dark web:**
			- Deep Web - is the space where Spiders and Crawlers are not allowed. for example : Facebook.com/abc is accessible to spiders and crawlers but messages sent ABC to XYZ is only accessible or visible to ABC and XYZ. i.e. not visible through public search engines or not visible publicly.
			- Dark Web - Dark web is a part of internet which is only accessible through TOR (The Onion Routing) Browser. These sites have special Top level Domain (TLD) Names '.onion'. For Example: 46787sd6fasdf69756g79aas6df96asd.onion, abc.onion -->

#K6). Information Security Threat Categories : (Optional)
		**Network Threats: Like**
			- ***MITM  - Man In The Middle*** - Hacker sit between client and Source
			- ***DOS - Denial of Service*** - Sending tons of junk packets to disturb server so that server was not able to respond authentic requests.
			- ***PASSWORD BASED ATTACKS*** - Default passwords, Brute Force, Dictionary ATTACKS
		**Host Threats: Like**
			- ***Unauthorized Access*** - Gaining Access without permission
			- ***Physical Security Threats*** - Open Access, Visible WiFi Routers
		**Operation Security Threats: Like**
			- ***Unpatched OS \ Insecure OS***
			- ***Zero Days***

#K8). Phases of Hacking or how to successfully hack into system
		- **Reconnaissance**
			Active = Acquiring Info without interacting with Target Directly.
			Passive = Gain Info by Acquiring the target Directly. (Via Calls, Emails, help Desk or Technical Department)
		- **Scanning**
			Scan IP's for Open Ports and Possible Vulnerabilities like Older version of OS, Running Services .
		- **Gaining Access**
			Attacker Gain Access by found Vulnerabilities in Scanning Phase (By Password Cracking, Insecure Authentication, Buffer Overflow, Etc)
		- **Maintaining Access**
			Maintain Access by Creating backdoor, installing Rootkit, Trojan, etc)
		- **Clearing Traces/Logs**
			Clear Footprints like connection established, Activities performed) Clear Date defining Hackers Identity

#K9). Some  information Security Standards: How Organizations prove there Security --> By Auditing.
		**PCI-DSS - Payment Card Industry - Data Security System** --> Security Checks how Payment Card info should be stored and what are the security checks to keep in mind.
		**HIPAA - Health Insurance Portability and Accountability Act** --> How employee or client Health related Info is stored, and Security Checks to maintain CIA Trait.
		**ISO 27000** --> ISO 27000 is a family of Standards defining security standards to be implemented in Organizations.
