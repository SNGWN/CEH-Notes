# Terms
	**Wireless network** is a computer network that uses wireless data connection between network nodes.
	**Access Point**: Access Point (AP) or Wireless Access Point (WAP) is a hardware device that allows wireless connectivity to the end devices.
	**Service Set Identifier (SSID)**: A 32 bit identification string of the Access Point, the AP's name. SSID inserted into the header of every data packet.
	**Basic Service Set Identifier (BSSID)**: MAC address of the Access Point.

# Wi-FI
	Wi-Fi is a local area networking technology based on the IEEE 802.11 standard.
	Wi-Fi stands for Wireless-Fidility
	In 1999, Six companies come together and form a global non-profit association, regardless of brand, using a new wireless networking technology.
	In 2000, the group adopted the term **Wi-Fi** for its technical work and announce its official name **Wi-Fi Alliance**.

# Wireless Standards
	**802.1X** is a set of standards that has set of rules which allow wired and wireless peripherals to work with each other. like Mobile with Router, Computer with Router, etc. We have Different Sub-Protocols in 802.11 Family which are categorized as per their Frequency and Modulation technique.

	| Protocol  |  Frequency  | Max Data Speed |
	|:---------:|:-----------:|:--------------:|
	|  802.11a  |    5 GHz    |    54 Mbps	   |
	|  802.11b  |   2.4 GHz   |    11 Mbps     | 		
	|  802.11g  |   2.4 Ghz   |    54 Mbps     |
	|  802.11n  |  2.4/5 Ghz  |    450 Mbps    | -> **Can handle a single device at a time**
	|  802.11ac |    5 Ghz    |    866.7 Mbps  | -> **Can handle 4 devices at a time** --

# Wi-Fi latest version and their speed
	| Protocol | Version |   Speed  |
	|:--------:|:-------:|:--------:|
	| 802.11n  | Wi-Fi 4 | 600 Mb/s | -> **802.11n is renamed as Wi-Fi 4**
	| 802.11ac | Wi-Fi 5 | 3.5 Gb/s | -> **802.11ac is renamed as Wi-fi 5**
	| 802.11ax | Wi-Fi 6 | 9.6 Gb/s | <- **Latest and fastest we can use, can handle 8 devices at a time**

# Authentication Progress
	**Open System Authentication** - In open system Authentication, client sent Authentication request from device that contain the Station ID (Typically the MAC Address). And Receive Authentication Response from AP/Router with a success or Failure message.
	**Shared Key Authentication** - In Shared key Authentication, a shared key, or passphrase, is manually set on both the mobile device and the AP/router for comparison. Authentication depends on match result.

# Wardriving
	Wardriving is the act of searching for Wi-Fi wireless networks by a person usually in a moving vehicle, using a laptop or smartphone.

# Types of Wireless Antennas
	# Directional Antenna
		Direction antennas are designed to function in a specific direction to improve efficiency
		Use case: Dish Antennas
	# Omnidirectional antennas
		Omnidirectional antenna radiates equal radio power in all directions.
		Use cases: radio broadcasting, cell phones, GPS
--------------------------------------------------------------------------------------------------------------
## Wireless Encryption

# Wired Equivalent Privacy (WEP) - 1997
	- Designed to provide the same level of security as that of a wired LAN
	- WEP is Standard protocol before 2004
	- Use Pre-shared Key, and plain text transmission.

# Wi-Fi Protected Access (WPA) - 2003 by Wi-Fi Alliance
	- Used for WLAN network based on 802.11i
	- Use RADIUS (**Remote Authentication Dial-In User Service**) Server
	- Only fesible for Corporate giants who can setup their Server, Not fesible for normal users

# WPA2 - 2004
	- Strong Encryption AES (Advanced Encryption Standard) - 128-256 bit key
	- In WPA2, when user try to connect with AP/Router, key is Encrypted by AES and then transmitted.

# Wireless Threats
	- **Access Control Attacks** : evading access control parameters (MAC spoofing point)
	- **Confidentiality Attacks** : traffic analysis, session hijacking, MITM, etc...
	- **Availability Attacks** : prevent user from accessing the wireless network (flooding, ARP poisoning, De-Authentication attacks)
	- **Authentication Attacks** : steal identity information or impersonating clients (password cracking, password guessing)
	- **Rogue Access Point** : a fake access point in a place with the legitimate one, with the same SSID to monitor victims activity by sniffing packets.
	- **Misconfigured Access Point Attacks** : default or week password, Open Authentication
	- **Jamming Signal Attacks** : jamming or blocking the wireless communication, causing a denial of service
--------------------------------------------------------------------------------------------------------------
# Hacking Methodology

# Wi-Fi Discovery
	- Passive footprinting (sniffing packets)
	- Active footprinting (probing the AP to get information)

# Wireless Traffic Analysis
	- Capture the packets to reveal any information (SSID, authentication method, ...)

# Launch Attacks
	- ARP poisoning - Poisoning the ARP cache of Target machine, so that Attacker AP/Router send Victims Traffic to Attacker.
	- MAC spoofing - Using False MAC Address
  - Attacker Send De-Authentication request with spoofed
	- Rogue access point - Installing Rogue access point in secure network without authorization of network Admin.
	- MITM - Man-In-The-Middle Attacks.

# Wireless Security Tools
	# Wireless Intrusion Prevention System (WIPS)
		- Monitors the wireless network
		- Protect against unauthorized access points
		- Perform automatic intrusion prevention
		- Monitors the radio spectrum to prevents rogue access point and alert the network administrator
		- Can detect AP misconfiguration
		- Detect honeypots
		- Mitigate DoS

	# Wi-Fi Countermeasures
		- Change default parameters
		- Disable remote login to wireless devices
		- Use strong password - use passphrases
		- Use the latest standards (WPA2 AES)
		- MAC filtering
		- Update software often
		- Enable firewall
--------------------------------------------------------------------------------------------------------------
# Aircrack Suite
	- Airmon-ng
	- Airodump-ng
	- Aireplay-ng
	- Aircrack-ng

-> **airmon-ng start <Interface>**																					// Using that interface for network monitoring
-> **airmon-ng check kill**																									// Killing Processes which may cause trouble
-> **airodump-ng <interface>**																							// We need AP/Router MAC Address
-> **airodump-ng -w <file> --bssid <MAC Address> <Interface>**							// Start Capturing packets
-> **aireplay-ng --deauth 0 -a <Access Point BSSID> <interface>**						// We send DE-Authentication packets to Target Access Point
-> **aircrack-ng -w <Wordlist /dir> <Airdump Captured file /dir>**					// This will prompt us for Network Selection. Try to Crack Key with help of Wordlist
--------------------------------------------------------------------------------------------------------------
# WiFiPhisher
	This tool use phishing attack to get WiFi password.
		- https://www.youtube.com/watch?v=8dhGWYCfrBc
--------------------------------------------------------------------------------------------------------------
