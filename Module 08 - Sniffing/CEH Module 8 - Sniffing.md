# Basic
	With sniffing, you can monitor all sorts of traffic either protected or unprotected.
	Sniffing is the process of scanning and monitoring captured data like DNS traffic, web traffic and many more by enabling the promiscuous mode on the network interface.
	The attacker can reveal information from it such as usernames and passwords.
	Anyone within the same LAN can sniff the packets.

# Working of Sniffers
	In the process of sniffing, the attacker gets connected to the target network to start sniffing.
	Sniffers turns Network Interface Card (NIC) into promiscuous mode.
	Promiscuous mode is a mode of the interface in which NIC respond for every packet it receives.
	The attacker decrypt the packets to extract information.

# Switch vs Hub
	- **Switch** forward broadcast and multicast to all ports, but forward unicast packets to a specific port.
	- **Hub** transmits all packets to all ports.

# Switch Port Analyzer (SPAN) Port
	In other name: **Port Mirroring**. It is used on a network switch to send a copy of network packets seen on one switch port (or an entire VLAN) to a network monitoring connection on an other switch port.
--------------------------------------------------------------------------------------------------------------
# Wiretapping
	Gaining information by tapping the signal from wire such as telephone lines or the internet. Wiretapping mostly performed by a third party. Legal Wiretapping is called **legal interception** which is mostly performed by governments or security agencies.

	**Active Wiretapping**
		Monitoring and recording the information with alteration of the communication.

	**Passive Wiretapping**
		Monitoring and recording the information without any alteration in the communication.

	**Lawful Interception/Wiretapping**
		Wiretapping with legal authorization which allows law enforcement agencies to wiretap the communication of user.
--------------------------------------------------------------------------------------------------------------
# MAC Attacks
	**Media Access Control** (MAC) is the physical address of a device. MAC address is a 48-bit unique identification number that is assigned to a network device for communication at data-link layer (layer 2). First 24 bits are the Object Unique Identifier (OUI), the last 24 bits are the Network Interface Controller (NIC).

	# MAC Flooding
		Attacker sends random MAC addresses mapped with random IP to overflow the storage capacity of **CAM (Content Address Memory)** table. CAM table has a fixed length, so when filled, switch act as a hub, broadcast every packet on every port, help attacker to sniff packets. Tool - **macof**

	# Defending against MAC Attacks
		Port Security is used to bind MAC address of known devices to the physical ports and violation action is also defined.
--------------------------------------------------------------------------------------------------------------
# DHCP Attacks
	# Dynamic Host Configuration Protocol (DHCP) - DHCP is the process of allocating the IP address dynamically so these addresses are assigned automatically and they can be reused when hosts don't need them. **Round Trip Time** is the measurement of time from discovery of DHCP server until obtaining the leased IP address.

	# IPv4 DHCP process
		1. By using UDP broadcast, DHCP client sends an initial **DHCP-Discovery** packet.
		2. The DHCP server reply with a **DHCP-Offer** packet, offering the configuration parameters.
		3. The DHCP client send back a **DHCP-Request** packet destined for DHCP server for requesting the DHCP parameters.
		4. Finally, the DHCP server send the **DHCP-Acknowledgement** packet containing configuration parameters.

		|         CLIENT         |    |        DHCP SERVER     |
		|:----------------------:|:--:|:----------------------:|
		|     DHCP-Discovery     | -> |	                       |
		|                        | <- |       DHCP-Offer       |
		|       DHCP-Request     | -> |                        |
		|                        | <- |  DHCP-Acknowledgement  |

- **IPv4 Ports**:
    - UDP port 67 for Server
    - UDP port 68 for Client
-----------------------------------------------
- **IPv6 Ports**:
    - UDP port 546 for Client
    - UDP port 547 for Server

	# DHCP Starvation Attack
		DHCP Starvation Attack is a Denial-of-Service attack on a DHCP server. Attacker send bogus requests to DHCP server with spoofed MAC address to lease all IP address in DHCP address pool. Once all IP address is allocated, upcoming users will be unable to obtain IP address or renew the lease.

	# Rogue DHCP Server
		Attacker deploy the rogue DHCP server in the network along with the DHCP starvation attack. When legitimate DHCP server is in Denial-of-Service attacks, DHCP clients are unable to gain IP address from the legitimate DHCP server. Upcoming DHCP Discovery (IPv4) and Solicit (IPv6) are replied by the bogus DHCP server with configuration parameter which directs the traffic towards it.
--------------------------------------------------------------------------------------------------------------
# ARP Poisoning
	# Address Resolution Protocol (ARP)
		The Address Resolution Protocol (ARP) is a communication protocol used for discovering the link layer address, such as a MAC address, associated with a given internet layer address, typically an IPv4 address.

	# ARP Spoofing Attack
		Attacker send forged ARP packets over Local Area Network (LAN). In this case, switch will update the attacker's MAC address with the IP address of a legitimate user or server, then start forwarding the packets to the attacker. Attacker can steal information by extracting it from packets.
		ARP Poisoning used for:
			- Session hijacking
			- Denial-of-Service attacks
			- Man-in-the-Middle attacks
			- Packet sniffing
			- Data interceptions
			- VoIP tapping ---> VOICE OVER IP
			- Stealing passwords
--------------------------------------------------------
# Spoofing Attacks
	# MAC Spoofing/Duplicating
		Manipulating the MAC address to impersonate the legitimate user or launch attack such as DoS.
		Attacker sniffs the MAC address of users which are active on switch ports and duplicate the MAC address.
		This can intercept the traffic and traffic destined to the legitimate user may direct to the attacker.

# DNS Poisoning   ---> WEB CACHE Poisoning

# Domain Name System (DNS)
	- DNS is used in networking to translate human-readable domain names to IP address.
	- When DNS Server receives the request, it doesn't have the entry, it generates the query to another DNS Server for the translation and so on.
	- DNS server having the translation will send back the IP address.

# DNS Cache Poisoning
	Attacker exploiting flaws in DNS software, adds or alter the entries.

------------------------------------------------------------------------------------------------------------
------------------------------------------------------------------------------------------------------------
# Wireshark
	Filters in Wireshark:
		- `==`			Equal
		- `eq`			Equal
		- `!=`			Not equal
		- `ne`			Not equal
		- `contains`	Contains specified value
		- ip.src  	source addresses
		- ip.dst 		destin addresses
		- ip.addr 	Match at both the places (source and destin)
--------------------------------------------------------------------------------------------------------------
# Sniffing Countermeasures
		- Use Secure Protocol instead of base Protocols (HTTPS over HTTP, SFTP over FTP, etc)
		- Switch instead of Hub (Hub broadcast packet by default, but Switch does not)
		- Strong encryption protocol (Strong Encrypted data is secure to transmit over any type of network)
