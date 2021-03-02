# TCP vs UDP
	- TCP and UDP (Transmission Control Protocol and User Datagram Protocol) are communications protocol that facilitate the exchange of message (in form of Packets) between computer devices in a network. These protocols decide how packet will reach the destination. 65535
						**TCP** 																											**UDP**
		- Connection Oriented Protocol												- Connection Less protocol
		- Provides Error checking															- No Error Checking Mechanism
		- Guarantees Delivery of Data													- No Guarantees of Data Delivery
		- Slower and less efficient for fast transmission			- Faster Transmission
		- All Packets follow the same path										- Packets can follow any path to reach destination
		- Automimic Retransmission possible  									- Retransmission is not possible
			in case of Packets loss
---------------------------------------------------
## TCP Flags:
	- **SYN** : Sync flag is used to Initiate 3 way handshake between hosts.
	- **ACK** : Acknowledgment flag is used to acknowledge the successful receipt of a packet.
	- **FIN** : The Finished flag means there is no more data from the sender.  1GB --> 50000 --> 1,2,3,4,5,6,.........50000 (FIN)
	- **URG** : The Urgent flag is used to notify the receiver to process the urgent packets before processing all other packets.
	- **PSH** : The Push flag is somewhat similar to the URG flag and tells the receiver to process these packets as they are received instead of buffering them.
	- **RST** : Reset a Connection
---------------------------------------------------
## TCP 3 Way Handshake:
	| Client		| Direction |   Server  |
	|:---------:|:---------:|:---------:|
	|    SYN    | ---->     |           |
	|	        	|    <----  |  SYN+ACK  |
	|    ACK 		| ---->     |           |
######################################################################################################
																		## TASK ##
																-------------------
# OSI Model

| Layer ||       Name         ||	 			Description													|| Example protocols |
|:-----:||:------------------:||:..........................................:||:-----------------:|
|   7   || Application layer  || Human Computer Interaction Layer.					|| 	  HTTP, SNMP     |
|   6   || Presentation layer || Ensure Data Usability Format								||    MIME, ASCII    |
|   5   || Session layer      || Maintain Con. and control Ports and Session||    SOCKS, NetBIOS |
|   4   || Transport layer    || Data Transmission by TCP or UDP						||    TCP, UDP       |
|   3   || Network layer      || Decide Physical Path for Transmission			||    IP, ICMP       |
|   2   || Data link layer    || Read MAC Address from data packet					||    MAC, ARP       |
|   1   || Physical layer     || Physical connection												||  Ethernet, Wi-Fi  |
-------------------------
# TCP/IP Model

| Layer |       Name         | Example protocols |
|:-----:|:------------------:|:-----------------:|
|   4   | Application layer  |    HTTP, SNMP     |
|   3   | Transport layer    |    TCP, UDP       |
|   2   | Internet layer     |    IP, ICMP       |
|   1   | Link layer         |    ARP, MAC       |
-------------------------
# TCP vs UDP
	How is TCP different from UDP and how packets are delivered to target.
###############################################################################################################
---------------------------------------------------------------------------------------------------------------
# Practical Part
------------------
# Main Objectives
	k1. **Scan live host**
	k2. **Open Ports and Running Services**
	k3. **OS and Architecture info**
	k4. **Security Implemented (Firewall, IDS, IPS) Detection and evasion**

# k1. Live hosts
	arp-scan --local
	nmap -sn <network>/<cidr>					-sn specify NO-Port Ping Scan
	ping <ip>
	netdiscover -r <network address>/<cidr>
--------------------------------------------------------------------------
# Nmap Port Scan Status
	Open - If No response is received by Nmap, it means Port is Open for connection.
	Closed - If response is received by nmap with RST or SYN flag, it means ports are closed.
	Filtered - May be some kind of firewall is implemented on client side.
	Open/Filtered - Nmap is confused, either port is open or filtered.
	Closed/Filtered - Nmap is confused, either port is closed or filtered
--------------------------------------------------------------------------
# k2. Open Ports and Running Services Scan
	**Nmap**
		nmap <ip>																		Simple Port Scan
		nmap -v <ip>																Port Scan with increase verbosity. (-vv is more powerful)
		nmap <ip> <ip> <ip>													Scan Multiple host in single go
		nmap <1.1.1.2-200>													Scan IP Range from 2 to 200
		nmap <network>/cidr													Scan Entire Subnet
		nmap -p 1-65535 <ip>												-p specify Port Numbers to scan.
		nmap -p U:<port>,T:<port> <ip>							Scan specified TCP and UDP ports. use "*" for all.
		nmap -sU <ip>																Scan 1000 Common UDP Ports
		nmap -T<0-5> <ip>														-T specify intensity of scan to time taken by scan. 5 is
																								fastest and 0 is slowest. Default Speed is 3(-T3).
		nmap -sT <ip>																TCP Connect Scan
		nmap -iL list.txt														scan ip written in list.txt file (Separate IP by Space, Tab or New Line). --exclude file list.txt (to exclude ip from search)
		nmap -A <ip>																Aggressive Scan (it use -O -sC --traceroute -sV) options
		nmap -O <ip>																-O is used for OS Detection
		nmap -sC <ip>																-sC is used to run Default NSE Scripts  --- **--script**
		nmap -sV <ip>																-sv is used for Service Version Detection
		nmap -6 <ip>																IPv6 Scan
		nmap -sS <ip>																Sync Scan/Ping. Helpful in case where ICMP pings are blocked.
		nmap -sA <ip>																ACK Scan/Ping. Helpful in case where ICMP pings are blocked. Null Scan
		nmap --scanflags SYNACKFIN <ip>							We can set flags using --scanflags option.
		nmap -Pn <ip>																Don't Ping Scan (When Firewall block Ping Packets)
		nmap -sR <ip>																Scan for RPC (Remote Procedure Call) Service
	**Hping3**
		hping3 --icmp <ip> --verbose								Ping Scan in Verbose
		hping3 --scan <ports> <ip>									Scan for Open Ports on IP (--ack, --syn, --fin, --urg)
		hping3 --udp <ip> --verbose									UDP port Scan in Verbose
--------------------------------------------------------------------------
# k3. OS Detection
		nmap -O <ip>																OS Detection with Nmap
--------------------------------------------------------------------------
# k4. Security Implemented (Firewall, IDS, IPS) Detection and evasion
		nmap -f <ip>								-f will fragment packets in 8-byte packets. Helpful when
													attempting to evade some older or improperly configured
													firewall or we can specify packet fragment size using
													--mtu <size>" option. Size should be multiple of 8

		nmap -D RND:<val> <ip>						-D Decoy option is used to mask an Nmap scan by using one
													or more decoys. Decoy is used to hide identity. RND is
													Number of Decoy Address to be used. We can also specify
													Addresses by our own. as
													 nmap -D decoy1,decoy2,decoy3,etc <ip>

		nmap -sX <ip>								Nmap XMas Scan (if Firewall is enable you get
													(all thousand ports are closed/filtered), if Firewall is
													disable you get (Closed). Xmas Scan use PSH+URG+FIN flag
													or All flag for packets and create abnormal situation for
													client for which client either respond with RST Flag or
													some relevant info.
--------------------------------------------------------------------------
--------------------------------------------------------------------------
# We can also use Zenmap
--------------------------------------------------------------------------
--------------------------------------------------------------------------
