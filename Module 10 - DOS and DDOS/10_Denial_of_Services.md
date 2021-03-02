# Basic
	Denial-of-Service is type of attack on which service offered by a system or a network is denied/unavailable. Service may either be denied, reduce the functionality or prevent the access.

# Symptoms of DoS attack: 
	- Slow performance
	- Increase in spam email --> SMTP
	- Unavailability of a resource
	- Loss of access to a website
	- Disconnection of a wireless or wired internet connection
	- Denial of access to any internet services

# Distributed Denial of Service (DDoS)
	- In DDoS, multiple compromised systems are involved to attack a target.
	- The attacker send several connection request to the server with fake return address, so the server can't find a user to send the connection approval.
	- The authentication process waits for a certain time to close the session.
	- The attacker is continuously sending requests which causing a number of open connection on the server that lead to a denial of service.

# Categories of DoS/DDoS Attacks
	**Volumetric Attacks**
		Denial of Service attack performed by sending a high amount of traffic towards the target.
		Volumetric attack are focused on overloading the bandwidth capability.
	**Fragmentation Attacks**
		DoS attacks witch fragment the IP datagram into multiple smaller size packets.
		It requires to reassembly at the destination which requires resources of routers.
	**TCP-State-Exhaustion Attacks**
		TCP-State-Exhaustion Attacks are focused on web servers, firewalls, load balancers and other infrastructure component to disrupt connections by exhausting their finite number of concurrent connections.
		Most common state-exhaustion attack is ping of death.

# DoD/DDoS Attack Techniques
	**Bandwidth Attacks - DDoS**
		Bandwidth attack requires multiple sources to generate requests to overload the target.
		The goal is to consume the bandwidth completely.
		Zombie servers or Botnets used to perform this type of attack.
	**Service Request Floods**
		Attacker flood the request towards a web service or server until it is overloaded.
	**SYN Attack / Flooding**
		The attacker sending a lot of SYN request to tying up a system.
		The victim waits for the acknowledgement from the Attacker, but Attacker never send the acknowledgement.
		This waiting period ties up a connection "listen to queue", that can tie up for 75 seconds.
	**ICMP Flood Attack - Ping of Death**
		Flooding ICMP request without waiting for the response overwhelm the resource of the network device.
	**Permanent DoS Attack (PDoS)**
		Permanent DoS attack is focused on hardware sabotage, cause irreversible damage to the hardware.
		Affected hardware require replacement or reinstall the software.
	**Distributed Reflection Denial of Service (DRDoS)**
		Attacker uses an intermediary victim which redirect the traffic to a secondary victim.
		Secondary victim redirects the traffic to the target.
		The intermediary and secondary victim is used for spoofing the attack.
	**Botnet**
		Attacker compromises victims to make bot, which compromise other system to create a botnet.
		These botnets are controlled by **Command and Control server** owned by the attacker.
		This server is used to send instructions to perform the attack.

# Tools
	- Ping command
	- Nmap DOS Script
	- Hping3
	- LOIC - Low Orbit Ion Cannon
	- MSF Auxiliary
	- Hulk - Github

# Preventive Measures
	- Use Load Balancers.
	- Protect your network with Network Firewall. -- IDS / IPS
	- Implement Web Application Firewall.
	- Take Help from Cloud, they have more bandwidth than an enterprise would, which can help in large volumetric attacks.
