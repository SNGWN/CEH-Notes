# Session Hijacking - Session Hijacking is the process of taking control of an active session over active User.
--------------------------------------------------------------------------------
# What is a Sessions ID
	-> After Validating user with on basis of username and password, server assign him a string value called **Session ID**
	-> These Session ID's are used to identify USERs.
	-> After Validating user's credentials a fresh Session ID is assigned to User Every time.
	-> This Session ID is Stored in Form of Cookies on User's Browser.
--------------------------------------------------------------------------------
# Cookies
	-> Cookies are the values which help server to validate requests for each user or session
	-> Cookies Contain User Identity Details, Personalization, and other information used to identify user and computer on network.
--------------------------------------------------------------------------------
# Cookie vs Tokens
  - Cookies -> 	Cookies are stored on Both Server Side and Client Side.
  				Cookies are just String Values that are validated by comparison.
  - Tokens  ->  Tokens are Stored on Client Side only.
  				Normal JWT (JSON Web Token) comprised of **Header.Payload.Signature** 3 concatenated Base64url-encoded Strings, separated by (.)
--------------------------------------------------------------------------------
# Session Hijacking Concept
--------------------------------------------------------------------------------
# Why Session Hijacking Works
	-> Insecure Session Handling
	-> Insecure Session Termination
	-> Weak Session ID generation algorithms - linear algo. used such as time or IP address for generating session ID.
	-> Unencrypted Session ID's
----------------------------------------------------------------------------------
# Types of Session Hijacking
	- Active -> In Active Session Hijacking, Attacker steal Session Cookies from victim's Browser and use those cookies. Also known Application-Level Hijacking.
	- Passive -> A passive Attack uses sniffers on the network, allowing attacker to obtain info. to log on as a valid user and enjoy the privileges. Also called Network-Level Hijacking.
----------------------------------------------------------------------------------
# Methods to obtain Session ID
	-> Predict Session
	-> MITM = Man In The Middle Attack
	-> MITB = Man In The Browser Attack => Hijack Victims Browser - BeEF
	-> Network Sniffing
	-> Malware Attack
	-> XSS = Cross-Site Scripting => Executing Malicious Script to fetch User Cookies, when Victim Browse a Website script executes and Attacker get Session ID.
	-> Proxy Server => Attacker user their System as a Proxy Server for Victim so that all the traffic pass through their machine, and they can extract juicy info from requests and responses.
----------------------------------------------------------------------------------
# Session Hijacking vs Spoofing
  - Spoofing -> In Spoofing, Attacker Steal User Credentials and initiate a new session.
  - Hijacking -> In Hijacking, Attacker Steal Active Session ID's and Use those Session ID's.
----------------------------------------------------------------------------------
# Session Related Attacks
	-> IDOR -> Insecure Direct Object Reference => Attacker Modify Session ID's to gain access over other active Session. Attacker do this by analyzing the Session ID's format.
	-> Session Fixation Attack
				=> Vulnerability => Session ID is assigned before validating user credentials.
								 	=> Session ID is not modified after validating user Credentials.
				=> How Attacker Exploit => Attacker Open the website, and copy session ID(12345678) from there, and send URL with this Session ID to victim.
									=> when Victim open and validate the credentials, then server consider requests with that session ID(12345678) as Actual User's request.
									=> After user login, Attacker simply refresh the page and in response server send actual users details.
	-> Browser Back Attack
									=> Vulnerability => Session is not expired from server side after user logout.
	-> Cookie Replay Attack
									=> Vulnerability => Cookies from last Session can be used to initiate new Sessions.
----------------------------------------------------------------------------------
# Session Hijacking Tools
	-> Burp Suite
	-> OWASP ZAP
	-> Bettercap
	-> SSL Strip
	-> DroidSheep
	-> Droidsniff
	-> Faceniff
----------------------------------------------------------------------------------
# Protection Against Session Hijacking
	-> Use SSH to create secure communication Channel
	-> Pass Authentication cookie over HTTPS Connection
	-> Generate Session ID After Verifying credentials
	-> Use Encryption Over Data and cookies
	-> Use Lengthy Session-ID's
	-> Set Low Timeout for session expiration
	-> Use Strong Authentication like Kerbros
	-> Check Website Certificates
	-> Use Secure Protocol
----------------------------------------------------------------------------------
