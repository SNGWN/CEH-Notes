## Terminology
**Web Applications** are that applications that is running on a remote application server and available for clients over the internet.
**Server Administrators** are responsible for the web server's safety, speed, functioning and performance.
**Application Administrators** are responsible for the management and configuration required for the web
application.
**Clients** are the endpoints which interact with the web application / server.

## How Web Applications work?
**Front-end** <-> **Back-end**
  Users are interacting with the front-end.
  The processing was controlled and processed by the back-end.

# Server-side languages:
  - PHP - Hypertext Processer
  - Java
  - C# - C-Sharp
  - Python
  - JavaScript
  - many more...

# Client-side languages:
- CSS - Cascading Style Sheet
- JavaScript
- HTML

 # Web Application Threats
  - **Insecure storage** - sensitive data is stored on client side in plain text.
  - **Information leakage** - Sensitive Data is leaked unintentionally
  - **Directory traversal** - end user is able to traverse server's directory
  - **Parameter/Form tampering** - Modify Parameter value
  - **DOS attack**
  - **Buffer overflow** - Flood Server Buffer with junk and inject payload
  - **SQL injection** - Inject SQL Query through Parameter Fields or URL
  - **Cross-site Script** - Inject JavaScript or PHP script
  - **Security misconfiguration** - misconfigured server (Default account, unwanted services, Default passwords, debugging enabled, insecure exception handling)
  - **Broken session management**
  - **Session hijacking**

# Invalidated input - Attack through User INPUT
  Process an non-validated input from the client to the back-end. This is a major vulnerability, this is the basics of injection attacks (SQL injection, xss, buffer overflow).

# Parameter / Form Tampering
Parameter tempering is an attack, where the attacker manipulate the parameter while client and server are communicating with each other. Parameters such as **Uniform Resource Locator** (URL) or web page form fields are modified (cookies, HTTP Header, form fields).

# SQL Injection
  Injection of malicious SQL queries.
  Attacker can manipulate the database
  These vulnerabilities can be detected by using an automated scanner.

# DoS Attack
  - **User Registration DoS** : an automated process, the attacker keep registering fake accounts.
  - **Login DoS** : attacker keep sending login requests.
  - **User Enumeration** : attacker brute force login credentials with a dictionary attacks.
  - **Account Lock** : attacker attempt to lock the user account by attempting invalid passwords.

# Web Application Hacking Methodology
  # Analyze Web Application
    - Observing functionality
    - Identify vulnerabilities, entry points, servers
    - HTTP request analyze
    - Hidden content discovery - Directories, Subdomain, parameters
**************************************************************************************
# Attack Authentication
    Exploit the authentication mechanism:
      - Username enumerate
      - Cookie exploitation
      - Session attacks
      - Password attacks
**----------------------------------------------------------------------------------**
# Session Management Attack
1. Impersonate a legitimate user. - Spoofing
2. Session hijacking techniques: - Cookie Stealing
  - Session token prediction
  - Session token tampering - IDOR - INSECURE DIRECT OBJECT REFERNCE
  - Session replay

# Injection Attacks
Inject malicious code, commands and files.
Techniques:
  - Web Script injection - Injecting PHP, HTML or other languages scripts
  - OS Command injection - Inject OS command
  - SQL injection - Inject SQL Query
  - Buffer Overflow - Inject JUNK and PAYLOAD for Buffer Overflow attack
**----------------------------------------------------------------------------------**
# Countermeasures
**-------------**
# Percent Encoding
[Percent Encoding](https://en.wikipedia.org/wiki/Percent-encoding) or URL Encoding is a technique for
secure handling of URL by replaces unsafe and non-ascii characters with % followed by two hexadecimal
digits.
  Example:
    **%20 or + both are used for SPACE**

In URL:, there are some reserved character such as '/' that is used to separate paths in URL. To use this not as separator, then it must be encoded.
  **%2F used for '/'**

- **Full list of percent encoded characters**
[here](https://www.degraeve.com/reference/urlencoding.php)

# HTML Encoding - HTML Encoding specify how special character will shown.
**----------------------------------------------------------------------------------**
# SQL Injection Countermeasures
  - Input validation
  - Customized error messages
  - Monitoring database traffic
  - Limit length of user input

# XSS Attack Countermeasures
  - Testing tools
  - Filtering output
  - Validated INPUT

# Other Countermeasures
  - Dynamic testing - Testing through Automated Tools
  - Source Code analysis - Analyze source code
  - Strong cryptography - Use Strong Encryption and Hashing Algorithms
  - Use TLS over SSL - Use TLS 1.3, TLS 1.2 over deprecated version of TLS 1.1 or SSL
  - Cookie timeout
**----------------------------------------------------------------------------------**
**----------------------------------------------------------------------------------**
# OWASP Top 10
  1. **Injection** -> Inject Malicious command, Scripts, Queries, etc.
  2. **Broken Authentication**
  3. **Sensitive Data Exposure**
  4. **XXE (XML External Entity)** -> Vulnerable when XML data from Untrusted source is processed.
  5. **Broken Access Control**
  6. **Security misconfiguration**
  7. **Cross-Site Scripting** -> Executing Java Script, PHP or any Language code on Victim Side is known as Cross-Site Scripting.
  8. **Insecure Deserialization** -> Deserialization is the reverse process where the byte stream is used to recreate the actual Java object in memory.
  9. **Using Component With Known vulnerability**
  10. **Insufficient Logging and Monitoring**
**----------------------------------------------------------------------------------**
**----------------------------------------------------------------------------------**
