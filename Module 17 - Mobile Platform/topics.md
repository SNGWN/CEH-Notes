# Mobile Platform Hacking - Topics Overview

## Topic Explanation
Mobile platform hacking focuses on exploiting vulnerabilities in mobile devices, applications, and communication protocols. This includes attacks on Android and iOS platforms, mobile application vulnerabilities, mobile device management (MDM) bypass, SMS/voice attacks, and mobile malware. Common attack vectors include app-based attacks, network-based attacks, physical attacks, and social engineering targeting mobile users.

## Articles for Further Reference
- [OWASP Mobile Security](https://owasp.org/www-project-mobile-security/)
- [NIST Mobile Device Security Guidelines](https://csrc.nist.gov/publications/detail/sp/800-124/rev-1/final)
- [Android Security](https://source.android.com/security)

## Reference Links
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [MobSF - Mobile Security Framework](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
- [Frida Dynamic Instrumentation](https://frida.re/)

## Available Tools for the Topic

### Tool Name: MobSF (Mobile Security Framework)
**Description:** Automated mobile application security testing framework for Android and iOS applications.

**Example Usage:**
```bash
# Install MobSF
git clone https://github.com/MobSF/Mobile-Security-Framework-MobSF.git
cd Mobile-Security-Framework-MobSF
./setup.sh

# Start MobSF
./run.sh

# Access web interface at http://localhost:8000
# Upload APK/IPA file for analysis
```

### Tool Name: Frida
**Description:** Dynamic instrumentation toolkit for mobile applications allowing runtime manipulation and analysis.

**Example Usage:**
```bash
# Install Frida
pip install frida-tools

# List running applications
frida-ps -U

# Hook into application
frida -U -l script.js com.example.app

# Spawn application with hooks
frida -U -f com.example.app -l script.js --no-pause
```

## All Possible Payloads for Manual Approach

### Android Application Testing
```bash
# APK analysis
aapt dump badging app.apk
apktool d app.apk
dex2jar app.apk

# ADB commands
adb devices
adb shell pm list packages
adb shell am start -n com.example/.MainActivity
adb logcat | grep "com.example"

# Intent fuzzing
adb shell am start -a android.intent.action.VIEW -d "malicious://payload"
```

### iOS Application Testing
```bash
# IPA analysis
unzip app.ipa
otool -L Payload/App.app/App
class-dump-z Payload/App.app/App

# Runtime manipulation with Frida
frida -U -l bypass.js "App Name"
```

## Example Payloads

### Mobile Application Security Scanner
```python
#!/usr/bin/env python3
import zipfile
import os
import re
import subprocess

class MobileAppScanner:
    def __init__(self, app_path):
        self.app_path = app_path
        self.vulnerabilities = []
        self.is_android = app_path.endswith('.apk')
        self.is_ios = app_path.endswith('.ipa')
    
    def scan_application(self):
        """Perform comprehensive mobile app security scan"""
        print(f"Scanning {self.app_path}...")
        
        if self.is_android:
            self.scan_android_app()
        elif self.is_ios:
            self.scan_ios_app()
        
        self.generate_report()
    
    def scan_android_app(self):
        """Scan Android APK file"""
        # Extract APK
        extract_dir = "extracted_apk"
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(self.app_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Check manifest permissions
        self.check_android_permissions(extract_dir)
        
        # Scan for hardcoded secrets
        self.scan_hardcoded_secrets(extract_dir)
        
        # Check for debug flags
        self.check_debug_flags(extract_dir)
    
    def check_android_permissions(self, extract_dir):
        """Check Android manifest permissions"""
        manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
        
        dangerous_permissions = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS", 
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS"
        ]
        
        if os.path.exists(manifest_path):
            with open(manifest_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
                
                for permission in dangerous_permissions:
                    if permission in content:
                        self.vulnerabilities.append(f"Dangerous permission: {permission}")
    
    def scan_hardcoded_secrets(self, extract_dir):
        """Scan for hardcoded secrets and sensitive data"""
        secret_patterns = [
            (r'password\s*=\s*["\']([^"\']+)["\']', 'Hardcoded password'),
            (r'api[_-]?key\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded API key'),
            (r'secret\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded secret'),
            (r'token\s*[=:]\s*["\']([^"\']+)["\']', 'Hardcoded token'),
            (r'jdbc:postgresql://([^/]+)/([^"\']+)', 'Database connection string')
        ]
        
        for root, dirs, files in os.walk(extract_dir):
            for file in files:
                if file.endswith(('.java', '.kt', '.xml', '.json', '.js')):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                            for pattern, desc in secret_patterns:
                                matches = re.finditer(pattern, content, re.IGNORECASE)
                                for match in matches:
                                    self.vulnerabilities.append(f"{desc} in {file}: {match.group(1)[:20]}...")
                    except:
                        pass
    
    def check_debug_flags(self, extract_dir):
        """Check for debug flags and development settings"""
        manifest_path = os.path.join(extract_dir, "AndroidManifest.xml")
        
        if os.path.exists(manifest_path):
            with open(manifest_path, 'rb') as f:
                content = f.read().decode('utf-8', errors='ignore')
                
                if 'android:debuggable="true"' in content:
                    self.vulnerabilities.append("Application is debuggable")
                
                if 'android:allowBackup="true"' in content:
                    self.vulnerabilities.append("Application allows backup")
    
    def scan_ios_app(self):
        """Scan iOS IPA file"""
        # Extract IPA
        extract_dir = "extracted_ipa"
        os.makedirs(extract_dir, exist_ok=True)
        
        with zipfile.ZipFile(self.app_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Find app bundle
        payload_dir = os.path.join(extract_dir, "Payload")
        if os.path.exists(payload_dir):
            app_dirs = [d for d in os.listdir(payload_dir) if d.endswith('.app')]
            if app_dirs:
                app_path = os.path.join(payload_dir, app_dirs[0])
                self.check_ios_plist(app_path)
                self.scan_hardcoded_secrets(app_path)
    
    def check_ios_plist(self, app_path):
        """Check iOS Info.plist for security issues"""
        plist_path = os.path.join(app_path, "Info.plist")
        
        if os.path.exists(plist_path):
            try:
                with open(plist_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore')
                    
                    if 'NSAllowsArbitraryLoads' in content:
                        self.vulnerabilities.append("App Transport Security disabled")
                    
                    if 'UIFileSharingEnabled' in content:
                        self.vulnerabilities.append("File sharing enabled")
            except:
                pass
    
    def generate_report(self):
        """Generate security assessment report"""
        print("\n" + "="*60)
        print("MOBILE APPLICATION SECURITY REPORT")
        print("="*60)
        print(f"Application: {os.path.basename(self.app_path)}")
        print(f"Platform: {'Android' if self.is_android else 'iOS' if self.is_ios else 'Unknown'}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nVulnerabilities:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln}")
        else:
            print("\nNo obvious vulnerabilities detected.")

# Example usage
scanner = MobileAppScanner("sample_app.apk")
scanner.scan_application()
```