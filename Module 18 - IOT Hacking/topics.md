# IoT Hacking - Topics Overview

## Topic Explanation
Internet of Things (IoT) hacking involves exploiting vulnerabilities in connected devices, embedded systems, and IoT infrastructure. Common attack vectors include firmware analysis, communication protocol exploitation, device authentication bypass, default credential abuse, and physical hardware attacks. IoT devices often lack proper security controls, making them attractive targets for attackers seeking to gain network access or build botnets.

## Articles for Further Reference
- [OWASP IoT Top 10](https://owasp.org/www-project-iot-top-10/)
- [NIST IoT Security Guidelines](https://csrc.nist.gov/publications/detail/sp/800-213/final)
- [IoT Security Foundation](https://www.iotsecurityfoundation.org/)

## Reference Links
- [IoT Vulnerability Database](https://www.iot-inspector.com/)
- [Shodan IoT Search Engine](https://www.shodan.io/)
- [Firmware Analysis Tools](https://github.com/ReFirmLabs/binwalk)

## Available Tools for the Topic

### Tool Name: Shodan
**Description:** Search engine for Internet-connected devices including IoT devices, industrial systems, and network infrastructure.

**Example Usage:**
```bash
# Search for specific IoT devices
shodan search "default password"
shodan search "webcam"
shodan search "raspberry pi"

# Search by service
shodan search "port:23 telnet"
shodan search "port:80 title:\"IP Camera\""
```

### Tool Name: Binwalk
**Description:** Firmware analysis tool for extracting and analyzing firmware images from IoT devices.

**Example Usage:**
```bash
# Analyze firmware image
binwalk firmware.bin

# Extract filesystem
binwalk -e firmware.bin

# Entropy analysis
binwalk -E firmware.bin
```

## All Possible Payloads for Manual Approach

### IoT Device Enumeration
```bash
# Network scanning for IoT devices
nmap -sn 192.168.1.0/24
nmap -p 80,443,23,22,8080 192.168.1.0/24

# Service enumeration
nmap -sV -p- iot-device-ip
telnet iot-device-ip 23
ssh iot-device-ip

# Default credential testing
admin:admin
admin:password
root:root
admin:123456
```

### Firmware Analysis Commands
```bash
# Extract firmware
binwalk -e firmware.bin
7z x firmware.bin
dd if=firmware.bin of=extracted.img bs=1 skip=offset

# File system analysis
file extracted/*
strings extracted/bin/busybox
grep -r "password" extracted/
find extracted/ -name "*.conf"
```

## Example Payloads

### IoT Security Assessment Framework
```python
#!/usr/bin/env python3
import socket
import telnetlib
import requests
import subprocess
import re

class IoTSecurityScanner:
    def __init__(self, target_ip):
        self.target_ip = target_ip
        self.vulnerabilities = []
        self.services = {}
    
    def scan_ports(self):
        """Scan for common IoT ports"""
        common_ports = [22, 23, 53, 80, 443, 554, 1883, 5683, 8080, 8883]
        
        print(f"Scanning ports on {self.target_ip}...")
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            try:
                result = sock.connect_ex((self.target_ip, port))
                if result == 0:
                    self.services[port] = self.identify_service(port)
                    print(f"Port {port} open: {self.services[port]}")
            except:
                pass
            finally:
                sock.close()
    
    def identify_service(self, port):
        """Identify service running on port"""
        service_map = {
            22: "SSH",
            23: "Telnet", 
            53: "DNS",
            80: "HTTP",
            443: "HTTPS",
            554: "RTSP",
            1883: "MQTT",
            5683: "CoAP",
            8080: "HTTP-Alt",
            8883: "MQTT-SSL"
        }
        return service_map.get(port, "Unknown")
    
    def test_default_credentials(self):
        """Test common default credentials"""
        credentials = [
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("admin", ""),
            ("", "admin")
        ]
        
        # Test Telnet
        if 23 in self.services:
            print("Testing Telnet default credentials...")
            for username, password in credentials:
                if self.test_telnet_login(username, password):
                    self.vulnerabilities.append(f"Default Telnet credentials: {username}:{password}")
                    break
        
        # Test SSH
        if 22 in self.services:
            print("Testing SSH default credentials...")
            for username, password in credentials:
                if self.test_ssh_login(username, password):
                    self.vulnerabilities.append(f"Default SSH credentials: {username}:{password}")
                    break
        
        # Test HTTP authentication
        if 80 in self.services or 8080 in self.services:
            port = 80 if 80 in self.services else 8080
            self.test_http_auth(port, credentials)
    
    def test_telnet_login(self, username, password):
        """Test Telnet login with credentials"""
        try:
            tn = telnetlib.Telnet(self.target_ip, 23, timeout=5)
            tn.read_until(b"login:", timeout=5)
            tn.write(username.encode() + b"\n")
            tn.read_until(b"Password:", timeout=5)
            tn.write(password.encode() + b"\n")
            
            response = tn.read_some().decode('utf-8', errors='ignore')
            tn.close()
            
            return "login incorrect" not in response.lower() and "$" in response
        except:
            return False
    
    def test_ssh_login(self, username, password):
        """Test SSH login with credentials"""
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(self.target_ip, 22, username, password, timeout=5)
            ssh.close()
            return True
        except:
            return False
    
    def test_http_auth(self, port, credentials):
        """Test HTTP basic authentication"""
        url = f"http://{self.target_ip}:{port}"
        
        try:
            response = requests.get(url, timeout=5)
            if response.status_code == 401:
                for username, password in credentials:
                    auth_response = requests.get(url, auth=(username, password), timeout=5)
                    if auth_response.status_code == 200:
                        self.vulnerabilities.append(f"Default HTTP credentials: {username}:{password}")
                        break
        except:
            pass
    
    def check_web_interfaces(self):
        """Check for insecure web interfaces"""
        if 80 in self.services or 8080 in self.services:
            port = 80 if 80 in self.services else 8080
            url = f"http://{self.target_ip}:{port}"
            
            try:
                response = requests.get(url, timeout=10)
                
                # Check for common IoT device indicators
                content = response.text.lower()
                
                if any(keyword in content for keyword in ['ip camera', 'webcam', 'dvr', 'router']):
                    print(f"IoT device web interface detected on port {port}")
                
                # Check for directory listing
                if 'index of' in content:
                    self.vulnerabilities.append("Directory listing enabled")
                
                # Check for exposed configuration
                if any(keyword in content for keyword in ['config', 'configuration', 'setup']):
                    self.vulnerabilities.append("Configuration interface exposed")
                    
            except:
                pass
    
    def check_mqtt_security(self):
        """Check MQTT broker security"""
        if 1883 in self.services:
            print("Testing MQTT security...")
            
            try:
                import paho.mqtt.client as mqtt
                
                def on_connect(client, userdata, flags, rc):
                    if rc == 0:
                        self.vulnerabilities.append("MQTT broker allows anonymous access")
                
                client = mqtt.Client()
                client.on_connect = on_connect
                client.connect(self.target_ip, 1883, 5)
                client.loop_start()
                time.sleep(2)
                client.disconnect()
            except:
                pass
    
    def firmware_analysis_check(self):
        """Check for firmware download endpoints"""
        if 80 in self.services or 8080 in self.services:
            port = 80 if 80 in self.services else 8080
            
            firmware_paths = [
                "/firmware.bin",
                "/update.bin", 
                "/backup.bin",
                "/config.bin",
                "/dump.bin"
            ]
            
            for path in firmware_paths:
                url = f"http://{self.target_ip}:{port}{path}"
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        self.vulnerabilities.append(f"Firmware/config file accessible: {path}")
                except:
                    pass
    
    def generate_report(self):
        """Generate IoT security assessment report"""
        print("\n" + "="*60)
        print("IOT DEVICE SECURITY ASSESSMENT REPORT")
        print("="*60)
        print(f"Target: {self.target_ip}")
        print(f"Open ports: {list(self.services.keys())}")
        print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nVulnerabilities:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln}")
        else:
            print("\nNo obvious vulnerabilities detected.")
        
        # Security recommendations
        print("\nSecurity Recommendations:")
        recommendations = [
            "Change default credentials",
            "Disable unnecessary services",
            "Enable encryption for communications",
            "Regular firmware updates",
            "Network segmentation for IoT devices",
            "Monitor device communications"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
    
    def run_assessment(self):
        """Run complete IoT security assessment"""
        print(f"Starting IoT security assessment for {self.target_ip}")
        
        self.scan_ports()
        self.test_default_credentials()
        self.check_web_interfaces()
        self.check_mqtt_security()
        self.firmware_analysis_check()
        self.generate_report()

# Example usage
import time
scanner = IoTSecurityScanner("192.168.1.100")
scanner.run_assessment()
```