## Mobile Platform Attack Vectors

### OWASP Top 10 Mobile Threats

[OWASP Mobile Security Project](https://www.owasp.org/index.php/OWASP_Mobile_Security_Project#Top_Ten_Mobile_Risks) maintain a list
of the most common mobile security risks.

# Top Ten (2014)

1. Weak Server Side Controls
2. Insecure Data Storage
3. Insufficient Transport Layer Protection
4. Unintended Data Leakage
5. Poor Authorization and Authentication
6. Broken Cryptography
7. Client Side Injection
8. Security Decisions via Untrusted Inputs
9. Improper Session Handling
10. Lack of Binary Protections

# Top Ten (2016)

1. **Improper Platform Usage**: misuse of a platform feature or failure to use a platform security controls
2. **Insecure Data Storage**: insecure data storage + unintended data leakage
3. **Insecure Communication**: poor handshaking, incorrect SSL, weak negotiation, cleartext communication of sensitive assets, ...
4. **Insecure Authentication**: captures notions of authenticating the end user or bad session management
5. **Insufficient Cryptography**: cryptography was attempted, but it wasn't done correctly
6. **Insecure Authorization**: capture any failures in authorization
7. **Client Code Quality**: all of the code-level implementation problem in the mobile client
8. **Code Tampering**: binary patching, local resource modification, method hooking, dynamic memory modification, ...
9. **Reverse Engineering**: analysis of the final core binary to determine the source code, libraries, ...
10. **Extraneous Functionality**: internal development security controls that are not intended to be released into a production environment

# Basic Threats
  - Malwares (Trojans, Rootkits, Ransomware, etc.)
  - Data Loss
  - Data Tampering

# OS Sandboxing Issue
  - Sandbox is a security mechanism for separating running programs, usually in an effort to mitigate system failures or software vulnerabilities from spreading
  - Sandbox limits the app's access to files, preferences, network resources, ...
  - Advanced malware designed to bypass it, by fragment code or put sleep timer in the script to bypass the inspection process

# Rooting
  - A process of allowing user to attain privileged control
  - Needed for modify settings, get full control over the kernel or install custom ROMs

## iOS
  **Jailbreaking**
    - Rooting the iOS
    - Escalating the privileges on iOS to remove or bypass the factory default restrictions

# Types of Jailbreaking
  - **Userland Exploit** : allow user-level access without escalating iBoot-level access
  - **iBoot Exploit** : allow user-level and boot-level access
  - **Bootrom Exploit** : allow user-level and boot-level access

# Jailbreaking Techniques
  **Untethered  Jailbreak**
    - Does not require to reboot with a connection to your computer
    - Exploit bypass the iBoot sequence

  **Tethered Jailbreak**
    - Need a connection to your computer to reboot, without it, the boot stuck with an Apple logo
    - Offers complete jailbreak features

  **Semi-Untethered Jailbreak**
    - Allows to boot into the iOS device, but with limited functionality
    - The jailbreak functions will be disabled until the launch of a jailbreak app

  **Semi-Tethered Jailbreak**
    - Allows you to boot with limited functionality
    - To get the full functionality, a reboot with a tethered jailbreak required
    - Semi-Tethered Jailbreak: tethered jailbreak + a package to allow reboot with limited functionality

# Windows Phone
  - Windows Phone 8 using the Windows NT Kernel
  - Windows Phone 8 include app sandboxing, remote device management, native code support (C++)

# BlackBerry OS
  - Support for Java Micro Edition MIDP 1.0 and MIDP 2.0
  - OS update with BlackBerry over the air software loading service (OTASL)

# Bring Your Own Device (BYOD)
BYOD is a trend of employees using their personal devices for work. It could be a laptop, a phone, etc...

# BYOD Policies
BYOD policies should include:
  - Device: which devices and operating systems are supported
  - Password: require all devices to be password protected
  - Access: determine which data can be accessed from employee's device
  - Application: which applications allowed, which should be banned

# Mobile Security Guideline
  - Avoid auto-upload of files
  - Perform security assessment of applications
  - Turn off Bluetooth - Blue Born Attack
  - Allow only necessary GPS-enabled applications
  - Do not connect to open network
  - Install applications from trusted sources
  - Use strong password
  - Use Mobile Device Management (MDM) softwares
  - Update operating system often
  - Do not allow rooting / jailbreaking
  - Encrypt phone storage
  - Periodic backup
