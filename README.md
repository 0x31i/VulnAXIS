# AXIS M1025 IoT Camera CTF Lab - Setup Guide

## Overview

CTF lab environment with 27 flags distributed across a realistic AXIS camera filesystem. This setup script creates intentionally vulnerable configurations for educational penetration testing.

**WARNING: ISOLATED LAB ONLY - NEVER USE IN PRODUCTION**

---

## Lab Specifications

- **Target Device**: AXIS M1025 Network Camera (or compatible Linux system)
- **Firmware Version**: 10.5.0
- **Total Flags**: 27 (5 Easy, 13 Medium, 9 Hard)
- **Flag Format**: `FLAG{POKEMON_NAME#########}`
- **Shell**: POSIX-compliant (BusyBox ash compatible)

---

## Prerequisites

### Network Requirements
- Isolated VLAN or air-gapped network
- Static IP for camera: `192.168.148.103`
- No internet access (prevents firmware updates)

### System Requirements
- Linux-based embedded system or VM
- Minimum 512MB storage for flag files
- Root/sudo access required
- SSH enabled

---

## Quick Setup

### Step 1: Transfer Script to Camera

```bash
# Download the script and change directory to the location of the file
cd /scripts

# From your admin workstation
cat vulnaxis.sh | ssh root@192.168.148.103 "cat › /tmp/vulnaxis.sh"

# Or via physical access/serial console
# Copy script to /tmp/ directory
```

### Step 2: Execute Setup Script

```bash
# SSH into camera
ssh root@192.168.148.103

# Make script executable
chmod +x /tmp/vulnaxis.sh

# Run setup (takes ~10 seconds)
sh /tmp/vulnaxis.sh
```

**Expected Output:**
```
[*] Starting Axis Camera CTF setup - v5.0
[+] Creating comprehensive Axis camera directory structure...
[+] Distributing EASY FLAGS across writable directories...
[+] Flag #1: VAPIX Configuration...
[+] Flag #4: System Log Entry...
...
[*] CTF Setup Complete - FIXED VERSION v5.0
    EASY flags: 5 (basic enumeration)
    MEDIUM flags: 13 (exploitation required)  
    HARD flags: 9 (advanced techniques)
    TOTAL: 27 flags
```

### Step 3: Verify Installation

```bash
# Check flag distribution
find /mnt -name "*.conf" -o -name "*.txt" 2>/dev/null | wc -l
find /var/lib/persistent -type f 2>/dev/null | wc -l
find /var/cache/recorder -type f 2>/dev/null | wc -l

# Quick flag check (should show flags)
grep -r "FLAG{" /var/lib/axis/conf/ 2>/dev/null | head -3
cat /var/log/messages | grep FLAG
```

### Step 4: Configure Access

**Default Credentials:**
```
Username: root
Password: pass
```

**SSH Access:**
```bash
ssh root@192.168.148.103
# Password: pass
```

**Web Interface:**
```
http://192.168.148.103
https://192.168.148.103
```

---

## Testing Access Points

### Web Services
```bash
# Test HTTP access
curl http://192.168.1.132/
```

### File System Enumeration
```bash
# Student reconnaissance commands
find /mnt -type f 2>/dev/null
find /var/lib/persistent -name "*.lic" 2>/dev/null
ls -laR /var/cache/recorder/ 2>/dev/null
cat /var/log/messages
``

---

## Reset and Cleanup

### Full Reset
```bash
# Remove all CTF files
rm -rf /var/lib/axis/conf/vapix.conf
rm -rf /var/lib/persistent/
rm -rf /var/cache/recorder/
rm -rf /mnt/flash/config/
rm -rf /usr/local/axis/
rm -rf /var/www/local/
rm -f /var/log/messages

# Or re-run script (overwrites all)
/tmp/vulnaxis.sh
```

---

## Troubleshooting

### Script Fails to Execute

**Symptom:** `Permission denied` or `not found`

**Solution:**
```bash
# Ensure script has execute permissions
chmod +x /tmp/vulnaxis.sh

# Verify POSIX shell compatibility
sh /tmp/vulnaxis.sh  # Use sh instead of bash
```

### Directories Not Writable

**Symptom:** `mkdir: cannot create directory`

**Solution:**
```bash
# Check available space
df -h
```
