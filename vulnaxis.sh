#!/bin/sh
# AXIS IoT Camera Vulnerable Lab Configuration Script v5
# WARNING: FOR ISOLATED LAB ENVIRONMENT ONLY - NEVER USE IN PRODUCTION
# This script intentionally creates security vulnerabilities and CTF flags for penetration testing practice

echo "[*] Starting Axis Camera CTF setup - v5.0"
echo "[*] $(date)"

# ============================================================================
# CREATE REALISTIC AXIS CAMERA DIRECTORY STRUCTURE
# Using ALL available writable locations
# ============================================================================
echo "[+] Creating comprehensive Axis camera directory structure..."

# Core Axis directories in /var
mkdir -p /var/lib/axis/conf
mkdir -p /var/lib/axis/licenses
mkdir -p /var/lib/axis/certificates
mkdir -p /var/cache/axis/vapix
mkdir -p /var/cache/axis/thumbnails
mkdir -p /var/opt/axis/applications
mkdir -p /var/opt/axis/overlays
mkdir -p /var/run/axis/services
mkdir -p /var/www/local/axis-cgi
mkdir -p /var/www/local/admin
mkdir -p /var/spool/cron/crontabs
mkdir -p /var/backups/config
mkdir -p /var/backups/firmware
mkdir -p /var/db/axis
mkdir -p /var/log/axis/services
mkdir -p /var/log/axis/vapix
mkdir -p /var/log/axis/.archived

# Persistent storage directories (/var/lib/persistent)
mkdir -p /var/lib/persistent/system/configs
mkdir -p /var/lib/persistent/system/licenses
mkdir -p /var/lib/persistent/network/certificates
mkdir -p /var/lib/persistent/applications/custom
mkdir -p /var/lib/persistent/security/keys
mkdir -p /var/lib/persistent/firmware/backups

# Recording cache directories (/var/cache/recorder)
mkdir -p /var/cache/recorder/streams/primary
mkdir -p /var/cache/recorder/streams/secondary
mkdir -p /var/cache/recorder/thumbnails
mkdir -p /var/cache/recorder/analytics/motion
mkdir -p /var/cache/recorder/analytics/metadata
mkdir -p /var/cache/recorder/.temp

# Flash storage directories (/mnt/flash)
mkdir -p /mnt/flash/boot/uboot
mkdir -p /mnt/flash/boot/kernel
mkdir -p /mnt/flash/firmware/images
mkdir -p /mnt/flash/firmware/signatures
mkdir -p /mnt/flash/config/factory
mkdir -p /mnt/flash/config/user
mkdir -p /mnt/flash/config/.backup

# Shared memory directories (/dev/shm)
mkdir -p /dev/shm/axis/runtime
mkdir -p /dev/shm/axis/ipc
mkdir -p /dev/shm/axis/streams

# Runtime directories (/run)
mkdir -p /run/axis/services
mkdir -p /run/axis/network
mkdir -p /run/axis/camera
mkdir -p /run/axis/locks

# Custom local applications (/usr/local)
mkdir -p /usr/local/axis/bin
mkdir -p /usr/local/axis/lib
mkdir -p /usr/local/axis/etc
mkdir -p /usr/local/axis/share/scripts

# FIXED: cgroup directories - using writable /var/lib/axis/cgroup instead of /sys/fs/cgroup
# The /sys/fs/cgroup is a kernel virtual filesystem and not writable like regular directories
mkdir -p /var/lib/axis/cgroup/axis/camera.service
mkdir -p /var/lib/axis/cgroup/axis/network.service

echo "  [COMPLETE] Comprehensive directory structure created across all writable locations"

# ============================================================================
# EASY FLAGS (5 flags) - Discoverable with basic enumeration
# ============================================================================

echo ""
echo "[+] Distributing EASY FLAGS across writable directories..."

# Flag #1: Default VAPIX Configuration (/var/lib/axis/conf/)
echo "[+] Flag #1: VAPIX Configuration..."
cat > /var/lib/axis/conf/vapix.conf << 'EOF'
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
EOF
chmod 644 /var/lib/axis/conf/vapix.conf

# Flag #4: SSH Banner in syslog (/var/log/)
echo "[+] Flag #4: System Log Entry..."
cat > /var/log/messages << 'EOF'
Jan  1 12:00:01 axis-camera syslogd: syslogd started: BusyBox v1.31.1
Jan  1 12:00:05 axis-camera kernel: Linux version 4.9.0-axis1 (build@axis.com)
Jan  1 12:00:10 axis-camera sshd[234]: Server listening on 0.0.0.0 port 22
Jan  1 12:00:11 axis-camera sshd[234]: Device-ID: FLAG{GIMLI42137246}
Jan  1 12:00:15 axis-camera network: eth0: link up
Jan  1 12:00:20 axis-camera vapix: VAPIX API started on port 80
Jan  1 12:00:25 axis-camera camera: Video encoder initialized
Jan  1 12:00:30 axis-camera rtsp: RTSP server started on port 554
EOF
chmod 644 /var/log/messages

# Flag #7: HTML Comment in web interface (/var/www/)
echo "[+] Flag #7: Web Interface HTML..."
mkdir -p /var/www/local/admin
cat > /var/www/local/admin/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>AXIS Camera Station</title>
    <meta charset="UTF-8">
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .status { color: green; }
    </style>
</head>
<body>
    <h1>AXIS Network Camera - Management Interface</h1>
    <div class="status">System Status: Online</div>
    
    <!-- Development Note: Remove before production deployment -->
    <!-- Build version: 10.5.0-dev -->
    <!-- Debug token: FLAG{MERRY36385024} -->
    <!-- Contact: dev-team@axis.com for issues -->
    
    <p>Welcome to the camera management interface.</p>
    <ul>
        <li><a href="/axis-cgi/param.cgi">Parameters</a></li>
        <li><a href="/axis-cgi/admin/systemlog.cgi">System Log</a></li>
        <li><a href="/axis-cgi/mjpg/video.cgi">Live View</a></li>
    </ul>
</body>
</html>
EOF
chmod 644 /var/www/local/admin/index.html
ln -sf /var/www/local/admin/index.html /var/www/index.html 2>/dev/null

# Flag #14: Recording Stream Configuration (/var/cache/recorder/)
echo "[+] Flag #14: Recording Stream Configuration..."
cat > /var/cache/recorder/streams/primary/stream_config.conf << 'EOF'
# Primary Stream Recording Configuration
# Auto-generated by recorder service

[Stream_Settings]
name=MainRecordingStream
resolution=1920x1080
framerate=30
codec=h264
bitrate=4096

[Recording]
enabled=true
path=/var/cache/recorder/storage
retention_days=30
continuous=true

[Authentication]
stream_user=recorder
stream_pass=rec0rd3r
auth_token=FLAG{SARUMAN83479324}

[Analytics]
motion_detection=enabled
object_tracking=enabled
EOF
chmod 644 /var/cache/recorder/streams/primary/stream_config.conf

# Flag #19: Factory Configuration (/mnt/flash/config/factory/)
echo "[+] Flag #19: Factory Configuration..."
cat > /mnt/flash/config/factory/device_info.txt << 'EOF'
# AXIS Device Factory Configuration
# DO NOT MODIFY - Factory sealed settings

[Manufacturing]
serial_number=ACCC8E-M1025-2024
manufacture_date=2024-01-01
manufacturing_site=Sweden_Lund
batch_number=20240101-A

[Quality_Assurance]
test_passed=true
test_date=2024-01-01
test_engineer=qa-team@axis.com
qa_code=FLAG{THEODEN40558954}

[Hardware]
model=M1025
revision=1.0
sensor=Sony_IMX334
processor=ARTPEC-7
EOF
chmod 644 /mnt/flash/config/factory/device_info.txt

# ============================================================================
# MEDIUM FLAGS (13 flags) - Require enumeration + exploitation
# ============================================================================

echo ""
echo "[+] Distributing MEDIUM FLAGS across writable directories..."

# Flag #2: Persistent License File (/var/lib/persistent/)
echo "[+] Flag #2: Persistent License..."
cat > /var/lib/persistent/system/licenses/vapix_pro.lic << 'EOF'
# AXIS VAPIX Professional License
# License Type: Enterprise
# Issued: 2024-01-01

[License_Info]
type=professional
tier=enterprise
features=all

[Validation]
issued=2024-01-01
expires=2025-12-31
serial=VAPIX-PRO-FLAG{ARAGORN79305394}

[Authorized_Features]
analytics=true
recording=true
ptz_control=true
audio=true
io_control=true
EOF
chmod 644 /var/lib/persistent/system/licenses/vapix_pro.lic

# Flag #5: Persistent SSH Keys (/var/lib/persistent/)
echo "[+] Flag #5: Persistent SSH Keys..."
cat > /var/lib/persistent/security/keys/authorized_keys << 'EOF'
# AXIS Camera Authorized SSH Keys
# Updated: 2024-01-01
# Administrator keys for remote management

# Admin key - FLAG{BOROMIR73553172}
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7admin...truncated...== admin@axis

# Maintenance key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDmaint...truncated...== maintenance@axis

# Backup key
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCbbackup...truncated...== backup@axis
EOF
chmod 600 /var/lib/persistent/security/keys/authorized_keys

# Flag #6: Analytics Metadata (/var/cache/recorder/)
echo "[+] Flag #6: Analytics Metadata..."
cat > /var/cache/recorder/analytics/metadata/stream_analysis.json << 'EOF'
{
    "analytics_version": "2.3.0",
    "stream_id": "primary_1080p",
    "analysis_type": "motion_detection",
    "configuration": {
        "sensitivity": 75,
        "threshold": 50,
        "zones": ["zone_1", "zone_2", "zone_3"],
        "api_callback": "http://localhost/api/motion"
    },
    "metadata": {
        "created": "2024-01-01T12:00:00Z",
        "last_event": "2024-01-01T14:30:22Z",
        "event_count": 1547,
        "auth_token": "FLAG{SAMWISE04969098}"
    },
    "performance": {
        "cpu_usage": 12.5,
        "memory_mb": 128,
        "fps_analyzed": 15
    }
}
EOF
chmod 644 /var/cache/recorder/analytics/metadata/stream_analysis.json

# Flag #8: Vulnerable param.cgi (/var/www/local/axis-cgi/)
echo "[+] Flag #8: Vulnerable Parameter CGI..."
cat > /var/www/local/axis-cgi/param.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-Type: text/plain"
echo ""

# AXIS VAPIX parameter handler
# WARNING: Known vulnerability - input not properly sanitized

QUERY="$QUERY_STRING"
ACTION=$(echo "$QUERY" | sed -n 's/.*action=\([^&]*\).*/\1/p')

case "$ACTION" in
    list)
        echo "# VAPIX Parameters"
        echo "root.Brand.ProdFullName=AXIS M1025"
        echo "root.Properties.Firmware.Version=10.5.0"
        echo "root.Network.eth0.IPAddress=192.168.1.132"
        echo "# Debug info: FLAG{PIPPIN67800950}"
        ;;
    get)
        PARAM=$(echo "$QUERY" | sed -n 's/.*param=\([^&]*\).*/\1/p')
        # Vulnerable: command injection possible here
        echo "Parameter: $PARAM"
        eval "echo $PARAM"
        ;;
    *)
        echo "Usage: action=list|get&param=<name>"
        ;;
esac
CGISCRIPT
chmod 755 /var/www/local/axis-cgi/param.cgi

# Flag #9: Firmware Signature (/mnt/flash/)
echo "[+] Flag #9: Firmware Signature..."
cat > /mnt/flash/firmware/signatures/firmware_10.5.0.sig << 'EOF'
# AXIS Firmware Digital Signature
# Firmware: axis-m1025-10.5.0.bin
# Signed: 2024-01-01 00:00:00 UTC

[Signature_Info]
algorithm=RSA-SHA256
key_id=axis-firmware-signing-2024
version=10.5.0

[Hash_Values]
sha256=a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
md5=1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d

[Verification]
status=valid
checked=2024-01-01
verifier_token=FLAG{LEGOLAS10721320}

-----BEGIN SIGNATURE-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...truncated...
-----END SIGNATURE-----
EOF
chmod 644 /mnt/flash/firmware/signatures/firmware_10.5.0.sig

# Flag #10: Vulnerable download.cgi (/var/www/local/axis-cgi/)
echo "[+] Flag #10: Vulnerable Download CGI..."
cat > /var/www/local/axis-cgi/download.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-Type: application/octet-stream"
echo ""

# AXIS File Download Handler
# WARNING: Path traversal vulnerability exists

QUERY="$QUERY_STRING"
FILE=$(echo "$QUERY" | sed -n 's/.*file=\([^&]*\).*/\1/p')

# Weak attempt at filtering (bypassable)
SAFE_FILE=$(echo "$FILE" | sed 's/\.\.\///g')

# This should read from /var/www/local but can be bypassed
BASE_DIR="/var/www/local"

if [ -f "${BASE_DIR}/${SAFE_FILE}" ]; then
    cat "${BASE_DIR}/${SAFE_FILE}"
elif [ -f "${SAFE_FILE}" ]; then
    # Fallback allows path traversal - FLAG{GALADRIEL57815620}
    cat "${SAFE_FILE}"
else
    echo "Error: File not found"
fi
CGISCRIPT
chmod 755 /var/www/local/axis-cgi/download.cgi

# Create a file that can be accessed via path traversal
cat > /var/lib/axis/conf/secret_config.txt << 'EOF'
# Secret Configuration File
# This file should not be accessible from web interface
# Path traversal flag: FLAG{GALADRIEL57815620}
admin_password=ChangeMeNow!
api_secret=super-secret-key-12345
EOF
chmod 644 /var/lib/axis/conf/secret_config.txt

# Flag #11: Runtime Service Configuration (/run/axis/)
echo "[+] Flag #11: Runtime Service Config..."
cat > /run/axis/services/camera_service.conf << 'EOF'
# Camera Service Runtime Configuration
# Generated at startup - do not modify manually

[Service]
name=axis-camera-service
type=simple
pid_file=/run/axis/camera.pid
status=running

[Process]
started=2024-01-01T12:00:00Z
uptime_seconds=86400
restart_count=0

[Configuration]
video_enabled=true
audio_enabled=false
analytics_enabled=true
runtime_token=FLAG{SAURON52063398}

[Health]
last_check=2024-01-01T13:00:00Z
status=healthy
cpu_percent=15.2
memory_mb=256
EOF
chmod 644 /run/axis/services/camera_service.conf

# Flag #12: Custom Application Script (/usr/local/axis/)
echo "[+] Flag #12: Custom Application..."
cat > /usr/local/axis/share/scripts/backup_service.sh << 'SCRIPT'
#!/bin/sh
# AXIS Backup Service Script
# Runs daily to backup configuration

BACKUP_DIR="/var/backups/config"
LOG_FILE="/var/log/axis/backup.log"

backup_configs() {
    echo "[$(date)] Starting configuration backup..." >> $LOG_FILE
    
    # API key for backup service
    API_KEY="FLAG{CELEBORN26694785}"
    
    tar -czf $BACKUP_DIR/config_$(date +%Y%m%d).tar.gz \
        /var/lib/axis/conf \
        /var/lib/persistent/system/configs
    
    echo "[$(date)] Backup completed successfully" >> $LOG_FILE
}

backup_configs
SCRIPT
chmod 755 /usr/local/axis/share/scripts/backup_service.sh

# FIXED: Flag #13: Cgroup Service Limits - Now using /var/lib/axis/cgroup/ instead of /sys/fs/cgroup/
echo "[+] Flag #13: CGroup Service Configuration..."
cat > /var/lib/axis/cgroup/axis/camera.service/cgroup.procs << 'EOF'
1234
1235
1236
EOF

cat > /var/lib/axis/cgroup/axis/camera.service/service.conf << 'EOF'
# Camera Service Control Group Configuration
# Controls resource limits for camera processes
# NOTE: This simulates /sys/fs/cgroup configuration in a writable location

[Limits]
memory_limit=512M
cpu_quota=200000
cpu_period=100000

[Monitoring]
enable_stats=true
stats_interval=60

[Security]
isolation_enabled=true
namespace=camera_ns
security_token=FLAG{GALADRIEL47829561}
EOF
chmod 644 /var/lib/axis/cgroup/axis/camera.service/service.conf

# Flag #15: UPnP Discovery (/run/axis/network/)
echo "[+] Flag #15: UPnP Service..."
cat > /run/axis/network/upnp_description.xml << 'EOF'
<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
    <specVersion>
        <major>1</major>
        <minor>0</minor>
    </specVersion>
    <device>
        <deviceType>urn:schemas-upnp-org:device:NetworkCamera:1</deviceType>
        <friendlyName>AXIS M1025 Network Camera</friendlyName>
        <manufacturer>AXIS Communications</manufacturer>
        <manufacturerURL>http://www.axis.com</manufacturerURL>
        <modelDescription>AXIS M1025 Network Camera</modelDescription>
        <modelName>M1025</modelName>
        <modelNumber>M1025</modelNumber>
        <serialNumber>ACCC8E</serialNumber>
        <UDN>uuid:axis-m1025-FLAG{HALDIR92336184}-accc8e</UDN>
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
EOF
chmod 644 /run/axis/network/upnp_description.xml

# Flag #16: Persistent Network Certificates (/var/lib/persistent/)
echo "[+] Flag #16: Persistent Certificates..."
cat > /var/lib/persistent/network/certificates/server_cert.pem << 'EOF'
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAK8yB7v3qZ9RMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjQwMTAxMTIwMDAwWhcNMjUwMTAxMTIwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# Certificate issued for: AXIS-M1025-ACCC8E
# Subject: CN=axis-camera.local
# Issuer: CN=AXIS-Root-CA
# Serial: FLAG{ELROND34719845}
CgKCAQEA7ZQwBD3...truncated...
-----END CERTIFICATE-----
EOF
chmod 644 /var/lib/persistent/network/certificates/server_cert.pem

# Flag #17: SUID Binary (/usr/local/axis/bin/)
echo "[+] Flag #17: Custom SUID Binary..."
cat > /usr/local/axis/bin/camera_admin << 'EOF'
#!/bin/sh
# AXIS Camera Administration Tool
# This binary has SUID bit set - security concern!

echo "AXIS Camera Administration Tool v1.0"
echo "Running as: $(whoami)"
echo "EUID: $(id -u)"

case "$1" in
    status)
        echo "Camera Status: Online"
        echo "Uptime: $(uptime)"
        ;;
    config)
        echo "Configuration file: /var/lib/axis/conf/vapix.conf"
        cat /var/lib/axis/conf/vapix.conf
        ;;
    secret)
        # Hidden command - FLAG{FARAMIR46311176}
        echo "Secret admin token: FLAG{FARAMIR46311176}"
        ;;
    *)
        echo "Usage: $0 {status|config}"
        echo "Hidden commands exist..."
        ;;
esac
EOF
chmod 4755 /usr/local/axis/bin/camera_admin

# ============================================================================
# HARD FLAGS (9 flags) - Require advanced techniques
# ============================================================================

echo ""
echo "[+] Distributing HARD FLAGS across writable directories..."

# Flag #18: Shared Memory IPC (/dev/shm/)
echo "[+] Flag #18: Shared Memory IPC..."
cat > /dev/shm/axis/ipc/camera_control.shm << 'EOF'
# Shared Memory Segment for Camera IPC
# Format: Binary with embedded strings
# Created by: camera_service (PID 1234)

[Header]
magic=0x41584953
version=2
size=4096

[Control_Registers]
reg_video_enable=0x01
reg_audio_enable=0x00
reg_motion_detect=0x01
reg_recording=0x01

[Authentication]
session_id=0xDEADBEEF
auth_token=FLAG{ARWEN09143028}
timeout=3600

[Performance]
fps=30
bitrate=4096
resolution=1920x1080
EOF
chmod 600 /dev/shm/axis/ipc/camera_control.shm

# Flag #19: Persistent Firmware Backup (/var/lib/persistent/)
echo "[+] Flag #19: Persistent Firmware Backup..."
cat > /var/lib/persistent/firmware/backups/bootloader.img << 'EOF'
# AXIS Bootloader Backup Image
# Created: 2024-01-01
# Size: 512KB (simulated)

[Bootloader_Info]
name=U-Boot
version=2019.01-axis
architecture=ARM
load_address=0x80000000

[Boot_Parameters]
console=ttyS0,115200
root=/dev/mmcblk0p2
rootfstype=squashfs
recovery_token=FLAG{RADAGAST03390806}

[Verification]
checksum=a1b2c3d4e5f6
signature=valid
EOF
chmod 600 /var/lib/persistent/firmware/backups/bootloader.img

# Flag #20: Hidden Flash Config Backup (/mnt/flash/)
echo "[+] Flag #20: Flash Config Backup..."
cat > /mnt/flash/config/.backup/.shadow_config << 'EOF'
# Emergency Configuration Backup
# DO NOT DELETE - Required for factory reset

[Factory_Credentials]
admin_user=root
admin_hash=$6$rounds=5000$salt$hashedpassword
recovery_code=FLAG{GLORFINDEL34806732}

[Network_Factory]
ip_mode=dhcp
fallback_ip=192.168.0.90
subnet=255.255.255.0

[Security_Keys]
api_master_key=0x1234567890ABCDEF
encryption_key=AES256-MASTER-KEY-HERE
EOF
chmod 600 /mnt/flash/config/.backup/.shadow_config

# Flag #21: U-Boot Environment (/mnt/flash/)
echo "[+] Flag #21: U-Boot Environment..."
cat > /mnt/flash/boot/uboot/uboot.env << 'EOF'
# U-Boot Environment Variables
# WARNING: Modifying these can brick the device

bootdelay=3
baudrate=115200
console=ttyS0,115200n8
bootargs=console=ttyS0,115200 root=/dev/mmcblk0p2 rootfstype=squashfs
bootcmd=mmc dev 0; fatload mmc 0:1 0x80000000 zImage; bootz 0x80000000

# Recovery settings
recovery_mode=0
factory_reset=0

# Debug settings (remove in production!)
debug_uart=enabled
jtag_enabled=true
debug_token=FLAG{BEORN85917263}

# Network boot
ethaddr=AC:CC:8E:XX:XX:XX
ipaddr=192.168.0.90
serverip=192.168.0.1
EOF
chmod 600 /mnt/flash/boot/uboot/uboot.env

# Flag #22: Hardware Debug Interface (/var/lib/axis/)
echo "[+] Flag #22: Hardware Debug Interface..."
cat > /var/lib/axis/conf/hardware_debug.conf << 'EOF'
# AXIS Hardware Debug Configuration
# INTERNAL USE ONLY - Manufacturing and RMA

[JTAG_Interface]
enabled=true
port=ARM-20-pin
voltage=3.3V
clock_speed=10MHz
access_code=FLAG{TAURIEL71836492}

[UART_Console]
enabled=true
baud_rate=115200
parity=none
data_bits=8
stop_bits=1

[Debug_Pins]
gpio_debug_1=17
gpio_debug_2=27
i2c_debug_bus=1
spi_debug_bus=0

[Manufacturing_Mode]
enabled=false
bypass_security=false
EOF
chmod 600 /var/lib/axis/conf/hardware_debug.conf

# Flag #23: SSRF Vulnerable Webhook (/var/www/local/axis-cgi/)
echo "[+] Flag #23: Webhook Integration CGI..."
cat > /var/www/local/axis-cgi/webhook.cgi << 'CGISCRIPT'
#!/bin/sh
echo "Content-Type: text/plain"
echo ""

# AXIS Webhook Integration
# Allows camera to send events to external URLs
# WARNING: SSRF vulnerability - URL not properly validated

QUERY="$QUERY_STRING"
URL=$(echo "$QUERY" | sed -n 's/.*url=\([^&]*\).*/\1/p' | sed 's/%3A/:/g' | sed 's/%2F/\//g')

echo "Webhook Notification Service"
echo "============================"

if [ -n "$URL" ]; then
    echo "Attempting to notify: $URL"
    
    # Vulnerable: No URL validation, allows SSRF
    # Internal flag accessible via: url=http://127.0.0.1:8888/internal
    
    if echo "$URL" | grep -q "127.0.0.1:8888"; then
        echo ""
        echo "Internal Service Response:"
        echo "Service: axis-internal-api"
        echo "Status: running"
        echo "Auth Token: FLAG{THRANDUIL29481756}"
    else
        # Attempt to fetch external URL (simulated)
        echo "Response: Connection attempt logged"
    fi
else
    echo "Usage: webhook.cgi?url=<notification_url>"
    echo "Example: webhook.cgi?url=http://example.com/notify"
fi
CGISCRIPT
chmod 755 /var/www/local/axis-cgi/webhook.cgi

# Flag #24: Database Configuration (/var/db/axis/)
echo "[+] Flag #24: Database Configuration..."
cat > /var/db/axis/camera_events.db << 'EOF'
# SQLite Database (simulated text format)
# Table: events
# Table: users
# Table: configurations

CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT DEFAULT 'viewer'
);

INSERT INTO users VALUES (1, 'admin', 'FLAG{GANDALF60470436}', 'administrator');
INSERT INTO users VALUES (2, 'viewer', 'viewerpass123', 'viewer');
INSERT INTO users VALUES (3, 'operator', 'operatorpass456', 'operator');

CREATE TABLE events (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    event_type TEXT,
    details TEXT
);

CREATE TABLE configurations (
    key TEXT PRIMARY KEY,
    value TEXT
);
EOF
chmod 600 /var/db/axis/camera_events.db

# Flag #25: Weak Crypto Library (/usr/local/axis/)
echo "[+] Flag #25: Weak Crypto Library..."
cat > /usr/local/axis/lib/crypto_weak.so.txt << 'EOF'
# AXIS Cryptographic Library (Simulated)
# Version: 1.0.0-legacy
# WARNING: Uses deprecated algorithms

[Library_Info]
name=libaxis_crypto.so
version=1.0.0
type=shared_object

[Algorithms_Supported]
# Weak algorithms still enabled for backward compatibility
DES=enabled        # WEAK - 56-bit key
3DES=enabled       # WEAK - Deprecated
MD5=enabled        # WEAK - Collisions found
SHA1=enabled       # WEAK - Deprecated
RC4=enabled        # WEAK - Biased output

# Modern algorithms (disabled for "compatibility")
AES256=disabled
SHA256=disabled
ChaCha20=disabled

[Master_Keys]
# Hardcoded keys - CRITICAL VULNERABILITY
legacy_des_key=0x0123456789ABCDEF
legacy_3des_key=0x0123456789ABCDEF0123456789ABCDEF
api_encryption_key=FLAG{DENETHOR48291756}

[Notes]
# TODO: Upgrade to modern cryptography
# JIRA: AXIS-CRYPTO-001 - Low priority
EOF
chmod 644 /usr/local/axis/lib/crypto_weak.so.txt

# Flag #26: Recording Session Cache (/var/cache/recorder/)
echo "[+] Flag #26: Recording Temp Cache..."
cat > /var/cache/recorder/.temp/.recording_session_20240101 << 'EOF'
# Active Recording Session Data
# Session ID: 20240101-143022
# DO NOT DELETE DURING ACTIVE RECORDING

[Session_Info]
id=20240101-143022
started=2024-01-01T14:30:22Z
user=admin
stream=primary
format=h264

[Temporary_Credentials]
session_token=tmp_session_ABC123
stream_key=FLAG{EOMER19847263}
encryption_iv=0x00112233445566778899AABBCCDDEEFF

[Recording_State]
frames_captured=54321
bytes_written=1073741824
current_file=/var/cache/recorder/active/recording_001.mp4
EOF
chmod 600 /var/cache/recorder/.temp/.recording_session_20240101

# Flag #27: Race Condition Script (/usr/local/axis/)
echo "[+] Flag #27: Race Condition Script..."
cat > /usr/local/axis/share/scripts/race_condition_test.sh << 'SCRIPT'
#!/bin/sh
# AXIS Service Race Condition Test
# This script has a TOCTOU vulnerability

TEMP_FLAG="/dev/shm/axis/runtime/temp_flag_$$"
RESULT_FILE="/tmp/race_result.txt"

# Create temporary flag file (race window starts)
echo "FLAG{THEODEN91827364}" > "$TEMP_FLAG"
chmod 600 "$TEMP_FLAG"

# Simulate processing delay (race window)
sleep 0.1

# Check if file still exists and read it
if [ -f "$TEMP_FLAG" ]; then
    cat "$TEMP_FLAG" > "$RESULT_FILE"
    rm -f "$TEMP_FLAG"
    echo "Race condition test completed"
else
    echo "File was modified during race window!"
fi

# Cleanup (race window ends)
rm -f "$TEMP_FLAG" 2>/dev/null
SCRIPT
chmod 755 /usr/local/axis/share/scripts/race_condition_test.sh

# ============================================================================
# CREATE INDEX AND DOCUMENTATION
# ============================================================================

echo ""
echo "[+] Creating challenge index and documentation..."

cat > /var/lib/axis/ctf_challenge_index.txt << 'EOF'
AXIS Camera IoT CTF - Challenge Index v5.0
==========================================
NOTE: /sys/fs/cgroup paths now use /var/lib/axis/cgroup/ (writable simulation)

EASY Challenges (5):
1. VAPIX Configuration                 → /var/lib/axis/conf/vapix.conf
4. System Log SSH Banner               → /var/log/messages
7. Web Interface HTML Comment          → /var/www/local/admin/index.html
14. Recording Stream Configuration     → /var/cache/recorder/streams/primary/
19. Factory Configuration              → /mnt/flash/config/factory/

MEDIUM Challenges (13):
2. Persistent License File             → /var/lib/persistent/system/licenses/
5. Persistent SSH Keys                 → /var/lib/persistent/security/keys/
6. Analytics Metadata                  → /var/cache/recorder/analytics/metadata/
8. Vulnerable param.cgi                → /var/www/local/axis-cgi/param.cgi
9. Firmware Signature                  → /mnt/flash/firmware/signatures/
10. Path Traversal (download.cgi)      → /var/www/local/axis-cgi/download.cgi
11. Runtime Service Configuration      → /run/axis/services/
13. CGroup Service Configuration       → /var/lib/axis/cgroup/axis/camera.service/
15. UPnP Device Description            → /run/axis/network/
16. Persistent Network Certificates    → /var/lib/persistent/network/certificates/
12. Backup Service Script              → /usr/local/axis/share/scripts/
17. SUID Binary Exploitation           → /usr/local/axis/bin/

HARD Challenges (9):
18. Shared Memory IPC                  → /dev/shm/axis/ipc/
19. Persistent Firmware Backup         → /var/lib/persistent/firmware/
20. Hidden Flash Config Backup         → /mnt/flash/config/.backup/
21. U-Boot Environment                 → /mnt/flash/boot/uboot/
22. Hardware Debug Interface           → /var/lib/axis/conf/
23. SSRF Exploitation (webhook.cgi)    → /var/www/local/axis-cgi/
24. Database Credential Extraction     → /var/db/axis/
25. Cryptographic Weakness             → /usr/local/axis/lib/
26. Recording Temp Cache               → /var/cache/recorder/.temp/
27. Race Condition (Shared Memory)     → /dev/shm/axis/runtime/

ENUMERATION STARTING POINTS:
General reconnaissance:
  find /var -type f -name '*.conf' 2>/dev/null
  find /var -type f -name '*.lic' 2>/dev/null
  find /mnt -type f 2>/dev/null
  find /usr/local -type f 2>/dev/null
  ls -laR /dev/shm/ 2>/dev/null
  ls -laR /run/axis/ 2>/dev/null

Specific directory searches:
  find /var/lib/persistent -type f 2>/dev/null
  find /var/cache/recorder -type f 2>/dev/null
  find /mnt/flash -name '.*' 2>/dev/null
  find /var/lib/axis/cgroup -type f 2>/dev/null
  grep -r 'FLAG' /var/lib/persistent/ 2>/dev/null
  grep -r 'FLAG' /usr/local/axis/ 2>/dev/null

Advanced techniques:
  # Race condition monitoring
  while true; do ls /dev/shm/axis/runtime/ 2>/dev/null; done
  
  # SUID binary discovery
  find /usr/local -perm -4000 2>/dev/null
  
  # Shared memory inspection
  cat /dev/shm/axis/ipc/* 2>/dev/null
  
  # CGroup inspection (now in /var/lib/axis/cgroup)
  find /var/lib/axis/cgroup -type f -exec cat {} \; 2>/dev/null

WEB INTERFACE ENDPOINTS:
  http://<camera-ip>/
  http://<camera-ip>/axis-cgi/param.cgi
  http://<camera-ip>/axis-cgi/download.cgi?file=/etc/passwd
  http://<camera-ip>/axis-cgi/webhook.cgi?url=http://127.0.0.1:8888
  http://<camera-ip>/local/admin/

TOTAL: 27 FLAGS distributed across 8 writable directory trees
EOF
chmod 644 /var/lib/axis/ctf_challenge_index.txt

# ============================================================================
# CREATE VISUAL FLAG MAP
# ============================================================================

cat > /var/lib/axis/flag_distribution_map.txt << 'EOF'
AXIS Camera CTF - Flag Distribution Map v5.0
=============================================
NOTE: CGroup paths now use /var/lib/axis/cgroup/ instead of /sys/fs/cgroup/

Directory Tree Visualization:

/mnt/flash/                         [WRITABLE - FIRMWARE & BOOT]
├── boot/
│   ├── uboot/
│   │   └── uboot.env                      → FLAG #21 (HARD)
│   └── kernel/
├── firmware/
│   ├── images/
│   └── signatures/
│       └── firmware_10.5.0.sig            → FLAG #9 (MEDIUM)
└── config/
    ├── factory/
    │   └── device_info.txt                → FLAG #19 (EASY)
    ├── user/
    └── .backup/
        └── .shadow_config                 → FLAG #20 (HARD)

/dev/shm/                           [WRITABLE - SHARED MEMORY]
└── axis/
    ├── runtime/
    │   └── temp_flag_*                    → FLAG #27 (HARD - Race)
    ├── ipc/
    │   └── camera_control.shm             → FLAG #18 (HARD)
    └── streams/

/run/                               [WRITABLE - RUNTIME]
└── axis/
    ├── services/
    │   └── camera_service.conf            → FLAG #11 (MEDIUM)
    ├── network/
    │   └── upnp_description.xml           → FLAG #15 (MEDIUM)
    ├── camera/
    └── locks/

/var/lib/axis/cgroup/               [WRITABLE - CGROUP SIMULATION]
└── axis/
    ├── camera.service/
    │   └── service.conf                   → FLAG #13 (MEDIUM)
    └── network.service/

/var/                               [WRITABLE - STANDARD]
├── lib/
│   ├── axis/
│   │   ├── conf/
│   │   │   ├── vapix.conf                 → FLAG #1 (EASY)
│   │   │   └── hardware_debug.conf        → FLAG #22 (HARD)
│   │   └── cgroup/                        → [CGROUP SIMULATION]
│   └── persistent/                [SUB-WRITABLE]
│       ├── system/
│       │   ├── configs/
│       │   └── licenses/
│       │       └── vapix_pro.lic          → FLAG #2 (MEDIUM)
│       ├── network/
│       │   └── certificates/
│       │       └── server_cert.pem        → FLAG #16 (MEDIUM)
│       ├── security/
│       │   └── keys/
│       │       └── authorized_keys        → FLAG #5 (MEDIUM)
│       └── firmware/
│           └── backups/
│               └── bootloader.img         → FLAG #19 (HARD)
├── cache/
│   └── recorder/                  [SUB-WRITABLE]
│       ├── streams/
│       │   └── primary/
│       │       └── stream_config.conf     → FLAG #14 (EASY)
│       ├── analytics/
│       │   └── metadata/
│       │       └── stream_analysis.json   → FLAG #6 (MEDIUM)
│       └── .temp/
│           └── .recording_session_*       → FLAG #26 (HARD)
├── db/
│   └── axis/
│       └── camera_events.db               → FLAG #24 (HARD)
├── log/
│   └── messages                           → FLAG #4 (EASY)
└── www/
    ├── index.html                         → FLAG #7 (EASY)
    └── local/
        └── axis-cgi/
            ├── param.cgi                  → FLAG #8 (MEDIUM)
            ├── download.cgi               → FLAG #10 (MEDIUM)
            └── webhook.cgi                → FLAG #23 (HARD)

/usr/local/                         [WRITABLE - CUSTOM APPS]
└── axis/
    ├── bin/
    │   └── camera_admin                   → FLAG #17 (MEDIUM - SUID)
    ├── lib/
    │   └── crypto_weak.so.txt             → FLAG #25 (HARD)
    ├── etc/
    └── share/
        └── scripts/
            ├── backup_service.sh          → FLAG #12 (MEDIUM)
            └── race_condition_test.sh     → FLAG #27 (HARD)

LEGEND:
[WRITABLE]     - Primary writable mount point
[SUB-WRITABLE] - Writable subdirectory within /var
→ FLAG #X      - Flag location and difficulty

DIFFICULTY LEVELS:
EASY (5)   - Basic file enumeration and reading
MEDIUM (13) - Requires scripts, tools, or CGI exploitation
HARD (9)   - Advanced techniques (race conditions, SSRF, crypto, etc.)

TOTAL: 27 flags across 8 writable directory trees
EOF
chmod 644 /var/lib/axis/flag_distribution_map.txt

# ============================================================================
# FINAL SUMMARY
# ============================================================================

echo ""
echo "[*] ========================================================================="
echo "[*] CTF Setup Complete - FIXED VERSION v5.0"
echo "[*] ========================================================================="
echo ""
echo "[+] FIXED: /sys/fs/cgroup paths now use /var/lib/axis/cgroup/"
echo ""
echo "[+] Flag Distribution Summary:"
echo "    EASY flags: 5 (basic enumeration)"
echo "    MEDIUM flags: 13 (exploitation required)"
echo "    HARD flags: 9 (advanced techniques)"
echo "    TOTAL: 27 flags"
echo ""
echo "[+] Writable Directories Used (8):"
echo "    • /mnt/flash             - Firmware, bootloader, factory configs"
echo "    • /dev/shm               - Shared memory, IPC, race conditions"
echo "    • /run                   - Runtime services and network"
echo "    • /var/lib/axis/cgroup   - Container/service control groups (FIXED)"
echo "    • /var                   - Standard Linux locations"
echo "    • /var/cache/recorder    - Recording stream caches"
echo "    • /var/lib/persistent    - Persistent storage configs"
echo "    • /usr/local             - Custom applications and scripts"
echo ""
echo "[+] Reference Files:"
echo "    • Challenge index: /var/lib/axis/ctf_challenge_index.txt"
echo "    • Flag map: /var/lib/axis/flag_distribution_map.txt"
echo ""
echo "[+] Quick Enumeration Commands:"
echo "    find /mnt -type f 2>/dev/null | head -20"
echo "    find /var/lib/persistent -type f 2>/dev/null"
echo "    find /usr/local/axis -type f 2>/dev/null"
echo "    ls -laR /dev/shm/ 2>/dev/null"
echo "    find /var/lib/axis/cgroup -type f 2>/dev/null"
echo ""
echo "[*] Setup completed at: $(date)"
echo "[*] ========================================================================="
