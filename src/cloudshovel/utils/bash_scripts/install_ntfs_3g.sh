#!/bin/bash

echo "[*] Starting ntfs-3g installation script"

# Check if ntfs-3g is already installed
if test -f /usr/bin/ntfs-3g || test -f /usr/local/bin/ntfs-3g || test -f /usr/local/bin/ntfs-3g.probe; then
    echo "[x] ntfs-3g is already installed"
    ntfs-3g --version 2>/dev/null || /usr/bin/ntfs-3g --version 2>/dev/null || echo "[x] Installation confirmed"
    exit 0
fi

# Detect OS version
OS_VERSION="unknown"
if grep -q "Amazon Linux 2023" /etc/os-release 2>/dev/null; then
    OS_VERSION="al2023"
    echo "[x] Detected Amazon Linux 2023"
elif grep -q "Amazon Linux 2" /etc/os-release 2>/dev/null || grep -q "Amazon Linux AMI" /etc/system-release 2>/dev/null; then
    OS_VERSION="al2"
    echo "[x] Detected Amazon Linux 2"
else
    echo "[!] Unknown OS version. Attempting generic installation..."
    cat /etc/os-release 2>/dev/null || cat /etc/system-release 2>/dev/null || echo "Could not determine OS"
fi

# Install ntfs-3g based on OS version
if [ "$OS_VERSION" = "al2023" ]; then
    echo "[x] Installing ntfs-3g on Amazon Linux 2023 using dnf..."
    dnf install -y ntfs-3g
    INSTALL_EXIT_CODE=$?

elif [ "$OS_VERSION" = "al2" ]; then
    echo "[x] Installing ntfs-3g on Amazon Linux 2..."
    echo "[x] Step 1: Enabling EPEL repository..."

    # AL2 requires EPEL for ntfs-3g
    # Try amazon-linux-extras first (preferred method)
    if command -v amazon-linux-extras &> /dev/null; then
        echo "[x] Using amazon-linux-extras to install EPEL..."
        amazon-linux-extras install epel -y
    else
        # Fallback: Install EPEL RPM directly
        echo "[x] Installing EPEL via RPM..."
        yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    fi

    echo "[x] Step 2: Installing ntfs-3g from EPEL..."
    yum install -y ntfs-3g
    INSTALL_EXIT_CODE=$?

else
    echo "[!] Unknown OS. Attempting generic yum/dnf installation..."
    # Try dnf first, then yum
    if command -v dnf &> /dev/null; then
        dnf install -y ntfs-3g
        INSTALL_EXIT_CODE=$?
    elif command -v yum &> /dev/null; then
        yum install -y ntfs-3g
        INSTALL_EXIT_CODE=$?
    else
        echo "[!] No package manager found (yum/dnf)"
        exit 1
    fi
fi

# Verify installation
if [ $INSTALL_EXIT_CODE -eq 0 ]; then
    echo "[x] Package manager installation completed successfully"

    # Verify ntfs-3g binary exists
    if test -f /usr/bin/ntfs-3g || test -f /sbin/mount.ntfs-3g; then
        echo "[x] ntfs-3g installation verified"
        ntfs-3g --version 2>/dev/null || /usr/bin/ntfs-3g --version 2>/dev/null
        exit 0
    else
        echo "[!] Installation appeared successful but ntfs-3g binary not found"
        echo "[!] Checking common locations..."
        find /usr -name "ntfs-3g" 2>/dev/null
        exit 1
    fi
else
    echo "[!] ntfs-3g installation failed with exit code: $INSTALL_EXIT_CODE"
    echo "[!] This may indicate:"
    echo "    - Network connectivity issues"
    echo "    - Package not available in repositories"
    echo "    - Insufficient permissions"
    exit 1
fi
