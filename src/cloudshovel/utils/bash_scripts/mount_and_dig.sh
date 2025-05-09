#!/bin/bash

# Start logging to file
mkdir -p /home/ec2-user/OUTPUT
LOG_FILE="/home/ec2-user/OUTPUT/mount_and_dig.log"
# Redirect both stdout and stderr to the terminal and the log file
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[*] Starting mount_and_dig.sh script at $(date)"
echo "[*] Script version: 1.0"
echo "[*] Arguments: $@"

if [ $# -lt 1 ]; then
        echo "[*] Usage: $0 <devices>"
        echo "    Multiple devices should be separated by spaces."
        echo "    E.g.: $0 /dev/sdf /dev/sdg"
        exit
fi

if [ "$EUID" -ne 0 ]; then
    echo "[*] This script must be run as root. Exiting."
    exit 1
fi

# Installing udisksctl
yum install udisks2 -y

check_and_fix_uuid() {
    local dev=$1
    local uuid=$(blkid -s UUID -o value $dev)
    local fs_type=$(blkid -s TYPE -o value $dev)
    
    if [ "$fs_type" == "xfs" ]; then
        # Check if this UUID is already in use
        if grep -q $uuid /etc/fstab || blkid | grep -v $dev | grep -q $uuid; then
            echo "[!] UUID collision detected for $dev"
            echo "[*] Will try to mount with current UUID first"
        fi
    fi
}

collect_system_info() {
    local output_dir=$1
    local mount_point=$2
    
    # Create output directory
    mkdir -p "$output_dir"

   
    # Get list of all files with timestamps
    echo "[x] Collecting file list with timestamps..."
    find "$mount_point" -maxdepth 7 -type f \( ! -path "$mount_point/proc/*" -a ! -path "$mount_point/sys/*" -a ! -path "$mount_point/usr/share/man/*" -a ! -path "$mount_point/usr/src/*" \) -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' | sort -r > "$output_dir/all_files.txt"
    sed -i "s|$mount_point/|/|" "$output_dir/all_files.txt"
    
    # Get list of all files without timestamps but with md5sum
    echo "[x] Collecting file list without timestamps but with md5sum..."
    # Using -print0 with find and xargs -0 to safely handle filenames with special characters
    find "$mount_point" -maxdepth 7 -type f \( ! -path "$mount_point/proc/*" -a ! -path "$mount_point/sys/*" -a ! -path "$mount_point/usr/share/man/*" -a ! -path "$mount_point/usr/src/*" \) -print0 | xargs -0 -I{} bash -c 'md5sum "$1" 2>/dev/null || echo "FAILED_MD5SUM $1"' _ {} >> "$output_dir/all_files_without_timestamps_md5sum.txt"
    sed -i "s|$mount_point/|/|" "$output_dir/all_files_without_timestamps_md5sum.txt"
    
    # # List files from key directories
    # echo "[x] Listing files from key directories..."
    # find "$mount_point/usr/local/bin" "$mount_point/opt" "$mount_point/etc/cron.d" "$mount_point/etc/cron.daily" "$mount_point/etc/cron.hourly" "$mount_point/etc/cron.weekly" "$mount_point/etc/cron.monthly" "$mount_point/var/spool/cron" "$mount_point/home" "$mount_point/root" -type f 2>/dev/null > "$output_dir/files_from_key_dirs.txt"
    
    # # List system configuration files
    # echo "[x] Listing system configuration files..."
    # find "$mount_point/etc/passwd" "$mount_point/etc/group" "$mount_point/etc/shadow" "$mount_point/etc/sudoers" "$mount_point/etc/hosts" "$mount_point/etc/resolv.conf" "$mount_point/etc/fstab" "$mount_point/etc/crontab" -type f 2>/dev/null > "$output_dir/system_config_files.txt"
    
    # # List startup scripts and services
    # echo "[x] Listing startup scripts and services..."
    # find "$mount_point/etc/init.d" "$mount_point/etc/rc.d" "$mount_point/etc/systemd/system" "$mount_point/lib/systemd/system" -type f 2>/dev/null > "$output_dir/startup_scripts.txt"
    
    # # List network configuration files
    # echo "[x] Listing network configuration files..."
    # find "$mount_point/etc/network/interfaces" "$mount_point/etc/sysconfig/network-scripts/ifcfg-*" "$mount_point/etc/netplan/*.yaml" -type f 2>/dev/null > "$output_dir/network_config_files.txt"
    
    # # List SSH configuration files
    # echo "[x] Listing SSH configuration files..."
    # find "$mount_point/etc/ssh" -type f 2>/dev/null > "$output_dir/ssh_config_files.txt"
    
    # # List AWS configuration files
    # echo "[x] Listing AWS configuration files..."
    # find "$mount_point/root/.aws" "$mount_point/home/*/.aws" -type f 2>/dev/null > "$output_dir/aws_config_files.txt"
    
    # # List suspicious files
    # echo "[x] Listing suspicious files..."
    # find "$mount_point" \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.js" -o -name "*.php" \) -type f -size -1M 2>/dev/null > "$output_dir/suspicious_files.txt"
    
    # # List files with unusual permissions
    # echo "[x] Listing files with unusual permissions..."
    # find "$mount_point" -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null > "$output_dir/suid_sgid_files.txt"
    
    # # List files modified in last 30 days
    # echo "[x] Listing recently modified files..."
    # find "$mount_point" -maxdepth 7 -type f \( ! -path "*/proc/*" -a ! -path "*/sys/*" -a ! -path "*/usr/share/man/*" \) -mtime -30 2>/dev/null > "$output_dir/recent_files.txt"
    
    # # List large files
    # echo "[x] Listing large files..."
    # find "$mount_point" -type f -size +10M 2>/dev/null > "$output_dir/large_files.txt"

    # # List dot files
    # echo "[x] Listing dot files..."
    # find "$mount_point" -type f -name ".*" 2>/dev/null > "$output_dir/dot_files.txt"

    # # List all files and hash them
    # echo "[x] Listing all files and hashing them md5sum..."
    # find "$mount_point" -type f -exec md5sum {} \; 2>/dev/null > "$output_dir/all_files_md5sum.txt"
    

    # Original commented out code for reference:
    # Collect files from key directories
    # echo "[x] Collecting files from key directories..."
    # for dir in "$mount_point/usr/local/bin" "$mount_point/opt" "$mount_point/etc/cron.d" "$mount_point/etc/cron.daily" "$mount_point/etc/cron.hourly" "$mount_point/etc/cron.weekly" "$mount_point/etc/cron.monthly" "$mount_point/var/spool/cron" "$mount_point/home" "$mount_point/root"; do
    #     if [ -d "$dir" ]; then
    #         dir_name=$(basename "$dir")
    #         mkdir -p "$output_dir/key_dirs/$dir_name"
    #         find "$dir" -type f -exec cp --parents {} "$output_dir/key_dirs/" \;
    #     fi
    # done
    
    # # Collect system configuration files
    # echo "[x] Collecting system configuration files..."
    # for conf_file in "$mount_point/etc/passwd" "$mount_point/etc/group" "$mount_point/etc/shadow" "$mount_point/etc/sudoers" "$mount_point/etc/hosts" "$mount_point/etc/resolv.conf" "$mount_point/etc/fstab" "$mount_point/etc/crontab"; do
    #     if [ -f "$conf_file" ]; then
    #         cp --parents "$conf_file" "$output_dir/system_config/"
    #     fi
    # done
    
    # # Collect startup scripts and services
    # echo "[x] Collecting startup scripts and services..."
    # for dir in "$mount_point/etc/init.d" "$mount_point/etc/rc.d" "$mount_point/etc/systemd/system" "$mount_point/lib/systemd/system"; do
    #     if [ -d "$dir" ]; then
    #         dir_name=$(basename "$dir")
    #         mkdir -p "$output_dir/startup_scripts/$dir_name"
    #         find "$dir" -type f -exec cp --parents {} "$output_dir/startup_scripts/" \;
    #     fi
    # done
    
    # # Collect network configuration
    # echo "[x] Collecting network configuration..."
    # for net_file in "$mount_point/etc/network/interfaces" "$mount_point/etc/sysconfig/network-scripts/ifcfg-*" "$mount_point/etc/netplan/*.yaml"; do
    #     if [ -f "$net_file" ]; then
    #         cp --parents "$net_file" "$output_dir/network_config/"
    #     fi
    # done
    
    # # Collect SSH configuration and keys
    # echo "[x] Collecting SSH configuration..."
    # if [ -d "$mount_point/etc/ssh" ]; then
    #     mkdir -p "$output_dir/ssh_config"
    #     find "$mount_point/etc/ssh" -type f -exec cp --parents {} "$output_dir/ssh_config/" \;
    # fi
    
    # # Collect AWS configuration
    # echo "[x] Collecting AWS configuration..."
    # for aws_dir in "$mount_point/root/.aws" "$mount_point/home/*/.aws"; do
    #     if [ -d "$aws_dir" ]; then
    #         mkdir -p "$output_dir/aws_config"
    #         find "$aws_dir" -type f -exec cp --parents {} "$output_dir/aws_config/" \;
    #     fi
    # done
    
    # # Collect suspicious files and directories
    # echo "[x] Collecting suspicious files..."
    # find "$mount_point" \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.rb" -o -name "*.js" -o -name "*.php" \) -type f -size -1M -exec cp --parents {} "$output_dir/suspicious_files/" \;
    
    # # Collect files with unusual permissions
    # echo "[x] Collecting files with unusual permissions..."
    # find "$mount_point" -type f \( -perm -4000 -o -perm -2000 \) -exec ls -la {} \; > "$output_dir/suid_sgid_files.txt"
    
    # # Collect files modified in last 30 days
    # echo "[x] Collecting recently modified files..."
    # find "$mount_point" -maxdepth 7 -type f \( ! -path "*/proc/*" -a ! -path "*/sys/*" -a ! -path "*/usr/share/man/*" \) -mtime -30 -printf '%TY-%Tm-%Td %TH:%TM:%TS %p\n' | sort -r > "$output_dir/recent_files.txt"
    
    # # Collect large files
    # echo "[x] Collecting large files..."
    # find "$mount_point" -type f -size +10M -exec ls -lh {} \; > "$output_dir/large_files.txt"
    
    # # Collect empty directories (potential mount points)
    # echo "[x] Collecting empty directories..."
    # find "$mount_point" -type d -empty > "$output_dir/empty_dirs.txt"
}

mount_and_search(){
    if [ $# -lt 1 ]; then
        echo "[!] Function $0 requires 1 argument. Something went wrong since no arguments were passed."
        return 1
    fi

    dev=$1
    echo "[x] Trying to mount $dev"
    
    # Get the actual device path (handles /dev/sdf -> /dev/nvme1n1 mapping)
    actual_dev=$(readlink -f $dev)
    echo "[x] Actual device path: $actual_dev"

    # Check if the filesystem is NTFS
    fs_type=$(blkid -o value -s TYPE $dev)
    echo "[x] Detected filesystem type: $fs_type"
    
    if [ "$fs_type" == "ntfs" ]; then
        echo "[x] NTFS filesystem detected. Using ntfs-3g driver."
        mount_point="/mnt/ntfs_$RANDOM"
        mkdir -p $mount_point
        if mount -t ntfs-3g $dev $mount_point; then
            echo "[x] Mount successful for $dev at $mount_point"
        else
            echo "[!] Failed to mount NTFS volume $dev"
            rmdir $mount_point
            return 1
        fi
    elif [ "$fs_type" == "xfs" ]; then
        echo "[x] XFS filesystem detected."
        # Check and fix UUID if necessary
        check_and_fix_uuid $dev

        mount_point="/mnt/xfs_$RANDOM"
        mkdir -p $mount_point
        
        # Try mounting with different options in order of increasing aggression
        if mount -t xfs $dev $mount_point 2>/dev/null; then
            echo "[x] Mount successful for $dev at $mount_point"
        elif mount -t xfs -o nologreplay $dev $mount_point 2>/dev/null; then
            echo "[x] Mount successful with nologreplay option for $dev at $mount_point"
        elif mount -t xfs -o rescue $dev $mount_point 2>/dev/null; then
            echo "[x] Mount successful with rescue option for $dev at $mount_point"
        else
            echo "[!] Standard mount options failed for XFS volume $dev"
            echo "[x] Attempting safe analysis with xfs_repair -n (no modifications)"
            xfs_repair -n $dev

            echo "[x] Attempting recovery with xfs_repair -L to clear the log"
            if xfs_repair -L $dev; then
                echo "[x] Log cleared, trying mount again"
                if mount -t xfs $dev $mount_point 2>/dev/null; then
                    echo "[x] Mount successful after log repair for $dev at $mount_point"
                elif mount -t xfs -o nouuid $dev $mount_point 2>/dev/null; then
                    echo "[x] Mount successful with nouuid option after log repair for $dev at $mount_point"
                else
                    echo "[!] Failed to mount XFS volume $dev even after repairs"
                    echo "[x] Creating empty directory for placeholder results"
                    # Create placeholder directories for inspection even though mounting failed
                    output_dir="/home/ec2-user/OUTPUT/$counter"
                    mkdir -p "$output_dir"
                    echo "MOUNT_FAILED_FILESYSTEM_ERRORS" > "$output_dir/mount_failure.txt"
                    echo "Device: $dev ($actual_dev)" >> "$output_dir/mount_failure.txt"
                    echo "Filesystem type: $fs_type" >> "$output_dir/mount_failure.txt"
                    blkid $dev >> "$output_dir/mount_failure.txt"
                    xfs_info $dev >> "$output_dir/mount_failure.txt" 2>&1
                    echo "[!] Mount failure logged to $output_dir/mount_failure.txt"
                    rmdir $mount_point
                    return 0
                fi
            else
                echo "[!] Failed to repair XFS volume $dev"
                rmdir $mount_point
                return 1
            fi
        fi
    elif [ "$fs_type" == "vfat" ]; then
        echo "[x] FAT filesystem detected."
        mount_point="/mnt/vfat_$RANDOM"
        mkdir -p $mount_point
        if mount -t vfat $dev $mount_point; then
            echo "[x] Mount successful for $dev at $mount_point"
        else
            echo "[!] Failed to mount FAT volume $dev"
            rmdir $mount_point
            return 1
        fi
    else
        # Try udisksctl for other filesystem types
        if udisksctl mount -b $dev 2>/dev/null; then
            mount_point=$(udisksctl info -b $dev | grep MountPoints | tr -s ' ' | cut -d ' ' -f 3)
            echo "[x] Mount successful for $dev at $mount_point"
        else
            echo "[!] Failed to mount $dev with udisksctl, trying direct mount"
            # Try a direct mount as fallback
            mount_point="/mnt/auto_$RANDOM"
            mkdir -p $mount_point
            if mount $dev $mount_point; then
                echo "[x] Mount successful for $dev at $mount_point"
            else
                echo "[!] All mount attempts failed for $dev"
                rmdir $mount_point
                return 1
            fi
        fi
    fi

    # Create output directory for this volume
    output_dir="/home/ec2-user/OUTPUT/$counter"
    mkdir -p "$output_dir"
    
    # Collect system information
    collect_system_info "$output_dir" "$mount_point"

    echo "[x] Unmounting $dev"
    if [ "$fs_type" == "ntfs" ] || [ "$fs_type" == "xfs" ] || [ "$fs_type" == "vfat" ]; then
        umount $mount_point
        rmdir $mount_point
    else
        udisksctl unmount -b $dev -f || umount $mount_point
        [ -d "$mount_point" ] && rmdir $mount_point
    fi

    return 0
}

counter=1
something_was_searched=0
mkdir /home/ec2-user/OUTPUT 2>/dev/null

echo "[*] Mounting $# devices ($@):"
for dev in "$@"; do
    device_was_searched=0
    echo "[x] Devices: "
    blkid -o device -u filesystem ${dev}*
    for device in $(blkid -o device -u filesystem ${dev}*); do if mount_and_search $device; then ((counter++)) && something_was_searched=1 && device_was_searched=1; fi done

    if [ $device_was_searched -eq 0 ]; then
        echo "[!] Mounting and secret searching for $dev did not work" 
    fi
done

if [ $something_was_searched -eq 0 ]; then
    echo "[!] Mounting or scanning not successful. Check output for lsblk:"
    lsblk --output NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,UUID,LABEL
    exit 3
fi