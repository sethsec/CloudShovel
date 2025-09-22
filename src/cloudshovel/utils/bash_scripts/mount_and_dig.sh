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

# Create a single TSV file for all devices with headers
OUTPUT_DIR="/home/ec2-user/OUTPUT"
TSV_FILE="${OUTPUT_DIR}/ami_files.tsv"
echo "hash	relative_path	modified_timestamp	full_path" > "$TSV_FILE"

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
    local mount_point=$1
    local dev_name=$2
    
    echo "[x] Collecting file information (hash, path, timestamp) for device $dev_name..."
    # Find all files (excluding specific directories) and process each one to get hash and timestamp
    find "$mount_point" -maxdepth 7 -type f \( ! -path "$mount_point/proc/*" -a ! -path "$mount_point/sys/*" -a ! -path "$mount_point/usr/share/man/*" -a ! -path "$mount_point/usr/src/*" \) -print0 | 
    while IFS= read -r -d '' file; do
        # Get MD5 hash
        md5=$(md5sum "$file" 2>/dev/null | awk '{print $1}' || echo "FAILED_MD5SUM")
        if [ "$md5" != "FAILED_MD5SUM" ]; then
            # Get modified timestamp in ISO format
            timestamp=$(date -r "$file" -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)
            # Get relative path (remove mount point prefix)
            rel_path=${file#$mount_point}
            # Write to TSV file
            echo "$md5	$rel_path	$timestamp  $file" >> "$TSV_FILE"
        fi
    done
    
    echo "[x] Finished collecting file information for device $dev_name."
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
                    # Create placeholder for mount failure information
                    echo "MOUNT_FAILED_FILESYSTEM_ERRORS" > "${OUTPUT_DIR}/mount_failure_${dev##*/}.txt"
                    echo "Device: $dev ($actual_dev)" >> "${OUTPUT_DIR}/mount_failure_${dev##*/}.txt"
                    echo "Filesystem type: $fs_type" >> "${OUTPUT_DIR}/mount_failure_${dev##*/}.txt"
                    blkid $dev >> "${OUTPUT_DIR}/mount_failure_${dev##*/}.txt"
                    xfs_info $dev >> "${OUTPUT_DIR}/mount_failure_${dev##*/}.txt" 2>&1
                    echo "[!] Mount failure logged to ${OUTPUT_DIR}/mount_failure_${dev##*/}.txt"
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
    
    # Collect system information
    collect_system_info "$mount_point" "$dev"

    # echo "[x] Unmounting $dev"
    # if [ "$fs_type" == "ntfs" ] || [ "$fs_type" == "xfs" ] || [ "$fs_type" == "vfat" ]; then
    #     umount $mount_point
    #     rmdir $mount_point
    # else
    #     udisksctl unmount -b $dev -f || umount $mount_point
    #     [ -d "$mount_point" ] && rmdir $mount_point
    # fi

    return 0
}

something_was_searched=0
mkdir -p "$OUTPUT_DIR" 2>/dev/null

echo "[*] Mounting $# devices ($@):"
for dev in "$@"; do
    device_was_searched=0
    echo "[x] Devices: "
    blkid -o device -u filesystem ${dev}*
    for device in $(blkid -o device -u filesystem ${dev}*); do 
        if mount_and_search $device; then 
            something_was_searched=1 
            device_was_searched=1
        fi 
    done

    if [ $device_was_searched -eq 0 ]; then
        echo "[!] Mounting and secret searching for $dev did not work" 
    fi
done

if [ $something_was_searched -eq 0 ]; then
    echo "[!] Mounting or scanning not successful. Check output for lsblk:"
    lsblk --output NAME,TYPE,SIZE,FSTYPE,MOUNTPOINT,UUID,LABEL
    exit 3
fi

# Count total file entries (minus header)
total_files=$(wc -l < "$TSV_FILE")
if [ "$total_files" -gt 1 ]; then
    actual_files=$((total_files - 1))
    echo "[*] Successfully processed $actual_files file entries across all devices"
else
    echo "[!] No files were processed"
fi