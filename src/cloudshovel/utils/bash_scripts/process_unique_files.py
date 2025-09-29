#!/usr/bin/env python3
"""
Process unique files from bloom filter analysis
Standalone script for CloudShovel bloom filter processing
"""
import json
import hashlib
import os
import subprocess
import argparse
import shutil
import logging
import sys
from pathlib import Path

def is_hash_unique(file_hash, bloom_data):
    """Check if file hash is unique (not in bloom filter) using the same hash function as the original bloom filter"""
    for i in range(bloom_data['hash_count']):
        # Create hash with iteration suffix
        hasher = hashlib.sha256()
        hasher.update(f"{file_hash}_{i}".encode('utf-8'))
        bit_index = int(hasher.hexdigest(), 16) % bloom_data['size']

        # If any bit is 0, hash is definitely unique
        if bloom_data['bit_array'][bit_index] != '1':
            return True  # Process this file

    return False  # Skip - likely already processed (0.01% false positive rate)

def should_upload_file(relative_path, full_path):
    """Determine if a file should be uploaded based on malware detection criteria"""

    # Convert paths to lowercase for case-insensitive matching
    rel_lower = relative_path.lower()

    # Size check - skip files larger than 1GB
    try:
        if os.path.getsize(full_path) > 1024 * 1024 * 1024:  # 1GB limit
            return False, "FILE_TOO_LARGE"
    except:
        return False, "SIZE_CHECK_ERROR"

    # Skip known benign unique files
    benign_files = {
        '/etc/hostname',
        '/etc/machine-id',
        '/var/lib/dbus/machine-id',
        '/etc/ssh/ssh_host_rsa_key',
        '/etc/ssh/ssh_host_dsa_key',
        '/etc/ssh/ssh_host_ecdsa_key',
        '/etc/ssh/ssh_host_ed25519_key',
        '/etc/ssh/ssh_host_rsa_key.pub',
        '/etc/ssh/ssh_host_dsa_key.pub',
        '/etc/ssh/ssh_host_ecdsa_key.pub',
        '/etc/ssh/ssh_host_ed25519_key.pub',         
        '/etc/udev/rules.d/70-persistent-net.rules'
    }

    if relative_path in benign_files:
        return False, "BENIGN_SYSTEM_FILE"

    # Skip large package manager directories (but allow small executables within them)
    skip_dirs_patterns = [        
        '/__pycache__/',
        '/dist-packages/',        
        '/node_modules/',
        '/site-packages/',
        '/usr/include/',
        '/usr/lib/',
        '/usr/share/doc/',
        '/usr/share/locale/',
        '/usr/share/man/',
        '/usr/src/',
        '/var/cache/apt/',
        '/var/cache/yum/',
        '/var/lib/apt/',
        '/var/lib/dpkg/',
        '/var/lib/yum/',
        '/var/spool/',
        '/venv/'
    ]

    for pattern in skip_dirs_patterns:
        if pattern in rel_lower:
            # Exception: still upload executables from these directories if they're small
            if not (rel_lower.endswith(('.exe', '.sh', '.py', '.pl', '.rb', '.php')) and os.path.getsize(full_path) < 10 * 1024 * 1024):
                return False, "BULK_PACKAGE_DIR"

    # High-priority files (always upload if under size limit)
    high_priority_patterns = [
        # Executables in suspicious locations
        '/tmp/', '/var/tmp/', '/dev/shm/', '/home/', '/root/',
        # Scripts and executables
        '.sh', '.py', '.pl', '.rb', '.php', '.jsp', '.asp', '.aspx',
        # Windows executables
        '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.jar',
        # Config files that might contain malicious content
        '/etc/cron', '/etc/systemd/', '/etc/init.d/', '/etc/rc.',
        # Web shells and backdoors common locations
        '/var/www/', '/usr/share/nginx/', '/usr/share/apache/',
        # SSH and auth related
        '/.ssh/', '/etc/passwd', '/etc/shadow', '/etc/sudoers'
    ]

    for pattern in high_priority_patterns:
        if pattern in rel_lower:
            return True, "HIGH_PRIORITY"

    # Binary executables (check if file is executable)
    try:
        if os.access(full_path, os.X_OK) and not rel_lower.endswith(('.txt', '.log', '.conf', '.cfg', '.ini', '.json', '.xml', '.yaml', '.yml')):
            return True, "EXECUTABLE_BINARY"
    except:
        pass

    # Script files (based on extension)
    script_extensions = ['.sh', '.py', '.pl', '.rb', '.php', '.jsp', '.asp', '.aspx', '.bat', '.cmd', '.ps1', '.vbs']
    if any(rel_lower.endswith(ext) for ext in script_extensions):
        return True, "SCRIPT_FILE"

    # Files with no extension (often suspicious)
    filename = os.path.basename(relative_path)
    if '.' not in filename and len(filename) > 0:
        # But skip common system files without extensions
        common_no_ext = {'readme', 'license', 'changelog', 'authors', 'contributors', 'copying', 'install', 'news', 'todo'}
        if filename.lower() not in common_no_ext:
            return True, "NO_EXTENSION"

    # Files in /bin, /sbin, /usr/bin, /usr/sbin that we haven't seen before
    if any(pattern in rel_lower for pattern in ['/bin/', '/sbin/']):
        return True, "SYSTEM_BINARY_PATH"

    # Default: skip (conservative approach - only upload likely interesting files)
    return False, "DEFAULT_SKIP"

def extract_file(full_path, hash_value, relative_path, extracted_dir):
    """Extract a file using its full path, preserving directory structure"""
    if not os.path.isfile(full_path):
        return "NOT_FOUND"

    # Check if we should upload this file
    should_upload, reason = should_upload_file(relative_path, full_path)
    if not should_upload:
        return f"SKIPPED_{reason}"

    # Create destination path preserving the relative directory structure
    # Remove leading slash from relative_path to avoid absolute path issues
    clean_relative_path = relative_path.lstrip('/')
    extracted_path = os.path.join(extracted_dir, clean_relative_path)

    # Create parent directories if they don't exist
    os.makedirs(os.path.dirname(extracted_path), exist_ok=True)

    try:
        shutil.copy2(full_path, extracted_path)
        return "EXTRACTED"
    except Exception as e:
        # Don't use logger here since it's not passed to this function
        # The error will be captured in the main processing loop
        return "COPY_ERROR"

def setup_logging(log_file):
    """Setup logging to both console and file"""
    # Create custom logger
    logger = logging.getLogger('bloom_processor')
    logger.setLevel(logging.INFO)

    # Create formatters
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    # Create file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(formatter)

    # Create console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(logging.Formatter('%(message)s'))  # Simple format for console

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Process unique files from bloom filter analysis')
    parser.add_argument('--target-ami', required=True, help='Target AMI ID')
    parser.add_argument('--unique-files-bucket', required=True, help='S3 bucket for unique files')
    parser.add_argument('--s3-bucket-region', default='us-east-1', help='S3 bucket region (default: us-east-1)')
    parser.add_argument('--bloom-filter-file', default='/home/ec2-user/bloom_filter.json', help='Path to bloom filter JSON file')
    parser.add_argument('--tsv-file', help='Path to TSV file (defaults to /home/ec2-user/{target-ami}.tsv)')
    parser.add_argument('--output-dir', default='/home/ec2-user', help='Output directory (default: /home/ec2-user)')

    return parser.parse_args()

def main():
    args = parse_arguments()

    # Set up file paths
    target_ami = args.target_ami
    unique_files_bucket = args.unique_files_bucket
    s3_bucket_region = args.s3_bucket_region

    bloom_filter_file = args.bloom_filter_file
    tsv_file = args.tsv_file or f"/home/ec2-user/{target_ami}.tsv"
    unique_files_tsv = f"{args.output_dir}/unique_files_{target_ami}.tsv"
    extracted_files_dir = f"{args.output_dir}/extracted_unique_files_{target_ami}"

    # Set up logging to file
    log_file = f"{args.output_dir}/bloom_processing_{target_ami}.log"
    logger = setup_logging(log_file)

    logger.info(f"Processing unique files for AMI: {target_ami}")
    logger.info(f"Using TSV file: {tsv_file}")
    logger.info(f"Using bloom filter: {bloom_filter_file}")
    logger.info(f"Output directory: {extracted_files_dir}")
    logger.info(f"Upload bucket: s3://{unique_files_bucket}")
    logger.info(f"Log file: {log_file}")
    logger.info("")

    # Create directories
    os.makedirs(extracted_files_dir, exist_ok=True)

    # Initialize unique files TSV with header
    with open(unique_files_tsv, 'w') as f:
        f.write("hash\trelative_path\tmodified_timestamp\tfull_path\textracted\n")

    # Read the bloom filter data from file
    try:
        with open(bloom_filter_file, 'r') as f:
            bloom_data = json.load(f)
        logger.info(f"Bloom filter loaded: capacity={bloom_data['capacity']}, hash_count={bloom_data['hash_count']}")
    except Exception as e:
        logger.error(f"Error loading bloom filter: {e}")
        return 1

    # Process TSV file to find unique files
    logger.info("Analyzing TSV file for unique files...")
    unique_files = []
    total_files_processed = 0
    valid_hashes = 0
    unique_hashes = 0

    try:
        with open(tsv_file, 'r') as f:
            lines = f.readlines()
            logger.info(f"Total lines in TSV file: {len(lines)} (including header)")

            for line in lines[1:]:  # Skip header
                parts = line.strip().split('\t')
                if len(parts) >= 4:
                    hash_value, relative_path, timestamp, full_path = parts[0], parts[1], parts[2], parts[3]
                    total_files_processed += 1

                    if hash_value and hash_value != "FAILED_MD5SUM":
                        valid_hashes += 1
                        if is_hash_unique(hash_value, bloom_data):
                            unique_hashes += 1
                            logger.info(f"Found unique file: {relative_path} (hash: {hash_value})")
                            unique_files.append((hash_value, relative_path, timestamp, full_path))
    except FileNotFoundError:
        logger.error(f"TSV file not found: {tsv_file}")
        return 1
    except Exception as e:
        logger.error(f"Error reading TSV file: {e}")
        return 1

    logger.info(f"TSV analysis complete: {total_files_processed} total files, {valid_hashes} valid hashes, {unique_hashes} unique hashes")
    logger.info(f"Found {len(unique_files)} unique files")

    if unique_files:
        logger.info(f"Processing {len(unique_files)} unique files for extraction...")
        logger.info("Extracting unique files using full paths from TSV...")

        # Extract files directly using full paths from TSV
        extracted_count = 0
        failed_count = 0
        skip_stats = {}

        for hash_value, relative_path, timestamp, full_path in unique_files:
            extraction_result = extract_file(full_path, hash_value, relative_path, extracted_files_dir)
            # Update the unique files list with extraction status
            with open(unique_files_tsv, 'a') as f:
                f.write(f"{hash_value}\t{relative_path}\t{timestamp}\t{full_path}\t{extraction_result}\n")

            # Show first few extractions and skips for debugging
            if (extracted_count + failed_count + len(skip_stats)) < 10:
                if extraction_result == "EXTRACTED":
                    logger.info(f"    ✓ EXTRACTED: {relative_path}")
                elif extraction_result.startswith("SKIPPED_"):
                    skip_reason = extraction_result.replace("SKIPPED_", "")
                    logger.info(f"    ✗ SKIPPED ({skip_reason}): {relative_path}")
                elif extraction_result in ["NOT_FOUND", "COPY_ERROR"]:
                    logger.warning(f"    ! FAILED ({extraction_result}): {relative_path}")

            # Count extraction results
            if extraction_result == "EXTRACTED":
                extracted_count += 1
            elif extraction_result in ["NOT_FOUND", "COPY_ERROR"]:
                failed_count += 1
            elif extraction_result.startswith("SKIPPED_"):
                skip_reason = extraction_result.replace("SKIPPED_", "")
                skip_stats[skip_reason] = skip_stats.get(skip_reason, 0) + 1

        logger.info(f"Extraction summary: {extracted_count} files extracted, {failed_count} files failed")
        if skip_stats:
            logger.info("Files skipped by reason:")
            for reason, count in sorted(skip_stats.items()):
                logger.info(f"    {reason}: {count} files")

        # Upload results
        logger.info("Uploading unique files data to S3...")
        try:
            subprocess.run([
                'aws', '--region', s3_bucket_region, 's3', 'cp',
                unique_files_tsv,
                f's3://{unique_files_bucket}/{target_ami}/unique_files.tsv'
            ], check=True, timeout=300)
            logger.info(f"Uploaded unique files TSV to s3://{unique_files_bucket}/{target_ami}/unique_files.tsv")
        except Exception as e:
            logger.error(f"Error uploading TSV: {e}")

        # Upload log file
        logger.info("Uploading processing log to S3...")
        try:
            subprocess.run([
                'aws', '--region', s3_bucket_region, 's3', 'cp',
                log_file,
                f's3://{unique_files_bucket}/{target_ami}/bloom_processing.log'
            ], check=True, timeout=300)
            logger.info(f"Uploaded processing log to s3://{unique_files_bucket}/{target_ami}/bloom_processing.log")
        except Exception as e:
            logger.error(f"Error uploading log file: {e}")

        # Upload extracted files if any
        if os.path.exists(extracted_files_dir):
            extracted_file_list = []
            for root, dirs, files in os.walk(extracted_files_dir):
                for file in files:
                    extracted_file_list.append(os.path.join(root, file))

            logger.info(f"Found {len(extracted_file_list)} files in extraction directory:")
            for i, file_path in enumerate(extracted_file_list[:10]):  # Show first 10
                rel_path = os.path.relpath(file_path, extracted_files_dir)
                file_size = os.path.getsize(file_path)
                logger.info(f"    {i+1}. {rel_path} ({file_size:,} bytes)")
            if len(extracted_file_list) > 10:
                logger.info(f"    ... and {len(extracted_file_list) - 10} more files")

            if extracted_file_list:
                logger.info("Uploading extracted unique files...")
                try:
                    result = subprocess.run([
                        'aws', '--region', s3_bucket_region, 's3', 'sync',
                        extracted_files_dir,
                        f's3://{unique_files_bucket}/{target_ami}/extracted_files/',
                        '--exclude', '*',
                        '--include', '*'  # Include all files explicitly
                    ], check=True, timeout=600, capture_output=True, text=True)
                    logger.info(f"S3 sync output: {result.stdout}")
                    if result.stderr:
                        logger.warning(f"S3 sync stderr: {result.stderr}")
                    logger.info(f"Uploaded {len(extracted_file_list)} files to s3://{unique_files_bucket}/{target_ami}/extracted_files/")
                except subprocess.CalledProcessError as e:
                    logger.error(f"S3 sync failed with return code {e.returncode}")
                    logger.error(f"stdout: {e.stdout}")
                    logger.error(f"stderr: {e.stderr}")
                except Exception as e:
                    logger.error(f"Error uploading extracted files: {e}")
            else:
                logger.info("No extracted files found in directory")
        else:
            logger.error(f"Extraction directory does not exist: {extracted_files_dir}")

        logger.info("Unique file processing completed")
    else:
        logger.info("No unique files found")

    logger.info("Processing completed - no cleanup needed since we used existing mount points")
    return 0

if __name__ == "__main__":
    exit(main())