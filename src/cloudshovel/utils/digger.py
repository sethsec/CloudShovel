import json
import time
import os
from pathlib import Path
from datetime import datetime
from botocore.exceptions import ClientError
from colorama import init, Fore, Style

secret_searcher_role_name = 'minimal-ssm'
tags = [{'Key': 'usage', 'Value': 'CloudQuarry'}, {'Key': 'Name', 'Value': 'whoami-EBS-volume-copy'}]
devices = ['/dev/sdf',
           '/dev/sdg',
           '/dev/sdh',
           '/dev/sdi',
           '/dev/sdj',
           '/dev/sdk',
           '/dev/sdl',
           '/dev/sdm',
           '/dev/sdn',
           '/dev/sdo',
           '/dev/sdp']

# list of objects of the form {'/dev/sdf':'ami-123456'} to keep track of what device in use
in_use_devices = {}
s3_bucket_name = ''
s3_bucket_region = ''
scanning_script_name = 'mount_and_dig.sh'
install_ntfs_3g_script_name = 'install_ntfs_3g.sh'
process_unique_files_script_name = 'process_unique_files.py'
malware_scanner_script_name = 'malware_scanner.py'
boto3_session = None

# Add new global variables for bloom filter functionality
bloom_filter_key = 'known-hashes-python.bloom'
unique_files_bucket = ''  # Will be set from args, no default

def get_ami(ami_id, region):
    try:
        log_success(f'Retrieving the data for AMI {ami_id} from region {region} (search is performed through deprecated AMIs as well)')
        ec2_client = boto3_session.client('ec2', region_name=region)
        
        response = ec2_client.describe_images(
            ImageIds=[ami_id],
            IncludeDeprecated=True  # This allows searching through deprecated AMIs as well
        )
        
        # Check if any images were returned
        if len(response['Images']) > 0:
            ami = response['Images'][0]
            log_success(f"AMI {ami_id} found in region {region}")
            log_success(f"AMI JSON Object: {ami}")
            return ami
        else:
            log_error(f"AMI {ami_id} not found in region {region}. Exiting...")
            cleanup(region)
            exit()
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'InvalidAMIID.Malformed':
            log_error(f"Invalid AMI ID format: {ami_id}. Exiting...")
        elif error_code == 'InvalidAMIID.NotFound':
            log_error(f"AMI {ami_id} not found in region {region}. Exiting...")
        else:
            log_error(f"Unexpected error: {error_message}. Exiting...")

        cleanup(region)
        exit()


def create_s3_bucket(region):
    log_success(f'Checking if S3 bucket {s3_bucket_name} exists...')
    log_success(f'Using region: {region}')
    log_success(f'Session region: {boto3_session.region_name}')
    s3 = boto3_session.client('s3')
    buckets = s3.list_buckets()['Buckets']

    for bucket in buckets:
        if bucket['Name'] == s3_bucket_name:
            log_success(f'Bucket {s3_bucket_name} exists in current AWS account')
            set_bucket_region(s3_bucket_name)
            return
    
    try:
        log_warning('Bucket not found. Creating...')
        # Set the bucket region before creating the bucket
        global s3_bucket_region
        s3_bucket_region = region
        
        # Handle us-east-1 special case (no LocationConstraint needed)
        if region == 'us-east-1':
            response = s3.create_bucket(Bucket=s3_bucket_name)
        else:
            response = s3.create_bucket(Bucket=s3_bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
        
        log_success(f'Bucket created: {response.get("Location", "us-east-1")}')
        # s3_bucket_region is already set above, no need to call set_bucket_region
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        if error_code == 'BucketAlreadyExists':
            log_error(f'Bucket {s3_bucket_name} already exists and is owned by somebody else. Please modify the bucket name and run the script again.')
            cleanup(region)
            exit()
        else:
            log_error(f'Failed to create S3 bucket {s3_bucket_name}: {error_code} - {error_message}')
            log_error('Cannot continue without the S3 bucket. Exiting...')
            cleanup(region)
            exit()
    except Exception as e:
        log_error(f'Unexpected error creating S3 bucket {s3_bucket_name}: {str(e)}')
        log_error('Cannot continue without the S3 bucket. Exiting...')
        cleanup(region)
        exit()


def set_bucket_region(bucket_name):
    s3 = boto3_session.client('s3')
    
    try:
        response = s3.get_bucket_location(Bucket=bucket_name)
        region = response['LocationConstraint']
        
        # AWS returns None for buckets in us-east-1 instead of 'us-east-1'
        global s3_bucket_region
        s3_bucket_region = region if region else 'us-east-1'
    
    except Exception as e:
        log_error(f"An error occurred: {e}")
        return None

def upload_script_to_bucket(script_name):
    log_success(f'Uploading script {script_name} to bucket {s3_bucket_name}...')
    # Use the region from the session if s3_bucket_region is not set
    region_to_use = s3_bucket_region if s3_bucket_region else boto3_session.region_name or 'us-east-1'
    s3 = boto3_session.client('s3', region_name=region_to_use)

    base_path = Path(__file__).parent
    
    f = open(f'{base_path}/bash_scripts/{script_name}')
    script = f.read()
    f.close()

    s3.put_object(Bucket=s3_bucket_name, Body=script, Key=script_name)
    log_success(f'Script {script_name} uploaded to bucket {s3_bucket_name}')


def get_instance_profile_secret_searcher(region):
    iam = boto3_session.client('iam')
    log_success(f'Checking if role {secret_searcher_role_name} for Secret Searcher instance exists')

    try:
        response = iam.get_role(RoleName=secret_searcher_role_name)

        log_success(f'Role {response["Role"]["Arn"]} was found')
    except ClientError as e:
        if e.response['Error']['Code'] != 'NoSuchEntity':
            log_error(f'Unknown error: {e["Error"]["Code"]}. Exiting...')
            cleanup(region)
            exit()
        
        log_warning('Role doesn\'t exist. Creating...')
        response = iam.create_role(RoleName=secret_searcher_role_name, AssumeRolePolicyDocument=
        """{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }""", Tags=tags)

        iam.attach_role_policy(RoleName=secret_searcher_role_name, PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')
        iam.attach_role_policy(RoleName=secret_searcher_role_name, PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess')

        log_success(f'Role {response["Role"]["Arn"]} created and policy configured')

    try:
        log_success(f'Checking if instance profile {secret_searcher_role_name} exists')
        response = iam.get_instance_profile(InstanceProfileName=secret_searcher_role_name)
        log_success(f'Instance profile found: {response["InstanceProfile"]["Arn"]}')

        return response["InstanceProfile"]["Arn"]
    except ClientError as e:
        log_warning('Instance profile not found')

        if e.response['Error']['Code'] != 'NoSuchEntity':
            log_error(f'Unknown error: {e["Error"]["Code"]}. Exiting...')
            cleanup(region)
            exit()
        
        log_warning('Creating instance profile...')
        response = iam.create_instance_profile(InstanceProfileName=secret_searcher_role_name, Tags=tags)
        iam.add_role_to_instance_profile(InstanceProfileName=secret_searcher_role_name, RoleName=secret_searcher_role_name)

        log_success(f'Created instance profile {response["InstanceProfile"]["Arn"]}')
        log_success('Waiting 1 min for the instance profile to be fully available in AWS')
        time.sleep(60)

        return response["InstanceProfile"]["Arn"]
        

def wait_for_instance_status(instance_id, desired_status, region):
    ec2 = boto3_session.client('ec2', region_name=region)  # Ensure region_name is used for client
    
    max_not_found_retries = 6 
    not_found_retry_delay_seconds = 10
    not_found_attempts = 0

    overall_poll_attempts = 0
    # Max poll duration: 15 min for 'running', 83 min for 'stopped' (like in stop_instance)
    # Defaulting to a general 15 mins, can be made more specific if needed by passing max duration
    max_overall_poll_duration_seconds = 15 * 60 
    poll_interval_seconds = 5 # Increased poll interval slightly

    log_success(f"Waiting for instance {instance_id} to reach status '{desired_status}' in region {region}. Polling every {poll_interval_seconds}s.")

    start_time = time.time()
    while True:
        if (time.time() - start_time) > max_overall_poll_duration_seconds:
            log_error(f"Timeout: Instance {instance_id} did not reach status '{desired_status}' within {max_overall_poll_duration_seconds // 60} minutes. Last known state unknown or not desired. Aborting wait.")
            raise Exception(f"Timeout waiting for instance {instance_id} to reach {desired_status}.")

        overall_poll_attempts += 1
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            
            if not response['Reservations'] or not response['Reservations'][0]['Instances']:
                log_warning(f"Instance {instance_id} described but no instance data returned. Attempt {not_found_attempts + 1}/{max_not_found_retries}. Retrying in {not_found_retry_delay_seconds}s.")
                not_found_attempts += 1
                if not_found_attempts >= max_not_found_retries:
                    log_error(f"Instance {instance_id} details not found after {max_not_found_retries} attempts (empty response). Aborting wait.")
                    raise Exception(f"Instance {instance_id} details not found after retries (empty response).")
                time.sleep(not_found_retry_delay_seconds)
                continue

            instance_data = response['Reservations'][0]['Instances'][0]
            current_status = instance_data['State']['Name']
            # More descriptive logging for each poll attempt might be too verbose, only log on status change or significant events.
            # log_success(f"Instance {instance_id} current status: {current_status}. Target: '{desired_status}'. Poll attempt: {overall_poll_attempts}.")


            if current_status == desired_status:
                log_success(f"Instance {instance_id} successfully reached status '{desired_status}' after ~{int(time.time() - start_time)} seconds.")
                return # Success

            # Check for unexpected terminal states
            # 'stopped' can be a desired state (e.g. for stop_instance), so it's only unexpected if not the target.
            unexpected_terminal_states = ['shutting-down', 'terminated']
            if current_status == 'stopping' and desired_status != 'stopped':
                 unexpected_terminal_states.append('stopping')
            if current_status == 'stopped' and desired_status != 'stopped':
                unexpected_terminal_states.append('stopped')


            if current_status in unexpected_terminal_states:
                 log_error(f"Instance {instance_id} entered unexpected terminal state '{current_status}' while waiting for '{desired_status}'. Aborting wait.")
                 raise Exception(f"Instance {instance_id} in unexpected state {current_status} when waiting for {desired_status}.")

            # Reset not_found_attempts because describe_instances succeeded and returned data this time
            not_found_attempts = 0 
            log_success(f"Instance {instance_id} is {current_status}. Waiting for {desired_status}. Polling again in {poll_interval_seconds}s.")
            time.sleep(poll_interval_seconds)

        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                not_found_attempts += 1
                log_warning(f"Instance {instance_id} not found (InvalidInstanceID.NotFound). Attempt {not_found_attempts}/{max_not_found_retries}. Retrying in {not_found_retry_delay_seconds}s.")
                if not_found_attempts >= max_not_found_retries:
                    log_error(f"Instance {instance_id} still not found (InvalidInstanceID.NotFound) after {max_not_found_retries} attempts. Aborting wait.")
                    raise 
                time.sleep(not_found_retry_delay_seconds)
            elif e.response['Error']['Code'] == 'RequestLimitExceeded':
                log_warning(f"Request limit exceeded when polling for {instance_id}. Retrying in 15s.")
                time.sleep(15)
            else:
                log_error(f"A non-retryable ClientError occurred for instance {instance_id}: {e}. Aborting wait.")
                raise 
        except Exception as e:
            log_error(f"An unexpected error occurred while waiting for instance {instance_id}: {e}. Aborting wait.")
            raise


def create_secret_searcher(region, instance_profile_arn, required_az=None, scanner_os='al2'):
    ec2 = boto3_session.client('ec2', region)

    preferred_instance_types = ['c6i.4xlarge', 'c6i.2xlarge']  # try these in order for spot
    availability_zones = ['a', 'b', 'c', 'd']  # try these AZs in order for default VPC
    use_on_demand_fallback = True  # Set this to False if you only want spot instances
    final_fallback_type = 't3.2xlarge'  # final on-demand fallback if all else fails

    log_warning('No secret searcher instance found. Starting creation process...')

    # Select AMI filter based on scanner OS
    if scanner_os == 'al2':
        ami_filter_pattern = 'amzn2-ami-hvm-2.0*-x86_64-gp2'
        log_success(f'Getting AMI for latest Amazon Linux 2 for current region...')
    else:  # al2023 (default)
        ami_filter_pattern = 'al2023-ami-2023*-x86_64'
        log_success(f'Getting AMI for latest Amazon Linux 2023 for current region...')

    response = ec2.describe_images(
        Filters=[{'Name': 'name', 'Values': [ami_filter_pattern]}],
        Owners=['amazon']
    )

    sorted_images = sorted(
        response['Images'],
        key=lambda x: datetime.strptime(x['CreationDate'], '%Y-%m-%dT%H:%M:%S.%fZ'),
        reverse=True
    )

    amazon_ami_id = sorted_images[0]['ImageId']
    log_success(f'Found Amazon Linux AMI {amazon_ami_id}')

    # If a specific AZ is required (to match target volumes), use only that AZ
    if required_az:
        log_success(f'Secret Searcher must launch in AZ {required_az} to match target volumes')
        azs_to_try = [required_az]
    else:
        # Try all AZs
        azs_to_try = [f'{region}{suffix}' for suffix in availability_zones]

    # Secret Searcher ALWAYS uses default VPC (never duplicator VPC)
    # It needs internet access for SSM, S3, etc.
    # Only the target AMI instance uses the isolated duplicator VPC

    # Try each instance type with the specified availability zone(s)
    for instance_type in preferred_instance_types:
        for az in azs_to_try:
            log_success(f'Trying to launch Secret Searcher as spot instance type {instance_type} in AZ {az}...')
            try:
                # Base params
                instance_params = {
                    'InstanceType': instance_type,
                    'IamInstanceProfile': {'Arn': instance_profile_arn},
                    'ImageId': amazon_ami_id,
                    'MinCount': 1,
                    'MaxCount': 1,
                    'BlockDeviceMappings': [{'DeviceName': '/dev/xvda', 'Ebs': {'VolumeSize': 50}}],
                    'TagSpecifications': [{
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'usage', 'Value': 'whoAMI-filesystem-scanner'},
                            {'Key': 'Name', 'Value': 'whoAMI-filesystem-scanner'}
                        ]
                    }],
                    'InstanceMarketOptions': {
                        'MarketType': 'spot',
                        'SpotOptions': {
                            'SpotInstanceType': 'one-time',
                            'InstanceInterruptionBehavior': 'terminate'
                        }
                    }
                }

                # Always use default VPC with AZ placement (never duplicator VPC)
                instance_params['Placement'] = {'AvailabilityZone': az}

                secret_searcher_instance = ec2.run_instances(**instance_params)
                instance_id = secret_searcher_instance['Instances'][0]['InstanceId']

                log_success(f"Spot instance {instance_id} created with type {instance_type} in AZ {az}. Waiting for it to be in 'running' state...")
                wait_for_instance_status(instance_id, 'running', region)

                log_success('Waiting 1 more min for the instance to start SSM Agent')
                time.sleep(60)
                return instance_id

            except Exception as e:
                log_warning(f"Spot instance launch failed for {instance_type} in AZ {az}: {str(e)}")
                continue

    if use_on_demand_fallback:
        log_warning('All spot attempts failed. Trying to launch on-demand instances instead...')

        # Try on-demand for the same preferred instance types
        for instance_type in preferred_instance_types:
            for az in azs_to_try:
                try:
                    log_success(f'Trying on-demand instance type {instance_type} in AZ {az}...')
                    instance_params = {
                        'InstanceType': instance_type,
                        'IamInstanceProfile': {'Arn': instance_profile_arn},
                        'ImageId': amazon_ami_id,
                        'MinCount': 1,
                        'MaxCount': 1,
                        'BlockDeviceMappings': [{'DeviceName': '/dev/xvda', 'Ebs': {'VolumeSize': 50}}],
                        'TagSpecifications': [{
                            'ResourceType': 'instance',
                            'Tags': [
                                {'Key': 'usage', 'Value': 'whoAMI-filesystem-scanner'},
                                {'Key': 'Name', 'Value': 'whoAMI-filesystem-scanner'}
                            ]
                        }]
                    }

                    # Always use default VPC with AZ placement (never duplicator VPC)
                    instance_params['Placement'] = {'AvailabilityZone': az}

                    secret_searcher_instance = ec2.run_instances(**instance_params)
                    instance_id = secret_searcher_instance['Instances'][0]['InstanceId']

                    log_success(f"On-demand instance {instance_id} ({instance_type}) created in AZ {az}. Waiting for it to be in 'running' state...")
                    wait_for_instance_status(instance_id, 'running', region)

                    log_success('Waiting 1 more min for the instance to start SSM Agent')
                    time.sleep(60)
                    return instance_id

                except Exception as e:
                    log_warning(f"On-demand instance launch failed for {instance_type} in AZ {az}: {str(e)}")
                    continue

        # Final fallback to t3.2xlarge on-demand
        log_warning(f'All preferred on-demand types failed. Trying final fallback: {final_fallback_type}...')
        for az in azs_to_try:
            try:
                log_success(f'Trying final fallback on-demand instance type {final_fallback_type} in AZ {az}...')
                instance_params = {
                    'InstanceType': final_fallback_type,
                    'IamInstanceProfile': {'Arn': instance_profile_arn},
                    'ImageId': amazon_ami_id,
                    'MinCount': 1,
                    'MaxCount': 1,
                    'BlockDeviceMappings': [{'DeviceName': '/dev/xvda', 'Ebs': {'VolumeSize': 50}}],
                    'TagSpecifications': [{
                        'ResourceType': 'instance',
                        'Tags': [
                            {'Key': 'usage', 'Value': 'whoAMI-filesystem-scanner'},
                            {'Key': 'Name', 'Value': 'whoAMI-filesystem-scanner'}
                        ]
                    }]
                }

                # Always use default VPC with AZ placement (never duplicator VPC)
                instance_params['Placement'] = {'AvailabilityZone': az}

                secret_searcher_instance = ec2.run_instances(**instance_params)
                instance_id = secret_searcher_instance['Instances'][0]['InstanceId']

                log_success(f"On-demand fallback instance {instance_id} ({final_fallback_type}) created in AZ {az}. Waiting for it to be in 'running' state...")
                wait_for_instance_status(instance_id, 'running', region)

                log_success('Waiting 1 more min for the instance to start SSM Agent')
                time.sleep(60)
                return instance_id

            except Exception as e:
                log_warning(f"Final fallback instance launch failed in AZ {az}: {str(e)}")
                continue

        log_error(f"Failed to launch any on-demand instance type in any availability zone")
        raise Exception('Failed to launch Secret Searcher in any availability zone')

    else:
        log_error('Failed to launch Secret Searcher with any spot instance type.')
        raise Exception('No spot capacity available and fallback disabled')



def install_searching_tools(instance_id, region, is_windows=False):
    log_success(f'Installing tools on Secret Searcher instance {instance_id} for searching secrets...')
    ssm = boto3_session.client('ssm', region)

    # Install YARA and ClamAV for malware scanning
    log_success(f'Installing YARA and ClamAV on instance {instance_id}...')
    install_commands = [
        # Detect OS and install ClamAV
        'if command -v yum &> /dev/null; then '
        '  amazon-linux-extras install epel -y 2>/dev/null || yum install -y epel-release; '
        '  yum install -y clamav clamav-update; '
        'elif command -v apt-get &> /dev/null; then '
        '  apt-get update && apt-get install -y clamav; '
        'fi',
        # Install yara-python 3.11.0 - this version bundles YARA 3.x and works with OpenSSL 1.0.2
        'pip3 install yara-python==3.11.0 || pip install yara-python==3.11.0',
        'freshclam || true',  # Update ClamAV signatures, don't fail if it errors
        'mkdir -p /opt/yara-rules'
    ]

    try:
        command = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName='AWS-RunShellScript',
            Parameters={'commands': install_commands}
        )
        waiter = ssm.get_waiter('command_executed')
        waiter.wait(CommandId=command['Command']['CommandId'], InstanceId=instance_id,
                    WaiterConfig={'Delay': 15, 'MaxAttempts': 40})  # ~10 min timeout

        output = ssm.get_command_invocation(CommandId=command['Command']['CommandId'], InstanceId=instance_id)
        log_success(f'YARA/ClamAV installation finished with status: {output["Status"]}')
    except Exception as e:
        log_warning(f'YARA/ClamAV installation encountered an error: {e}. Malware scanning may be limited.')

    # Download the script at /home/ec2-user/ and execute it
    if is_windows:
        command = ssm.send_command(InstanceIds=[instance_id],
                                DocumentName='AWS-RunRemoteScript',
                                Parameters={
                                    'sourceType': ['S3'],
                                    'sourceInfo': [f'{{"path":"https://{s3_bucket_name}.s3.{s3_bucket_region or "us-east-1"}.amazonaws.com/{install_ntfs_3g_script_name}"}}'],
                                    'commandLine': [f'bash /home/ec2-user/{install_ntfs_3g_script_name}'],
                                    'workingDirectory': ['/home/ec2-user/']
                                    })
        
        log_success('Installation started. Waiting for completion...')
        waiter = ssm.get_waiter('command_executed')
        waiter.wait(CommandId=command['Command']['CommandId'], InstanceId=instance_id, WaiterConfig={'Delay':15, 'MaxAttempts':60})

        output = ssm.get_command_invocation(CommandId=command['Command']['CommandId'], InstanceId=instance_id)
        log_success(f'Command execution finished with status: {output["Status"]}')

        if output['Status'] != 'Success':
            log_error(f'Installation failed. Please check what went wrong or install it manually and disable this step. Exiting...')
            cleanup(region, instance_id=instance_id)
            exit()

    log_success(f'Copying {scanning_script_name} from S3 bucket {s3_bucket_name} to Secret Searcher instance {instance_id} using SSM...')
    bash_command = f"if test -f /home/ec2-user/{scanning_script_name}; then echo '[INFO] Script already present on disk';else aws --region {s3_bucket_region or 'us-east-1'} s3 cp s3://{s3_bucket_name}/{scanning_script_name} /home/ec2-user/{scanning_script_name} && chmod +x /home/ec2-user/{scanning_script_name}; fi"
    command = ssm.send_command(InstanceIds=[instance_id],
                            DocumentName='AWS-RunShellScript',
                            Parameters={'commands':[bash_command]})
    
    waiter = ssm.get_waiter('command_executed')
    waiter.wait(CommandId=command['Command']['CommandId'], InstanceId=instance_id)

    output = ssm.get_command_invocation(CommandId=command['Command']['CommandId'], InstanceId=instance_id)
    log_success(f'Command execution finished with status: {output["Status"]}')


def get_targets(region, os='all'):
    f = open('targets.json')
    all_amis = json.loads(f.read())
    f.close()
    
    targets = [x for x in all_amis if x['Region'] == region]
    
    if os == 'all':
        return targets

    if os == 'linux':
        linux_targets = [x for x in targets if 'Platform' not in x]
        return linux_targets
    
    if os == 'windows':
        windows_targets = [x for x in targets if 'Platform' in x]
        return windows_targets

def start_instance_with_target_ami(ami_object, region, is_ena=False, tried_types=None):
    ec2 = boto3_session.client('ec2', region)
    ami_id = ami_object['ImageId']
    architecture = ami_object.get('Architecture', 'x86_64')
    tried_types = tried_types or []

    ARCH_INSTANCE_MAP = {
        "x86_64": ["c6i.large", "m6i.large", "c5.large", "t2.medium", "c3.large"],
        "arm64": ["c6g.large","t4g.small", "c7g.large", "m6g.medium"]
    }

    fallback_types = [t for t in ARCH_INSTANCE_MAP.get(architecture, []) if t not in tried_types]
    if not fallback_types:
        log_error(f"All instance types for architecture '{architecture}' have been tried and failed.")
        exit(1)

    instance_type = fallback_types[0]
    tried_types.append(instance_type)

    log_success(f"Attempting to launch {architecture} instance with type {instance_type} for AMI {ami_id}...")

    # Get VPC configuration from environment variables
    vpc_id = os.environ.get('DUPLICATOR_VPC_ID')
    subnet_ids_str = os.environ.get('DUPLICATOR_SUBNET_IDS')
    security_group_id = os.environ.get('DUPLICATOR_SECURITY_GROUP_ID')
    
    if not all([vpc_id, subnet_ids_str, security_group_id]):
        log_warning(f"VPC configuration not found for region {region}. Using default VPC.")
        # Let AWS pick any available AZ - Secret Searcher will launch in same AZ later
        instance_params = {
            'InstanceType': instance_type,
            'MaxCount': 1,
            'MinCount': 1,
            'ImageId': ami_id,
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'usage', 'Value': 'whoAMI-filesystem-duplicator'},
                    {'Key': 'Name', 'Value': f'whoAMI-filesystem--duplicator-{ami_id}'}
                ]
            }]
        }
    else:
        # Use isolated VPC configuration
        subnet_ids = subnet_ids_str.split(',')
        # Use the first subnet (you could implement round-robin or random selection)
        subnet_id = subnet_ids[0]

        log_success(f"Using isolated VPC configuration: VPC {vpc_id}, Subnet {subnet_id}, SG {security_group_id}")

        instance_params = {
            'InstanceType': instance_type,
            'MaxCount': 1,
            'MinCount': 1,
            'ImageId': ami_id,
            'SubnetId': subnet_id,
            'SecurityGroupIds': [security_group_id],
            'TagSpecifications': [{
                'ResourceType': 'instance',
                'Tags': [
                    {'Key': 'usage', 'Value': 'whoAMI-filesystem-duplicator'},
                    {'Key': 'Name', 'Value': f'whoAMI-filesystem--duplicator-{ami_id}'},
                    {'Key': 'VPC', 'Value': 'isolated-duplicator-vpc'},
                    {'Key': 'Security', 'Value': 'no-internet-access'}
                ]
            }]
        }

    # Only add NetworkInterfaces when not using VPC configuration (SubnetId)
    if not is_ena and 'SubnetId' not in instance_params:
        instance_params['NetworkInterfaces'] = [{
            'AssociatePublicIpAddress': False,
            'DeviceIndex': 0
        }]

    try:
        instance = ec2.run_instances(**instance_params)

        instance_id = instance['Instances'][0]['InstanceId']
        log_success(f"Instance {instance_id} created in isolated VPC. Waiting to be in 'running' state...")

        waiter = ec2.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id], WaiterConfig={'Delay': 5, 'MaxAttempts': 120})

        log_success(f"Instance {instance_id} based on AMI {ami_id} is ready")
        return {"instanceId": instance_id, "ami": ami_id}

    except Exception as e:
        error = str(e)
        if '(ENA)' in error and not is_ena:
            log_warning(f"AMI {ami_id} requires ENA support. Retrying with ENA-compatible settings...")
            return start_instance_with_target_ami(ami_object, region, is_ena=True, tried_types=tried_types)
        else:
            log_warning(f"Failed to launch instance with {instance_type}. Error: {error}")
            return start_instance_with_target_ami(ami_object, region, is_ena=is_ena, tried_types=tried_types)

def stop_instance(instance_ids, region):
    try:
        log_success(f'Stopping EC2 instances {instance_ids}')
        ec2 = boto3_session.client('ec2', region)
        ec2.stop_instances(InstanceIds=instance_ids)

        waiter = ec2.get_waiter('instance_stopped')
        waiter.wait(InstanceIds=instance_ids, WaiterConfig={'Delay':5, 'MaxAttempts':1000})

    except Exception as e:
        log_error(f'Error when stopping instances {instance_ids}. Error: {str(e)}')


def move_volumes_and_terminate_instance(instance_id, instance_id_secret_searcher, ami, region):
    ec2 = boto3_session.client('ec2', region)
    log_success('Starting detaching volumes procedure...')

    volumes = ec2.describe_volumes(Filters=[{'Name':'attachment.instance-id', 'Values':[instance_id]}])
    volume_ids = [x['VolumeId'] for x in volumes['Volumes']]

    # Print number of volumes
    log_success(f'Number of volumes: {len(volume_ids)}')
    if len(devices) < len(volume_ids):
        log_error('Target AMI has more EBS volumes than the number of supported EBS volumes that can be attached to an EC2 instance. This case is not covered by the script. Exiting...')
        exit()

    log_success(f'Volumes to detach: {volume_ids}')

    for volume_id in volume_ids:
        log_success(f'Detaching volume {volume_id}...')
        ec2.detach_volume(VolumeId=volume_id)

    log_success("Waiting for all detached volumes to be in 'available' state...")

    is_available = False
    while is_available == False:
        volumes = ec2.describe_volumes(VolumeIds=volume_ids)
        is_available = all([x['State'] == 'available' for x in volumes['Volumes']])

        if is_available == False:
            time.sleep(5)
    
    log_success("All volumes are in 'available' state")
    
    log_warning(f'Terminating instance {instance_id} created for target AMI...')
    ec2.terminate_instances(InstanceIds=[instance_id])
    log_success('Instance {instance_id} terminated')

    log_success('Moving volumes to secret searching instance...')

    # Check volume AZ and Secret Searcher AZ to ensure they match
    if volume_ids:
        volume_info = ec2.describe_volumes(VolumeIds=[volume_ids[0]])
        volume_az = volume_info['Volumes'][0]['AvailabilityZone']
        log_success(f'First volume {volume_ids[0]} is in AZ {volume_az}')

        # Check Secret Searcher AZ
        try:
            searcher_info = ec2.describe_instances(InstanceIds=[instance_id_secret_searcher])
            searcher_state = searcher_info['Reservations'][0]['Instances'][0]['State']['Name']
            searcher_az = searcher_info['Reservations'][0]['Instances'][0]['Placement']['AvailabilityZone']

            if searcher_state != 'running':
                log_error(f'Secret Searcher instance {instance_id_secret_searcher} is in state "{searcher_state}", not "running". Cannot attach volumes.')
                if searcher_state in ['stopping', 'stopped', 'shutting-down', 'terminated']:
                    log_error(f'Secret Searcher instance {instance_id_secret_searcher} was terminated or stopped (state: {searcher_state}). This may be due to spot interruption.')
                    raise Exception(f'Secret Searcher instance was lost (state: {searcher_state}). Likely spot interruption. Manual retry required.')
                else:
                    log_warning(f'Secret Searcher in state "{searcher_state}". Waiting for it to be running...')
                    wait_for_instance_status(instance_id_secret_searcher, 'running', region)

            # Check AZ mismatch
            if searcher_az != volume_az:
                log_error(f'AZ MISMATCH: Secret Searcher is in {searcher_az} but volume is in {volume_az}')
                log_error(f'Cannot attach volumes across availability zones.')
                raise Exception(f'Availability zone mismatch: Secret Searcher in {searcher_az}, volume in {volume_az}. Cannot attach volumes.')
            else:
                log_success(f'AZ match confirmed: Both Secret Searcher and volumes are in {volume_az}')

        except ClientError as e:
            if 'InvalidInstanceID' in str(e):
                log_error(f'Secret Searcher instance {instance_id_secret_searcher} no longer exists. Likely terminated by spot interruption.')
                raise Exception('Secret Searcher instance was terminated. Likely spot interruption. Manual retry required.')
            else:
                log_error(f'Failed to verify Secret Searcher instance state: {e}')
                raise
        except Exception as e:
            log_error(f'Unexpected error verifying Secret Searcher state: {e}')
            raise

    for volume_id in volume_ids:
        device = devices[0]

        log_success(f'Attaching volume {volume_id} as device {device}')
        ec2.attach_volume(Device=device, InstanceId=instance_id_secret_searcher, VolumeId=volume_id)
        
        # Tag the volume for cleanup purposes
        try:
            ec2.create_tags(
                Resources=[volume_id],
                Tags=[
                    {'Key': 'CloudShovel', 'Value': 'true'},
                    {'Key': 'AMI', 'Value': ami},
                    {'Key': 'ScannerInstance', 'Value': instance_id_secret_searcher},
                    {'Key': 'CreatedBy', 'Value': 'CloudShovel-Digger'},
                    {'Key': 'Purpose', 'Value': 'filesystem-scanning'}
                ]
            )
            log_success(f'Tagged volume {volume_id} for cleanup identification')
        except Exception as e:
            log_warning(f'Failed to tag volume {volume_id}: {e}')
        
        devices.remove(device)
        in_use_devices[device]=ami

    log_success("Waiting for volumes to be in 'in-use' state...")
    waiter = ec2.get_waiter('volume_in_use')
    waiter.wait(VolumeIds=volume_ids, WaiterConfig={'Delay':3, 'MaxAttempts':60})
    log_success('Volumes are ready to be searched')

    return volume_ids


def start_digging_for_secrets(instance_id_secret_searcher, target_ami, region):
    log_success('Starting digging for secrets...')
    ssm = boto3_session.client('ssm', region)
    volumes = []

    for in_use_device in in_use_devices.keys():
        if target_ami in in_use_devices[in_use_device]:
            volumes.append(in_use_device)

    parameter_volumes = ' '.join(volumes)

    command = ssm.send_command(InstanceIds=[instance_id_secret_searcher],
                        DocumentName='AWS-RunShellScript',
                        Parameters={'commands':[f'/home/ec2-user/{scanning_script_name} {parameter_volumes}']})

    log_success(f'Secret searching in {parameter_volumes} started. Waiting for completion...')

    waiter = ssm.get_waiter('command_executed')
    waiter.wait(CommandId=command['Command']['CommandId'],
                InstanceId=instance_id_secret_searcher,
                WaiterConfig={'Delay':10, 'MaxAttempts':720})
    
    log_success('Scanning completed')


def upload_results(instance_id_secret_searcher, target_ami, region):
    log_success(f'Uploading results for AMI {target_ami} to S3 bucket {s3_bucket_name}...')

    ssm = boto3_session.client('ssm', region)
    
    # Rename the combined TSV file to match the AMI ID
    command = ssm.send_command(InstanceIds=[instance_id_secret_searcher],
                        DocumentName='AWS-RunShellScript',
                        Parameters={'commands':[
                            f'cp /home/ec2-user/OUTPUT/ami_files.tsv /home/ec2-user/{target_ami}.tsv'
                        ]})
    
    log_success(f'Preparing file for upload. Waiting for completion...')
    waiter = ssm.get_waiter('command_executed')
    waiter.wait(CommandId=command['Command']['CommandId'], InstanceId=instance_id_secret_searcher, WaiterConfig={'Delay':5, 'MaxAttempts':60})
    
    log_success(f'Uploading mount_and_dig.log to S3 bucket {s3_bucket_name}/ami-processing-logs/{target_ami}/mount_and_dig.log')
    log_success(f'Uploading {target_ami}.tsv to S3 bucket {s3_bucket_name}/tsv/{target_ami}.tsv')
    # Upload the TSV file to the bucket with the tsv/ prefix
    command = ssm.send_command(InstanceIds=[instance_id_secret_searcher],
                        DocumentName='AWS-RunShellScript',
                        Parameters={'commands':[
                            f'aws --region {s3_bucket_region or "us-east-1"} s3 cp /home/ec2-user/{target_ami}.tsv s3://{s3_bucket_name}/tsv/{target_ami}.tsv',
                            f'aws --region {s3_bucket_region or "us-east-1"} s3 cp /home/ec2-user/OUTPUT/mount_and_dig.log s3://{s3_bucket_name}/ami-processing-logs/{target_ami}/mount_and_dig.log',
                            'rm -rf /home/ec2-user/OUTPUT/'
                        ]})
    
    log_success(f'Upload started. Waiting for upload to complete...')
    waiter = ssm.get_waiter('command_executed')
    waiter.wait(CommandId=command['Command']['CommandId'], InstanceId=instance_id_secret_searcher, WaiterConfig={'Delay':5, 'MaxAttempts':800})
    log_success(f'Upload completed')

    
def delete_volumes(volume_ids, region):
    log_success(f'Starting deleting volumes {volume_ids} procedure...')
    ec2 = boto3_session.client('ec2', region)
    successfully_detached_volume_ids = []

    log_success(f'Detaching volumes {volume_ids}...')
    for volume_id in volume_ids:
        try:
            ec2.detach_volume(VolumeId=volume_id)
            log_success(f"Detachment initiated for volume {volume_id}.")
            successfully_detached_volume_ids.append(volume_id)
        except ClientError as e:
            # If the volume is already detached or in a state where detach is not possible (e.g., instance terminated)
            # it might still be possible to delete it. Log error and proceed.
            log_warning(f"Could not detach volume {volume_id} (may already be detached or instance gone): {e}. Will still attempt deletion.")
            successfully_detached_volume_ids.append(volume_id) # Add to list to attempt deletion
        except Exception as e:
            log_error(f"Error during detach_volume for {volume_id}: {e}. It might not be deleted.")
    
    if not successfully_detached_volume_ids:
        log_warning("No volumes were successfully detached or marked for deletion attempt. Skipping deletion phase.")
        return

    log_success(f"Waiting for volumes {successfully_detached_volume_ids} to be in 'available' state...")
    try:
        # This waiter will wait for all specified volumes to become available.
        # If some are already available, it will proceed faster for those.
        waiter = ec2.get_waiter('volume_available')
        waiter.wait(VolumeIds=successfully_detached_volume_ids, WaiterConfig={'Delay':5, 'MaxAttempts':36}) # Reduced max attempts (3 min)
    except Exception as e:
        # If waiter fails, it could be that some volumes never became available or the call timed out.
        # Proceed to attempt deletion for all volumes we tried to detach.
        log_error(f"Error while waiting for volumes {successfully_detached_volume_ids} to become available: {e}. Attempting to delete them anyway.")

    log_warning(f'Deleting volumes: {successfully_detached_volume_ids}')
    for volume_id in successfully_detached_volume_ids:
        try:
            ec2.delete_volume(VolumeId=volume_id)
            log_success(f"Deletion initiated for volume {volume_id}.")
        except Exception as e:
            log_error(f"Error deleting volume {volume_id}: {e}. Please check manually.")
    
    log_warning("Volume deletion process completed. The script doesn't wait for full deletion confirmation for each volume. Please check AWS console if necessary.")


def cleanup(region, instance_id=None):
    log_warning('Starting cleanup (the S3 bucket will not be deleted)...')
    ec2 = boto3_session.client('ec2', region)

    if instance_id:
        log_success(f'Terminating EC2 secret searcher instance {instance_id}...')
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
            # Consider adding a waiter for termination here if confirmation is critical
            # waiter = ec2.get_waiter('instance_terminated')
            # waiter.wait(InstanceIds=[instance_id])
            log_success(f'Termination initiated for instance {instance_id}')
        except Exception as e:
            log_error(f'Error terminating instance {instance_id}: {str(e)}')
    else:
        log_warning('No specific instance ID provided for cleanup. Attempting to find and terminate secret searcher instance(s) by tags...')
        try:
            instances = ec2.describe_instances(Filters=[{'Name':'tag-key', 'Values':['usage']},
                                                    {'Name':'tag-value','Values':['whoAMI-filesystem-scanner']}, # CORRECTED TAG
                                                    {'Name':'instance-state-name', 'Values':['pending','running']}])

            instance_ids_to_terminate = []
            if instances['Reservations']:
                for reservation in instances['Reservations']:
                    for inst in reservation['Instances']:
                        instance_ids_to_terminate.append(inst['InstanceId'])
            
            if instance_ids_to_terminate:
                log_success(f'Found and terminating instances by tag: {instance_ids_to_terminate}')
                ec2.terminate_instances(InstanceIds=instance_ids_to_terminate)
                # Consider adding a waiter for termination here
                log_success(f'Termination initiated for instances: {instance_ids_to_terminate}')
            else:
                log_warning('No running or pending instances found matching the "whoAMI-filesystem-scanner" usage tag.')
        except Exception as e:
            log_error(f'Error during tag-based instance cleanup: {str(e)}')


    # iam = boto3_session.client('iam')
    
    # log_success('Deleting role and instance profile...')
    # try:
    #     iam.remove_role_from_instance_profile(InstanceProfileName=secret_searcher_role_name, RoleName=secret_searcher_role_name)
    #     iam.delete_instance_profile(InstanceProfileName=secret_searcher_role_name)
    #     iam.detach_role_policy(RoleName=secret_searcher_role_name, PolicyArn='arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore')
    #     iam.detach_role_policy(RoleName=secret_searcher_role_name, PolicyArn='arn:aws:iam::aws:policy/AmazonS3FullAccess')
    #     iam.delete_role(RoleName=secret_searcher_role_name)
    #     log_success('Role and instance profile deleted')
    # except ClientError as e:
    #     if e.response['Error']['Code'] != 'NoSuchEntity':
    #         log_error(f'Unknown error: {e["Error"]["Code"]}. Exiting...')
    #         exit()
    #     else:
    #         log_success(f'No role {secret_searcher_role_name} found.')


init()  # Initialize colorama

def log_success(message):
    print(f"{Fore.GREEN}[INFO]{Style.RESET_ALL} {message}")

def log_warning(message):
    print(f"{Fore.YELLOW}[WARN]{Style.RESET_ALL} {message}")

def log_error(message):
    print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

def upload_mount_and_dig_log_only(instance_id_secret_searcher, target_ami, region):
    log_success(f'Uploading mount_and_dig.log for AMI {target_ami} to S3 bucket {s3_bucket_name} (log-only fallback)...')
    ssm = boto3_session.client('ssm', region)
    command = ssm.send_command(InstanceIds=[instance_id_secret_searcher],
                        DocumentName='AWS-RunShellScript',
                        Parameters={'commands':[
                            f'aws --region {s3_bucket_region or "us-east-1"} s3 cp /home/ec2-user/OUTPUT/mount_and_dig.log s3://{s3_bucket_name}/ami-processing-logs/{target_ami}/mount_and_dig.log'
                        ]})
    log_success(f'Log upload started. Waiting for upload to complete...')
    waiter = ssm.get_waiter('command_executed')
    waiter.wait(CommandId=command['Command']['CommandId'], InstanceId=instance_id_secret_searcher, WaiterConfig={'Delay':5, 'MaxAttempts':60})
    log_success(f'Log upload completed')


def execute_unique_files_processing_script(instance_id_secret_searcher, target_ami, region):
    """Execute the unique files processing script on the scanner instance"""
    ssm = boto3_session.client('ssm', region)

    region_to_use = s3_bucket_region if s3_bucket_region else boto3_session.region_name or 'us-east-1'

    # Execute the script on the instance with command-line arguments
    # The script will download the bloom filter directly from the unique files bucket
    # Also copy malware_scanner.py for malware scanning functionality
    command = ssm.send_command(
        InstanceIds=[instance_id_secret_searcher],
        DocumentName='AWS-RunShellScript',
        Parameters={'commands': [
            f'aws --region {region_to_use} s3 cp s3://{s3_bucket_name}/{process_unique_files_script_name} /home/ec2-user/process_unique_files.py',
            f'aws --region {region_to_use} s3 cp s3://{s3_bucket_name}/{malware_scanner_script_name} /home/ec2-user/malware_scanner.py',
            f'aws --region {region_to_use} s3 cp s3://{unique_files_bucket}/{bloom_filter_key} /home/ec2-user/bloom_filter.json',
            f'chmod +x /home/ec2-user/process_unique_files.py',
            f'chmod +x /home/ec2-user/malware_scanner.py',
            f'python3 /home/ec2-user/process_unique_files.py --target-ami {target_ami} --unique-files-bucket {unique_files_bucket} --s3-bucket-region {region_to_use}'
        ]}
    )
    
    log_success(f'Unique file processing started. Waiting for completion...')
    waiter = ssm.get_waiter('command_executed')
    waiter.wait(
        CommandId=command['Command']['CommandId'],
        InstanceId=instance_id_secret_searcher,
        WaiterConfig={'Delay': 15, 'MaxAttempts': 180}  # Increased timeout for file extraction
    )
    
    # Get command output
    output = ssm.get_command_invocation(
        CommandId=command['Command']['CommandId'],
        InstanceId=instance_id_secret_searcher
    )
    
    log_success(f'Unique file processing completed with status: {output["Status"]}')
    
    

def process_unique_files_with_remount(instance_id_secret_searcher, target_ami, region, volume_devices):
    """Process TSV file to find unique files, remount volumes, and upload actual files"""
    if not unique_files_bucket:
        log_warning('Unique files bucket not configured. Skipping unique file processing.')
        return

    log_success(f'Processing unique files for AMI {target_ami}...')

    # Execute the standalone script
    execute_unique_files_processing_script(instance_id_secret_searcher, target_ami, region)


def check_and_alert_malware_findings(target_ami, region):
    """
    Check S3 for malware findings and send Slack alert if critical/high findings detected.

    This function runs on the processor instance (which has Secrets Manager access)
    after the scanner uploads findings to S3.
    """
    import urllib.request

    s3 = boto3_session.client('s3', region_name=region)

    try:
        # Download findings from S3
        response = s3.get_object(
            Bucket=unique_files_bucket,
            Key=f'{target_ami}/malware_findings.json'
        )
        findings_data = json.loads(response['Body'].read().decode('utf-8'))
    except s3.exceptions.NoSuchKey:
        log_warning(f'No malware findings file for {target_ami}')
        return
    except Exception as e:
        log_error(f'Error reading malware findings: {e}')
        return

    # Check for critical/high findings
    findings = findings_data.get('findings', [])
    critical_high = [f for f in findings if f.get('severity') in ['CRITICAL', 'HIGH']]

    if not critical_high:
        log_success(f'No critical/high malware findings for {target_ami}')
        return

    log_warning(f'ALERT: {len(critical_high)} critical/high findings for {target_ami}!')

    # Get Slack webhook from Secrets Manager
    try:
        secrets = boto3_session.client('secretsmanager', region_name=region)
        webhook_data = json.loads(
            secrets.get_secret_value(SecretId='slack-webhook-malware-alerts')['SecretString']
        )
        webhook_url = webhook_data.get('webhook_url')
    except Exception as e:
        log_error(f'Could not get Slack webhook: {e}')
        return

    # Build and send Slack message
    critical = [f for f in critical_high if f['severity'] == 'CRITICAL']
    high = [f for f in critical_high if f['severity'] == 'HIGH']

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"Malware Detected: {target_ami}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{len(critical)} CRITICAL* | *{len(high)} HIGH*"}}
    ]

    for finding in critical_high[:5]:
        yara_rules = [m.get('rule', '?') for m in finding.get('yara_matches', [])]
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text":
                f"*[{finding['severity']}]* `{finding['file_path']}`\n"
                f"YARA: {yara_rules}\nClamAV: {finding.get('clamav_result', 'None')}"
            }
        })

    if len(critical_high) > 5:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"_...and {len(critical_high) - 5} more findings_"}
        })

    blocks.append({
        "type": "section",
        "text": {"type": "mrkdwn", "text": f"<https://s3.console.aws.amazon.com/s3/buckets/{unique_files_bucket}?prefix={target_ami}/|View in S3>"}
    })

    try:
        payload = json.dumps({"blocks": blocks}).encode('utf-8')
        req = urllib.request.Request(webhook_url, data=payload, headers={'Content-Type': 'application/json'})
        urllib.request.urlopen(req, timeout=10)
        log_success(f'Slack alert sent for {target_ami}')
    except Exception as e:
        log_error(f'Failed to send Slack alert: {e}')

def dig(args, session):
    global boto3_session
    boto3_session = session
    global s3_bucket_name
    if hasattr(args, 'bucket') and args.bucket:
        s3_bucket_name = args.bucket
    
    # Add unique files bucket configuration
    global unique_files_bucket
    if hasattr(args, 'unique_files_bucket') and args.unique_files_bucket:
        unique_files_bucket = args.unique_files_bucket
    
    region = args.region
    
    # Initialize variables to ensure they are defined for the finally block
    instance_id_secret_searcher = None
    volume_ids = []
    target_ami_obj = None # To store the result of get_ami
    instance_duplicator_details = None # To store result of start_instance_with_target_ami
    main_operation_success = False
    scan_start_time_for_logging = time.time() # Initialize early for broader scope if needed

    try:
        log_warning("If ran in an EC2 instance, make sure it has the required permissions to execute the tool")
        target_ami_obj = get_ami(args.ami_id, region)
        if not target_ami_obj: # get_ami calls exit() on failure, but as a safeguard
            log_error("Failed to retrieve AMI details. Aborting.")
            return # Should not be reached if get_ami exits

        # Check if unique files bucket is specified for bloom filter processing
        if unique_files_bucket:
            log_success(f'Unique files bucket configured: {unique_files_bucket}. Bloom filter will be downloaded directly by EC2 instance.')
        else:
            log_success('No unique files bucket specified. Skipping bloom filter processing.')

        # NEW WORKFLOW: Launch target first, detect its AZ, then launch Secret Searcher in same AZ
        # This ensures they're always in the same AZ regardless of VPC configuration

        # Step 1: Launch and prepare target instance
        log_success("Step 1: Launching target AMI instance...")
        instance_duplicator_details = start_instance_with_target_ami(target_ami_obj, region)
        stop_instance([instance_duplicator_details['instanceId']], region)

        # Step 2: Detach volumes and detect their AZ
        log_success("Step 2: Detaching volumes and detecting AZ...")
        ec2 = boto3_session.client('ec2', region)
        volumes = ec2.describe_volumes(Filters=[{'Name':'attachment.instance-id', 'Values':[instance_duplicator_details['instanceId']]}])
        volume_ids = [x['VolumeId'] for x in volumes['Volumes']]

        if not volume_ids:
            raise Exception("No volumes found attached to target instance")

        # Get the AZ from the first volume
        target_volume_az = volumes['Volumes'][0]['AvailabilityZone']
        log_success(f"Target instance volumes are in AZ: {target_volume_az}")

        # Detach the volumes
        for volume_id in volume_ids:
            log_success(f'Detaching volume {volume_id}...')
            ec2.detach_volume(VolumeId=volume_id)

        log_success("Waiting for all detached volumes to be in 'available' state...")
        all_available = False
        max_wait_time = 300
        start_time = time.time()
        while not all_available and (time.time() - start_time) < max_wait_time:
            volumes_status = ec2.describe_volumes(VolumeIds=volume_ids)
            all_available = all(vol['State'] == 'available' for vol in volumes_status['Volumes'])
            if not all_available:
                time.sleep(5)

        if not all_available:
            raise Exception("Volumes did not become available in time")
        log_success("All volumes are in 'available' state")

        # Terminate the target instance
        log_warning(f'Terminating instance {instance_duplicator_details["instanceId"]} created for target AMI...')
        ec2.terminate_instances(InstanceIds=[instance_duplicator_details['instanceId']])
        log_success('Instance terminated')

        # Step 3: Now launch Secret Searcher in the SAME AZ as the volumes
        log_success(f"Step 3: Launching Secret Searcher in AZ {target_volume_az} to match volumes...")
        instance_profile_arn_secret_searcher = get_instance_profile_secret_searcher(region)
        scanner_os = args.scanner_os if hasattr(args, 'scanner_os') else 'al2'  # Default to al2 for backwards compatibility
        instance_id_secret_searcher = create_secret_searcher(region, instance_profile_arn_secret_searcher, required_az=target_volume_az, scanner_os=scanner_os)

        # Step 4: Prepare Secret Searcher with scripts and tools
        log_success("Step 4: Preparing Secret Searcher with scanning tools...")
        create_s3_bucket(region)
        upload_script_to_bucket(scanning_script_name)

        # Upload the unique files processing script and malware scanner if bloom filter is configured
        if unique_files_bucket:
            upload_script_to_bucket(process_unique_files_script_name)
            upload_script_to_bucket(malware_scanner_script_name)

        is_windows = 'Platform' in target_ami_obj and target_ami_obj['Platform'].lower() == 'windows'
        if is_windows:
            upload_script_to_bucket(install_ntfs_3g_script_name)

        install_searching_tools(instance_id_secret_searcher, region, is_windows)

        # Step 5: Attach volumes to Secret Searcher
        log_success("Step 5: Attaching volumes to Secret Searcher...")
        for volume_id in volume_ids:
            device = devices[0]
            log_success(f'Attaching volume {volume_id} as device {device}')
            ec2.attach_volume(Device=device, InstanceId=instance_id_secret_searcher, VolumeId=volume_id)

            # Tag the volume for cleanup purposes
            try:
                ec2.create_tags(
                    Resources=[volume_id],
                    Tags=[
                        {'Key': 'CloudShovel', 'Value': 'true'},
                        {'Key': 'AMI', 'Value': instance_duplicator_details['ami']},
                        {'Key': 'ScannerInstance', 'Value': instance_id_secret_searcher},
                        {'Key': 'CreatedBy', 'Value': 'CloudShovel-Digger'},
                        {'Key': 'Purpose', 'Value': 'filesystem-scanning'}
                    ]
                )
                log_success(f'Tagged volume {volume_id} for cleanup identification')
            except Exception as e:
                log_warning(f'Failed to tag volume {volume_id}: {e}')

            devices.remove(device)
            in_use_devices[device] = instance_duplicator_details['ami']

        log_success("Waiting for volumes to be in 'in-use' state...")
        waiter = ec2.get_waiter('volume_in_use')
        waiter.wait(VolumeIds=volume_ids, WaiterConfig={'Delay':3, 'MaxAttempts':60})
        log_success('Volumes are ready to be searched')
        
        scan_start_time_for_logging = time.time() # More precise start time for digging duration
        start_digging_for_secrets(instance_id_secret_searcher, instance_duplicator_details['ami'], region)
        scan_duration = time.time() - scan_start_time_for_logging
        scan_minutes = int(scan_duration // 60)
        scan_seconds = int(scan_duration % 60)
        log_success(f'File scanning completed in {scan_minutes}m {scan_seconds}s')

        # If we've gotten this far, primary operations involving volumes are done or started.
        # Upload results before declaring main success
        upload_results(instance_id_secret_searcher, instance_duplicator_details['ami'], region)
        
        # Process unique files if configured
        if unique_files_bucket:
            # Get the volume devices that were used for this AMI
            volume_devices = []
            for in_use_device in in_use_devices.keys():
                if instance_duplicator_details['ami'] in in_use_devices[in_use_device]:
                    volume_devices.append(in_use_device)
            
            if volume_devices:
                process_unique_files_with_remount(instance_id_secret_searcher, instance_duplicator_details['ami'], region, volume_devices)
                # Check for malware findings and send Slack alert if needed (processor has Secrets Manager access)
                check_and_alert_malware_findings(instance_duplicator_details['ami'], region)
            else:
                log_warning('No volume devices found for unique file processing')
        
        main_operation_success = True

    except Exception as e:
        # Construct a more reliable ami_id for error logging
        ami_id_for_error_msg = args.ami_id
        if target_ami_obj and 'ImageId' in target_ami_obj:
            ami_id_for_error_msg = target_ami_obj['ImageId']
        elif instance_duplicator_details and 'ami' in instance_duplicator_details:
            ami_id_for_error_msg = instance_duplicator_details['ami']
        
        log_error(f'An unrecoverable error occurred during operations for AMI {ami_id_for_error_msg}.')
        log_error(f'Error details: {e}')
        # Try to upload the log file even if digging failed
        if instance_id_secret_searcher and (target_ami_obj or instance_duplicator_details):
            ami_id_for_log = None
            if target_ami_obj and 'ImageId' in target_ami_obj:
                ami_id_for_log = target_ami_obj['ImageId']
            elif instance_duplicator_details and 'ami' in instance_duplicator_details:
                ami_id_for_log = instance_duplicator_details['ami']
            if ami_id_for_log:
                try:
                    upload_mount_and_dig_log_only(instance_id_secret_searcher, ami_id_for_log, region)
                except Exception as log_e:
                    log_error(f"Failed to upload mount_and_dig.log in error handler: {log_e}")

    finally:
        log_warning(f"Entering finally block for AMI {args.ami_id}. Attempting resource cleanup.")

        current_ami_id_for_logging = args.ami_id
        if target_ami_obj and 'ImageId' in target_ami_obj:
            current_ami_id_for_logging = target_ami_obj['ImageId']
        elif instance_duplicator_details and 'ami' in instance_duplicator_details:
             current_ami_id_for_logging = instance_duplicator_details['ami']

        if main_operation_success:
            # This logging was previously in an 'else' block
            duration_seconds = int(time.time() - scan_start_time_for_logging)
            log_success(f"Total duration for AMI {current_ami_id_for_logging} (digging & upload): {duration_seconds} seconds")
            log_success(f'Scan finished. Check results in s3://{s3_bucket_name}/tsv/')
            if unique_files_bucket:
                log_success(f'Check unique files in s3://{unique_files_bucket}/unique-files/')
        else:
            log_warning(f"Main operations for AMI {current_ami_id_for_logging} did not complete successfully.")

        # 1. Attempt to delete volumes
        if volume_ids: # Check if volume_ids list was populated
            log_warning(f"Attempting to delete volumes in finally block: {volume_ids}")
            try:
                delete_volumes(volume_ids, region) # region is from dig's scope
            except Exception as vol_del_e:
                log_error(f"Error during delete_volumes in finally block: {vol_del_e}")
                log_error(f"Volumes {volume_ids} might be orphaned. Please check AWS console.")
        else:
            log_warning("No volume IDs were recorded; skipping volume deletion in finally block.")

        # 2. Attempt to cleanup the secret searcher instance
        # This uses instance_id_secret_searcher if available, otherwise falls back to tag-based cleanup (now corrected)
        log_warning(f"Attempting to cleanup secret searcher instance in finally block.")
        try:
            cleanup(region, instance_id=instance_id_secret_searcher) # Pass ID if we have it, else cleanup uses tags
        except Exception as cleanup_e:
            instance_id_msg = instance_id_secret_searcher if instance_id_secret_searcher else "tag-based lookup"
            log_error(f"Error during cleanup of secret searcher instance ({instance_id_msg}) in finally block: {cleanup_e}")
            log_error("Secret searcher instance may be orphaned. Please check AWS console.")
        
        log_warning(f"Cleanup process in finally block for AMI {args.ami_id} has concluded.")

if __name__ == '__main__':
    dig()
