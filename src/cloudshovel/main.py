import argparse
import boto3
import botocore
from pyfiglet import figlet_format
from cloudshovel.utils.digger import dig, log_error, log_warning

def parse_args():
    parser = argparse.ArgumentParser()

    print(figlet_format('CloudShovel', font='rectangles'))

    print("Authors:")
    print("\t- Eduard Agavriloae / @saw_your_packet / hacktodef.com")
    print("\t- Matei Josephs / hivehack.tech\n")

    # Positional argument for AMI ID (without a flag)
    parser.add_argument("ami_id", help="AWS AMI ID to launch")

    # Global arguments
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument("--profile", help="AWS CLI profile name (Default is 'default')", default="default")
    auth_group.add_argument("--access-key", help="AWS Access Key ID (Default profile will be used if access keys not provided)")
    
    parser.add_argument("--secret-key", help="AWS Secret Access Key")
    parser.add_argument("--session-token", help="AWS Session Token (optional)")

    parser.add_argument("--region", help="AWS Region", default="us-east-1")

    parser.add_argument("--bucket", help="S3 Bucket name to upload and download auxiliary scripts (Bucket will be created if doesn't already exist in your account)", required=True)

    return parser.parse_args()

# Create the create_boto3_session function that first tries to create a session using the environment variables, and only if that fails does it look for the profile and then the args
def create_boto3_session(args):
    session_kwargs = {'region_name': args.region}

    if args.profile:
        session_kwargs['profile_name'] = args.profile
    elif args.access_key:
        if not args.secret_key:
            raise ValueError("Secret key must be provided with access key")
        session_kwargs['aws_access_key_id'] = args.access_key
        session_kwargs['aws_secret_access_key'] = args.secret_key
        if args.session_token:
            session_kwargs['aws_session_token'] = args.session_token

    try:
        session = boto3.Session()
        identity = session.client('sts').get_caller_identity()
        log_warning(f'The script will run using the identity {identity["Arn"]}')
        return session
    except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
        log_warning(f"Failed to create default boto3 session: {str(e)}")
        log_warning("Attempting to create session with provided credentials...")
        try:
            session = boto3.Session(**session_kwargs)
            print("Testing session with provided credentials...")
            identity = session.client('sts').get_caller_identity()
            print(identity)
            log_warning(f'The script will run using the identity {identity["Arn"]}')
            return session
        except (botocore.exceptions.ClientError, botocore.exceptions.NoCredentialsError) as e:
            log_error(f"Failed to create boto3 session with provided credentials: {str(e)}")
            exit()

def main():
    args = parse_args()

    print(f"AMI ID: {args.ami_id}")
    print(f"Region: {args.region}")
    print(f"Authentication method: { args.secret_key and args.access_key or args.profile}")
    
    session = create_boto3_session(args)
    
    dig(args, session)

if __name__ == '__main__':
    main()
    