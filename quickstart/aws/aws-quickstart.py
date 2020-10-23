#!/usr/bin/env python3

# Copyright (c) 2020 Teradici Corporation
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import base64
import datetime
import getpass
import importlib
import json
import os
import re
import shutil
import site
import subprocess
import sys
import textwrap
import time

REQUIRED_PACKAGES = {
    'boto3': None
}

AWS_CENTOS_AMI_URL = 'https://aws.amazon.com/marketplace/pp/B00O7WM7QW'

# Service Account ID of the service account to create
SA_ID       = 'cloud-access-manager'

iso_time = datetime.datetime.utcnow().isoformat(timespec='seconds').replace(':','').replace('-','') + 'Z'
DEPLOYMENT_NAME = 'quickstart_deployment_' + iso_time
CONNECTOR_NAME  = 'quickstart_cac_' + iso_time

# User entitled to workstations
ENTITLE_USER = 'Administrator'

HOME               = os.path.expanduser('~')
TERRAFORM_BIN_DIR  = f'{HOME}/bin'
TERRAFORM_BIN_PATH = TERRAFORM_BIN_DIR + '/terraform'
TERRAFORM_VER_PATH = '../../deployments/aws/single-connector/versions.tf'
CFG_FILE_PATH      = 'aws-quickstart.cfg'
POLICY_FILE_PATH   = 'aws-quickstart-policy.json'
DEPLOYMENT_PATH    = 'deployments/aws/single-connector'

# All of the following paths are relative to the deployment directory, DEPLOYMENT_PATH
TF_VARS_REF_PATH = 'terraform.tfvars.sample'
TF_VARS_PATH     = 'terraform.tfvars'
SECRETS_DIR      = 'secrets'
AWS_SA_KEY_PATH  = SECRETS_DIR + '/aws_service_account_credentials'
SSH_KEY_PATH     = SECRETS_DIR + '/cam_admin_id_rsa'
CAM_DEPLOYMENT_SA_KEY_PATH = SECRETS_DIR + '/cam_deployment_sa_key.json'

# Types of workstations
WS_TYPES = ['scent', 'gcent', 'swin', 'gwin']

next_steps = """
Next steps:

- Connect to a workstation:
  1. from a PCoIP client, connect to the Cloud Access Connector at {cac_public_ip}
  2. sign in with the "{entitle_user}" user credentials
  3. When connecting to a workstation immediately after this script completes,
     the workstation (especially graphics ones) may still be setting up. You may
     see "Remote Desktop is restarting..." in the client. Please wait a few
     minutes or reconnect if it times out.

- Clean up:
  1. Using AWS console, delete all workstations created by Cloud Access Manager
     web interface and manually created workstations. Resources not created by
     the Terraform scripts must be manually removed before Terraform can
     properly destroy resources it created.
  2. In a terminal, from the project's root directory (cloud_deployment_scripts),
     change directory using the command "cd {deployment_path}"
  3. Remove resources deployed by Terraform using the command "terraform destroy". Enter "yes" when prompted.
     "{terraform_path} destroy"
  4. Log in to https://cam.teradici.com and delete the deployment named
     "quickstart_deployment_<timestamp>"
"""


def ensure_requirements():
    ensure_required_packages()
    import_modules()
    ensure_aws_cli()
    ensure_aws_credentials()
    ensure_terraform()


def ensure_required_packages():
    """A function that ensures the correct version of Python packages are installed. 

    The function first checks if the required packages are installed. If a package is 
    installed, the required version number will then be checked. It will next prompt 
    the user to update or install the required packages.
    """

    packages_to_install_list = []

    for package, required_version in REQUIRED_PACKAGES.items():
        check_cmd = f'{sys.executable} -m pip show {package}'
        output = subprocess.run(check_cmd.split(' '), stdout=subprocess.PIPE).stdout.decode('utf-8')

        # If a package is not found, skip version checking and simply install the latest package
        if not output:
            packages_to_install_list.append(package)

        elif required_version is not None:
            # Second line outputs the version of the specified package
            current_version = output.splitlines()[1].split(' ')[-1]

            # Convert the string into a tuple of numbers for comparison
            current_version_tuple  = tuple( map(int, current_version.split('.')) )
            required_version_tuple = tuple( map(int, required_version.split('.')) )

            if current_version_tuple < required_version_tuple:
                packages_to_install_list.append(package)

    if packages_to_install_list:
        # Convert the list to a string of packages delimited by a space
        packages_to_install = " ".join(packages_to_install_list)
        install_cmd = f'{sys.executable} -m pip install --upgrade {packages_to_install} --user'

        install_permission = input(
            'One or more of the following Python packages are outdated or missing:\n'
            f'  {packages_to_install}\n\n'
            'The script can install these packages in the user\'s home directory using the following command:\n' 
            f'  {install_cmd}\n'
            'Proceed? (y/n)? ').strip().lower()

        if install_permission not in ('y', 'yes'):
            print('Python packages are required for deployment. Exiting...')
            sys.exit(1)

        subprocess.check_call(install_cmd.split(' '))

        # Refresh sys.path to detect new modules in user's home directory.
        importlib.reload(site)


def import_modules():
    """A function that dynamically imports required Python packages.
    """

    # Global calls for import statements are required to avoid module not found error
    import_required_packages = '''\
    import boto3
    from botocore.exceptions import ClientError

    sys.path.insert(1, '..')
    import cam

    sys.path.insert(2, '../../tools')
    import kms_secrets_encryption
    '''

    # Recommended to clear cache after installing python packages for dynamic imports
    importlib.invalidate_caches()

    exec(textwrap.dedent(import_required_packages), globals())

    print('Successfully imported required Python packages.')


def ensure_terraform():
    """A function that ensures the required Terraform version is installed. 

    The function first checks if the required Terraform version is installed in 
    the user's system. If Terraform is not installed, it will prompt the user to 
    install Terraform in the user's home directory. 
    """

    global TERRAFORM_BIN_PATH

    path = shutil.which('terraform')

    # Reference versions.tf file for the required version
    with open(TERRAFORM_VER_PATH,"r") as f:
        data = f.read()

    required_version = re.search(r'\">=\s([\d.]+)\"', data).group(1)

    if path:
        cmd = 'terraform -v'
        # Run the command 'terraform -v' and use the first line as the Terraform version
        terraform_version = subprocess.run(cmd.split(' '),  stdout=subprocess.PIPE).stdout.decode('utf-8').splitlines()[0]
        print(f'Found {terraform_version} in {path}.')

        # Use regex to parse the version number from string (i.e. 0.12.18)
        current_version = re.search(r'Terraform\s*v([\d.]+)', terraform_version).group(1)

        # Convert the string into a tuple of numbers for comparison
        current_version_tuple  = tuple( map(int, current_version.split('.')) )
        required_version_tuple = tuple( map(int, required_version.split('.')) )

        if current_version_tuple >= required_version_tuple:
            TERRAFORM_BIN_PATH = path
            return

    install_permission = input(
        f'This system is missing Terraform version >= {required_version}.\n'
        f'Proceed to download and install Terraform in {TERRAFORM_BIN_DIR} (y/n)? ').strip().lower()

    if install_permission not in ('y', 'yes'):
        print('Terraform is required for deployment. Exiting...\n')
        sys.exit(1)

    install_cmd = f'{sys.executable} ../install-terraform.py {TERRAFORM_BIN_DIR}'
    subprocess.run(install_cmd.split(' '), check=True)


def ensure_aws_cli():
    path = shutil.which('aws')
    
    if path:
        cmd = 'aws --version'

        # Command returns a string 'aws-cli/1.16.300 Python/2.7.18 Linux/4.14.186-146.268.amzn2.x86_64 botocore/1.13.36'
        # Stderr redirection is required as that's where the output of the command is printed out to
        output = subprocess.run(cmd.split(' '), stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        aws_cli_version = output.stdout.decode('utf-8').split(' ', 1)[0].split('/', 1)[1]
        print(f'Found AWS CLI {aws_cli_version} in {path}.')
        return

    #TODO Add install-aws-cli.py script similar to install-terraform.py if AWS CLI is not installed.

    print('AWS CLI not found. Please install and try again. Exiting...\n')
    sys.exit(1)


def ensure_aws_credentials():
    # Check that AWS credentials are valid
    sts = boto3.client('sts')
    try:
        sts.get_caller_identity()
        print("Found valid AWS credentials.")

    except ClientError:
        print('\nMissing valid AWS credentials.')
        print('Please run "aws configure" to configure account credentials.')
        print('See: https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html#cli-quick-configuration\n')
        sys.exit(1)


def quickstart_config_read(cfg_file):
    cfg_data = {}

    with open(cfg_file, 'r') as f:
        for line in f:
            if line[0] in ('#', '\n'):
                continue

            key, value = map(str.strip, line.split(':'))
            cfg_data[key] = value

    invalid_cfg_data = []

    if len(cfg_data.get('reg_code')) != 32:
        invalid_cfg_data.append('reg_code')

    if len(cfg_data.get('api_token')) != 1367:
        invalid_cfg_data.append('api_token')

    if invalid_cfg_data:
        print('Invalid configuration data entered.')
        print('Please ensure the following fields are entered correctly in aws-quickstart.cfg file:')
        for data in invalid_cfg_data:
            print('  ' + data)
        sys.exit(1)

    return cfg_data


def ad_password_get():
    txt = r'''
    Please enter a password for the Active Directory Administrator.

    Note Windows password complexity requirements:
    1. Must not contain user's account name or display name
    2. Must have 3 of the following categories:
       - A-Z
       - a-z
       - 0-9
       - special characters: (~!@#$%^&*_-+=`|\(){}[]:;"'<>,.?/)
       - unicode characters

    See: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements
    '''
    print(textwrap.dedent(txt))
    while True:
        password1 = getpass.getpass('Enter a password: ').strip()
        password2 = getpass.getpass('Re-enter the password: ').strip()

        if password1 == password2:
            print('')
            break

        print('The passwords do not match. Please try again.')

    return password1


def ssh_key_create(path):
    print('Creating SSH key...')

    # note the space after '-N' is required
    ssh_cmd = f'ssh-keygen -f {path} -t rsa -q -N '
    subprocess.run(ssh_cmd.split(' '), check=True)


def iam_user_use(username):
    print(f"Searching for IAM user '{username}'...")

    # Create IAM client
    iam = boto3.client('iam')
    iam_user = None

    try:
        iam_user = iam.get_user(UserName = username)
        print(f"Found IAM user '{username}'.")

    except ClientError as err:
        if err.response['Error']['Code'] == 'NoSuchEntity':
            print(f"IAM user '{username}' does not exist.")
        else:
            print("An exception occurred creating IAM user. Exiting...\n")
            raise SystemExit(err)

    except Exception as err:
        print("An exception occurred creating IAM user. Exiting...\n")
        raise SystemExit(err)

    finally:
        return iam_user


def iam_user_create(username):
    print(f"Creating IAM user '{username}'...")

    # Create IAM client
    iam = boto3.client('iam')
    iam_user = None

    try:
        iam_user = iam.create_user(UserName = username)
        print(f"Created IAM user '{username}'.")
        return iam_user

    except Exception as err:
        print("An exception occurred creating IAM user. Exiting...\n")
        raise SystemExit(err)


def iam_user_key_create(iam_user):
    # Create IAM client
    iam = boto3.client('iam')
    access_key = None
    username   = iam_user.get('User').get('UserName')

    print(f'Creating access key for IAM user {username}...')

    try:
        access_key = iam.create_access_key(UserName=username)

    except ClientError as err:
        if err.response['Error']['Code'] == 'LimitExceeded':
            print(f'Limit exceeded for AWS access keys to the IAM user {SA_ID}.')

            # List access keys through the pagination interface.
            paginator = iam.get_paginator('list_access_keys')
            access_key_id = None
            for response in paginator.paginate(UserName=SA_ID):
                access_key_list = response.get('AccessKeyMetadata')

                for access_key in access_key_list:
                    access_key_to_delete = access_key.get('AccessKeyId')

                    # Hide all access key characters except the last four
                    access_key_string = "".join(['*' for char in access_key_to_delete[:-4]]) + (access_key_to_delete[-4:])
                    print(f'Deleting access key: {access_key_string}')

                    # Delete an access key for the SA_ID username.
                    iam.delete_access_key(
                        UserName=SA_ID,
                        AccessKeyId=access_key_to_delete
                    )

            # Attempt to create access key again.
            access_key = iam.create_access_key(UserName=username)

        else:
            print("An exception occurred creating IAM user. Exiting...\n")
            raise SystemExit(err)

    except Exception as err:
        print("An exception occurred creating access key for IAM user. Exiting...\n")
        raise SystemExit(err)

    print(f"Created access key for {username}.")

    return access_key


def iam_user_key_file_create(access_key, filepath):
    print('Creating key file using access key data...')

    key_data = '''\
    [default]
    aws_access_key_id     = {access_key_id}
    aws_secret_access_key = {secret_access_key}
    '''

    key_data = key_data.format(
        access_key_id     = access_key.get('AccessKey').get('AccessKeyId'),
        secret_access_key = access_key.get('AccessKey').get('SecretAccessKey')
    )

    with open(filepath, 'w') as keyfile:
        keyfile.write(textwrap.dedent(key_data))

    print(f'  Key written to {filepath}')


def iam_policy_use_or_create(path):
    # Create IAM client
    iam = boto3.client('iam')
    sts = boto3.client('sts')

    policy_name = 'quickstart_policy'
    policy      = None
    policy_arn  = None

    with open(path) as json_file:
        quickstart_policy = json.load(json_file)

    try:
        policy = iam.create_policy(
            PolicyName=policy_name,
            PolicyDocument=json.dumps(quickstart_policy)
        )
        print(policy)
        policy_arn = policy.get('Policy').get('Arn')

    except ClientError as err:
        if err.response['Error']['Code'] == 'EntityAlreadyExists':
            print(f'IAM policy {policy_name} already exists. Using \'{policy_name}\'...')
            account_id = sts.get_caller_identity()['Account']
            policy_arn = f'arn:aws:iam::{account_id}:policy/{policy_name}'

        else:
            print("An exception occurred creating IAM policy. Exiting...\n")
            raise SystemExit(err)

    except Exception as err:
        print("An exception occurred creating IAM policy. Exiting...\n")
        raise SystemExit(err)

    finally:
        return policy_arn


def iam_policy_attach(policy_arn, iam_user):
    # Create IAM client
    iam = boto3.client('iam')

    username = iam_user.get('User').get('UserName')

    response = iam.attach_user_policy(
        UserName=username,
        PolicyArn=policy_arn
    )


# Creates a new .tfvar based on the .tfvar.sample file
def tf_vars_create(ref_file_path, tfvar_file_path, settings):

    if os.path.exists(tfvar_file_path):
        overwrite = input("Found an existing .tfvar file, overwrite (y/n)? ").strip().lower()
        if overwrite not in ('y', 'yes'):
            print(f'{tfvar_file_path} already exist. Exiting...')
            sys.exit(1)

    with open(ref_file_path, 'r') as ref_file, open(tfvar_file_path, 'w') as out_file:
        for line in ref_file:
            # Comments and blank lines are unchanged
            if line[0] in ('#', '\n'):
                out_file.write(line)
                continue

            key = line.split('=')[0].strip()
            try:
                out_file.write(f'{key} = "{settings[key]}"\n')
            except KeyError:
                # Remove file and error out
                os.remove(tfvar_file_path)
                print(f'Required value for {key} missing. tfvars file {tfvar_file_path} not created.')
                sys.exit(1)


def tf_vars_encrypt(tfvar_file_path):
    print('Encrypting secrets...')

    # cwd is /deployments/aws/single-connector
    tfvars_parser = kms_secrets_encryption.Tfvars_Parser(tfvar_file_path)
    tfvars_encryptor = kms_secrets_encryption.AWS_Tfvars_Encryptor(tfvars_parser)
    tfvars_encryptor.encrypt_tfvars_secrets()

    print('Done encrypting secrets.')


if __name__ == '__main__':
    ensure_requirements()

    cfg_data = quickstart_config_read(CFG_FILE_PATH)

    # Prompt user to subscribe to CentOS AMI
    if int(cfg_data.get('gcent')) > 0 or int(cfg_data.get('scent')) > 0:
        subscription_confirmation = input(
            f'\nThe deployment of CentOS remote workstations require a subscription to the AWS CentOS AMI.\n'
            f'Please visit {AWS_CENTOS_AMI_URL} and click on subscribe before continuing with this deployment.\n'
            f'Continue (y/n)? ').strip().lower()

        if subscription_confirmation not in ('y', 'yes'):
            print('AWS CentOS AMI subscription is required for deployment. Exiting...\n')
            sys.exit(1)

    password = ad_password_get()

    print('Preparing local requirements...')

    os.chdir('../../')
    os.chdir(DEPLOYMENT_PATH)
    # Paths passed into terraform.tfvars should be absolute paths
    cwd = os.getcwd() + '/'

    try:
        print(f'Creating directory {SECRETS_DIR} to store secrets...')
        os.mkdir(SECRETS_DIR, 0o700)
    except FileExistsError:
        print(f'Directory {SECRETS_DIR} already exist.')

    ssh_key_create(SSH_KEY_PATH)

    print('Local requirements setup complete.\n')

    print('Setting AWS project...')

    # Use or create new IAM user 'cloud-access-manager'
    iam_user = iam_user_use(SA_ID)
    if not iam_user:
        iam_user = iam_user_create(SA_ID)

    # Handle the access_key_id and secret_access_key pair creation
    iam_access_key = iam_user_key_create(iam_user)
    iam_user_key_file_create(iam_access_key, AWS_SA_KEY_PATH)

    # Use or create quickstart IAM policy and attach to the user
    iam_policy_arn = iam_policy_use_or_create('../../../quickstart/aws/' + POLICY_FILE_PATH)
    iam_policy_attach(iam_policy_arn, iam_user)

    # Newly created IAM access key needs to wait to avoid security token error
    #TODO Investigate if there is a better way to wait for IAM access key to be ready
    time.sleep(5)
    print('AWS setup complete.\n')

    print('Setting Cloud Access Manager...')
    mycam = cam.CloudAccessManager(cfg_data.get('api_token'))

    print(f'Creating deployment {DEPLOYMENT_NAME}...')
    deployment = mycam.deployment_create(DEPLOYMENT_NAME, cfg_data.get('reg_code'))
    #TODO: Use aws for power management instead of onprem in CAM

    print('Creating CAM API key...')
    cam_deployment_key = mycam.deployment_key_create(deployment)

    with open(CAM_DEPLOYMENT_SA_KEY_PATH, 'w+') as keyfile:
        keyfile.write(json.dumps(cam_deployment_key))

    print('  Key written to ' + CAM_DEPLOYMENT_SA_KEY_PATH)

    print('Cloud Access Manager setup complete.\n')

    print('Setting terraform.tfvars...\n')
    #TODO: refactor this to work with more types of deployments
    settings = {
        'aws_credentials_file':           cwd + AWS_SA_KEY_PATH,
        'aws_region':                     cfg_data.get('aws_region'),
        'dc_admin_password':              password,
        'safe_mode_admin_password':       password,
        'ad_service_account_password':    password,
        'admin_ssh_pub_key_file':         cwd + SSH_KEY_PATH + '.pub',
        'win_gfx_instance_count':         cfg_data.get('gwin'),
        'win_std_instance_count':         cfg_data.get('swin'),
        'centos_gfx_instance_count':      cfg_data.get('gcent'),
        'centos_std_instance_count':      cfg_data.get('scent'),
        'pcoip_registration_code':        cfg_data.get('reg_code'),
        'cam_deployment_sa_file':         cwd + CAM_DEPLOYMENT_SA_KEY_PATH
    }

    # update tfvars
    tf_vars_create(TF_VARS_REF_PATH, TF_VARS_PATH, settings)

    # encrypt tfvars
    tf_vars_encrypt(cwd + TF_VARS_PATH)

    print('Deploying with Terraform...')

    tf_cmd = 'terraform init'
    subprocess.run(tf_cmd.split(' '), check=True)

    tf_cmd = 'terraform apply -auto-approve'
    subprocess.run(tf_cmd.split(' '), check=True)

    comp_proc = subprocess.run(['terraform','output','cac-public-ip'],
                               check=True,
                               stdout=subprocess.PIPE)
    cac_public_ip = comp_proc.stdout.decode().split('"')[1]

    print('Terraform deployment complete.\n')

    # Add existing workstations
    #TODO: need to wait for CAM bug to be resolved for adding existing remote workstations to work
    for t in WS_TYPES:
        for i in range(int(cfg_data.get(t))):
            hostname = f'{t}-{i}'
            print(f'Adding "{hostname}" to Cloud Access Manager...')
            mycam.machine_add_existing(
                'aws',
                hostname,
                deployment
            )

    # Loop until Administrator user is found in CAM
    while True:
        entitle_user = mycam.user_get(ENTITLE_USER, deployment)
        if entitle_user:
            break

        print(f'Waiting for user "{ENTITLE_USER}" to be synced. Retrying in 10 seconds...')
        time.sleep(10)

    # Add entitlements for each workstation
    machines_list = mycam.machines_get(deployment)
    for machine in machines_list:
        print(f'Assigning workstation \"{machine["machineName"]}\" to user \"{ENTITLE_USER}\"...')
        mycam.entitlement_add(entitle_user, machine)

    print('\nQuickstart deployment finished.\n')

    #TODO: update 'next_steps' with 'Add additional workstations' if using aws instead of onprem for CAM
    print('')
    print(next_steps.format(cac_public_ip=cac_public_ip,
                            entitle_user=ENTITLE_USER,
                            deployment_path=DEPLOYMENT_PATH,
                            terraform_path=('terraform'
                            if TERRAFORM_BIN_PATH == shutil.which('terraform') 
                            else TERRAFORM_BIN_PATH)))
    print('')
