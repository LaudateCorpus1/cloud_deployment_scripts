/*
 * Copyright (c) 2020 Teradici Corporation
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

variable "aws_credentials_file" {
    description = "Location of AWS credentials file"
    type        = string

    validation {
      condition = fileexists(var.aws_credentials_file)
      error_message = "The aws_credentials_file specified does not exist. Please check the file path."
    }
}

variable "aws_region" {
  description = "AWS region"
  default     = "us-west-1"
}

# "usw2-az4" failed to provision t2.xlarge EC2 instances in April 2020
# "use1-az3" failed to provision g4dn.xlarge Windows EC2 instances in April 2020
variable "az_id_exclude_list" {
  description = "List of Availability Zone IDs to exclude."
  default     = ["usw2-az4", "use1-az3"]
}

variable "prefix" {
  description = "Prefix to add to name of new resources. Must be <= 9 characters."
  default     = ""
}

variable "allowed_admin_cidrs" {
  description = "Open VPC firewall to allow ICMP, SSH, WinRM and RDP from these IP Addresses or CIDR ranges. e.g. ['a.b.c.d/32', 'e.f.g.0/24']"
  default     = []
}

variable "allowed_client_cidrs" {
  description = "Open VPC firewall to allow PCoIP connections from these IP Addresses or CIDR ranges. e.g. ['a.b.c.d/32', 'e.f.g.0/24']"
  default     = ["0.0.0.0/0"]
}

variable "admin_ssh_key_name" {
  description = "Name of Admin SSH Key"
  default     = "cas_admin"
}

variable "admin_ssh_pub_key_file" {
  description = "Admin SSH public key file"
  type        = string
  
  validation {
    condition = fileexists(var.admin_ssh_pub_key_file)
    error_message = "The admin_ssh_pub_key_file specified does not exist. Please check the file path."
  }
}

variable "vpc_name" {
  description = "Name for VPC containing the Cloud Access Software deployment"
  default     = "vpc-cas"
}

variable "vpc_cidr" {
  description = "CIDR for the VPC containing the CAS deployment"
  default     = "10.0.0.0/16" 
}

variable "dc_subnet_name" {
  description = "Name for subnet containing the Domain Controller"
  default     = "subnet-dc"
}

variable "dc_subnet_cidr" {
  description = "CIDR for subnet containing the Domain Controller"
  default     = "10.0.0.0/28"
}

variable "dc_private_ip" {
  description = "Static internal IP address for the Domain Controller"
  default     = "10.0.0.10"
}

variable "dc_instance_type" {
  description = "Instance type for the Domain Controller"
  default     = "t2.xlarge"
}

variable "dc_disk_size_gb" {
  description = "Disk size (GB) of the Domain Controller"
  default     = "50"
}

variable "dc_ami_owner" {
  description = "Owner of AMI for the Domain Controller"
  default     = "amazon"
}

variable "dc_ami_name" {
  description = "Name of the Windows AMI to create workstation from"
  default     = "Windows_Server-2019-English-Full-Base-2021.03.10"
}

variable "domain_name" {
  description = "Domain name for the new domain"
  default     = "example.com"

  /* validation notes:
      - the name is at least 2 levels and at most 3, as we have only tested up to 3 levels
  */
  validation {
    condition = (
      length(regexall("([.]local$)",var.domain_name)) == 0 &&
      length(var.domain_name) < 256 &&
      can(regex(
        "(^[A-Za-z0-9][A-Za-z0-9-]{0,13}[A-Za-z0-9][.])([A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9][.]){0,1}([A-Za-z]{2,}$)", 
        var.domain_name))
    )
    error_message = "Domain name is invalid. Please try again."
  }
}

variable "dc_admin_password" {
  description = "Password for the Administrator of the Domain Controller"
  type        = string
}

variable "safe_mode_admin_password" {
  description = "Safe Mode Admin Password (Directory Service Restore Mode - DSRM)"
  type        = string
}

variable "ad_service_account_username" {
  description = "Active Directory Service account name to be created"
  default     = "cas_admin"
}

variable "ad_service_account_password" {
  description = "Active Directory Service account password"
  type        = string
}

variable "domain_users_list" {
  description = "Active Directory users to create, in CSV format"
  type        = string
  default     = ""

  validation {
    condition = var.domain_users_list == "" ? true : fileexists(var.domain_users_list)
    error_message = "The domain_users_list file specified does not exist. Please check the file path."
  }
}

variable "lls_subnet_name" {
  description = "Name for subnet containing the PCoIP License Servers"
  default     = "subnet-lls"
}

variable "lls_subnet_cidr" {
  description = "CIDR for subnet containing the PCoIP License Servers"
  default     = "10.0.0.32/28"
}

variable "lls_subnet_ips" {
  description = "IP addresses used in the PCoIP License Server subnet"
  default = {
    haproxy_vip    = "10.0.0.40"
    haproxy_master = "10.0.0.41"
    haproxy_backup = "10.0.0.42"
    lls_main       = "10.0.0.43"
    lls_backup     = "10.0.0.44"
    subnet_mask    = "/28"
  }
}

variable "haproxy_instance_type" {
  description = "Instance type for the HAProxy"
  default     = "t2.medium"
}

variable "haproxy_disk_size_gb" {
  description = "Disk size (GB) of the HAProxy"
  default     = "10"
}

variable "haproxy_ami_owner" {
  description = "Owner of AMI for the HAProxy"
  default     = "125523088429"
}

variable "haproxy_ami_name" {
  description = "Name of the CentOS AMI to run HAProxy on"
  default     = "CentOS 8.2.2004 x86_64"
}

variable "lls_instance_type" {
  description = "Instance type for the PCoIP License Server"
  default     = "t2.medium"
}

variable "lls_disk_size_gb" {
  description = "Disk size (GB) of the PCoIP License Server"
  default     = "10"
}

variable "lls_ami_owner" {
  description = "Owner of AMI for the PCoIP License Server"
  default     = "aws-marketplace"
}

variable "lls_ami_name" {
  description = "Name of the CentOS AMI to run PCoIP License Server on"
  default     = "CentOS Linux 7 x86_64 HVM EBS ENA 2002*"
}

variable "lls_admin_password" {
  description = "Administrative password for the Teradici License Server"
  default     = ""
}

variable "lls_activation_code" {
  description = "Activation Code for PCoIP session licenses"
  default     = ""
}

variable "lls_license_count" {
  description = "Number of PCoIP session licenses to activate"
  default     = 0
}

variable "cas_mgr_subnet_name" {
  description = "Name for subnet containing the CAS Manager"
  default     = "subnet-cas-mgr"
}

variable "cas_mgr_subnet_cidr" {
  description = "CIDR for subnet containing the CAS Manager"
  default     = "10.0.0.16/28"
}

variable "cas_mgr_instance_type" {
  description = "Instance type for the CAS Manager"
  default     = "t2.xlarge"
}

variable "cas_mgr_disk_size_gb" {
  description = "Disk size (GB) of the CAS Manager"
  default     = "60"
}

variable "cas_mgr_ami_owner" {
  description = "Owner of AMI for the CAS Manager"
  default     = "aws-marketplace"
}

variable "cas_mgr_ami_product_code" {
  description = "Product Code of the AMI to create CAS Manager from"
  default     = "47k9ia2igxpcce2bzo8u3kj03"
}

variable "cas_mgr_admin_password" {
  description = "Password for the Administrator of CAS Manager"
  type        = string
}

variable "cas_mgr_aws_credentials_file" {
    description = "Location of AWS credentials file for CAS Manager"
    type        = string

    validation {
      condition = fileexists(var.cas_mgr_aws_credentials_file)
      error_message = "The cas_mgr_aws_credentials_file specified does not exist. Please check the file path."
    }
}

variable "cac_zone_list" {
  description = "Zones in which to deploy Connectors"
  type        = list(string)
}

variable "cac_subnet_name" {
  description = "Name for subnets containing the Cloud Access Connector"
  default     = "subnet-cac"
}

variable "cac_subnet_cidr_list" {
  description = "CIDRs for subnets containing the Cloud Access Connector"
  type        = list(string)
}

variable "cac_instance_count_list" {
  description = "Number of Cloud Access Connector instances to deploy in each region"
  type        = list(number)
}

variable "cac_instance_type" {
  description = "Instance type for the Cloud Access Connector"
  default     = "t2.xlarge"
}

variable "cac_disk_size_gb" {
  description = "Disk size (GB) of the Cloud Access Connector"
  default     = "50"
}

variable "cac_ami_owner" {
  description = "Owner of AMI for the Cloud Access Connector"
  default     = "099720109477"
}

variable "cac_ami_name" {
  description = "Name of the AMI to create Cloud Access Connector from"
  default = "ubuntu/images/hvm-ssd/ubuntu-bionic-18.04-amd64-server-20210325"
}

variable "cac_version" {
  description = "Version of the Cloud Access Connector to install"
  default     = "latest"
}

# Note the following limits for health check:
# interval_sec: min 5, max 300, default 30
# timeout_sec:  min 2, max 120, default 5
variable "cac_health_check" {
  description = "Health check configuration for Cloud Access Connector"
  default = {
    path         = "/pcoip-broker/xml"
    protocol     = "HTTPS"
    port         = 443
    interval_sec = 30
    timeout_sec  = 5
  }
}

variable "ssl_key" {
  description = "SSL private key for the Connector in PEM format"
  default     = ""

  validation {
    condition = var.ssl_key == "" ? true : fileexists(var.ssl_key)
    error_message = "The ssl_key file specified does not exist. Please check the file path."
  }
}

variable "ssl_cert" {
  description = "SSL certificate for the Connector in PEM format"
  default     = ""

  validation {
    condition = var.ssl_cert == "" ? true : fileexists(var.ssl_cert)
    error_message = "The ssl_cert file specified does not exist. Please check the file path."
  }
}

variable "cac_extra_install_flags" {
  description = "Additional flags for installing CAC"
  default     = ""
}

variable "pcoip_registration_code" {
  description = "PCoIP Registration code"
  type        = string
}

variable "teradici_download_token" {
  description = "Token used to download from Teradici"
  default     = "yj39yHtgj68Uv2Qf"
}

variable "ws_subnet_name" {
  description = "Name for subnet containing Remote Workstations"
  default     = "subnet-ws"
}

variable "ws_subnet_cidr" {
  description = "CIDR for subnet containing Remote Workstations"
  default     = "10.0.2.0/24"
}

variable "enable_workstation_public_ip" {
  description = "Enable public IP for Workstations"
  default     = false
}

variable "win_gfx_instance_count" {
  description = "Number of Windows Graphics Workstations"
  default     = 0
}

variable "win_gfx_instance_name" {
  description = "Name for Windows Graphics Workstations"
  default     = "gwin"
}

# G4s are Tesla T4s
# G3s are M60
variable "win_gfx_instance_type" {
  description = "Instance type for the Windows Graphics Workstations"
  default     = "g4dn.xlarge"
}

variable "win_gfx_disk_size_gb" {
  description = "Disk size (GB) of the Windows Graphics Workstations"
  default     = "50"
}

variable "win_gfx_ami_owner" {
  description = "Owner of AMI for the Windows Graphics Workstations"
  default     = "amazon"
}

variable "win_gfx_ami_name" {
  description = "Name of the Windows AMI to create workstation from"
  default     = "Windows_Server-2019-English-Full-Base-2021.03.10"
}

variable "win_gfx_pcoip_agent_version" {
  description = "Version of PCoIP Agent to install for Windows Graphics Workstations"
  default     = "latest"
}

variable "win_std_instance_count" {
  description = "Number of Windows Standard Workstations"
  default     = 0
}

variable "win_std_instance_name" {
  description = "Name for Windows Standard Workstations"
  default     = "swin"
}

variable "win_std_instance_type" {
  description = "Instance type for the Windows Standard Workstations"
  default     = "t2.xlarge"
}

variable "win_std_disk_size_gb" {
  description = "Disk size (GB) of the Windows Standard Workstations"
  default     = "50"
}

variable "win_std_ami_owner" {
  description = "Owner of AMI for the Windows Standard Workstations"
  default     = "amazon"
}

variable "win_std_ami_name" {
  description = "Name of the Windows AMI to create workstation from"
  default     = "Windows_Server-2019-English-Full-Base-2021.03.10"
}

variable "win_std_pcoip_agent_version" {
  description = "Version of PCoIP Agent to install for Windows Standard Workstations"
  default     = "latest"
}

variable "centos_gfx_instance_count" {
  description = "Number of CentOS Graphics Workstations"
  default     = 0
}

variable "centos_gfx_instance_name" {
  description = "Name for CentOS Graphics Workstations"
  default     = "gcent"
}

# G4s are Tesla T4s
# G3s are M60
variable "centos_gfx_instance_type" {
  description = "Instance type for the CentOS Graphics Workstations"
  default     = "g4dn.xlarge"
}

variable "centos_gfx_disk_size_gb" {
  description = "Disk size (GB) of the CentOS Graphics Workstations"
  default     = "50"
}

variable "centos_gfx_ami_owner" {
  description = "Owner of AMI for the CentOS Graphics Workstations"
  default     = "aws-marketplace"
}

variable "centos_gfx_ami_product_code" {
  description = "Product Code of the AMI for the CentOS Graphics Workstation"
  default     = "aw0evgkw8e5c1q413zgy5pjce"
}

variable "centos_gfx_ami_name" {
  description = "Name of the CentOS AMI to create workstation from"
  default     = "CentOS Linux 7 x86_64 HVM EBS ENA 2002*"
}

variable "centos_std_instance_count" {
  description = "Number of CentOS Standard Workstations"
  default     = 0
}

variable "centos_std_instance_name" {
  description = "Name for CentOS Standard Workstations"
  default     = "scent"
}

variable "centos_std_instance_type" {
  description = "Instance type for the CentOS Standard Workstations"
  default     = "t2.xlarge"
}

variable "centos_std_disk_size_gb" {
  description = "Disk size (GB) of the CentOS Standard Workstations"
  default     = "50"
}

variable "centos_std_ami_owner" {
  description = "Owner of AMI for the CentOS Standard Workstations"
  default     = "aws-marketplace"
}

variable "centos_std_ami_product_code" {
  description = "Product Code of the AMI for the CentOS Standard Workstation"
  default     = "aw0evgkw8e5c1q413zgy5pjce"
}

variable "centos_std_ami_name" {
  description = "Name of the CentOS AMI to create workstation from"
  default     = "CentOS Linux 7 x86_64 HVM EBS ENA 2002*"
}

variable "customer_master_key_id" {
  description = "The ID of the AWS KMS Customer Master Key used to decrypt secrets"
  default     = ""
}
