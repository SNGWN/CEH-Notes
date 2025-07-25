# Cloud Computing Security - Topics Overview

## Topic Explanation
Cloud computing security involves protecting cloud infrastructure, services, and data from various threats and vulnerabilities. This includes securing Infrastructure as a Service (IaaS), Platform as a Service (PaaS), and Software as a Service (SaaS) environments. Common security challenges include data breaches, account hijacking, insider threats, insecure APIs, insufficient due diligence, shared technology vulnerabilities, and data loss. The module covers cloud security assessment techniques, misconfigurations, and attack vectors specific to major cloud providers like AWS, Azure, and Google Cloud.

## Articles for Further Reference
- [NIST Cloud Computing Security](https://csrc.nist.gov/publications/detail/sp/800-144/final)
- [Cloud Security Alliance (CSA) Guidelines](https://cloudsecurityalliance.org/)
- [OWASP Cloud Security](https://owasp.org/www-project-cloud-security/)

## Reference Links
- [AWS Security Best Practices](https://aws.amazon.com/security/security-learning/)
- [Azure Security Documentation](https://docs.microsoft.com/en-us/azure/security/)
- [Google Cloud Security](https://cloud.google.com/security)

## Available Tools for the Topic

### Tool Name: ScoutSuite
**Description:** Multi-cloud security auditing tool for AWS, Azure, Google Cloud, and other cloud providers.

**Example Usage:**
```bash
# Install ScoutSuite
pip install scoutsuite

# AWS assessment
scout aws --profile default

# Azure assessment
scout azure --cli

# Google Cloud assessment
scout gcp --service-account service-account.json
```

### Tool Name: CloudMapper
**Description:** AWS security assessment tool that visualizes and analyzes cloud infrastructure.

**Example Usage:**
```bash
# Install CloudMapper
git clone https://github.com/duo-labs/cloudmapper.git
cd cloudmapper && pip install -r requirements.txt

# Collect AWS data
python cloudmapper.py collect --account-name demo

# Generate report
python cloudmapper.py report --account-name demo
```

## All Possible Payloads for Manual Approach

### AWS Security Assessment
```bash
# AWS CLI enumeration
aws sts get-caller-identity
aws s3 ls
aws iam list-users
aws ec2 describe-instances
aws rds describe-db-instances

# S3 bucket enumeration
aws s3 ls s3://bucket-name --no-sign-request
aws s3 sync s3://bucket-name . --no-sign-request

# IAM policy analysis
aws iam get-policy --policy-arn arn:aws:iam::123456789:policy/policy-name
aws iam list-attached-user-policies --user-name username
```

### Azure Security Assessment
```bash
# Azure CLI enumeration
az account show
az group list
az vm list
az storage account list

# Azure AD enumeration
az ad user list
az role assignment list
```

## Example Payloads

### Cloud Security Assessment Tool
```python
#!/usr/bin/env python3
import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError

class CloudSecurityAssessment:
    def __init__(self):
        self.vulnerabilities = []
        self.findings = {}
    
    def assess_aws_security(self):
        """Perform AWS security assessment"""
        print("Starting AWS security assessment...")
        
        try:
            # Initialize AWS clients
            self.iam_client = boto3.client('iam')
            self.s3_client = boto3.client('s3')
            self.ec2_client = boto3.client('ec2')
            
            # Check IAM security
            self.check_iam_security()
            
            # Check S3 security
            self.check_s3_security()
            
            # Check EC2 security
            self.check_ec2_security()
            
        except NoCredentialsError:
            print("AWS credentials not configured")
        except Exception as e:
            print(f"Error during AWS assessment: {e}")
    
    def check_iam_security(self):
        """Check IAM security configurations"""
        print("Checking IAM security...")
        
        try:
            # Check for root account usage
            account_summary = self.iam_client.get_account_summary()
            if account_summary['SummaryMap'].get('AccountAccessKeysPresent', 0) > 0:
                self.vulnerabilities.append("Root account has access keys")
            
            # Check password policy
            try:
                password_policy = self.iam_client.get_account_password_policy()
                policy = password_policy['PasswordPolicy']
                
                if not policy.get('RequireUppercaseCharacters', False):
                    self.vulnerabilities.append("Password policy doesn't require uppercase")
                
                if policy.get('MinimumPasswordLength', 0) < 8:
                    self.vulnerabilities.append("Password minimum length is less than 8")
                    
            except ClientError:
                self.vulnerabilities.append("No password policy configured")
            
            # Check for users with admin privileges
            users = self.iam_client.list_users()['Users']
            for user in users:
                policies = self.iam_client.list_attached_user_policies(UserName=user['UserName'])
                for policy in policies['AttachedPolicies']:
                    if 'Admin' in policy['PolicyName']:
                        self.vulnerabilities.append(f"User {user['UserName']} has admin privileges")
        
        except ClientError as e:
            print(f"IAM check failed: {e}")
    
    def check_s3_security(self):
        """Check S3 bucket security"""
        print("Checking S3 security...")
        
        try:
            buckets = self.s3_client.list_buckets()['Buckets']
            
            for bucket in buckets:
                bucket_name = bucket['Name']
                
                # Check public read access
                try:
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl['Grants']:
                        grantee = grant.get('Grantee', {})
                        if grantee.get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                            self.vulnerabilities.append(f"S3 bucket {bucket_name} allows public read")
                except ClientError:
                    pass
                
                # Check encryption
                try:
                    encryption = self.s3_client.get_bucket_encryption(Bucket=bucket_name)
                except ClientError:
                    self.vulnerabilities.append(f"S3 bucket {bucket_name} not encrypted")
                
                # Check versioning
                try:
                    versioning = self.s3_client.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        self.vulnerabilities.append(f"S3 bucket {bucket_name} versioning disabled")
                except ClientError:
                    pass
        
        except ClientError as e:
            print(f"S3 check failed: {e}")
    
    def check_ec2_security(self):
        """Check EC2 security configurations"""
        print("Checking EC2 security...")
        
        try:
            # Check security groups
            security_groups = self.ec2_client.describe_security_groups()['SecurityGroups']
            
            for sg in security_groups:
                for rule in sg['IpPermissions']:
                    for ip_range in rule.get('IpRanges', []):
                        if ip_range.get('CidrIp') == '0.0.0.0/0':
                            port_range = f"{rule.get('FromPort', 'All')}-{rule.get('ToPort', 'All')}"
                            self.vulnerabilities.append(
                                f"Security group {sg['GroupName']} allows access from 0.0.0.0/0 on ports {port_range}"
                            )
            
            # Check instances
            instances = self.ec2_client.describe_instances()
            for reservation in instances['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] == 'running':
                        # Check if instance has public IP
                        if instance.get('PublicIpAddress'):
                            self.vulnerabilities.append(
                                f"EC2 instance {instance['InstanceId']} has public IP"
                            )
        
        except ClientError as e:
            print(f"EC2 check failed: {e}")
    
    def check_public_s3_buckets(self, bucket_list):
        """Check for publicly accessible S3 buckets"""
        print("Checking for public S3 buckets...")
        
        for bucket_name in bucket_list:
            try:
                # Try to list bucket contents without authentication
                import requests
                url = f"https://{bucket_name}.s3.amazonaws.com/"
                response = requests.get(url, timeout=5)
                
                if response.status_code == 200:
                    self.vulnerabilities.append(f"Public S3 bucket found: {bucket_name}")
                    
                    # Try to list objects
                    if "Contents" in response.text or "Key" in response.text:
                        self.vulnerabilities.append(f"S3 bucket {bucket_name} contents are listable")
            except:
                pass
    
    def generate_cloud_security_report(self):
        """Generate comprehensive cloud security report"""
        print("\n" + "="*70)
        print("CLOUD SECURITY ASSESSMENT REPORT")
        print("="*70)
        
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        
        if self.vulnerabilities:
            print("\nSecurity Issues:")
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"{i}. {vuln}")
        
        print("\nSecurity Recommendations:")
        recommendations = [
            "Enable MFA for all IAM users",
            "Implement least privilege access",
            "Enable CloudTrail logging",
            "Encrypt data at rest and in transit",
            "Regular security assessments",
            "Implement network segmentation",
            "Monitor for unauthorized access",
            "Backup and disaster recovery planning"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"{i}. {rec}")
        
        # Generate JSON report
        report = {
            "assessment_type": "cloud_security",
            "vulnerabilities": self.vulnerabilities,
            "recommendations": recommendations,
            "total_issues": len(self.vulnerabilities)
        }
        
        with open('cloud_security_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\nDetailed report saved to: cloud_security_report.json")

# Example usage
assessment = CloudSecurityAssessment()
assessment.assess_aws_security()

# Test common public buckets
common_buckets = [
    "backup", "logs", "data", "files", "documents",
    "images", "uploads", "temp", "test", "dev"
]
assessment.check_public_s3_buckets(common_buckets)
assessment.generate_cloud_security_report()
```