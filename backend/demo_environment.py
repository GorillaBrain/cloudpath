"""
Northstar Financial Technologies — Realistic Enterprise AWS Demonstration Environment.
Contains IAM Users, IAM Roles, IAM Groups, Managed & Inline Policies, S3 Buckets,
EC2 Instances, Security Groups, VPCs, and External Principals.
All findings and attack paths are dynamically discovered by the CloudPath analysis engine.
"""

from __future__ import annotations
from typing import Any


def get_northstar_demo_environment() -> dict[str, Any]:
    return {
        "organization": "Northstar Financial Technologies",
        "account_id": "492018472910",
        "region": "us-east-1",
        "provider": "aws",
        "assets": [
            # 1. IAM Users
            {
                "id": "arn:aws:iam::492018472910:user/ci-deploy-assistant",
                "name": "ci-deploy-assistant",
                "type": "IAMUser",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "medium",
                "groups": ["arn:aws:iam::492018472910:group/DevOpsAutomationGroup"],
                "attached_policies": [
                    "arn:aws:iam::492018472910:policy/NorthstarCIBuildPolicy"
                ],
                "tags": {"Team": "Platform-Engineering", "AccessKeyAgeDays": "214"},
            },
            {
                "id": "arn:aws:iam::492018472910:user/contractor-analytics-ro",
                "name": "contractor-analytics-ro",
                "type": "IAMUser",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "low",
                "attached_policies": [
                    "arn:aws:iam::492018472910:policy/AnalyticsAssumeRolePolicy"
                ],
                "tags": {"Vendor": "ApexDataConsultants", "MFAEnabled": "false"},
            },
            {
                "id": "arn:aws:iam::492018472910:user/legacy-migration-admin",
                "name": "legacy-migration-admin",
                "type": "IAMUser",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "high",
                "attached_policies": [
                    "arn:aws:iam::aws:policy/AdministratorAccess"
                ],
                "tags": {"LastUsedDaysAgo": "188", "Status": "OrphanedAccount"},
            },
            # 2. IAM Group
            {
                "id": "arn:aws:iam::492018472910:group/DevOpsAutomationGroup",
                "name": "DevOpsAutomationGroup",
                "type": "IAMGroup",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "medium",
                "attached_policies": [
                    "arn:aws:iam::492018472910:policy/WorkloadComputePassRolePolicy"
                ],
            },
            # 3. IAM Policies
            {
                "id": "arn:aws:iam::492018472910:policy/NorthstarCIBuildPolicy",
                "name": "NorthstarCIBuildPolicy",
                "type": "IAMPolicy",
                "provider": "aws",
                "service": "iam",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "ArtifactUploadAndECR",
                            "Effect": "Allow",
                            "Action": [
                                "ecr:GetAuthorizationToken",
                                "ecr:BatchCheckLayerAvailability",
                                "s3:PutObject",
                                "s3:GetObject"
                            ],
                            "Resource": "arn:aws:s3:::northstar-public-marketing-assets/*",
                        }
                    ],
                },
            },
            {
                "id": "arn:aws:iam::492018472910:policy/WorkloadComputePassRolePolicy",
                "name": "WorkloadComputePassRolePolicy",
                "type": "IAMPolicy",
                "provider": "aws",
                "service": "iam",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PassAnyRoleAndLaunchCompute",
                            "Effect": "Allow",
                            "Action": [
                                "iam:PassRole",
                                "ec2:RunInstances",
                                "lambda:CreateFunction",
                                "lambda:InvokeFunction"
                            ],
                            "Resource": "*",
                        }
                    ],
                },
            },
            {
                "id": "arn:aws:iam::492018472910:policy/AnalyticsAssumeRolePolicy",
                "name": "AnalyticsAssumeRolePolicy",
                "type": "IAMPolicy",
                "provider": "aws",
                "service": "iam",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowAssumeDataPipelineRole",
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::492018472910:role/DataLakeIngestionRole",
                        }
                    ],
                },
            },
            {
                "id": "arn:aws:iam::aws:policy/AdministratorAccess",
                "name": "AdministratorAccess",
                "type": "IAMPolicy",
                "provider": "aws",
                "service": "iam",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "FullWildcardAdmin",
                            "Effect": "Allow",
                            "Action": "*",
                            "Resource": "*",
                        }
                    ],
                },
            },
            # 4. IAM Roles
            {
                "id": "arn:aws:iam::492018472910:role/ProdSettlementInstanceRole",
                "name": "ProdSettlementInstanceRole",
                "type": "IAMRole",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "critical",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "EC2AndLambdaTrust",
                            "Effect": "Allow",
                            "Principal": {
                                "Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
                            },
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                "inline_policies": [
                    {
                        "name": "SettlementVaultFullAccess",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "FullAccessToCoreVaultAndKMS",
                                    "Effect": "Allow",
                                    "Action": ["s3:*", "kms:Decrypt", "secretsmanager:GetSecretValue"],
                                    "Resource": [
                                        "arn:aws:s3:::northstar-pci-cardholder-vault",
                                        "arn:aws:s3:::northstar-pci-cardholder-vault/*",
                                        "arn:aws:secretsmanager:us-east-1:492018472910:secret:prod/swift-signing-key"
                                    ],
                                }
                            ],
                        },
                    }
                ],
            },
            {
                "id": "arn:aws:iam::492018472910:role/DataLakeIngestionRole",
                "name": "DataLakeIngestionRole",
                "type": "IAMRole",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "high",
                "trust_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "InternalAnalyticsUserTrust",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::492018472910:user/contractor-analytics-ro"
                            },
                            "Action": "sts:AssumeRole",
                        },
                        {
                            "Sid": "ThirdPartyVendorAccountTrustWithoutExternalId",
                            "Effect": "Allow",
                            "Principal": {
                                "AWS": "arn:aws:iam::998877665544:root"
                            },
                            "Action": "sts:AssumeRole",
                        },
                    ],
                },
                "inline_policies": [
                    {
                        "name": "DataPipelineSelfManageAndS3",
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Sid": "ExcessiveIAMPolicyModification",
                                    "Effect": "Allow",
                                    "Action": [
                                        "iam:CreatePolicyVersion",
                                        "iam:AttachRolePolicy",
                                        "s3:GetObject",
                                        "s3:ListBucket"
                                    ],
                                    "Resource": "*",
                                }
                            ],
                        },
                    }
                ],
            },
            # 5. External Principal
            {
                "id": "arn:aws:iam::998877665544:root",
                "name": "External Vendor AWS Account (998877665544)",
                "type": "ExternalPrincipal",
                "provider": "aws",
                "service": "sts",
                "is_public": True,
                "sensitivity": "high",
                "tags": {"Partner": "ExternalTelemetrySaaS", "ExternalIdRequired": "false"},
            },
            # 6. VPC & Security Group & EC2 Instance
            {
                "id": "vpc-0a1b2c3d4e5f60001",
                "name": "northstar-prod-core-vpc",
                "type": "VPC",
                "provider": "aws",
                "service": "vpc",
                "is_public": False,
                "sensitivity": "high",
                "network_config": {"cidr_block": "10.24.0.0/16", "flow_logs": True},
            },
            {
                "id": "sg-09988776655443322",
                "name": "settlement-bastion-sg",
                "type": "SecurityGroup",
                "provider": "aws",
                "service": "ec2",
                "is_public": True,
                "sensitivity": "high",
                "network_config": {
                    "vpc_id": "vpc-0a1b2c3d4e5f60001",
                    "ingress_rules": [
                        {"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0", "description": "World-open SSH"},
                        {"port": 443, "protocol": "tcp", "cidr": "0.0.0.0/0", "description": "HTTPS"},
                    ],
                },
            },
            {
                "id": "i-0f9e8d7c6b5a43210",
                "name": "prod-settlement-worker-01",
                "type": "EC2Instance",
                "provider": "aws",
                "service": "ec2",
                "is_public": True,
                "sensitivity": "critical",
                "associated_identity": "arn:aws:iam::492018472910:role/ProdSettlementInstanceRole",
                "network_config": {
                    "vpc_id": "vpc-0a1b2c3d4e5f60001",
                    "security_groups": ["sg-09988776655443322"],
                    "public_ip": "54.209.118.42",
                    "imdsv1_enabled": True,
                },
            },
            # 7. S3 Buckets & Sensitive Resources
            {
                "id": "arn:aws:s3:::northstar-pci-cardholder-vault",
                "name": "northstar-pci-cardholder-vault",
                "type": "S3Bucket",
                "provider": "aws",
                "service": "s3",
                "is_public": False,
                "sensitivity": "critical",
                "tags": {"DataClassification": "PCI-DSS-Level-1", "ContainsPII": "true"},
            },
            {
                "id": "arn:aws:s3:::northstar-public-marketing-assets",
                "name": "northstar-public-marketing-assets",
                "type": "S3Bucket",
                "provider": "aws",
                "service": "s3",
                "is_public": True,
                "sensitivity": "medium",
                "resource_policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "PublicReadGetObjectAndPut",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": "arn:aws:s3:::northstar-public-marketing-assets/*",
                        }
                    ],
                },
                "tags": {"DataClassification": "Public-Web", "BlockPublicAccess": "false"},
            },
            {
                "id": "arn:aws:secretsmanager:us-east-1:492018472910:secret:prod/swift-signing-key",
                "name": "prod/swift-signing-key",
                "type": "SensitiveResource",
                "provider": "aws",
                "service": "secretsmanager",
                "is_public": False,
                "sensitivity": "critical",
                "tags": {"DataClassification": "Critical-Financial-Signing-Key"},
            },
        ],
    }
