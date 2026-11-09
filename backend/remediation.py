"""
Module F & G: MITRE ATT&CK Cloud Matrix Mapping & Actionable Remediation Intelligence.
Provides least-privilege before/after configuration diffs, operational impact analysis,
and MITRE ATT&CK Cloud technique mappings while strictly distinguishing static configuration
weaknesses from observed adversary behavior.
"""

from __future__ import annotations
import json
from typing import Any
from backend.models import MitreTechnique, RemediationGuidance


MITRE_CLOUD_CATALOG: dict[str, MitreTechnique] = {
    "T1078.004": MitreTechnique(
        technique_id="T1078.004",
        tactic="Initial Access / Privilege Escalation",
        name="Valid Accounts: Cloud Accounts",
        url="https://attack.mitre.org/techniques/T1078/004/",
        mapping_note="Configuration weakness enables abuse if cloud identity credentials or roles are compromised (Not an observed intrusion).",
    ),
    "T1098.001": MitreTechnique(
        technique_id="T1098.001",
        tactic="Persistence / Privilege Escalation",
        name="Account Manipulation: Additional Cloud Credentials",
        url="https://attack.mitre.org/techniques/T1098/001/",
        mapping_note="Policy allows iam:CreatePolicyVersion / iam:AttachRolePolicy / iam:PassRole which could permit privilege escalation.",
    ),
    "T1098.003": MitreTechnique(
        technique_id="T1098.003",
        tactic="Privilege Escalation",
        name="Account Manipulation: Additional Cloud Roles",
        url="https://attack.mitre.org/techniques/T1098/003/",
        mapping_note="Role assumption or PassRole configuration enables lateral or vertical movement across IAM roles.",
    ),
    "T1199": MitreTechnique(
        technique_id="T1199",
        tactic="Initial Access",
        name="Trusted Relationship",
        url="https://attack.mitre.org/techniques/T1199/",
        mapping_note="Cross-account trust policy allows external AWS account principal without sts:ExternalId or MFA constraints.",
    ),
    "T1530": MitreTechnique(
        technique_id="T1530",
        tactic="Collection",
        name="Data from Cloud Storage Object",
        url="https://attack.mitre.org/techniques/T1530/",
        mapping_note="Attack path terminates at an S3 bucket or Secrets Manager secret accessible via evaluated permissions or public policy.",
    ),
    "T1190": MitreTechnique(
        technique_id="T1190",
        tactic="Initial Access",
        name="Exploit Public-Facing Application / Network Service",
        url="https://attack.mitre.org/techniques/T1190/",
        mapping_note="Security group exposes management port (0.0.0.0/0) on public-facing compute instance with attached IAM role.",
    ),
}


def build_remediation_for_rule(
    rule_id: str,
    resource_name: str,
    before_obj: dict[str, Any] | None = None,
) -> RemediationGuidance:
    before_str = json.dumps(before_obj, indent=2) if before_obj else "{}"

    if rule_id == "CP-IAM-001":  # Wildcard / Excessive Admin Permissions
        suggested = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "LeastPrivilegeScopedAccess",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [
                        f"arn:aws:s3:::{resource_name}-scoped-bucket",
                        f"arn:aws:s3:::{resource_name}-scoped-bucket/*",
                    ],
                }
            ],
        }
        return RemediationGuidance(
            title="Replace Wildcard (*:*) Permissions with Scoped Least-Privilege Statements",
            summary=f"Remove full administrative wildcard permissions from '{resource_name}' and scope actions to explicit ARNs.",
            why_it_matters="Wildcard actions ('*') combined with Resource '*' grant unrestricted control over the AWS account, allowing immediate privilege escalation and data exfiltration if compromised.",
            operational_impact="Workloads relying on implicit administrative permissions must be audited via AWS CloudTrail Access Advisor before applying scoped ARNs.",
            priority="P1 — Immediate (Critical)",
            before_config=before_str,
            suggested_config=json.dumps(suggested, indent=2),
        )

    if rule_id == "CP-IAM-002":  # iam:PassRole + Execution Escalation
        suggested = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "RestrictPassRoleToApprovedWorkloadRoleOnly",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::492018472910:role/ApprovedNonPrivilegedWorkerRole",
                    "Condition": {
                        "StringEquals": {
                            "iam:PassedToService": ["ec2.amazonaws.com", "lambda.amazonaws.com"]
                        }
                    },
                }
            ],
        }
        return RemediationGuidance(
            title="Constrain iam:PassRole with Explicit Role ARNs and iam:PassedToService Condition",
            summary=f"Restrict '{resource_name}' from passing high-privilege roles to EC2 or Lambda compute instances.",
            why_it_matters="An identity with both iam:PassRole on '*' and ec2:RunInstances or lambda:CreateFunction can attach a privileged IAM role to a new compute workload and execute arbitrary commands under that role's identity.",
            operational_impact="CI/CD pipelines will only be permitted to pass explicitly allow-listed workload roles to designated AWS services.",
            priority="P1 — Immediate (Critical)",
            before_config=before_str,
            suggested_config=json.dumps(suggested, indent=2),
        )

    if rule_id == "CP-IAM-003":  # Policy Modification Escalation
        suggested = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "DenyDirectIAMPolicyMutation",
                    "Effect": "Deny",
                    "Action": [
                        "iam:CreatePolicyVersion",
                        "iam:SetDefaultPolicyVersion",
                        "iam:AttachRolePolicy",
                        "iam:AttachUserPolicy",
                        "iam:PutRolePolicy",
                    ],
                    "Resource": "*",
                }
            ],
        }
        return RemediationGuidance(
            title="Remove IAM Self-Modification Permissions & Enforce IAM Permissions Boundary",
            summary=f"Revoke iam:CreatePolicyVersion and iam:AttachRolePolicy from '{resource_name}'.",
            why_it_matters="Permissions that mutate IAM policies allow a principal to rewrite its own policy document to 'Action: *', achieving full administrative takeover in a single API call.",
            operational_impact="IAM policy updates must be executed exclusively by dedicated Infrastructure-as-Code deployment roles.",
            priority="P1 — Immediate (Critical)",
            before_config=before_str,
            suggested_config=json.dumps(suggested, indent=2),
        )

    if rule_id == "CP-TRUST-001":  # Cross-Account / Wildcard Trust Policy
        suggested = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "HardenedCrossAccountTrustWithExternalIdAndMFA",
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::998877665544:role/VendorDesignatedAuditRole"},
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": {"sts:ExternalId": "northstar-verified-ext-id-98c1a"},
                        "Bool": {"aws:MultiFactorAuthPresent": "true"},
                    },
                }
            ],
        }
        return RemediationGuidance(
            title="Harden Role Trust Policy with Specific Principal ARN and sts:ExternalId",
            summary=f"Restrict trust policy on '{resource_name}' to explicit partner role ARNs and require sts:ExternalId.",
            why_it_matters="Trusting an external account root ('arn:aws:iam::<account>:root') or '*' without an ExternalId exposes the role to confused-deputy and cross-account lateral movement attacks.",
            operational_impact="Third-party integrations must pass the configured sts:ExternalId parameter during AssumeRole API calls.",
            priority="P1 — High Priority",
            before_config=before_str,
            suggested_config=json.dumps(suggested, indent=2),
        )

    if rule_id == "CP-S3-001":  # Public S3 Bucket
        suggested = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
            "BucketPolicy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AllowCloudFrontOACOnly",
                        "Effect": "Allow",
                        "Principal": {"Service": "cloudfront.amazonaws.com"},
                        "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{resource_name}/*",
                    }
                ],
            },
        }
        return RemediationGuidance(
            title="Enable S3 Block Public Access & Remove Wildcard Principal Bucket Policy",
            summary=f"Enable all four S3 PublicAccessBlock flags on '{resource_name}' and remove Principal '*' statements.",
            why_it_matters="Publicly writable or readable S3 buckets allow unauthenticated actors on the internet to exfiltrate objects or tamper with hosted assets.",
            operational_impact="If static assets must be served publicly, route traffic through CloudFront Origin Access Control (OAC) instead of direct bucket ACLs.",
            priority="P2 — High",
            before_config=before_str,
            suggested_config=json.dumps(suggested, indent=2),
        )

    if rule_id == "CP-NET-001":  # Public Security Group / Exposed EC2 with Role
        suggested = {
            "GroupId": resource_name,
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.24.0.0/16", "Description": "Internal VPC HTTPS"}],
                }
            ],
            "InstanceMetadataOptions": {"HttpTokens": "required", "HttpPutResponseHopLimit": 1},
        }
        return RemediationGuidance(
            title="Eliminate 0.0.0.0/0 SSH Ingress & Require IMDSv2 on Compute Instances",
            summary=f"Remove world-open port 22 on '{resource_name}', migrate to AWS Systems Manager Session Manager, and enforce IMDSv2.",
            why_it_matters="Internet-exposed instances with attached privileged IAM roles allow attackers who compromise the instance or exploit SSRF against IMDSv1 to steal temporary role credentials.",
            operational_impact="Administrators must connect via AWS SSM Session Manager or a zero-trust bastion rather than direct public SSH.",
            priority="P1 — Immediate (Critical)",
            before_config=before_str,
            suggested_config=json.dumps(suggested, indent=2),
        )

    # Default / Orphaned Identity remediation
    suggested = {
        "RecommendedAction": "DecommissionOrRotate",
        "Identity": resource_name,
        "Controls": [
            "Deactivate unused access keys older than 90 days",
            "Enforce hardware MFA on all interactive IAM principals",
            "Detach AdministratorAccess and migrate to short-lived SSO roles",
        ],
    }
    return RemediationGuidance(
        title="Revoke Dormant Credentials & Migrate to Federated Short-Lived Roles",
        summary=f"Disable dormant long-lived credentials on '{resource_name}' and remove standing privileges.",
        why_it_matters="Dormant identities with standing administrative privileges represent high-value, low-visibility persistence targets for attackers.",
        operational_impact="Verify no legacy cron jobs or scripts authenticate with this user's access key before deletion.",
        priority="P2 — Medium-High",
        before_config=before_str,
        suggested_config=json.dumps(suggested, indent=2),
    )
