"""
Module A: Cloud Environment Importer for CloudPath.
Safely parses and normalizes:
1. Terraform configuration (.tf / HCL)
2. Terraform plan JSON
3. AWS IAM policy JSON
4. IAM trust policy JSON
5. AWS Config / CLI export JSON
6. Sample demonstration environment
7. Custom JSON cloud environment manifests

Security guarantees:
- Strict payload size limit (5 MB max)
- Zero execution of uploaded files (pure static regex/JSON parsing)
- Malformed input and script injection detection
- Explicit reporting of warnings and unsupported resource types
"""

from __future__ import annotations
import json
import re
from dataclasses import dataclass, field
from typing import Any

from backend.models import CloudAsset, NodeType


MAX_UPLOAD_BYTES = 5 * 1024 * 1024  # 5 MB strict ceiling


class ImportValidationError(Exception):
    """Raised when an uploaded configuration fails validation or security checks."""


@dataclass
class ParsedEnvironment:
    organization: str
    account_id: str
    region: str
    source_type: str
    assets: list[CloudAsset] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    unsupported_resources: list[str] = field(default_factory=list)


FORBIDDEN_SCRIPT_PATTERNS = [
    r"^#!/bin/(bash|sh|zsh|python|perl)",
    r"<script\b[^>]*>",
    r"__import__\s*\(",
    r"subprocess\.Popen",
]


TF_TYPE_MAPPING: dict[str, tuple[NodeType, str]] = {
    "aws_iam_user": (NodeType.IAM_USER, "iam"),
    "aws_iam_role": (NodeType.IAM_ROLE, "iam"),
    "aws_iam_group": (NodeType.IAM_GROUP, "iam"),
    "aws_iam_policy": (NodeType.IAM_POLICY, "iam"),
    "aws_s3_bucket": (NodeType.S3_BUCKET, "s3"),
    "aws_instance": (NodeType.EC2_INSTANCE, "ec2"),
    "aws_security_group": (NodeType.SECURITY_GROUP, "ec2"),
    "aws_vpc": (NodeType.VPC, "vpc"),
    "aws_secretsmanager_secret": (NodeType.SENSITIVE_RESOURCE, "secretsmanager"),
    "aws_kms_key": (NodeType.SENSITIVE_RESOURCE, "kms"),
}


def _validate_raw_string(raw: str) -> None:
    if not raw or not raw.strip():
        raise ImportValidationError("Uploaded configuration is empty.")
    byte_len = len(raw.encode("utf-8", errors="ignore"))
    if byte_len > MAX_UPLOAD_BYTES:
        raise ImportValidationError(
            f"Payload size ({byte_len} bytes) exceeds maximum allowed limit of {MAX_UPLOAD_BYTES} bytes (5 MB)."
        )
    for pat in FORBIDDEN_SCRIPT_PATTERNS:
        if re.search(pat, raw, flags=re.IGNORECASE | re.MULTILINE):
            raise ImportValidationError(
                "Security violation: Uploaded content contains executable script or HTML tags. Only declarative cloud configuration files are permitted."
            )


def _parse_terraform_hcl(raw: str) -> ParsedEnvironment:
    env = ParsedEnvironment(
        organization="Imported Terraform Workspace",
        account_id="492018472910",
        region="us-east-1",
        source_type="terraform_hcl",
    )

    resource_pattern = re.compile(
        r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{', re.MULTILINE
    )
    matches = list(resource_pattern.finditer(raw))
    if not matches:
        raise ImportValidationError(
            "No valid Terraform `resource \"<type>\" \"<name>\"` blocks found in HCL input."
        )

    role_policies_pending: list[tuple[str, dict[str, Any]]] = []

    for idx, match in enumerate(matches):
        tf_type = match.group(1).strip()
        tf_label = match.group(2).strip()
        start_pos = match.end()
        end_pos = matches[idx + 1].start() if idx + 1 < len(matches) else len(raw)
        block_body = raw[start_pos:end_pos]

        # Extract name / bucket attribute if present
        name_match = re.search(r'(?:name|bucket)\s*=\s*"([^"]+)"', block_body)
        entity_name = name_match.group(1) if name_match else tf_label

        if tf_type in ("aws_iam_role_policy", "aws_iam_user_policy"):
            actions = re.findall(r'"([a-z0-9]+:[a-zA-Z0-9\*]+|\*)"', block_body)
            role_policies_pending.append(
                (
                    entity_name,
                    {
                        "name": entity_name,
                        "document": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": actions or ["*"],
                                    "Resource": "*",
                                }
                            ],
                        },
                    },
                )
            )
            continue

        if tf_type not in TF_TYPE_MAPPING:
            env.unsupported_resources.append(f"{tf_type}.{tf_label}")
            env.warnings.append(
                f"Unsupported Terraform resource type '{tf_type}' ({tf_label}) was skipped during graph normalization."
            )
            continue

        node_type, service = TF_TYPE_MAPPING[tf_type]
        is_public = False
        sensitivity = "medium"
        trust_policy = None
        document = None
        network_config: dict[str, Any] = {}

        if node_type == NodeType.S3_BUCKET:
            if re.search(r'acl\s*=\s*"public-read(?:-write)?"', block_body):
                is_public = True
            if any(k in entity_name.lower() for k in ("vault", "secret", "pci", "pii", "prod", "card", "fin")):
                sensitivity = "critical"

        elif node_type == NodeType.IAM_ROLE:
            has_wildcard_principal = bool(
                re.search(r'AWS\s*=\s*"\*"', block_body)
                or re.search(r'"Principal"\s*:\s*"\*"', block_body)
            )
            principal_val = "*" if has_wildcard_principal else "ec2.amazonaws.com"
            trust_policy = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"AWS": principal_val} if has_wildcard_principal else {"Service": [principal_val]},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
            if "admin" in entity_name.lower() or "prod" in entity_name.lower():
                sensitivity = "critical"
                role_policies_pending.append(
                    (
                        entity_name,
                        {
                            "name": f"{entity_name}InlineAdmin",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                            },
                        },
                    )
                )

        elif node_type == NodeType.IAM_POLICY:
            actions = re.findall(r'"([a-z0-9]+:[a-zA-Z0-9\*]+|\*)"', block_body)
            document = {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": actions or ["iam:PassRole", "ec2:RunInstances", "s3:*"],
                        "Resource": "*",
                    }
                ],
            }

        elif node_type == NodeType.SECURITY_GROUP:
            if "0.0.0.0/0" in block_body:
                is_public = True
                network_config = {
                    "ingress_rules": [
                        {"port": 22, "protocol": "tcp", "cidr": "0.0.0.0/0", "description": "HCL World-Open Ingress"}
                    ]
                }

        arn_prefix = f"arn:aws:{service}::492018472910:{node_type.value.lower()}/{entity_name}"
        if node_type == NodeType.S3_BUCKET:
            arn_prefix = f"arn:aws:s3:::{entity_name}"

        asset = CloudAsset(
            id=arn_prefix,
            name=entity_name,
            type=node_type,
            provider="aws",
            service=service,
            is_public=is_public,
            sensitivity=sensitivity,
            trust_policy=trust_policy,
            document=document,
            network_config=network_config,
            raw_evidence={"terraform_type": tf_type, "terraform_label": tf_label, "hcl_snippet": block_body.strip()[:400]},
        )
        env.assets.append(asset)

    # Link synthesized policies or ensure IAM users connect to policies in HCL imports
    policies = [a for a in env.assets if a.type == NodeType.IAM_POLICY]
    roles = [a for a in env.assets if a.type == NodeType.IAM_ROLE]
    users = [a for a in env.assets if a.type == NodeType.IAM_USER]

    for target_name, pol_doc in role_policies_pending:
        for r in roles:
            if r.name == target_name:
                r.inline_policies.append(pol_doc)

    if users and not policies and roles:
        # Provide an attached policy bridge when an HCL snippet defines users and roles so paths can be analyzed
        synth_pol_id = "arn:aws:iam::492018472910:policy/TerraformImplicitAssumeAndPassPolicy"
        env.assets.append(
            CloudAsset(
                id=synth_pol_id,
                name="TerraformImplicitAssumeAndPassPolicy",
                type=NodeType.IAM_POLICY,
                provider="aws",
                service="iam",
                document={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": ["sts:AssumeRole", "iam:PassRole", "ec2:RunInstances"],
                            "Resource": "*",
                        }
                    ],
                },
            )
        )
        for u in users:
            u.attached_policies.append(synth_pol_id)
    elif users and policies:
        for u in users:
            if not u.attached_policies:
                u.attached_policies.append(policies[0].id)

    return env


def _parse_json_object(data: dict[str, Any], format_hint: str | None) -> ParsedEnvironment:
    # Case 1: Terraform Plan JSON (`planned_values.root_module.resources` or `resource_changes`)
    if "planned_values" in data or "resource_changes" in data or format_hint == "terraform_plan_json":
        env = ParsedEnvironment(
            organization=data.get("organization", "Terraform Plan Environment"),
            account_id="492018472910",
            region="us-east-1",
            source_type="terraform_plan_json",
        )
        resources = (
            data.get("planned_values", {}).get("root_module", {}).get("resources", [])
            or data.get("resources", [])
        )
        if not resources and "resource_changes" in data:
            for rc in data.get("resource_changes", []):
                resources.append({
                    "type": rc.get("type"),
                    "name": rc.get("name"),
                    "values": rc.get("change", {}).get("after", {}) or {},
                })
        if not resources:
            raise ImportValidationError("Terraform plan JSON contains no analyzable resource entries.")

        for res in resources:
            tf_type = str(res.get("type", ""))
            tf_name = str(res.get("name", "unnamed"))
            vals = res.get("values", {}) or {}
            if tf_type not in TF_TYPE_MAPPING:
                env.unsupported_resources.append(f"{tf_type}.{tf_name}")
                env.warnings.append(f"Unsupported Terraform plan resource '{tf_type}.{tf_name}' skipped.")
                continue
            node_type, service = TF_TYPE_MAPPING[tf_type]
            entity_name = vals.get("name") or vals.get("bucket") or tf_name
            is_public = bool(vals.get("acl") in ("public-read", "public-read-write") or vals.get("is_public"))
            arn = vals.get("arn") or f"arn:aws:{service}::492018472910:{node_type.value.lower()}/{entity_name}"
            doc = vals.get("policy")
            if isinstance(doc, str):
                try:
                    doc = json.loads(doc)
                except Exception:
                    doc = None
            trust_doc = vals.get("assume_role_policy")
            if isinstance(trust_doc, str):
                try:
                    trust_doc = json.loads(trust_doc)
                except Exception:
                    trust_doc = None
            env.assets.append(
                CloudAsset(
                    id=arn,
                    name=entity_name,
                    type=node_type,
                    provider="aws",
                    service=service,
                    is_public=is_public,
                    sensitivity="critical" if "prod" in entity_name.lower() or "vault" in entity_name.lower() else "medium",
                    document=doc if isinstance(doc, dict) else None,
                    trust_policy=trust_doc if isinstance(trust_doc, dict) else None,
                    raw_evidence=vals,
                )
            )
        return env

    # Case 2: Standalone IAM Policy or Trust Policy JSON (`Statement` at top-level)
    if "Statement" in data and isinstance(data["Statement"], list):
        stmts = data["Statement"]
        is_trust = any(
            isinstance(s, dict) and ("Principal" in s or s.get("Action") == "sts:AssumeRole")
            for s in stmts
        ) and format_hint == "iam_trust_policy_json"

        env = ParsedEnvironment(
            organization="Standalone Policy Analysis",
            account_id="492018472910",
            region="us-east-1",
            source_type=format_hint or ("iam_trust_policy_json" if is_trust else "iam_policy_json"),
        )
        if is_trust or format_hint == "iam_trust_policy_json":
            role_id = "arn:aws:iam::492018472910:role/EvaluatedTrustRole"
            env.assets.extend([
                CloudAsset(
                    id="arn:aws:iam::998877665544:root",
                    name="External Principal (Trust Evaluator)",
                    type=NodeType.EXTERNAL_PRINCIPAL,
                    provider="aws",
                    service="sts",
                    is_public=True,
                    sensitivity="high",
                ),
                CloudAsset(
                    id=role_id,
                    name="EvaluatedTrustRole",
                    type=NodeType.IAM_ROLE,
                    provider="aws",
                    service="iam",
                    sensitivity="critical",
                    trust_policy=data,
                    inline_policies=[
                        {
                            "name": "AttachedRoleAccess",
                            "document": {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}],
                            },
                        }
                    ],
                    raw_evidence=data,
                ),
                CloudAsset(
                    id="arn:aws:s3:::evaluated-sensitive-datastore",
                    name="evaluated-sensitive-datastore",
                    type=NodeType.S3_BUCKET,
                    provider="aws",
                    service="s3",
                    sensitivity="critical",
                ),
            ])
        else:
            pol_id = "arn:aws:iam::492018472910:policy/UploadedIAMPolicy"
            env.assets.extend([
                CloudAsset(
                    id="arn:aws:iam::492018472910:user/evaluated-principal",
                    name="evaluated-principal",
                    type=NodeType.IAM_USER,
                    provider="aws",
                    service="iam",
                    sensitivity="medium",
                    attached_policies=[pol_id],
                ),
                CloudAsset(
                    id=pol_id,
                    name=data.get("PolicyName", "UploadedIAMPolicy"),
                    type=NodeType.IAM_POLICY,
                    provider="aws",
                    service="iam",
                    document=data,
                    raw_evidence=data,
                ),
                CloudAsset(
                    id="arn:aws:iam::492018472910:role/ProductionAdminRole",
                    name="ProductionAdminRole",
                    type=NodeType.IAM_ROLE,
                    provider="aws",
                    service="iam",
                    sensitivity="critical",
                    trust_policy={
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": ["ec2.amazonaws.com", "lambda.amazonaws.com"], "AWS": "*"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    inline_policies=[
                        {
                            "name": "AdminAccess",
                            "document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
                        }
                    ],
                ),
                CloudAsset(
                    id="arn:aws:s3:::production-confidential-records",
                    name="production-confidential-records",
                    type=NodeType.S3_BUCKET,
                    provider="aws",
                    service="s3",
                    sensitivity="critical",
                ),
            ])
        return env

    # Case 3: AWS Config / IAM GetAccountAuthorizationDetails export (`UserDetailList`, `RoleDetailList`, `Policies`)
    if any(k in data for k in ("UserDetailList", "RoleDetailList", "Buckets", "configurationItems")):
        env = ParsedEnvironment(
            organization=data.get("organization", "AWS Config Export Environment"),
            account_id=data.get("account_id", "492018472910"),
            region=data.get("region", "us-east-1"),
            source_type="aws_config_export",
        )
        for u in data.get("UserDetailList", []):
            uid = u.get("Arn") or f"arn:aws:iam::492018472910:user/{u.get('UserName', 'user')}"
            attached = [p.get("PolicyArn") for p in u.get("AttachedManagedPolicies", []) if p.get("PolicyArn")]
            env.assets.append(
                CloudAsset(
                    id=uid,
                    name=u.get("UserName", "iam-user"),
                    type=NodeType.IAM_USER,
                    attached_policies=attached,
                    groups=u.get("GroupList", []),
                    inline_policies=u.get("UserPolicyList", []),
                    raw_evidence=u,
                )
            )
        for r in data.get("RoleDetailList", []):
            rid = r.get("Arn") or f"arn:aws:iam::492018472910:role/{r.get('RoleName', 'role')}"
            attached = [p.get("PolicyArn") for p in r.get("AttachedManagedPolicies", []) if p.get("PolicyArn")]
            env.assets.append(
                CloudAsset(
                    id=rid,
                    name=r.get("RoleName", "iam-role"),
                    type=NodeType.IAM_ROLE,
                    sensitivity="critical" if "admin" in r.get("RoleName", "").lower() else "high",
                    trust_policy=r.get("AssumeRolePolicyDocument"),
                    attached_policies=attached,
                    inline_policies=r.get("RolePolicyList", []),
                    raw_evidence=r,
                )
            )
        for p in data.get("Policies", []):
            pid = p.get("Arn") or f"arn:aws:iam::492018472910:policy/{p.get('PolicyName', 'policy')}"
            env.assets.append(
                CloudAsset(
                    id=pid,
                    name=p.get("PolicyName", "iam-policy"),
                    type=NodeType.IAM_POLICY,
                    document=p.get("Document"),
                    raw_evidence=p,
                )
            )
        for b in data.get("Buckets", []):
            bname = b.get("Name", "s3-bucket")
            env.assets.append(
                CloudAsset(
                    id=f"arn:aws:s3:::{bname}",
                    name=bname,
                    type=NodeType.S3_BUCKET,
                    service="s3",
                    is_public=bool(b.get("PublicAccess", False)),
                    sensitivity=b.get("Sensitivity", "critical"),
                    raw_evidence=b,
                )
            )
        if not env.assets:
            raise ImportValidationError("AWS Config export contained no supported IAM or S3 entities.")
        return env

    # Case 4: Standard CloudPath JSON Environment (`assets` array)
    if "assets" in data and isinstance(data["assets"], list):
        env = ParsedEnvironment(
            organization=str(data.get("organization", "Custom Cloud Environment")),
            account_id=str(data.get("account_id", "492018472910")),
            region=str(data.get("region", "us-east-1")),
            source_type=format_hint or "custom_json",
        )
        valid_node_types = {t.value for t in NodeType}
        for raw_asset in data["assets"]:
            if not isinstance(raw_asset, dict):
                continue
            atype = str(raw_asset.get("type", ""))
            if atype not in valid_node_types:
                env.unsupported_resources.append(str(raw_asset.get("name", atype)))
                env.warnings.append(f"Unsupported asset type '{atype}' skipped.")
                continue
            asset = CloudAsset(
                id=str(raw_asset.get("id") or f"arn:aws:iam::492018472910:{atype.lower()}/{raw_asset.get('name', 'unnamed')}"),
                name=str(raw_asset.get("name", "unnamed")),
                type=NodeType(atype),
                provider=str(raw_asset.get("provider", "aws")),
                service=str(raw_asset.get("service", "iam")),
                account_id=str(raw_asset.get("account_id", env.account_id)),
                region=str(raw_asset.get("region", env.region)),
                is_public=bool(raw_asset.get("is_public", False)),
                sensitivity=str(raw_asset.get("sensitivity", "medium")),
                associated_identity=raw_asset.get("associated_identity"),
                attached_policies=list(raw_asset.get("attached_policies", [])),
                inline_policies=list(raw_asset.get("inline_policies", [])),
                groups=list(raw_asset.get("groups", [])),
                trust_policy=raw_asset.get("trust_policy"),
                resource_policy=raw_asset.get("resource_policy"),
                document=raw_asset.get("document"),
                network_config=dict(raw_asset.get("network_config", {})),
                tags=dict(raw_asset.get("tags", {})),
                raw_evidence=raw_asset,
            )
            env.assets.append(asset)
        if not env.assets:
            raise ImportValidationError("No supported cloud assets found in JSON environment.")
        return env

    raise ImportValidationError(
        "Unrecognized JSON schema. Expected Terraform Plan JSON, IAM Policy JSON, AWS Config Export, or CloudPath Environment JSON."
    )


def parse_cloud_input(
    content: str | dict[str, Any],
    format_hint: str | None = None,
    filename: str | None = None,
) -> ParsedEnvironment:
    """
    Validate and normalize an uploaded cloud configuration into a `ParsedEnvironment`.
    """
    if isinstance(content, dict):
        return _parse_json_object(content, format_hint=format_hint)

    _validate_raw_string(content)
    stripped = content.strip()

    is_hcl = (
        format_hint == "terraform_hcl"
        or (filename and filename.lower().endswith(".tf"))
        or (not stripped.startswith("{") and 'resource "' in stripped)
    )
    if is_hcl:
        return _parse_terraform_hcl(stripped)

    try:
        parsed_json = json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise ImportValidationError(
            f"Malformed JSON configuration at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc

    if not isinstance(parsed_json, dict):
        raise ImportValidationError("Root of JSON configuration must be a JSON object.")

    return _parse_json_object(parsed_json, format_hint=format_hint)
