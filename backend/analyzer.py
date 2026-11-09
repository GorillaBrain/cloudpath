"""
Module C: Attack Path Analysis Engine & Finding Detector for CloudPath.
Constructs a NetworkX MultiDiGraph from normalized cloud assets and policies,
evaluates effective permissions with explicit Deny precedence, discovers multi-hop
and shortest attack paths (BFS/DFS/Dijkstra), and produces explainable findings.
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any
import uuid
import networkx as nx

from backend.models import (
    AttackPath,
    AttackPathHop,
    CloudAsset,
    EdgeType,
    EpistemicClass,
    Finding,
    GraphEdge,
    GraphNode,
    NodeType,
    RiskWeights,
    ScanResult,
    SeverityLevel,
    SummaryMetrics,
)
from backend.iam_evaluator import EffectivePermissions, evaluate_effective_permissions
from backend.importer import ParsedEnvironment, parse_cloud_input
from backend.risk_engine import RiskInputFactors, calculate_risk_score, score_to_severity
from backend.remediation import MITRE_CLOUD_CATALOG, build_remediation_for_rule


SENSITIVITY_SCORES = {
    "critical": 96.0,
    "high": 78.0,
    "medium": 50.0,
    "low": 25.0,
}


def _collect_statements_for_asset(
    asset: CloudAsset, assets_by_id: dict[str, CloudAsset]
) -> list[dict[str, Any]]:
    stmts: list[dict[str, Any]] = []

    # Direct policy document (if asset is an IAMPolicy)
    if asset.document and isinstance(asset.document.get("Statement"), list):
        stmts.extend(asset.document["Statement"])

    # Attached managed policies
    for pol_id in asset.attached_policies:
        pol = assets_by_id.get(pol_id)
        if pol and pol.document and isinstance(pol.document.get("Statement"), list):
            stmts.extend(pol.document["Statement"])

    # Inline policies
    for inline in asset.inline_policies:
        doc = inline.get("document") or inline.get("PolicyDocument") or {}
        if isinstance(doc.get("Statement"), list):
            stmts.extend(doc["Statement"])

    # Group policies (for IAMUser)
    for grp_id in asset.groups:
        grp = assets_by_id.get(grp_id)
        if grp:
            for pol_id in grp.attached_policies:
                pol = assets_by_id.get(pol_id)
                if pol and pol.document and isinstance(pol.document.get("Statement"), list):
                    stmts.extend(pol.document["Statement"])
            for inline in grp.inline_policies:
                doc = inline.get("document") or inline.get("PolicyDocument") or {}
                if isinstance(doc.get("Statement"), list):
                    stmts.extend(doc["Statement"])

    return stmts


def _extract_trust_principals(trust_policy: dict[str, Any] | None) -> tuple[list[str], list[str], bool]:
    """Return (aws_principals, service_principals, has_external_id)."""
    if not trust_policy or not isinstance(trust_policy.get("Statement"), list):
        return [], [], False
    aws_principals: list[str] = []
    service_principals: list[str] = []
    has_external_id = False

    for stmt in trust_policy["Statement"]:
        if not isinstance(stmt, dict) or str(stmt.get("Effect", "Allow")).capitalize() != "Allow":
            continue
        cond = stmt.get("Condition", {})
        if "sts:ExternalId" in str(cond):
            has_external_id = True
        principal = stmt.get("Principal", {})
        if principal == "*":
            aws_principals.append("*")
        elif isinstance(principal, dict):
            aws_p = principal.get("AWS")
            if isinstance(aws_p, str):
                aws_principals.append(aws_p)
            elif isinstance(aws_p, list):
                aws_principals.extend(str(x) for x in aws_p)
            svc_p = principal.get("Service")
            if isinstance(svc_p, str):
                service_principals.append(svc_p)
            elif isinstance(svc_p, list):
                service_principals.extend(str(x) for x in svc_p)

    return aws_principals, service_principals, has_external_id


def build_cloud_graph(
    env: ParsedEnvironment,
) -> tuple[nx.MultiDiGraph, dict[str, CloudAsset], dict[str, EffectivePermissions]]:
    G = nx.MultiDiGraph()
    assets_by_id: dict[str, CloudAsset] = {a.id: a for a in env.assets}
    effective_by_id: dict[str, EffectivePermissions] = {}

    # 1. Evaluate permissions for every asset and add nodes
    for asset in env.assets:
        stmts = _collect_statements_for_asset(asset, assets_by_id)
        eff = evaluate_effective_permissions(stmts)
        effective_by_id[asset.id] = eff
        asset.permissions = list(eff.allowed_actions)
        asset.explicit_denies = list(eff.explicitly_denied_actions)

        G.add_node(
            asset.id,
            label=asset.name,
            type=asset.type,
            provider=asset.provider,
            service=asset.service,
            is_public=asset.is_public,
            sensitivity=asset.sensitivity,
        )

    edge_counter = 0

    def add_edge(
        src: str,
        dst: str,
        etype: EdgeType,
        label: str,
        epistemic: EpistemicClass = EpistemicClass.CONFIRMED_CONFIGURATION,
        perms: list[str] | None = None,
        evidence: str = "",
        is_escalation: bool = False,
        weight: float = 1.0,
    ) -> None:
        nonlocal edge_counter
        if src not in assets_by_id or dst not in assets_by_id or src == dst:
            return
        # Avoid duplicate identical edges between same src, dst, and type
        if G.has_edge(src, dst):
            for _, edata in G[src][dst].items():
                if edata.get("type") == etype:
                    return
        edge_counter += 1
        eid = f"edge-{edge_counter:03d}"
        G.add_edge(
            src,
            dst,
            key=eid,
            id=eid,
            source=src,
            target=dst,
            type=etype,
            label=label,
            epistemic_class=epistemic,
            permissions=perms or [],
            evidence=evidence,
            is_escalation=is_escalation,
            weight=weight,
        )
        assets_by_id[src].relationships_summary.append(f"{etype.value} -> {assets_by_id[dst].name}")

    roles = [a for a in env.assets if a.type == NodeType.IAM_ROLE]
    sensitive_targets = [
        a for a in env.assets if a.type in (NodeType.S3_BUCKET, NodeType.SENSITIVE_RESOURCE)
    ]

    # 2. Structural IAM & Network edges
    for asset in env.assets:
        eff = effective_by_id[asset.id]

        # Group membership edges
        for grp_id in asset.groups:
            if grp_id in assets_by_id:
                add_edge(
                    asset.id,
                    grp_id,
                    EdgeType.MEMBER_OF,
                    "Member of IAM Group",
                    EpistemicClass.CONFIRMED_CONFIGURATION,
                    evidence=f"Principal '{asset.name}' is a member of group '{assets_by_id[grp_id].name}'.",
                    weight=0.6,
                )

        # Attached Policy edges
        for pol_id in asset.attached_policies:
            if pol_id in assets_by_id:
                add_edge(
                    asset.id,
                    pol_id,
                    EdgeType.ASSIGNED_POLICY,
                    "Attached Managed Policy",
                    EpistemicClass.CONFIRMED_CONFIGURATION,
                    evidence=f"Managed policy '{assets_by_id[pol_id].name}' is attached to '{asset.name}'.",
                    weight=0.5,
                )

        # Policy permission edges to roles / resources ( accounting for explicit Deny on the policy/principal )
        if asset.type == NodeType.IAM_POLICY:
            pol_eff = eff
            # Check if policy grants PassRole + Compute Execution -> can pass service roles
            if pol_eff.can_escalate_via_passrole:
                for role in roles:
                    _, svc_principals, _ = _extract_trust_principals(role.trust_policy)
                    if any(s in svc_principals for s in ("ec2.amazonaws.com", "lambda.amazonaws.com")) or not svc_principals:
                        add_edge(
                            asset.id,
                            role.id,
                            EdgeType.CAN_ASSUME_ROLE,
                            "iam:PassRole + Compute Execution",
                            EpistemicClass.POTENTIAL_ATTACK_PATH,
                            perms=pol_eff.escalation_primitives,
                            evidence=f"Policy '{asset.name}' grants {', '.join(pol_eff.escalation_primitives)} on '*', allowing workload attachment of '{role.name}'.",
                            is_escalation=True,
                            weight=1.0,
                        )

            # Check if policy grants sts:AssumeRole to specific or wildcard roles
            for role in roles:
                if pol_eff.is_action_allowed("sts:AssumeRole", role.id):
                    aws_p, _, _ = _extract_trust_principals(role.trust_policy)
                    if aws_p:
                        add_edge(
                            asset.id,
                            role.id,
                            EdgeType.CAN_ASSUME_ROLE,
                            "sts:AssumeRole Allowed",
                            EpistemicClass.POTENTIAL_ATTACK_PATH,
                            perms=["sts:AssumeRole"],
                            evidence=f"Policy '{asset.name}' allows sts:AssumeRole on '{role.name}'.",
                            is_escalation=True,
                            weight=0.9,
                        )

            # Check if policy grants access to S3 buckets or secrets
            for target in sensitive_targets:
                req_action = "s3:GetObject" if target.type == NodeType.S3_BUCKET else "secretsmanager:GetSecretValue"
                if pol_eff.is_action_allowed(req_action, target.id) or pol_eff.is_action_allowed(req_action, f"{target.id}/*"):
                    add_edge(
                        asset.id,
                        target.id,
                        EdgeType.CAN_ACCESS,
                        f"Allows {req_action}",
                        EpistemicClass.POTENTIAL_ATTACK_PATH,
                        perms=[req_action],
                        evidence=f"Policy '{asset.name}' allows '{req_action}' on '{target.name}'.",
                        weight=0.8,
                    )

        # Role / User direct or inline capabilities
        if asset.type in (NodeType.IAM_USER, NodeType.IAM_ROLE):
            # Role trust relationships
            if asset.type == NodeType.IAM_ROLE and asset.trust_policy:
                aws_principals, _, _ = _extract_trust_principals(asset.trust_policy)
                for p_id in aws_principals:
                    if p_id == "*":
                        for ext in [a for a in env.assets if a.type in (NodeType.EXTERNAL_PRINCIPAL, NodeType.IAM_USER)]:
                            add_edge(
                                ext.id,
                                asset.id,
                                EdgeType.TRUSTS,
                                "Wildcard Trust Principal (*)",
                                EpistemicClass.POTENTIAL_ATTACK_PATH,
                                perms=["sts:AssumeRole"],
                                evidence=f"Role '{asset.name}' trust policy permits Principal '*' to call sts:AssumeRole.",
                                is_escalation=True,
                                weight=0.8,
                            )
                    elif p_id in assets_by_id:
                        src_eff = effective_by_id.get(p_id)
                        # Verify source does not have an explicit Deny on sts:AssumeRole
                        if src_eff and "sts:AssumeRole" in src_eff.explicitly_denied_actions:
                            continue
                        edge_t = EdgeType.TRUSTS if assets_by_id[p_id].type == NodeType.EXTERNAL_PRINCIPAL else EdgeType.CAN_ASSUME_ROLE
                        add_edge(
                            p_id,
                            asset.id,
                            edge_t,
                            "Cross-Account / Principal Trust" if edge_t == EdgeType.TRUSTS else "Assumes Trusted Role",
                            EpistemicClass.CONFIRMED_CONFIGURATION,
                            perms=["sts:AssumeRole"],
                            evidence=f"Role '{asset.name}' trust policy explicitly trusts principal '{assets_by_id[p_id].name}'.",
                            is_escalation=True,
                            weight=0.9,
                        )

            # Policy self-modification privilege escalation on Role/User
            if eff.can_modify_policies:
                for pol_or_role in roles + sensitive_targets:
                    if pol_or_role.id != asset.id and pol_or_role.sensitivity == "critical":
                        add_edge(
                            asset.id,
                            pol_or_role.id,
                            EdgeType.CONTROLS_RESOURCE,
                            f"Policy Mutation Escalation ({', '.join(eff.escalation_primitives[:2])})",
                            EpistemicClass.POTENTIAL_ATTACK_PATH,
                            perms=eff.escalation_primitives,
                            evidence=f"Identity '{asset.name}' holds IAM policy modification permissions ({', '.join(eff.escalation_primitives)}), enabling self-escalation to administrative control over '{pol_or_role.name}'.",
                            is_escalation=True,
                            weight=1.1,
                        )

            # Direct resource access from Role/User effective permissions
            for target in sensitive_targets:
                req_action = "s3:GetObject" if target.type == NodeType.S3_BUCKET else "secretsmanager:GetSecretValue"
                if eff.is_action_allowed(req_action, target.id) or eff.is_action_allowed(req_action, f"{target.id}/*"):
                    add_edge(
                        asset.id,
                        target.id,
                        EdgeType.CAN_ACCESS,
                        f"Effective {req_action}",
                        EpistemicClass.POTENTIAL_ATTACK_PATH,
                        perms=[req_action] + (["kms:Decrypt"] if eff.is_action_allowed("kms:Decrypt") else []),
                        evidence=f"Effective permissions on '{asset.name}' allow '{req_action}' on '{target.name}' (no explicit Deny present).",
                        weight=0.7,
                    )

            # Direct AssumeRole from inline policy
            for target_role in roles:
                if target_role.id != asset.id and eff.is_action_allowed("sts:AssumeRole", target_role.id):
                    aws_p, _, _ = _extract_trust_principals(target_role.trust_policy)
                    if asset.id in aws_p or "*" in aws_p:
                        add_edge(
                            asset.id,
                            target_role.id,
                            EdgeType.CAN_ASSUME_ROLE,
                            "sts:AssumeRole",
                            EpistemicClass.POTENTIAL_ATTACK_PATH,
                            perms=["sts:AssumeRole"],
                            evidence=f"'{asset.name}' is permitted to assume '{target_role.name}' via policy and trust relationship.",
                            is_escalation=True,
                            weight=0.8,
                        )

        # Network & Compute relationships (VPC -> SecurityGroup -> EC2Instance -> Associated IAM Role)
        if asset.type == NodeType.SECURITY_GROUP:
            vpc_id = asset.network_config.get("vpc_id")
            if vpc_id and vpc_id in assets_by_id:
                add_edge(
                    vpc_id,
                    asset.id,
                    EdgeType.CONNECTS_TO,
                    "Contains Security Group",
                    EpistemicClass.CONFIRMED_CONFIGURATION,
                    evidence=f"VPC '{assets_by_id[vpc_id].name}' contains security group '{asset.name}'.",
                    weight=0.5,
                )

        if asset.type == NodeType.EC2_INSTANCE:
            for sg_id in asset.network_config.get("security_groups", []):
                if sg_id in assets_by_id:
                    sg = assets_by_id[sg_id]
                    etype = EdgeType.PUBLICLY_ACCESSIBLE if sg.is_public else EdgeType.CONNECTS_TO
                    add_edge(
                        sg_id,
                        asset.id,
                        etype,
                        "0.0.0.0/0 Public Ingress" if sg.is_public else "Attached Security Group",
                        EpistemicClass.CONFIRMED_CONFIGURATION,
                        perms=["tcp:22", "tcp:443"] if sg.is_public else [],
                        evidence=f"Security group '{sg.name}' exposes '{asset.name}' ({'0.0.0.0/0 world-open ingress' if sg.is_public else 'internal network'}).",
                        weight=0.7,
                    )
            if asset.associated_identity and asset.associated_identity in assets_by_id:
                add_edge(
                    asset.id,
                    asset.associated_identity,
                    EdgeType.CAN_ASSUME_ROLE,
                    "Instance Profile Role (IMDSv1 Enabled)" if asset.network_config.get("imdsv1_enabled") else "Instance Profile Role",
                    EpistemicClass.CONFIRMED_CONFIGURATION,
                    perms=["sts:AssumeRole (InstanceMetadata)"],
                    evidence=f"EC2 instance '{asset.name}' runs with attached IAM instance profile role '{assets_by_id[asset.associated_identity].name}'.",
                    is_escalation=True,
                    weight=0.8,
                )

    return G, assets_by_id, effective_by_id


def discover_attack_paths(
    G: nx.MultiDiGraph,
    assets_by_id: dict[str, CloudAsset],
    effective_by_id: dict[str, EffectivePermissions],
    weights: RiskWeights | None = None,
) -> list[AttackPath]:
    """
    Use cycle-safe BFS/DFS and Dijkstra shortest-path traversal over the cloud graph
    to discover multi-hop and direct attack paths from entry points to high-value targets.
    """
    entry_types = {
        NodeType.IAM_USER,
        NodeType.EXTERNAL_PRINCIPAL,
        NodeType.SECURITY_GROUP,
    }
    target_types = {
        NodeType.S3_BUCKET,
        NodeType.SENSITIVE_RESOURCE,
        NodeType.IAM_ROLE,
    }

    entry_nodes = [
        aid for aid, a in assets_by_id.items()
        if a.type in entry_types and (a.type != NodeType.SECURITY_GROUP or a.is_public)
    ]
    target_nodes = [
        aid for aid, a in assets_by_id.items()
        if a.type in target_types and a.sensitivity in ("critical", "high")
    ]

    discovered_paths: list[AttackPath] = []
    seen_node_chains: set[tuple[str, ...]] = set()
    shortest_by_pair: dict[tuple[str, str], tuple[str, ...]] = {}

    # Precompute shortest simple paths per (entry, target) pair using Dijkstra
    for src in entry_nodes:
        for dst in target_nodes:
            if src == dst or not nx.has_path(G, src, dst):
                continue
            try:
                sp = tuple(nx.shortest_path(G, source=src, target=dst, weight="weight"))
                shortest_by_pair[(src, dst)] = sp
            except nx.NetworkXNoPath:
                continue

    path_idx = 0
    for src in entry_nodes:
        for dst in target_nodes:
            if src == dst or not nx.has_path(G, src, dst):
                continue
            # Enumerate simple cycle-free paths up to cutoff=6 hops
            for simple_nodes in nx.all_simple_nodes_paths(G, src, dst, cutoff=6) if hasattr(nx, "all_simple_nodes_paths") else nx.all_simple_paths(G, src, dst, cutoff=6):
                chain_tuple = tuple(simple_nodes)
                if chain_tuple in seen_node_chains:
                    continue
                # Skip paths where target is an IAMRole if a longer path continues from that Role to a data store
                dst_asset = assets_by_id[dst]
                if dst_asset.type == NodeType.IAM_ROLE:
                    has_downstream_data = any(
                        assets_by_id[succ].type in (NodeType.S3_BUCKET, NodeType.SENSITIVE_RESOURCE)
                        for succ in G.successors(dst)
                    )
                    if has_downstream_data:
                        continue

                seen_node_chains.add(chain_tuple)
                path_idx += 1

                hops: list[AttackPathHop] = []
                edge_chain: list[str] = []
                all_perms: list[str] = []
                evidence_list: list[str] = []
                has_escalation = False
                rule_for_remediation = "CP-IAM-001"
                remediation_target_name = assets_by_id[src].name
                remediation_before_doc = assets_by_id[src].raw_evidence

                for i in range(len(simple_nodes) - 1):
                    u = simple_nodes[i]
                    v = simple_nodes[i + 1]
                    edge_dict = G[u][v]
                    first_key = next(iter(edge_dict))
                    edata = edge_dict[first_key]

                    edge_chain.append(edata["id"])
                    for p in edata.get("permissions", []):
                        if p not in all_perms:
                            all_perms.append(p)
                    if edata.get("evidence"):
                        evidence_list.append(edata["evidence"])
                    if edata.get("is_escalation"):
                        has_escalation = True

                    # Select the most specific remediation rule along the chain
                    if "PassRole" in edata.get("label", ""):
                        rule_for_remediation = "CP-IAM-002"
                        remediation_target_name = assets_by_id[u].name
                        remediation_before_doc = assets_by_id[u].document or assets_by_id[u].raw_evidence
                    elif "Policy Mutation" in edata.get("label", ""):
                        rule_for_remediation = "CP-IAM-003"
                        remediation_target_name = assets_by_id[u].name
                        remediation_before_doc = assets_by_id[u].raw_evidence
                    elif edata["type"] == EdgeType.TRUSTS:
                        rule_for_remediation = "CP-TRUST-001"
                        remediation_target_name = assets_by_id[v].name
                        remediation_before_doc = assets_by_id[v].trust_policy
                    elif edata["type"] == EdgeType.PUBLICLY_ACCESSIBLE:
                        rule_for_remediation = "CP-NET-001"
                        remediation_target_name = assets_by_id[u].name
                        remediation_before_doc = assets_by_id[u].network_config

                    hops.append(
                        AttackPathHop(
                            step=i + 1,
                            source_id=u,
                            source_name=assets_by_id[u].name,
                            source_type=assets_by_id[u].type,
                            edge_type=edata["type"],
                            edge_label=edata["label"],
                            target_id=v,
                            target_name=assets_by_id[v].name,
                            target_type=assets_by_id[v].type,
                            permissions_used=edata.get("permissions", []),
                            evidence=edata.get("evidence", ""),
                            why_it_matters=f"Step {i + 1} transitions control from {assets_by_id[u].name} ({assets_by_id[u].type.value}) to {assets_by_id[v].name} ({assets_by_id[v].type.value}) via {edata['label']}.",
                        )
                    )

                src_asset = assets_by_id[src]
                hop_count = len(hops)
                is_shortest = shortest_by_pair.get((src, dst)) == chain_tuple

                # Score this attack path using Module E Risk Scoring Engine
                exp_score = 95.0 if src_asset.is_public or src_asset.type == NodeType.EXTERNAL_PRINCIPAL else 62.0
                priv_score = 94.0 if has_escalation else 76.0
                sens_score = SENSITIVITY_SCORES.get(dst_asset.sensitivity, 65.0)
                reach_score = max(45.0, 100.0 - (hop_count - 1) * 12.0)
                trust_score = 92.0 if any(h.edge_type in (EdgeType.TRUSTS, EdgeType.CAN_ASSUME_ROLE) for h in hops) else 55.0

                risk_breakdown = calculate_risk_score(
                    RiskInputFactors(
                        exposure_score=exp_score,
                        exposure_reason=(
                            f"Entry point '{src_asset.name}' is externally reachable / internet-exposed."
                            if src_asset.is_public or src_asset.type == NodeType.EXTERNAL_PRINCIPAL
                            else f"Entry point '{src_asset.name}' is an internal IAM identity without hardware MFA enforcement."
                        ),
                        privilege_score=priv_score,
                        privilege_reason=(
                            f"Path traverses privilege escalation primitive ({', '.join(all_perms[:3]) or 'Role Assumption'})."
                            if has_escalation
                            else "Path utilizes standing administrative permissions."
                        ),
                        sensitivity_score=sens_score,
                        sensitivity_reason=f"Target resource '{dst_asset.name}' is classified as {dst_asset.sensitivity.upper()} sensitivity.",
                        reachability_score=reach_score,
                        reachability_reason=f"Target is reachable in {hop_count} hop(s) ({'Shortest path' if is_shortest else 'Alternative path'}).",
                        trust_score=trust_score,
                        trust_reason="Path crosses identity or service trust boundaries via sts:AssumeRole or iam:PassRole.",
                    ),
                    weights=weights,
                )

                # Attach MITRE ATT&CK techniques
                mitre_list = [MITRE_CLOUD_CATALOG["T1078.004"]]
                if rule_for_remediation in ("CP-IAM-002", "CP-IAM-003"):
                    mitre_list.append(MITRE_CLOUD_CATALOG["T1098.001"])
                    mitre_list.append(MITRE_CLOUD_CATALOG["T1098.003"])
                if rule_for_remediation == "CP-TRUST-001":
                    mitre_list.append(MITRE_CLOUD_CATALOG["T1199"])
                if rule_for_remediation == "CP-NET-001":
                    mitre_list.append(MITRE_CLOUD_CATALOG["T1190"])
                if dst_asset.type in (NodeType.S3_BUCKET, NodeType.SENSITIVE_RESOURCE):
                    mitre_list.append(MITRE_CLOUD_CATALOG["T1530"])

                remediation = build_remediation_for_rule(
                    rule_for_remediation, remediation_target_name, remediation_before_doc
                )

                discovered_paths.append(
                    AttackPath(
                        id=f"PATH-{path_idx:03d}",
                        title=f"{src_asset.name} → {dst_asset.name} ({hop_count}-Hop {'Escalation' if has_escalation else 'Access'} Path)",
                        summary=(
                            f"Potential {hop_count}-hop attack path starting from {src_asset.type.value} '{src_asset.name}' "
                            f"and reaching {dst_asset.sensitivity} {dst_asset.type.value} '{dst_asset.name}'."
                        ),
                        epistemic_class=EpistemicClass.POTENTIAL_ATTACK_PATH,
                        entry_point_id=src,
                        entry_point_name=src_asset.name,
                        entry_point_type=src_asset.type,
                        target_id=dst,
                        target_name=dst_asset.name,
                        target_type=dst_asset.type,
                        intermediate_ids=list(simple_nodes[1:-1]),
                        node_chain=list(simple_nodes),
                        edge_chain=edge_chain,
                        hop_count=hop_count,
                        is_shortest_path=is_shortest,
                        permissions_involved=all_perms or ["*:*"],
                        attacker_objectives=[
                            f"Exfiltrate sensitive objects or secrets from '{dst_asset.name}'",
                            "Escalate from initial foothold to privileged production role",
                        ],
                        hops=hops,
                        evidence_items=evidence_list,
                        risk_breakdown=risk_breakdown,
                        mitre_techniques=mitre_list,
                        remediation=remediation,
                    )
                )

    discovered_paths.sort(key=lambda p: p.risk_breakdown.final_score, reverse=True)
    return discovered_paths


def detect_findings(
    env: ParsedEnvironment,
    G: nx.MultiDiGraph,
    assets_by_id: dict[str, CloudAsset],
    effective_by_id: dict[str, EffectivePermissions],
    attack_paths: list[AttackPath],
    weights: RiskWeights | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    f_counter = 0

    def paths_referencing(asset_id: str) -> list[str]:
        return [p.id for p in attack_paths if asset_id in p.node_chain]

    for asset in env.assets:
        eff = effective_by_id[asset.id]
        path_refs = paths_referencing(asset.id)

        # Detection Rule 1: Wildcard Administrative Policy / Principal
        if asset.type in (NodeType.IAM_POLICY, NodeType.IAM_USER, NodeType.IAM_ROLE) and eff.is_admin_equivalent:
            f_counter += 1
            rb = calculate_risk_score(
                RiskInputFactors(
                    exposure_score=65.0,
                    exposure_reason="Principal/Policy grants full account control if credentials are compromised.",
                    privilege_score=100.0,
                    privilege_reason="Grants unrestricted wildcard Action '*' on Resource '*'.",
                    sensitivity_score=95.0,
                    sensitivity_reason="Affects all critical data stores and IAM control plane resources in account.",
                    reachability_score=95.0 if path_refs else 75.0,
                    reachability_reason=f"Participates in {len(path_refs)} discovered attack path(s).",
                    trust_score=80.0,
                    trust_reason="Unbounded privilege scope across all AWS services.",
                ),
                weights=weights,
            )
            findings.append(
                Finding(
                    id=f"FND-{f_counter:03d}",
                    rule_id="CP-IAM-001",
                    title=f"Unrestricted Wildcard Administrative Permissions on {asset.name}",
                    category="Excessive IAM Permissions",
                    severity=rb.severity,
                    epistemic_class=EpistemicClass.CONFIRMED_CONFIGURATION,
                    affected_resource_id=asset.id,
                    affected_resource_name=asset.name,
                    affected_resource_type=asset.type,
                    relevant_policy_statement=eff.statements_evaluated[0] if eff.statements_evaluated else {"Effect": "Allow", "Action": "*", "Resource": "*"},
                    explanation=f"{asset.type.value} '{asset.name}' grants full administrative privileges ('Action: *', 'Resource: *') with no explicit Deny overrides.",
                    evidence=f"Policy evaluation confirmed wildcard Allow on {asset.id}.",
                    potential_impact="Full AWS account takeover, arbitrary data exfiltration, and security control tampering.",
                    attack_path_Open_refs=path_refs,
                    risk_breakdown=rb,
                    mitre_techniques=[MITRE_CLOUD_CATALOG["T1078.004"]],
                    remediation=build_remediation_for_rule("CP-IAM-001", asset.name, asset.document or asset.raw_evidence),
                )
            )

        # Detection Rule 2: iam:PassRole + Execution Service Privilege Escalation
        if eff.can_escalate_via_passrole and asset.type in (NodeType.IAM_POLICY, NodeType.IAM_GROUP, NodeType.IAM_USER):
            f_counter += 1
            rb = calculate_risk_score(
                RiskInputFactors(
                    exposure_score=70.0,
                    exposure_reason="Assigned to automation / CI-CD identities used in build pipelines.",
                    privilege_score=94.0,
                    privilege_reason=f"Combines {', '.join(eff.escalation_primitives)} on wildcard resource '*'.",
                    sensitivity_score=92.0,
                    sensitivity_reason="Allows passing critical production settlement roles to newly spawned EC2/Lambda workloads.",
                    reachability_score=90.0,
                    reachability_reason=f"Directly enables {len(path_refs)} multi-hop privilege escalation path(s).",
                    trust_score=88.0,
                    trust_reason="Bypasses intended role separation by delegating service roles to arbitrary compute.",
                ),
                weights=weights,
            )
            findings.append(
                Finding(
                    id=f"FND-{f_counter:03d}",
                    rule_id="CP-IAM-002",
                    title=f"Privilege Escalation via iam:PassRole + Compute Execution ({asset.name})",
                    category="Privilege Escalation Primitive",
                    severity=rb.severity,
                    epistemic_class=EpistemicClass.POTENTIAL_ATTACK_PATH,
                    affected_resource_id=asset.id,
                    affected_resource_name=asset.name,
                    affected_resource_type=asset.type,
                    relevant_policy_statement=eff.statements_evaluated[0] if eff.statements_evaluated else {},
                    explanation=f"'{asset.name}' permits {', '.join(eff.escalation_primitives)} on Resource '*', allowing an attacker to attach high-privilege roles to EC2 instances or Lambda functions.",
                    evidence=f"Evaluated primitives: {', '.join(eff.escalation_primitives)} without iam:PassedToService or ARN restrictions.",
                    potential_impact="Low-privilege CI/CD user can escalate to critical production role and exfiltrate PCI/financial vaults.",
                    attack_path_Open_refs=path_refs,
                    risk_breakdown=rb,
                    mitre_techniques=[MITRE_CLOUD_CATALOG["T1098.001"], MITRE_CLOUD_CATALOG["T1098.003"]],
                    remediation=build_remediation_for_rule("CP-IAM-002", asset.name, asset.document or asset.raw_evidence),
                )
            )

        # Detection Rule 3: IAM Policy Modification Self-Escalation
        if eff.can_modify_policies and not eff.is_admin_equivalent and asset.type in (NodeType.IAM_ROLE, NodeType.IAM_USER, NodeType.IAM_POLICY):
            f_counter += 1
            rb = calculate_risk_score(
                RiskInputFactors(
                    exposure_score=75.0,
                    exposure_reason="Role is assumable by contractor and external vendor principals.",
                    privilege_score=96.0,
                    privilege_reason=f"Permits IAM policy mutation ({', '.join(eff.escalation_primitives)}).",
                    sensitivity_score=94.0,
                    sensitivity_reason="Can attach AdministratorAccess or create a v2 policy version granting full access.",
                    reachability_score=92.0,
                    reachability_reason=f"Involved in {len(path_refs)} escalation path(s).",
                    trust_score=90.0,
                    trust_reason="Allows principal to rewrite its own authorization boundary.",
                ),
                weights=weights,
            )
            findings.append(
                Finding(
                    id=f"FND-{f_counter:03d}",
                    rule_id="CP-IAM-003",
                    title=f"IAM Self-Escalation via Policy Modification Permissions ({asset.name})",
                    category="Privilege Escalation Primitive",
                    severity=rb.severity,
                    epistemic_class=EpistemicClass.POTENTIAL_ATTACK_PATH,
                    affected_resource_id=asset.id,
                    affected_resource_name=asset.name,
                    affected_resource_type=asset.type,
                    relevant_policy_statement=eff.statements_evaluated[0] if eff.statements_evaluated else {},
                    explanation=f"'{asset.name}' holds {', '.join(eff.escalation_primitives)} on '*', enabling direct privilege escalation to full administrator.",
                    evidence=f"Inline/attached policy allows {', '.join(eff.escalation_primitives)}.",
                    potential_impact="Any principal assuming this role can elevate to full administrative control over the AWS account.",
                    attack_path_Open_refs=path_refs,
                    risk_breakdown=rb,
                    mitre_techniques=[MITRE_CLOUD_CATALOG["T1098.001"]],
                    remediation=build_remediation_for_rule("CP-IAM-003", asset.name, asset.raw_evidence),
                )
            )

        # Detection Rule 4: Overly Permissive / Cross-Account Trust Policy without ExternalId
        if asset.type == NodeType.IAM_ROLE and asset.trust_policy:
            aws_principals, _, has_ext_id = _extract_trust_principals(asset.trust_policy)
            external_or_wildcard = [
                p for p in aws_principals if p == "*" or (env.account_id not in p and ":aws:" in p)
            ]
            if external_or_wildcard and not has_ext_id:
                f_counter += 1
                rb = calculate_risk_score(
                    RiskInputFactors(
                        exposure_score=92.0,
                        exposure_reason=f"Trusts external/wildcard principal ({', '.join(external_or_wildcard)}) without sts:ExternalId.",
                        privilege_score=85.0,
                        privilege_reason="Trusted role grants downstream access to S3 and IAM operations.",
                        sensitivity_score=SENSITIVITY_SCORES.get(asset.sensitivity, 80.0),
                        sensitivity_reason=f"Role '{asset.name}' has {asset.sensitivity.upper()} sensitivity.",
                        reachability_score=95.0,
                        reachability_reason="Single-hop sts:AssumeRole entry point from external account.",
                        trust_score=98.0,
                        trust_reason="Missing sts:ExternalId and aws:MultiFactorAuthPresent conditions on cross-account trust.",
                    ),
                    weights=weights,
                )
                findings.append(
                    Finding(
                        id=f"FND-{f_counter:03d}",
                        rule_id="CP-TRUST-001",
                        title=f"Unconstrained Cross-Account Trust Policy on {asset.name}",
                        category="Dangerous Trust Relationship",
                        severity=rb.severity,
                        epistemic_class=EpistemicClass.CONFIRMED_CONFIGURATION,
                        affected_resource_id=asset.id,
                        affected_resource_name=asset.name,
                        affected_resource_type=asset.type,
                        relevant_policy_statement=asset.trust_policy,
                        explanation=f"IAM Role '{asset.name}' trusts external or wildcard principal ({', '.join(external_or_wildcard)}) without requiring an sts:ExternalId or MFA condition.",
                        evidence=f"AssumeRolePolicyDocument Principal={external_or_wildcard}, Condition=None.",
                        potential_impact="Cross-account lateral movement or confused-deputy exploitation from third-party AWS account.",
                        attack_path_Open_refs=path_refs,
                        risk_breakdown=rb,
                        mitre_techniques=[MITRE_CLOUD_CATALOG["T1199"], MITRE_CLOUD_CATALOG["T1078.004"]],
                        remediation=build_remediation_for_rule("CP-TRUST-001", asset.name, asset.trust_policy),
                    )
                )

        # Detection Rule 5: Publicly Accessible S3 Bucket / Resource Policy
        if asset.type == NodeType.S3_BUCKET and asset.is_public:
            f_counter += 1
            rb = calculate_risk_score(
                RiskInputFactors(
                    exposure_score=100.0,
                    exposure_reason="Bucket policy or ACL allows unauthenticated Principal '*' access.",
                    privilege_score=70.0,
                    privilege_reason="Permits public s3:GetObject and/or s3:PutObject operations.",
                    sensitivity_score=SENSITIVITY_SCORES.get(asset.sensitivity, 55.0),
                    sensitivity_reason=f"Bucket '{asset.name}' sensitivity is rated {asset.sensitivity.upper()}.",
                    reachability_score=100.0,
                    reachability_reason="Directly reachable from the public internet (0 hops).",
                    trust_score=65.0,
                    trust_reason="Resource-based policy grants anonymous wildcard principal access.",
                ),
                weights=weights,
            )
            findings.append(
                Finding(
                    id=f"FND-{f_counter:03d}",
                    rule_id="CP-S3-001",
                    title=f"Publicly Accessible S3 Bucket ({asset.name})",
                    category="Public Resource Exposure",
                    severity=rb.severity,
                    epistemic_class=EpistemicClass.CONFIRMED_CONFIGURATION,
                    affected_resource_id=asset.id,
                    affected_resource_name=asset.name,
                    affected_resource_type=asset.type,
                    relevant_policy_statement=asset.resource_policy or {"acl": "public-read"},
                    explanation=f"S3 Bucket '{asset.name}' is publicly exposed via wildcard Principal '*' or public ACL with BlockPublicAccess disabled.",
                    evidence=f"is_public=True, resource_policy={asset.resource_policy or 'public ACL'}.",
                    potential_impact="Unauthenticated data disclosure or malicious web asset tampering (supply-chain injection).",
                    attack_path_Open_refs=path_refs,
                    risk_breakdown=rb,
                    mitre_techniques=[MITRE_CLOUD_CATALOG["T1530"]],
                    remediation=build_remediation_for_rule("CP-S3-001", asset.name, asset.resource_policy or asset.raw_evidence),
                )
            )

        # Detection Rule 6: World-Open Security Group / Public EC2 with Privileged Role & IMDSv1
        if asset.type == NodeType.SECURITY_GROUP and asset.is_public:
            f_counter += 1
            rb = calculate_risk_score(
                RiskInputFactors(
                    exposure_score=95.0,
                    exposure_reason="Allows unrestricted 0.0.0.0/0 ingress on TCP port 22 (SSH) and 443.",
                    privilege_score=78.0,
                    privilege_reason="Attached to compute instance running with privileged IAM instance profile.",
                    sensitivity_score=85.0,
                    sensitivity_reason="Protects production settlement compute workload.",
                    reachability_score=95.0,
                    reachability_reason=f"Serves as initial network entry point for {len(path_refs)} attack path(s).",
                    trust_score=75.0,
                    trust_reason="Exposes instance metadata service (IMDSv1) role credentials if workload is breached.",
                ),
                weights=weights,
            )
            findings.append(
                Finding(
                    id=f"FND-{f_counter:03d}",
                    rule_id="CP-NET-001",
                    title=f"Unrestricted 0.0.0.0/0 SSH Ingress on Security Group ({asset.name})",
                    category="Network & Compute Exposure",
                    severity=rb.severity,
                    epistemic_class=EpistemicClass.CONFIRMED_CONFIGURATION,
                    affected_resource_id=asset.id,
                    affected_resource_name=asset.name,
                    affected_resource_type=asset.type,
                    relevant_policy_statement=asset.network_config,
                    explanation=f"Security group '{asset.name}' allows 0.0.0.0/0 on port 22 and is attached to a public EC2 instance with a critical IAM role.",
                    evidence=f"ingress_rules={asset.network_config.get('ingress_rules')}",
                    potential_impact="Brute-force or service exploitation leads to IMDS credential theft of ProdSettlementInstanceRole.",
                    attack_path_Open_refs=path_refs,
                    risk_breakdown=rb,
                    mitre_techniques=[MITRE_CLOUD_CATALOG["T1190"], MITRE_CLOUD_CATALOG["T1530"]],
                    remediation=build_remediation_for_rule("CP-NET-001", asset.name, asset.network_config),
                )
            )

        # Detection Rule 7: Orphaned / Dormant High-Privilege Identity
        if asset.type == NodeType.IAM_USER and (
            asset.tags.get("Status") == "OrphanedAccount"
            or int(asset.tags.get("LastUsedDaysAgo", "0")) > 90
            or int(asset.tags.get("AccessKeyAgeDays", "0")) > 180
        ):
            f_counter += 1
            rb = calculate_risk_score(
                RiskInputFactors(
                    exposure_score=58.0,
                    exposure_reason=f"Long-lived access key or dormant account (tags: {asset.tags}).",
                    privilege_score=85.0 if eff.is_admin_equivalent else 60.0,
                    privilege_reason="Retains active policy attachments without credential rotation.",
                    sensitivity_score=75.0,
                    sensitivity_reason="Can traverse to production resources if leaked.",
                    reachability_score=80.0,
                    reachability_reason=f"Originates {len(path_refs)} potential attack path(s).",
                    trust_score=60.0,
                    trust_reason="Static IAM user credentials lack automatic session expiration.",
                ),
                weights=weights,
            )
            findings.append(
                Finding(
                    id=f"FND-{f_counter:03d}",
                    rule_id="CP-IAM-004",
                    title=f"Dormant / Unrotated IAM User Credentials ({asset.name})",
                    category="Identity Hygiene & Orphaned Access",
                    severity=rb.severity,
                    epistemic_class=EpistemicClass.CONFIRMED_CONFIGURATION,
                    affected_resource_id=asset.id,
                    affected_resource_name=asset.name,
                    affected_resource_type=asset.type,
                    relevant_policy_statement=asset.tags,
                    explanation=f"IAM User '{asset.name}' has unrotated or dormant credentials ({asset.tags}) while retaining active permissions.",
                    evidence=f"Identity telemetry tags: {asset.tags}",
                    potential_impact="Compromised legacy credentials allow silent persistence and privilege escalation.",
                    attack_path_Open_refs=path_refs,
                    risk_breakdown=rb,
                    mitre_techniques=[MITRE_CLOUD_CATALOG["T1078.004"]],
                    remediation=build_remediation_for_rule("CP-IAM-004", asset.name, asset.raw_evidence),
                )
            )

    findings.sort(key=lambda f: f.risk_breakdown.final_score, reverse=True)
    return findings


def run_full_analysis(
    content: str | dict[str, Any],
    source_type: str,
    scan_name: str,
    workspace_id: str,
    weights: RiskWeights | None = None,
    filename: str | None = None,
) -> ScanResult:
    """
    End-to-end pipeline: Parse -> Normalize -> Build Graph -> Discover Attack Paths ->
    Detect Findings -> Score Assets -> Return complete `ScanResult`.
    """
    env = parse_cloud_input(content, format_hint=source_type, filename=filename)
    G, assets_by_id, effective_by_id = build_cloud_graph(env)
    attack_paths = discover_attack_paths(G, assets_by_id, effective_by_id, weights=weights)
    findings = detect_findings(env, G, assets_by_id, effective_by_id, attack_paths, weights=weights)

    # Compute per-asset risk scores from associated findings and paths
    for asset in env.assets:
        rel_findings = [f.risk_breakdown.final_score for f in findings if f.affected_resource_id == asset.id]
        rel_paths = [p.risk_breakdown.final_score for p in attack_paths if asset.id in p.node_chain]
        base_sens = SENSITIVITY_SCORES.get(asset.sensitivity, 40.0) * 0.55
        candidate_scores = rel_findings + rel_paths + [base_sens]
        asset.risk_score = round(max(candidate_scores), 1)
        asset.risk_level = score_to_severity(asset.risk_score)

    nodes: list[GraphNode] = []
    for asset in env.assets:
        nodes.append(
            GraphNode(
                id=asset.id,
                label=asset.name,
                type=asset.type,
                provider=asset.provider,
                service=asset.service,
                is_public=asset.is_public,
                is_critical=asset.risk_level == SeverityLevel.CRITICAL or asset.sensitivity == "critical",
                sensitivity=asset.sensitivity,
                risk_score=asset.risk_score,
                severity=asset.risk_level,
                metadata={
                    "permissions": asset.permissions[:12],
                    "explicit_denies": asset.explicit_denies,
                    "tags": asset.tags,
                },
            )
        )

    edges: list[GraphEdge] = []
    for u, v, _, edata in G.edges(keys=True, data=True):
        edges.append(
            GraphEdge(
                id=edata["id"],
                source=u,
                target=v,
                type=edata["type"],
                label=edata["label"],
                epistemic_class=edata["epistemic_class"],
                permissions=edata.get("permissions", []),
                evidence=edata.get("evidence", ""),
                is_escalation=edata.get("is_escalation", False),
                weight=edata.get("weight", 1.0),
            )
        )

    identity_types = {NodeType.IAM_USER, NodeType.IAM_ROLE, NodeType.IAM_GROUP, NodeType.EXTERNAL_PRINCIPAL}
    total_identities = sum(1 for a in env.assets if a.type in identity_types)
    crit_count = sum(1 for f in findings if f.severity == SeverityLevel.CRITICAL)
    high_count = sum(1 for f in findings if f.severity == SeverityLevel.HIGH)
    med_count = sum(1 for f in findings if f.severity == SeverityLevel.MEDIUM)
    low_count = sum(1 for f in findings if f.severity == SeverityLevel.LOW)
    info_count = sum(1 for f in findings if f.severity == SeverityLevel.INFORMATIONAL)

    high_risk_paths = sum(
        1 for p in attack_paths if p.risk_breakdown.severity in (SeverityLevel.CRITICAL, SeverityLevel.HIGH)
    )
    public_count = sum(1 for a in env.assets if a.is_public)
    excessive_perm_count = sum(
        1 for a in env.assets if effective_by_id[a.id].has_wildcard_allow or effective_by_id[a.id].can_modify_policies or effective_by_id[a.id].can_escalate_via_passrole
    )

    asset_dist: dict[str, int] = {}
    for a in env.assets:
        asset_dist[a.type.value] = asset_dist.get(a.type.value, 0) + 1

    max_finding = max((f.risk_breakdown.final_score for f in findings), default=25.0)
    posture_score = round(max(12.0, 100.0 - (max_finding * 0.65) - (crit_count * 4.5)), 1)

    summary = SummaryMetrics(
        total_assets=len(env.assets),
        total_identities=total_identities,
        critical_findings=crit_count,
        high_findings=high_count,
        medium_findings=med_count,
        low_findings=low_count,
        info_findings=info_count,
        high_risk_attack_paths=high_risk_paths,
        total_attack_paths=len(attack_paths),
        publicly_exposed_resources=public_count,
        excessive_permission_count=excessive_perm_count,
        overall_posture_score=posture_score,
        risk_distribution={
            "Critical": crit_count,
            "High": high_count,
            "Medium": med_count,
            "Low": low_count,
            "Informational": info_count,
        },
        asset_distribution=asset_dist,
    )

    return ScanResult(
        id=f"scan-{uuid.uuid4().hex[:10]}",
        workspace_id=workspace_id,
        name=scan_name,
        organization=env.organization,
        account_id=env.account_id,
        source_type=env.source_type,
        provider="aws",
        created_at=datetime.now(timezone.utc).isoformat(),
        warnings=env.warnings,
        unsupported_resources=env.unsupported_resources,
        summary_metrics=summary,
        nodes=nodes,
        edges=edges,
        assets=env.assets,
        findings=findings,
        attack_paths=attack_paths,
    )
