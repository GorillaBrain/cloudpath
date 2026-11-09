"""
Pydantic domain models for CloudPath Attack Path Mapper & Identity Risk Intelligence Platform.
"""

from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class NodeType(str, Enum):
    IAM_USER = "IAMUser"
    IAM_ROLE = "IAMRole"
    IAM_GROUP = "IAMGroup"
    IAM_POLICY = "IAMPolicy"
    S3_BUCKET = "S3Bucket"
    EC2_INSTANCE = "EC2Instance"
    SECURITY_GROUP = "SecurityGroup"
    VPC = "VPC"
    EXTERNAL_PRINCIPAL = "ExternalPrincipal"
    SENSITIVE_RESOURCE = "SensitiveResource"
    TRUST_RELATIONSHIP = "TrustRelationship"


class EdgeType(str, Enum):
    ASSIGNED_POLICY = "ASSIGNED_POLICY"
    MEMBER_OF = "MEMBER_OF"
    CAN_ASSUME_ROLE = "CAN_ASSUME_ROLE"
    TRUSTS = "TRUSTS"
    HAS_PERMISSION = "HAS_PERMISSION"
    PUBLICLY_ACCESSIBLE = "PUBLICLY_ACCESSIBLE"
    CAN_ACCESS = "CAN_ACCESS"
    CONNECTS_TO = "CONNECTS_TO"
    CONTROLS_RESOURCE = "CONTROLS_RESOURCE"


class SeverityLevel(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFORMATIONAL = "Informational"


class EpistemicClass(str, Enum):
    CONFIRMED_CONFIGURATION = "Confirmed Configuration Relationship"
    POTENTIAL_ATTACK_PATH = "Potential Attack Path (Policy Evaluation)"
    HYPOTHETICAL_SCENARIO = "Hypothetical Attack Scenario"
    OBSERVED_INCIDENT = "Observed Security Incident"


class RiskWeights(BaseModel):
    exposure: float = Field(default=0.25, ge=0.0, le=1.0)
    privilege: float = Field(default=0.25, ge=0.0, le=1.0)
    sensitivity: float = Field(default=0.20, ge=0.0, le=1.0)
    reachability: float = Field(default=0.15, ge=0.0, le=1.0)
    trust: float = Field(default=0.15, ge=0.0, le=1.0)

    def normalized(self) -> dict[str, float]:
        total = self.exposure + self.privilege + self.sensitivity + self.reachability + self.trust
        if total <= 0:
            return {
                "exposure": 0.25,
                "privilege": 0.25,
                "sensitivity": 0.20,
                "reachability": 0.15,
                "trust": 0.15,
            }
        return {
            "exposure": self.exposure / total,
            "privilege": self.privilege / total,
            "sensitivity": self.sensitivity / total,
            "reachability": self.reachability / total,
            "trust": self.trust / total,
        }


class RiskFactorScore(BaseModel):
    factor: str
    raw_score: float = Field(ge=0.0, le=100.0)
    weight: float
    weighted_contribution: float
    justification: str


class RiskBreakdown(BaseModel):
    final_score: float = Field(ge=0.0, le=100.0)
    severity: SeverityLevel
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    confidence_reason: str = "Complete static policy and resource configuration available."
    formula_summary: str
    factors: list[RiskFactorScore]


class MitreTechnique(BaseModel):
    technique_id: str
    tactic: str
    name: str
    url: str
    mapping_note: str


class RemediationGuidance(BaseModel):
    title: str
    summary: str
    why_it_matters: str
    operational_impact: str
    priority: str
    before_config: str
    suggested_config: str


class CloudAsset(BaseModel):
    id: str
    name: str
    type: NodeType
    provider: str = "aws"
    service: str = "iam"
    account_id: str = "492018472910"
    region: str = "us-east-1"
    is_public: bool = False
    sensitivity: str = "medium"  # low, medium, high, critical
    associated_identity: str | None = None
    permissions: list[str] = Field(default_factory=list)
    explicit_denies: list[str] = Field(default_factory=list)
    attached_policies: list[str] = Field(default_factory=list)
    inline_policies: list[dict[str, Any]] = Field(default_factory=list)
    groups: list[str] = Field(default_factory=list)
    trust_policy: dict[str, Any] | None = None
    resource_policy: dict[str, Any] | None = None
    document: dict[str, Any] | None = None
    network_config: dict[str, Any] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)
    raw_evidence: dict[str, Any] = Field(default_factory=dict)
    risk_score: float = 0.0
    risk_level: SeverityLevel = SeverityLevel.INFORMATIONAL
    relationships_summary: list[str] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    type: NodeType
    provider: str = "aws"
    service: str = "iam"
    is_public: bool = False
    is_critical: bool = False
    sensitivity: str = "medium"
    risk_score: float = 0.0
    severity: SeverityLevel = SeverityLevel.INFORMATIONAL
    metadata: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    type: EdgeType
    label: str
    epistemic_class: EpistemicClass = EpistemicClass.CONFIRMED_CONFIGURATION
    permissions: list[str] = Field(default_factory=list)
    evidence: str = ""
    is_escalation: bool = False
    weight: float = 1.0


class AttackPathHop(BaseModel):
    step: int
    source_id: str
    source_name: str
    source_type: NodeType
    edge_type: EdgeType
    edge_label: str
    target_id: str
    target_name: str
    target_type: NodeType
    permissions_used: list[str] = Field(default_factory=list)
    evidence: str = ""
    why_it_matters: str = ""


class AttackPath(BaseModel):
    id: str
    title: str
    summary: str
    epistemic_class: EpistemicClass = EpistemicClass.POTENTIAL_ATTACK_PATH
    entry_point_id: str
    entry_point_name: str
    entry_point_type: NodeType
    target_id: str
    target_name: str
    target_type: NodeType
    intermediate_ids: list[str] = Field(default_factory=list)
    node_chain: list[str] = Field(default_factory=list)
    edge_chain: list[str] = Field(default_factory=list)
    hop_count: int
    is_shortest_path: bool = False
    permissions_involved: list[str] = Field(default_factory=list)
    attacker_objectives: list[str] = Field(default_factory=list)
    hops: list[AttackPathHop] = Field(default_factory=list)
    evidence_items: list[str] = Field(default_factory=list)
    risk_breakdown: RiskBreakdown
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    remediation: RemediationGuidance


class Finding(BaseModel):
    id: str
    rule_id: str
    title: str
    category: str
    severity: SeverityLevel
    epistemic_class: EpistemicClass = EpistemicClass.CONFIRMED_CONFIGURATION
    affected_resource_id: str
    affected_resource_name: str
    affected_resource_type: NodeType
    relevant_policy_statement: dict[str, Any] = Field(default_factory=dict)
    explanation: str
    evidence: str
    potential_impact: str
    attack_path_Open_refs: list[str] = Field(default_factory=list)
    risk_breakdown: RiskBreakdown
    mitre_techniques: list[MitreTechnique] = Field(default_factory=list)
    remediation: RemediationGuidance


class SummaryMetrics(BaseModel):
    total_assets: int
    total_identities: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    high_risk_attack_paths: int
    total_attack_paths: int
    publicly_exposed_resources: int
    excessive_permission_count: int
    overall_posture_score: float
    risk_distribution: dict[str, int]
    asset_distribution: dict[str, int]


class ScanResult(BaseModel):
    id: str
    workspace_id: str
    name: str
    organization: str
    account_id: str
    source_type: str
    provider: str = "aws"
    created_at: str
    warnings: list[str] = Field(default_factory=list)
    unsupported_resources: list[str] = Field(default_factory=list)
    summary_metrics: SummaryMetrics
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    assets: list[CloudAsset]
    findings: list[Finding]
    attack_paths: list[AttackPath]
