/**
 * TypeScript domain types for CloudPath Attack Path Mapper & Identity Risk Intelligence Platform.
 * Matches the FastAPI Pydantic schema 1:1.
 */

export type NodeType =
  | "IAMUser"
  | "IAMRole"
  | "IAMGroup"
  | "IAMPolicy"
  | "S3Bucket"
  | "EC2Instance"
  | "SecurityGroup"
  | "VPC"
  | "ExternalPrincipal"
  | "SensitiveResource"
  | "TrustRelationship";

export type EdgeType =
  | "ASSIGNED_POLICY"
  | "MEMBER_OF"
  | "CAN_ASSUME_ROLE"
  | "TRUSTS"
  | "HAS_PERMISSION"
  | "PUBLICLY_ACCESSIBLE"
  | "CAN_ACCESS"
  | "CONNECTS_TO"
  | "CONTROLS_RESOURCE";

export type SeverityLevel =
  | "Critical"
  | "High"
  | "Medium"
  | "Low"
  | "Informational";

export type EpistemicClass =
  | "Confirmed Configuration Relationship"
  | "Potential Attack Path (Policy Evaluation)"
  | "Hypothetical Attack Scenario"
  | "Observed Security Incident";

export interface RiskWeights {
  exposure: number;
  privilege: number;
  sensitivity: number;
  reachability: number;
  trust: number;
}

export interface RiskFactorScore {
  factor: string;
  raw_score: number;
  weight: number;
  weighted_contribution: number;
  justification: string;
}

export interface RiskBreakdown {
  final_score: number;
  severity: SeverityLevel;
  confidence: number;
  confidence_reason: string;
  formula_summary: string;
  factors: RiskFactorScore[];
}

export interface MitreTechnique {
  technique_id: string;
  tactic: string;
  name: string;
  url: string;
  mapping_note: string;
}

export interface RemediationGuidance {
  title: string;
  summary: string;
  why_it_matters: string;
  operational_impact: string;
  priority: string;
  before_config: string;
  suggested_config: string;
}

export interface CloudAsset {
  id: string;
  name: string;
  type: NodeType;
  provider: string;
  service: string;
  account_id: string;
  region: string;
  is_public: boolean;
  sensitivity: string;
  associated_identity?: string | null;
  permissions: string[];
  explicit_denies: string[];
  attached_policies: string[];
  inline_policies: Record<string, unknown>[];
  groups: string[];
  trust_policy?: Record<string, unknown> | null;
  resource_policy?: Record<string, unknown> | null;
  document?: Record<string, unknown> | null;
  network_config: Record<string, unknown>;
  tags: Record<string, string>;
  raw_evidence: Record<string, unknown>;
  risk_score: number;
  risk_level: SeverityLevel;
  relationships_summary: string[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: NodeType;
  provider: string;
  service: string;
  is_public: boolean;
  is_critical: boolean;
  sensitivity: string;
  risk_score: number;
  severity: SeverityLevel;
  metadata: {
    permissions?: string[];
    explicit_denies?: string[];
    tags?: Record<string, string>;
  };
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  type: EdgeType;
  label: string;
  epistemic_class: EpistemicClass;
  permissions: string[];
  evidence: string;
  is_escalation: boolean;
  weight: number;
}

export interface AttackPathHop {
  step: number;
  source_id: string;
  source_name: string;
  source_type: NodeType;
  edge_type: EdgeType;
  edge_label: string;
  target_id: string;
  target_name: string;
  target_type: NodeType;
  permissions_used: string[];
  evidence: string;
  why_it_matters: string;
}

export interface AttackPath {
  id: string;
  title: string;
  summary: string;
  epistemic_class: EpistemicClass;
  entry_point_id: string;
  entry_point_name: string;
  entry_point_type: NodeType;
  target_id: string;
  target_name: string;
  target_type: NodeType;
  intermediate_ids: string[];
  node_chain: string[];
  edge_chain: string[];
  hop_count: number;
  is_shortest_path: boolean;
  permissions_involved: string[];
  attacker_objectives: string[];
  hops: AttackPathHop[];
  evidence_items: string[];
  risk_breakdown: RiskBreakdown;
  mitre_techniques: MitreTechnique[];
  remediation: RemediationGuidance;
}

export interface Finding {
  id: string;
  rule_id: string;
  title: string;
  category: string;
  severity: SeverityLevel;
  epistemic_class: EpistemicClass;
  affected_resource_id: string;
  affected_resource_name: string;
  affected_resource_type: NodeType;
  relevant_policy_statement: Record<string, unknown>;
  explanation: string;
  evidence: string;
  potential_impact: string;
  attack_path_Open_refs: string[];
  risk_breakdown: RiskBreakdown;
  mitre_techniques: MitreTechnique[];
  remediation: RemediationGuidance;
}

export interface SummaryMetrics {
  total_assets: number;
  total_identities: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  info_findings: number;
  high_risk_attack_paths: number;
  total_attack_paths: number;
  publicly_exposed_resources: number;
  excessive_permission_count: number;
  overall_posture_score: number;
  risk_distribution: Record<string, number>;
  asset_distribution: Record<string, number>;
}

export interface ScanResult {
  id: string;
  workspace_id: string;
  name: string;
  organization: string;
  account_id: string;
  source_type: string;
  provider: string;
  created_at: string;
  warnings: string[];
  unsupported_resources: string[];
  summary_metrics: SummaryMetrics;
  nodes: GraphNode[];
  edges: GraphEdge[];
  assets: CloudAsset[];
  findings: Finding[];
  attack_paths: AttackPath[];
}

export type ActiveTab =
  | "landing"
  | "dashboard"
  | "graph"
  | "findings"
  | "assets"
  | "investigations"
  | "reports"
  | "import"
  | "settings";
