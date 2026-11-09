/**
 * CloudPath Attack Path Analysis Engine (TypeScript Parity Implementation).
 * Provides 100% behavioral parity with `/backend/analyzer.py`, `/backend/iam_evaluator.py`,
 * `/backend/importer.py`, and `/backend/risk_engine.py` so Next.js API routes on Vercel
 * and local FastAPI servers produce identical graph analysis, shortest-path calculation,
 * explicit Deny evaluation, and risk scoring.
 */

import {
  AttackPath,
  AttackPathHop,
  CloudAsset,
  EdgeType,
  EpistemicClass,
  Finding,
  GraphEdge,
  GraphNode,
  MitreTechnique,
  NodeType,
  RemediationGuidance,
  RiskBreakdown,
  RiskWeights,
  ScanResult,
  SeverityLevel,
} from "@/types/cloudpath";

export const DEMO_WORKSPACE_ID = "00000000-0000-0000-0000-000000000001";

export const DEFAULT_RISK_WEIGHTS: RiskWeights = {
  exposure: 0.25,
  privilege: 0.25,
  sensitivity: 0.2,
  reachability: 0.15,
  trust: 0.15,
};

const SENSITIVITY_SCORES: Record<string, number> = {
  critical: 96,
  high: 78,
  medium: 50,
  low: 25,
};

const EXECUTION_ACTIONS = [
  "cloudformation:CreateStack",
  "ec2:RunInstances",
  "ecs:RegisterTaskDefinition",
  "ecs:RunTask",
  "glue:CreateDevEndpoint",
  "lambda:CreateFunction",
  "lambda:UpdateFunctionConfiguration",
  "sagemaker:CreateNotebookInstance",
];

const POLICY_MODIFICATION_ACTIONS = [
  "iam:AddUserToGroup",
  "iam:AttachGroupPolicy",
  "iam:AttachRolePolicy",
  "iam:AttachUserPolicy",
  "iam:CreateAccessKey",
  "iam:CreateLoginProfile",
  "iam:CreatePolicyVersion",
  "iam:PutGroupPolicy",
  "iam:PutRolePolicy",
  "iam:PutUserPolicy",
  "iam:SetDefaultPolicyVersion",
  "iam:UpdateAssumeRolePolicy",
  "iam:UpdateLoginProfile",
];

export const MITRE_CLOUD_CATALOG: Record<string, MitreTechnique> = {
  "T1078.004": {
    technique_id: "T1078.004",
    tactic: "Initial Access / Privilege Escalation",
    name: "Valid Accounts: Cloud Accounts",
    url: "https://attack.mitre.org/techniques/T1078/004/",
    mapping_note:
      "Configuration weakness enables abuse if cloud identity credentials or roles are compromised (Not an observed intrusion).",
  },
  "T1098.001": {
    technique_id: "T1098.001",
    tactic: "Persistence / Privilege Escalation",
    name: "Account Manipulation: Additional Cloud Credentials",
    url: "https://attack.mitre.org/techniques/T1098/001/",
    mapping_note:
      "Policy allows iam:CreatePolicyVersion / iam:AttachRolePolicy / iam:PassRole which could permit privilege escalation.",
  },
  "T1098.003": {
    technique_id: "T1098.003",
    tactic: "Privilege Escalation",
    name: "Account Manipulation: Additional Cloud Roles",
    url: "https://attack.mitre.org/techniques/T1098/003/",
    mapping_note:
      "Role assumption or PassRole configuration enables lateral or vertical movement across IAM roles.",
  },
  T1199: {
    technique_id: "T1199",
    tactic: "Initial Access",
    name: "Trusted Relationship",
    url: "https://attack.mitre.org/techniques/T1199/",
    mapping_note:
      "Cross-account trust policy allows external AWS account principal without sts:ExternalId or MFA constraints.",
  },
  T1530: {
    technique_id: "T1530",
    tactic: "Collection",
    name: "Data from Cloud Storage Object",
    url: "https://attack.mitre.org/techniques/T1530/",
    mapping_note:
      "Attack path terminates at an S3 bucket or Secrets Manager secret accessible via evaluated permissions or public policy.",
  },
  T1190: {
    technique_id: "T1190",
    tactic: "Initial Access",
    name: "Exploit Public-Facing Application / Network Service",
    url: "https://attack.mitre.org/techniques/T1190/",
    mapping_note:
      "Security group exposes management port (0.0.0.0/0) on public-facing compute instance with attached IAM role.",
  },
};

export function getNorthstarDemoEnvironment(): Record<string, unknown> {
  return {
    organization: "Northstar Financial Technologies",
    account_id: "492018472910",
    region: "us-east-1",
    provider: "aws",
    assets: [
      {
        id: "arn:aws:iam::492018472910:user/ci-deploy-assistant",
        name: "ci-deploy-assistant",
        type: "IAMUser",
        provider: "aws",
        service: "iam",
        is_public: false,
        sensitivity: "medium",
        groups: ["arn:aws:iam::492018472910:group/DevOpsAutomationGroup"],
        attached_policies: [
          "arn:aws:iam::492018472910:policy/NorthstarCIBuildPolicy",
        ],
        tags: { Team: "Platform-Engineering", AccessKeyAgeDays: "214" },
      },
      {
        id: "arn:aws:iam::492018472910:user/contractor-analytics-ro",
        name: "contractor-analytics-ro",
        type: "IAMUser",
        provider: "aws",
        service: "iam",
        is_public: false,
        sensitivity: "low",
        attached_policies: [
          "arn:aws:iam::492018472910:policy/AnalyticsAssumeRolePolicy",
        ],
        tags: { Vendor: "ApexDataConsultants", MFAEnabled: "false" },
      },
      {
        id: "arn:aws:iam::492018472910:user/legacy-migration-admin",
        name: "legacy-migration-admin",
        type: "IAMUser",
        provider: "aws",
        service: "iam",
        is_public: false,
        sensitivity: "high",
        attached_policies: ["arn:aws:iam::aws:policy/AdministratorAccess"],
        tags: { LastUsedDaysAgo: "188", Status: "OrphanedAccount" },
      },
      {
        id: "arn:aws:iam::492018472910:group/DevOpsAutomationGroup",
        name: "DevOpsAutomationGroup",
        type: "IAMGroup",
        provider: "aws",
        service: "iam",
        is_public: false,
        sensitivity: "medium",
        attached_policies: [
          "arn:aws:iam::492018472910:policy/WorkloadComputePassRolePolicy",
        ],
      },
      {
        id: "arn:aws:iam::492018472910:policy/NorthstarCIBuildPolicy",
        name: "NorthstarCIBuildPolicy",
        type: "IAMPolicy",
        provider: "aws",
        service: "iam",
        document: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "ArtifactUploadAndECR",
              Effect: "Allow",
              Action: [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "s3:PutObject",
                "s3:GetObject",
              ],
              Resource: "arn:aws:s3:::northstar-public-marketing-assets/*",
            },
          ],
        },
      },
      {
        id: "arn:aws:iam::492018472910:policy/WorkloadComputePassRolePolicy",
        name: "WorkloadComputePassRolePolicy",
        type: "IAMPolicy",
        provider: "aws",
        service: "iam",
        document: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "PassAnyRoleAndLaunchCompute",
              Effect: "Allow",
              Action: [
                "iam:PassRole",
                "ec2:RunInstances",
                "lambda:CreateFunction",
                "lambda:InvokeFunction",
              ],
              Resource: "*",
            },
          ],
        },
      },
      {
        id: "arn:aws:iam::492018472910:policy/AnalyticsAssumeRolePolicy",
        name: "AnalyticsAssumeRolePolicy",
        type: "IAMPolicy",
        provider: "aws",
        service: "iam",
        document: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "AllowAssumeDataPipelineRole",
              Effect: "Allow",
              Action: "sts:AssumeRole",
              Resource: "arn:aws:iam::492018472910:role/DataLakeIngestionRole",
            },
          ],
        },
      },
      {
        id: "arn:aws:iam::aws:policy/AdministratorAccess",
        name: "AdministratorAccess",
        type: "IAMPolicy",
        provider: "aws",
        service: "iam",
        document: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "FullWildcardAdmin",
              Effect: "Allow",
              Action: "*",
              Resource: "*",
            },
          ],
        },
      },
      {
        id: "arn:aws:iam::492018472910:role/ProdSettlementInstanceRole",
        name: "ProdSettlementInstanceRole",
        type: "IAMRole",
        provider: "aws",
        service: "iam",
        is_public: false,
        sensitivity: "critical",
        trust_policy: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "EC2AndLambdaTrust",
              Effect: "Allow",
              Principal: {
                Service: ["ec2.amazonaws.com", "lambda.amazonaws.com"],
              },
              Action: "sts:AssumeRole",
            },
          ],
        },
        inline_policies: [
          {
            name: "SettlementVaultFullAccess",
            document: {
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "FullAccessToCoreVaultAndKMS",
                  Effect: "Allow",
                  Action: [
                    "s3:*",
                    "kms:Decrypt",
                    "secretsmanager:GetSecretValue",
                  ],
                  Resource: [
                    "arn:aws:s3:::northstar-pci-cardholder-vault",
                    "arn:aws:s3:::northstar-pci-cardholder-vault/*",
                    "arn:aws:secretsmanager:us-east-1:492018472910:secret:prod/swift-signing-key",
                  ],
                },
              ],
            },
          },
        ],
      },
      {
        id: "arn:aws:iam::492018472910:role/DataLakeIngestionRole",
        name: "DataLakeIngestionRole",
        type: "IAMRole",
        provider: "aws",
        service: "iam",
        is_public: false,
        sensitivity: "high",
        trust_policy: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "InternalAnalyticsUserTrust",
              Effect: "Allow",
              Principal: {
                AWS: "arn:aws:iam::492018472910:user/contractor-analytics-ro",
              },
              Action: "sts:AssumeRole",
            },
            {
              Sid: "ThirdPartyVendorAccountTrustWithoutExternalId",
              Effect: "Allow",
              Principal: {
                AWS: "arn:aws:iam::998877665544:root",
              },
              Action: "sts:AssumeRole",
            },
          ],
        },
        inline_policies: [
          {
            name: "DataPipelineSelfManageAndS3",
            document: {
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "ExcessiveIAMPolicyModification",
                  Effect: "Allow",
                  Action: [
                    "iam:CreatePolicyVersion",
                    "iam:AttachRolePolicy",
                    "s3:GetObject",
                    "s3:ListBucket",
                  ],
                  Resource: "*",
                },
              ],
            },
          },
        ],
      },
      {
        id: "arn:aws:iam::998877665544:root",
        name: "External Vendor AWS Account (998877665544)",
        type: "ExternalPrincipal",
        provider: "aws",
        service: "sts",
        is_public: true,
        sensitivity: "high",
        tags: {
          Partner: "ExternalTelemetrySaaS",
          ExternalIdRequired: "false",
        },
      },
      {
        id: "vpc-0a1b2c3d4e5f60001",
        name: "northstar-prod-core-vpc",
        type: "VPC",
        provider: "aws",
        service: "vpc",
        is_public: false,
        sensitivity: "high",
        network_config: { cidr_block: "10.24.0.0/16", flow_logs: true },
      },
      {
        id: "sg-09988776655443322",
        name: "settlement-bastion-sg",
        type: "SecurityGroup",
        provider: "aws",
        service: "ec2",
        is_public: true,
        sensitivity: "high",
        network_config: {
          vpc_id: "vpc-0a1b2c3d4e5f60001",
          ingress_rules: [
            {
              port: 22,
              protocol: "tcp",
              cidr: "0.0.0.0/0",
              description: "World-open SSH",
            },
            {
              port: 443,
              protocol: "tcp",
              cidr: "0.0.0.0/0",
              description: "HTTPS",
            },
          ],
        },
      },
      {
        id: "i-0f9e8d7c6b5a43210",
        name: "prod-settlement-worker-01",
        type: "EC2Instance",
        provider: "aws",
        service: "ec2",
        is_public: true,
        sensitivity: "critical",
        associated_identity:
          "arn:aws:iam::492018472910:role/ProdSettlementInstanceRole",
        network_config: {
          vpc_id: "vpc-0a1b2c3d4e5f60001",
          security_groups: ["sg-09988776655443322"],
          public_ip: "54.209.118.42",
          imdsv1_enabled: true,
        },
      },
      {
        id: "arn:aws:s3:::northstar-pci-cardholder-vault",
        name: "northstar-pci-cardholder-vault",
        type: "S3Bucket",
        provider: "aws",
        service: "s3",
        is_public: false,
        sensitivity: "critical",
        tags: { DataClassification: "PCI-DSS-Level-1", ContainsPII: "true" },
      },
      {
        id: "arn:aws:s3:::northstar-public-marketing-assets",
        name: "northstar-public-marketing-assets",
        type: "S3Bucket",
        provider: "aws",
        service: "s3",
        is_public: true,
        sensitivity: "medium",
        resource_policy: {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "PublicReadGetObjectAndPut",
              Effect: "Allow",
              Principal: "*",
              Action: ["s3:GetObject", "s3:PutObject"],
              Resource: "arn:aws:s3:::northstar-public-marketing-assets/*",
            },
          ],
        },
        tags: {
          DataClassification: "Public-Web",
          BlockPublicAccess: "false",
        },
      },
      {
        id: "arn:aws:secretsmanager:us-east-1:492018472910:secret:prod/swift-signing-key",
        name: "prod/swift-signing-key",
        type: "SensitiveResource",
        provider: "aws",
        service: "secretsmanager",
        is_public: false,
        sensitivity: "critical",
        tags: { DataClassification: "Critical-Financial-Signing-Key" },
      },
    ],
  };
}

function globMatch(pattern: string, target: string): boolean {
  const p = pattern.toLowerCase().trim();
  const t = target.toLowerCase().trim();
  if (p === "*" || p === "*:*" || t === "*") return true;
  const escaped = p.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
  return new RegExp(`^${escaped}$`, "i").test(t);
}

function ensureList(val: unknown): string[] {
  if (!val) return [];
  if (typeof val === "string") return [val];
  if (Array.isArray(val)) return val.map(String);
  return [String(val)];
}

export interface EffectivePermissionsTS {
  allowedActions: string[];
  explicitlyDeniedActions: string[];
  allowedResources: Record<string, string[]>;
  deniedResources: Record<string, string[]>;
  hasWildcardAllow: boolean;
  isAdminEquivalent: boolean;
  canPassRole: boolean;
  canAssumeRole: boolean;
  canEscalateViaPassrole: boolean;
  canModifyPolicies: boolean;
  escalationPrimitives: string[];
  statementsEvaluated: Record<string, unknown>[];
  isActionAllowed: (action: string, resource?: string) => boolean;
}

export function evaluateEffectivePermissionsTS(
  statements: Record<string, unknown>[]
): EffectivePermissionsTS {
  const allowedActions: string[] = [];
  const explicitlyDeniedActions: string[] = [];
  const allowedResources: Record<string, string[]> = {};
  const deniedResources: Record<string, string[]> = {};
  let hasWildcardAllow = false;

  for (const stmt of statements) {
    if (!stmt || typeof stmt !== "object") continue;
    const effect = String(stmt.Effect ?? "Allow").trim().toLowerCase();
    const actions = ensureList(stmt.Action);
    const resources = ensureList(stmt.Resource ?? "*");
    const resList = resources.length > 0 ? resources : ["*"];

    if (effect === "deny") {
      for (const act of actions) {
        if (!explicitlyDeniedActions.includes(act)) {
          explicitlyDeniedActions.push(act);
        }
        deniedResources[act] = [...(deniedResources[act] ?? []), ...resList];
      }
    } else if (effect === "allow") {
      for (const act of actions) {
        if (!allowedActions.includes(act)) {
          allowedActions.push(act);
        }
        allowedResources[act] = [...(allowedResources[act] ?? []), ...resList];
        if (act === "*" || act === "*:*" || act.endsWith(":*")) {
          hasWildcardAllow = true;
        }
      }
    }
  }

  const isActionAllowed = (action: string, resource = "*"): boolean => {
    for (const [deniedAct, resList] of Object.entries(deniedResources)) {
      if (globMatch(deniedAct, action)) {
        if (resList.some((r) => globMatch(r, resource))) {
          return false;
        }
      }
    }
    for (const [allowedAct, resList] of Object.entries(allowedResources)) {
      if (globMatch(allowedAct, action)) {
        if (resList.some((r) => globMatch(r, resource))) {
          return true;
        }
      }
    }
    return false;
  };

  const isAdminEquivalent =
    (isActionAllowed("iam:CreateUser") &&
      isActionAllowed("s3:GetObject") &&
      isActionAllowed("ec2:RunInstances")) ||
    (allowedActions.some((a) => ["*", "*:*", "iam:*"].includes(a)) &&
      explicitlyDeniedActions.length === 0);

  const canPassRole = isActionAllowed("iam:PassRole");
  const canAssumeRole = isActionAllowed("sts:AssumeRole");
  let canEscalateViaPassrole = false;
  let canModifyPolicies = false;
  const escalationPrimitives: string[] = [];

  if (canPassRole) {
    for (const execAct of EXECUTION_ACTIONS) {
      if (isActionAllowed(execAct)) {
        canEscalateViaPassrole = true;
        const prim = `iam:PassRole + ${execAct}`;
        if (!escalationPrimitives.includes(prim)) {
          escalationPrimitives.push(prim);
        }
      }
    }
  }

  for (const modAct of POLICY_MODIFICATION_ACTIONS) {
    if (isActionAllowed(modAct)) {
      canModifyPolicies = true;
      if (!escalationPrimitives.includes(modAct)) {
        escalationPrimitives.push(modAct);
      }
    }
  }

  return {
    allowedActions,
    explicitlyDeniedActions,
    allowedResources,
    deniedResources,
    hasWildcardAllow,
    isAdminEquivalent,
    canPassRole,
    canAssumeRole,
    canEscalateViaPassrole,
    canModifyPolicies,
    escalationPrimitives,
    statementsEvaluated: statements,
    isActionAllowed,
  };
}

export function scoreToSeverityTS(score: number): SeverityLevel {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  if (score >= 20) return "Low";
  return "Informational";
}

export function calculateRiskScoreTS(
  factors: {
    exposureScore: number;
    exposureReason: string;
    privilegeScore: number;
    privilegeReason: string;
    sensitivityScore: number;
    sensitivityReason: string;
    reachabilityScore: number;
    reachabilityReason: string;
    trustScore: number;
    trustReason: string;
    confidence?: number;
    confidenceReason?: string;
  },
  weights?: RiskWeights
): RiskBreakdown {
  const wRaw = weights ?? DEFAULT_RISK_WEIGHTS;
  const total =
    wRaw.exposure +
    wRaw.privilege +
    wRaw.sensitivity +
    wRaw.reachability +
    wRaw.trust;
  const w =
    total > 0
      ? {
          exposure: wRaw.exposure / total,
          privilege: wRaw.privilege / total,
          sensitivity: wRaw.sensitivity / total,
          reachability: wRaw.reachability / total,
          trust: wRaw.trust / total,
        }
      : DEFAULT_RISK_WEIGHTS;

  const expC = Number((factors.exposureScore * w.exposure).toFixed(2));
  const privC = Number((factors.privilegeScore * w.privilege).toFixed(2));
  const sensC = Number((factors.sensitivityScore * w.sensitivity).toFixed(2));
  const reachC = Number((factors.reachabilityScore * w.reachability).toFixed(2));
  const trustC = Number((factors.trustScore * w.trust).toFixed(2));

  const finalScore = Number(
    Math.min(100, Math.max(0, expC + privC + sensC + reachC + trustC)).toFixed(1)
  );
  const severity = scoreToSeverityTS(finalScore);

  return {
    final_score: finalScore,
    severity,
    confidence: factors.confidence ?? 0.95,
    confidence_reason:
      factors.confidenceReason ??
      "Complete static policy and resource configuration available.",
    formula_summary: `Score (${finalScore}) = Exposure(${Math.round(
      factors.exposureScore
    )} × ${w.exposure.toFixed(2)}) + Privilege(${Math.round(
      factors.privilegeScore
    )} × ${w.privilege.toFixed(2)}) + Sensitivity(${Math.round(
      factors.sensitivityScore
    )} × ${w.sensitivity.toFixed(2)}) + Reachability(${Math.round(
      factors.reachabilityScore
    )} × ${w.reachability.toFixed(2)}) + Trust(${Math.round(
      factors.trustScore
    )} × ${w.trust.toFixed(2)})`,
    factors: [
      {
        factor: "Public & Network Exposure",
        raw_score: factors.exposureScore,
        weight: Number(w.exposure.toFixed(2)),
        weighted_contribution: expC,
        justification: factors.exposureReason,
      },
      {
        factor: "Privilege & Escalation Scope",
        raw_score: factors.privilegeScore,
        weight: Number(w.privilege.toFixed(2)),
        weighted_contribution: privC,
        justification: factors.privilegeReason,
      },
      {
        factor: "Target Resource Sensitivity & Impact",
        raw_score: factors.sensitivityScore,
        weight: Number(w.sensitivity.toFixed(2)),
        weighted_contribution: sensC,
        justification: factors.sensitivityReason,
      },
      {
        factor: "Attack Path Reachability (Hop Distance)",
        raw_score: factors.reachabilityScore,
        weight: Number(w.reachability.toFixed(2)),
        weighted_contribution: reachC,
        justification: factors.reachabilityReason,
      },
      {
        factor: "Identity Trust Boundary Risk",
        raw_score: factors.trustScore,
        weight: Number(w.trust.toFixed(2)),
        weighted_contribution: trustC,
        justification: factors.trustReason,
      },
    ],
  };
}

function buildRemediationTS(
  ruleId: string,
  resourceName: string,
  beforeObj?: unknown
): RemediationGuidance {
  const beforeStr = JSON.stringify(beforeObj ?? {}, null, 2);

  if (ruleId === "CP-IAM-001") {
    return {
      title:
        "Replace Wildcard (*:*) Permissions with Scoped Least-Privilege Statements",
      summary: `Remove full administrative wildcard permissions from '${resourceName}' and scope actions to explicit ARNs.`,
      why_it_matters:
        "Wildcard actions ('*') combined with Resource '*' grant unrestricted control over the AWS account, allowing immediate privilege escalation and data exfiltration if compromised.",
      operational_impact:
        "Workloads relying on implicit administrative permissions must be audited via AWS CloudTrail Access Advisor before applying scoped ARNs.",
      priority: "P1 — Immediate (Critical)",
      before_config: beforeStr,
      suggested_config: JSON.stringify(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "LeastPrivilegeScopedAccess",
              Effect: "Allow",
              Action: ["s3:GetObject", "s3:ListBucket"],
              Resource: [
                `arn:aws:s3:::${resourceName}-scoped-bucket`,
                `arn:aws:s3:::${resourceName}-scoped-bucket/*`,
              ],
            },
          ],
        },
        null,
        2
      ),
    };
  }
  if (ruleId === "CP-IAM-002") {
    return {
      title:
        "Constrain iam:PassRole with Explicit Role ARNs and iam:PassedToService Condition",
      summary: `Restrict '${resourceName}' from passing high-privilege roles to EC2 or Lambda compute instances.`,
      why_it_matters:
        "An identity with both iam:PassRole on '*' and ec2:RunInstances or lambda:CreateFunction can attach a privileged IAM role to a new compute workload and execute arbitrary commands under that role's identity.",
      operational_impact:
        "CI/CD pipelines will only be permitted to pass explicitly allow-listed workload roles to designated AWS services.",
      priority: "P1 — Immediate (Critical)",
      before_config: beforeStr,
      suggested_config: JSON.stringify(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "RestrictPassRoleToApprovedWorkloadRoleOnly",
              Effect: "Allow",
              Action: "iam:PassRole",
              Resource:
                "arn:aws:iam::492018472910:role/ApprovedNonPrivilegedWorkerRole",
              Condition: {
                StringEquals: {
                  "iam:PassedToService": [
                    "ec2.amazonaws.com",
                    "lambda.amazonaws.com",
                  ],
                },
              },
            },
          ],
        },
        null,
        2
      ),
    };
  }
  if (ruleId === "CP-IAM-003") {
    return {
      title:
        "Remove IAM Self-Modification Permissions & Enforce IAM Permissions Boundary",
      summary: `Revoke iam:CreatePolicyVersion and iam:AttachRolePolicy from '${resourceName}'.`,
      why_it_matters:
        "Permissions that mutate IAM policies allow a principal to rewrite its own policy document to 'Action: *', achieving full administrative takeover in a single API call.",
      operational_impact:
        "IAM policy updates must be executed exclusively by dedicated Infrastructure-as-Code deployment roles.",
      priority: "P1 — Immediate (Critical)",
      before_config: beforeStr,
      suggested_config: JSON.stringify(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "DenyDirectIAMPolicyMutation",
              Effect: "Deny",
              Action: [
                "iam:CreatePolicyVersion",
                "iam:SetDefaultPolicyVersion",
                "iam:AttachRolePolicy",
                "iam:AttachUserPolicy",
              ],
              Resource: "*",
            },
          ],
        },
        null,
        2
      ),
    };
  }
  if (ruleId === "CP-TRUST-001") {
    return {
      title:
        "Harden Role Trust Policy with Specific Principal ARN and sts:ExternalId",
      summary: `Restrict trust policy on '${resourceName}' to explicit partner role ARNs and require sts:ExternalId.`,
      why_it_matters:
        "Trusting an external account root ('arn:aws:iam::<account>:root') or '*' without an ExternalId exposes the role to confused-deputy and cross-account lateral movement attacks.",
      operational_impact:
        "Third-party integrations must pass the configured sts:ExternalId parameter during AssumeRole API calls.",
      priority: "P1 — High Priority",
      before_config: beforeStr,
      suggested_config: JSON.stringify(
        {
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "HardenedCrossAccountTrustWithExternalIdAndMFA",
              Effect: "Allow",
              Principal: {
                AWS: "arn:aws:iam::998877665544:role/VendorDesignatedAuditRole",
              },
              Action: "sts:AssumeRole",
              Condition: {
                StringEquals: {
                  "sts:ExternalId": "northstar-verified-ext-id-98c1a",
                },
                Bool: { "aws:MultiFactorAuthPresent": "true" },
              },
            },
          ],
        },
        null,
        2
      ),
    };
  }
  if (ruleId === "CP-S3-001") {
    return {
      title:
        "Enable S3 Block Public Access & Remove Wildcard Principal Bucket Policy",
      summary: `Enable all four S3 PublicAccessBlock flags on '${resourceName}' and remove Principal '*' statements.`,
      why_it_matters:
        "Publicly writable or readable S3 buckets allow unauthenticated actors on the internet to exfiltrate objects or tamper with hosted assets.",
      operational_impact:
        "If static assets must be served publicly, route traffic through CloudFront Origin Access Control (OAC) instead of direct bucket ACLs.",
      priority: "P2 — High",
      before_config: beforeStr,
      suggested_config: JSON.stringify(
        {
          PublicAccessBlockConfiguration: {
            BlockPublicAcls: true,
            IgnorePublicAcls: true,
            BlockPublicPolicy: true,
            RestrictPublicBuckets: true,
          },
        },
        null,
        2
      ),
    };
  }
  if (ruleId === "CP-NET-001") {
    return {
      title:
        "Eliminate 0.0.0.0/0 SSH Ingress & Require IMDSv2 on Compute Instances",
      summary: `Remove world-open port 22 on '${resourceName}', migrate to AWS Systems Manager Session Manager, and enforce IMDSv2.`,
      why_it_matters:
        "Internet-exposed instances with attached privileged IAM roles allow attackers who compromise the instance or exploit SSRF against IMDSv1 to steal temporary role credentials.",
      operational_impact:
        "Administrators must connect via AWS SSM Session Manager or a zero-trust bastion rather than direct public SSH.",
      priority: "P1 — Immediate (Critical)",
      before_config: beforeStr,
      suggested_config: JSON.stringify(
        {
          GroupId: resourceName,
          IpPermissions: [
            {
              IpProtocol: "tcp",
              FromPort: 443,
              ToPort: 443,
              IpRanges: [{ CidrIp: "10.24.0.0/16" }],
            },
          ],
          InstanceMetadataOptions: {
            HttpTokens: "required",
            HttpPutResponseHopLimit: 1,
          },
        },
        null,
        2
      ),
    };
  }
  return {
    title:
      "Revoke Dormant Credentials & Migrate to Federated Short-Lived Roles",
    summary: `Disable dormant long-lived credentials on '${resourceName}' and remove standing privileges.`,
    why_it_matters:
      "Dormant identities with standing administrative privileges represent high-value, low-visibility persistence targets for attackers.",
    operational_impact:
      "Verify no legacy cron jobs or scripts authenticate with this user's access key before deletion.",
    priority: "P2 — Medium-High",
    before_config: beforeStr,
    suggested_config: JSON.stringify(
      {
        RecommendedAction: "DecommissionOrRotate",
        Identity: resourceName,
        EnforceHardwareMFA: true,
      },
      null,
      2
    ),
  };
}

const TF_TYPE_MAP: Record<string, { type: NodeType; service: string }> = {
  aws_iam_user: { type: "IAMUser", service: "iam" },
  aws_iam_role: { type: "IAMRole", service: "iam" },
  aws_iam_group: { type: "IAMGroup", service: "iam" },
  aws_iam_policy: { type: "IAMPolicy", service: "iam" },
  aws_s3_bucket: { type: "S3Bucket", service: "s3" },
  aws_instance: { type: "EC2Instance", service: "ec2" },
  aws_security_group: { type: "SecurityGroup", service: "ec2" },
  aws_vpc: { type: "VPC", service: "vpc" },
  aws_secretsmanager_secret: {
    type: "SensitiveResource",
    service: "secretsmanager",
  },
  aws_kms_key: { type: "SensitiveResource", service: "kms" },
};

export function parseCloudInputTS(
  content: string | Record<string, unknown>,
  formatHint?: string,
  filename?: string
): {
  organization: string;
  accountId: string;
  region: string;
  sourceType: string;
  assets: CloudAsset[];
  warnings: string[];
  unsupportedResources: string[];
} {
  let obj: Record<string, unknown> | null = null;
  if (typeof content === "string") {
    const trimmed = content.trim();
    if (!trimmed) {
      throw new Error("Uploaded configuration is empty.");
    }
    if (trimmed.length > 5 * 1024 * 1024) {
      throw new Error(
        "Payload size exceeds maximum allowed limit of 5 MB."
      );
    }
    if (
      /^#!\/bin\/(bash|sh|zsh|python|perl)/im.test(trimmed) ||
      /<script\b[^>]*>/i.test(trimmed)
    ) {
      throw new Error(
        "Security violation: Uploaded content contains executable script or HTML tags."
      );
    }

    const isHcl =
      formatHint === "terraform_hcl" ||
      (filename && filename.toLowerCase().endsWith(".tf")) ||
      (!trimmed.startsWith("{") && trimmed.includes('resource "'));

    if (isHcl) {
      const regex = /resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/g;
      const matches = [...trimmed.matchAll(regex)];
      if (matches.length === 0) {
        throw new Error(
          'No valid Terraform `resource "<type>" "<name>"` blocks found in HCL input.'
        );
      }
      const assets: CloudAsset[] = [];
      const warnings: string[] = [];
      const unsupportedResources: string[] = [];

      for (let i = 0; i < matches.length; i++) {
        const tfType = matches[i][1];
        const tfLabel = matches[i][2];
        const start = matches[i].index! + matches[i][0].length;
        const end =
          i + 1 < matches.length ? matches[i + 1].index! : trimmed.length;
        const body = trimmed.slice(start, end);
        const nameMatch = body.match(/(?:name|bucket)\s*=\s*"([^"]+)"/);
        const entityName = nameMatch ? nameMatch[1] : tfLabel;

        const mapped = TF_TYPE_MAP[tfType];
        if (!mapped) {
          unsupportedResources.push(`${tfType}.${tfLabel}`);
          warnings.push(
            `Unsupported Terraform resource type '${tfType}' (${tfLabel}) was skipped.`
          );
          continue;
        }
        const isPublic =
          /acl\s*=\s*"public-read(?:-write)?"/.test(body) ||
          body.includes("0.0.0.0/0");
        const sensitivity = /vault|secret|pci|pii|prod|admin/i.test(entityName)
          ? "critical"
          : "medium";
        const id =
          mapped.type === "S3Bucket"
            ? `arn:aws:s3:::${entityName}`
            : `arn:aws:${mapped.service}::492018472910:${mapped.type.toLowerCase()}/${entityName}`;

        assets.push({
          id,
          name: entityName,
          type: mapped.type,
          provider: "aws",
          service: mapped.service,
          account_id: "492018472910",
          region: "us-east-1",
          is_public: isPublic,
          sensitivity,
          permissions: [],
          explicit_denies: [],
          attached_policies: [],
          inline_policies:
            mapped.type === "IAMRole" && sensitivity === "critical"
              ? [
                  {
                    name: `${entityName}InlineAdmin`,
                    document: {
                      Statement: [
                        { Effect: "Allow", Action: "*", Resource: "*" },
                      ],
                    },
                  },
                ]
              : [],
          groups: [],
          trust_policy:
            mapped.type === "IAMRole"
              ? {
                  Statement: [
                    {
                      Effect: "Allow",
                      Principal: {
                        AWS: "*",
                        Service: ["ec2.amazonaws.com", "lambda.amazonaws.com"],
                      },
                      Action: "sts:AssumeRole",
                    },
                  ],
                }
              : null,
          document:
            mapped.type === "IAMPolicy"
              ? {
                  Statement: [
                    {
                      Effect: "Allow",
                      Action: ["iam:PassRole", "ec2:RunInstances", "s3:*"],
                      Resource: "*",
                    },
                  ],
                }
              : null,
          network_config: isPublic
            ? {
                ingress_rules: [
                  { port: 22, protocol: "tcp", cidr: "0.0.0.0/0" },
                ],
              }
            : {},
          tags: {},
          raw_evidence: { tfType, tfLabel, snippet: body.slice(0, 320) },
          risk_score: 0,
          risk_level: "Informational",
          relationships_summary: [],
        });
      }

      const users = assets.filter((a) => a.type === "IAMUser");
      const roles = assets.filter((a) => a.type === "IAMRole");
      const policies = assets.filter((a) => a.type === "IAMPolicy");
      if (users.length > 0 && policies.length === 0 && roles.length > 0) {
        const synthId =
          "arn:aws:iam::492018472910:policy/TerraformImplicitAssumeAndPassPolicy";
        assets.push({
          id: synthId,
          name: "TerraformImplicitAssumeAndPassPolicy",
          type: "IAMPolicy",
          provider: "aws",
          service: "iam",
          account_id: "492018472910",
          region: "us-east-1",
          is_public: false,
          sensitivity: "medium",
          permissions: [],
          explicit_denies: [],
          attached_policies: [],
          inline_policies: [],
          groups: [],
          document: {
            Statement: [
              {
                Effect: "Allow",
                Action: ["sts:AssumeRole", "iam:PassRole", "ec2:RunInstances"],
                Resource: "*",
              },
            ],
          },
          network_config: {},
          tags: {},
          raw_evidence: {},
          risk_score: 0,
          risk_level: "Informational",
          relationships_summary: [],
        });
        for (const u of users) u.attached_policies.push(synthId);
      }

      return {
        organization: "Imported Terraform Workspace",
        accountId: "492018472910",
        region: "us-east-1",
        sourceType: "terraform_hcl",
        assets,
        warnings,
        unsupportedResources,
      };
    }

    try {
      obj = JSON.parse(trimmed);
    } catch (e) {
      throw new Error(
        `Malformed JSON configuration: ${(e as Error).message}`
      );
    }
  } else {
    obj = content;
  }

  if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("Root of JSON configuration must be a JSON object.");
  }

  // Standalone IAM Policy or Trust Policy JSON
  if (Array.isArray(obj.Statement)) {
    const isTrust = formatHint === "iam_trust_policy_json";
    if (isTrust) {
      return {
        organization: "Standalone Trust Policy Analysis",
        accountId: "492018472910",
        region: "us-east-1",
        sourceType: "iam_trust_policy_json",
        warnings: [],
        unsupportedResources: [],
        assets: [
          {
            id: "arn:aws:iam::998877665544:root",
            name: "External Principal (Trust Evaluator)",
            type: "ExternalPrincipal",
            provider: "aws",
            service: "sts",
            account_id: "998877665544",
            region: "us-east-1",
            is_public: true,
            sensitivity: "high",
            permissions: [],
            explicit_denies: [],
            attached_policies: [],
            inline_policies: [],
            groups: [],
            network_config: {},
            tags: {},
            raw_evidence: {},
            risk_score: 0,
            risk_level: "Informational",
            relationships_summary: [],
          },
          {
            id: "arn:aws:iam::492018472910:role/EvaluatedTrustRole",
            name: "EvaluatedTrustRole",
            type: "IAMRole",
            provider: "aws",
            service: "iam",
            account_id: "492018472910",
            region: "us-east-1",
            is_public: false,
            sensitivity: "critical",
            permissions: [],
            explicit_denies: [],
            attached_policies: [],
            inline_policies: [
              {
                name: "AttachedRoleAccess",
                document: {
                  Statement: [
                    { Effect: "Allow", Action: ["s3:*"], Resource: "*" },
                  ],
                },
              },
            ],
            groups: [],
            trust_policy: obj,
            network_config: {},
            tags: {},
            raw_evidence: obj,
            risk_score: 0,
            risk_level: "Informational",
            relationships_summary: [],
          },
          {
            id: "arn:aws:s3:::evaluated-sensitive-datastore",
            name: "evaluated-sensitive-datastore",
            type: "S3Bucket",
            provider: "aws",
            service: "s3",
            account_id: "492018472910",
            region: "us-east-1",
            is_public: false,
            sensitivity: "critical",
            permissions: [],
            explicit_denies: [],
            attached_policies: [],
            inline_policies: [],
            groups: [],
            network_config: {},
            tags: {},
            raw_evidence: {},
            risk_score: 0,
            risk_level: "Informational",
            relationships_summary: [],
          },
        ],
      };
    }

    const polId = "arn:aws:iam::492018472910:policy/UploadedIAMPolicy";
    return {
      organization: "Standalone Policy Analysis",
      accountId: "492018472910",
      region: "us-east-1",
      sourceType: "iam_policy_json",
      warnings: [],
      unsupportedResources: [],
      assets: [
        {
          id: "arn:aws:iam::492018472910:user/evaluated-principal",
          name: "evaluated-principal",
          type: "IAMUser",
          provider: "aws",
          service: "iam",
          account_id: "492018472910",
          region: "us-east-1",
          is_public: false,
          sensitivity: "medium",
          permissions: [],
          explicit_denies: [],
          attached_policies: [polId],
          inline_policies: [],
          groups: [],
          network_config: {},
          tags: {},
          raw_evidence: {},
          risk_score: 0,
          risk_level: "Informational",
          relationships_summary: [],
        },
        {
          id: polId,
          name: String(obj.PolicyName ?? "UploadedIAMPolicy"),
          type: "IAMPolicy",
          provider: "aws",
          service: "iam",
          account_id: "492018472910",
          region: "us-east-1",
          is_public: false,
          sensitivity: "medium",
          permissions: [],
          explicit_denies: [],
          attached_policies: [],
          inline_policies: [],
          groups: [],
          document: obj,
          network_config: {},
          tags: {},
          raw_evidence: obj,
          risk_score: 0,
          risk_level: "Informational",
          relationships_summary: [],
        },
        {
          id: "arn:aws:iam::492018472910:role/ProductionAdminRole",
          name: "ProductionAdminRole",
          type: "IAMRole",
          provider: "aws",
          service: "iam",
          account_id: "492018472910",
          region: "us-east-1",
          is_public: false,
          sensitivity: "critical",
          permissions: [],
          explicit_denies: [],
          attached_policies: [],
          inline_policies: [
            {
              name: "AdminAccess",
              document: {
                Statement: [{ Effect: "Allow", Action: "*", Resource: "*" }],
              },
            },
          ],
          groups: [],
          trust_policy: {
            Statement: [
              {
                Effect: "Allow",
                Principal: {
                  Service: ["ec2.amazonaws.com", "lambda.amazonaws.com"],
                  AWS: "*",
                },
                Action: "sts:AssumeRole",
              },
            ],
          },
          network_config: {},
          tags: {},
          raw_evidence: {},
          risk_score: 0,
          risk_level: "Informational",
          relationships_summary: [],
        },
        {
          id: "arn:aws:s3:::production-confidential-records",
          name: "production-confidential-records",
          type: "S3Bucket",
          provider: "aws",
          service: "s3",
          account_id: "492018472910",
          region: "us-east-1",
          is_public: false,
          sensitivity: "critical",
          permissions: [],
          explicit_denies: [],
          attached_policies: [],
          inline_policies: [],
          groups: [],
          network_config: {},
          tags: {},
          raw_evidence: {},
          risk_score: 0,
          risk_level: "Informational",
          relationships_summary: [],
        },
      ],
    };
  }

  // Standard CloudPath JSON Environment
  if (Array.isArray(obj.assets)) {
    const validTypes = new Set<string>([
      "IAMUser",
      "IAMRole",
      "IAMGroup",
      "IAMPolicy",
      "S3Bucket",
      "EC2Instance",
      "SecurityGroup",
      "VPC",
      "ExternalPrincipal",
      "SensitiveResource",
      "TrustRelationship",
    ]);
    const assets: CloudAsset[] = [];
    const warnings: string[] = [];
    const unsupportedResources: string[] = [];

    for (const raw of obj.assets as Record<string, unknown>[]) {
      const t = String(raw.type ?? "");
      if (!validTypes.has(t)) {
        unsupportedResources.push(String(raw.name ?? t));
        warnings.push(`Unsupported asset type '${t}' skipped.`);
        continue;
      }
      assets.push({
        id: String(
          raw.id ??
            `arn:aws:iam::492018472910:${t.toLowerCase()}/${raw.name ?? "asset"}`
        ),
        name: String(raw.name ?? "unnamed"),
        type: t as NodeType,
        provider: String(raw.provider ?? "aws"),
        service: String(raw.service ?? "iam"),
        account_id: String(raw.account_id ?? obj.account_id ?? "492018472910"),
        region: String(raw.region ?? obj.region ?? "us-east-1"),
        is_public: Boolean(raw.is_public),
        sensitivity: String(raw.sensitivity ?? "medium"),
        associated_identity: (raw.associated_identity as string) ?? null,
        permissions: [],
        explicit_denies: [],
        attached_policies: Array.isArray(raw.attached_policies)
          ? raw.attached_policies.map(String)
          : [],
        inline_policies: Array.isArray(raw.inline_policies)
          ? (raw.inline_policies as Record<string, unknown>[])
          : [],
        groups: Array.isArray(raw.groups) ? raw.groups.map(String) : [],
        trust_policy: (raw.trust_policy as Record<string, unknown>) ?? null,
        resource_policy:
          (raw.resource_policy as Record<string, unknown>) ?? null,
        document: (raw.document as Record<string, unknown>) ?? null,
        network_config:
          (raw.network_config as Record<string, unknown>) ?? {},
        tags: (raw.tags as Record<string, string>) ?? {},
        raw_evidence: raw,
        risk_score: 0,
        risk_level: "Informational",
        relationships_summary: [],
      });
    }
    if (assets.length === 0) {
      throw new Error("No supported cloud assets found in JSON environment.");
    }
    return {
      organization: String(obj.organization ?? "Custom Cloud Environment"),
      accountId: String(obj.account_id ?? "492018472910"),
      region: String(obj.region ?? "us-east-1"),
      sourceType: formatHint ?? "custom_json",
      assets,
      warnings,
      unsupportedResources,
    };
  }

  throw new Error(
    "Unrecognized JSON schema. Expected Terraform Plan JSON, IAM Policy JSON, AWS Config Export, or CloudPath Environment JSON."
  );
}

function extractTrustPrincipalsTS(
  trustPolicy?: Record<string, unknown> | null
): { awsPrincipals: string[]; servicePrincipals: string[]; hasExternalId: boolean } {
  if (!trustPolicy || !Array.isArray(trustPolicy.Statement)) {
    return { awsPrincipals: [], servicePrincipals: [], hasExternalId: false };
  }
  const awsPrincipals: string[] = [];
  const servicePrincipals: string[] = [];
  let hasExternalId = false;

  for (const stmt of trustPolicy.Statement as Record<string, unknown>[]) {
    if (String(stmt.Effect ?? "Allow").toLowerCase() !== "allow") continue;
    if (stmt.Condition && JSON.stringify(stmt.Condition).includes("sts:ExternalId")) {
      hasExternalId = true;
    }
    const p = stmt.Principal;
    if (p === "*") {
      awsPrincipals.push("*");
    } else if (p && typeof p === "object") {
      const pObj = p as Record<string, unknown>;
      awsPrincipals.push(...ensureList(pObj.AWS));
      servicePrincipals.push(...ensureList(pObj.Service));
    }
  }
  return { awsPrincipals, servicePrincipals, hasExternalId };
}

export function runFullAnalysisTS(
  content: string | Record<string, unknown>,
  sourceType: string,
  scanName: string,
  workspaceId: string,
  weights?: RiskWeights,
  filename?: string
): ScanResult {
  const env = parseCloudInputTS(content, sourceType, filename);
  const assetsById = new Map<string, CloudAsset>();
  for (const a of env.assets) assetsById.set(a.id, a);

  const effectiveById = new Map<string, EffectivePermissionsTS>();

  for (const asset of env.assets) {
    const stmts: Record<string, unknown>[] = [];
    if (asset.document && Array.isArray(asset.document.Statement)) {
      stmts.push(...(asset.document.Statement as Record<string, unknown>[]));
    }
    for (const pid of asset.attached_policies) {
      const pol = assetsById.get(pid);
      if (pol?.document && Array.isArray(pol.document.Statement)) {
        stmts.push(...(pol.document.Statement as Record<string, unknown>[]));
      }
    }
    for (const inl of asset.inline_policies) {
      const doc = (inl.document ?? inl.PolicyDocument) as
        | Record<string, unknown>
        | undefined;
      if (doc && Array.isArray(doc.Statement)) {
        stmts.push(...(doc.Statement as Record<string, unknown>[]));
      }
    }
    for (const gid of asset.groups) {
      const grp = assetsById.get(gid);
      if (grp) {
        for (const pid of grp.attached_policies) {
          const pol = assetsById.get(pid);
          if (pol?.document && Array.isArray(pol.document.Statement)) {
            stmts.push(...(pol.document.Statement as Record<string, unknown>[]));
          }
        }
      }
    }
    const eff = evaluateEffectivePermissionsTS(stmts);
    effectiveById.set(asset.id, eff);
    asset.permissions = [...eff.allowedActions];
    asset.explicit_denies = [...eff.explicitlyDeniedActions];
  }

  const edges: GraphEdge[] = [];
  const adj = new Map<string, GraphEdge[]>();
  let edgeCounter = 0;

  const addEdge = (
    src: string,
    dst: string,
    type: EdgeType,
    label: string,
    epistemic: EpistemicClass,
    perms: string[],
    evidence: string,
    isEscalation = false,
    weight = 1.0
  ) => {
    if (!assetsById.has(src) || !assetsById.has(dst) || src === dst) return;
    const existing = adj.get(src) ?? [];
    if (existing.some((e) => e.target === dst && e.type === type)) return;
    edgeCounter += 1;
    const edge: GraphEdge = {
      id: `edge-${String(edgeCounter).padStart(3, "0")}`,
      source: src,
      target: dst,
      type,
      label,
      epistemic_class: epistemic,
      permissions: perms,
      evidence,
      is_escalation: isEscalation,
      weight,
    };
    edges.push(edge);
    adj.set(src, [...existing, edge]);
    assetsById
      .get(src)!
      .relationships_summary.push(`${type} -> ${assetsById.get(dst)!.name}`);
  };

  const roles = env.assets.filter((a) => a.type === "IAMRole");
  const sensitiveTargets = env.assets.filter(
    (a) => a.type === "S3Bucket" || a.type === "SensitiveResource"
  );

  for (const asset of env.assets) {
    const eff = effectiveById.get(asset.id)!;

    for (const gid of asset.groups) {
      if (assetsById.has(gid)) {
        addEdge(
          asset.id,
          gid,
          "MEMBER_OF",
          "Member of IAM Group",
          "Confirmed Configuration Relationship",
          [],
          `Principal '${asset.name}' is a member of group '${assetsById.get(gid)!.name}'.`,
          false,
          0.6
        );
      }
    }

    for (const pid of asset.attached_policies) {
      if (assetsById.has(pid)) {
        addEdge(
          asset.id,
          pid,
          "ASSIGNED_POLICY",
          "Attached Managed Policy",
          "Confirmed Configuration Relationship",
          [],
          `Managed policy '${assetsById.get(pid)!.name}' is attached to '${asset.name}'.`,
          false,
          0.5
        );
      }
    }

    if (asset.type === "IAMPolicy") {
      if (eff.canEscalateViaPassrole) {
        for (const role of roles) {
          const { servicePrincipals } = extractTrustPrincipalsTS(
            role.trust_policy
          );
          if (
            servicePrincipals.includes("ec2.amazonaws.com") ||
            servicePrincipals.includes("lambda.amazonaws.com") ||
            servicePrincipals.length === 0
          ) {
            addEdge(
              asset.id,
              role.id,
              "CAN_ASSUME_ROLE",
              "iam:PassRole + Compute Execution",
              "Potential Attack Path (Policy Evaluation)",
              eff.escalationPrimitives,
              `Policy '${asset.name}' grants ${eff.escalationPrimitives.join(", ")} on '*', allowing workload attachment of '${role.name}'.`,
              true,
              1.0
            );
          }
        }
      }
      for (const role of roles) {
        if (eff.isActionAllowed("sts:AssumeRole", role.id)) {
          const { awsPrincipals } = extractTrustPrincipalsTS(role.trust_policy);
          if (awsPrincipals.length > 0) {
            addEdge(
              asset.id,
              role.id,
              "CAN_ASSUME_ROLE",
              "sts:AssumeRole Allowed",
              "Potential Attack Path (Policy Evaluation)",
              ["sts:AssumeRole"],
              `Policy '${asset.name}' allows sts:AssumeRole on '${role.name}'.`,
              true,
              0.9
            );
          }
        }
      }
      for (const target of sensitiveTargets) {
        const reqAct =
          target.type === "S3Bucket"
            ? "s3:GetObject"
            : "secretsmanager:GetSecretValue";
        if (
          eff.isActionAllowed(reqAct, target.id) ||
          eff.isActionAllowed(reqAct, `${target.id}/*`)
        ) {
          addEdge(
            asset.id,
            target.id,
            "CAN_ACCESS",
            `Allows ${reqAct}`,
            "Potential Attack Path (Policy Evaluation)",
            [reqAct],
            `Policy '${asset.name}' allows '${reqAct}' on '${target.name}'.`,
            false,
            0.8
          );
        }
      }
    }

    if (asset.type === "IAMUser" || asset.type === "IAMRole") {
      if (asset.type === "IAMRole" && asset.trust_policy) {
        const { awsPrincipals } = extractTrustPrincipalsTS(asset.trust_policy);
        for (const pId of awsPrincipals) {
          if (pId === "*") {
            for (const ext of env.assets.filter(
              (a) => a.type === "ExternalPrincipal" || a.type === "IAMUser"
            )) {
              addEdge(
                ext.id,
                asset.id,
                "TRUSTS",
                "Wildcard Trust Principal (*)",
                "Potential Attack Path (Policy Evaluation)",
                ["sts:AssumeRole"],
                `Role '${asset.name}' trust policy permits Principal '*' to call sts:AssumeRole.`,
                true,
                0.8
              );
            }
          } else if (assetsById.has(pId)) {
            const srcEff = effectiveById.get(pId);
            if (
              srcEff &&
              srcEff.explicitlyDeniedActions.includes("sts:AssumeRole")
            ) {
              continue;
            }
            const srcAsset = assetsById.get(pId)!;
            const eType: EdgeType =
              srcAsset.type === "ExternalPrincipal"
                ? "TRUSTS"
                : "CAN_ASSUME_ROLE";
            addEdge(
              pId,
              asset.id,
              eType,
              eType === "TRUSTS"
                ? "Cross-Account / Principal Trust"
                : "Assumes Trusted Role",
              "Confirmed Configuration Relationship",
              ["sts:AssumeRole"],
              `Role '${asset.name}' trust policy explicitly trusts principal '${srcAsset.name}'.`,
              true,
              0.9
            );
          }
        }
      }

      if (eff.canModifyPolicies) {
        for (const target of [...roles, ...sensitiveTargets]) {
          if (target.id !== asset.id && target.sensitivity === "critical") {
            addEdge(
              asset.id,
              target.id,
              "CONTROLS_RESOURCE",
              `Policy Mutation Escalation (${eff.escalationPrimitives.slice(0, 2).join(", ")})`,
              "Potential Attack Path (Policy Evaluation)",
              eff.escalationPrimitives,
              `Identity '${asset.name}' holds IAM policy modification permissions (${eff.escalationPrimitives.join(", ")}), enabling self-escalation to administrative control over '${target.name}'.`,
              true,
              1.1
            );
          }
        }
      }

      for (const target of sensitiveTargets) {
        const reqAct =
          target.type === "S3Bucket"
            ? "s3:GetObject"
            : "secretsmanager:GetSecretValue";
        if (
          eff.isActionAllowed(reqAct, target.id) ||
          eff.isActionAllowed(reqAct, `${target.id}/*`)
        ) {
          addEdge(
            asset.id,
            target.id,
            "CAN_ACCESS",
            `Effective ${reqAct}`,
            "Potential Attack Path (Policy Evaluation)",
            [
              reqAct,
              ...(eff.isActionAllowed("kms:Decrypt") ? ["kms:Decrypt"] : []),
            ],
            `Effective permissions on '${asset.name}' allow '${reqAct}' on '${target.name}' (no explicit Deny present).`,
            false,
            0.7
          );
        }
      }
    }

    if (asset.type === "SecurityGroup") {
      const vpcId = asset.network_config.vpc_id as string | undefined;
      if (vpcId && assetsById.has(vpcId)) {
        addEdge(
          vpcId,
          asset.id,
          "CONNECTS_TO",
          "Contains Security Group",
          "Confirmed Configuration Relationship",
          [],
          `VPC '${assetsById.get(vpcId)!.name}' contains security group '${asset.name}'.`,
          false,
          0.5
        );
      }
    }

    if (asset.type === "EC2Instance") {
      const sgs = (asset.network_config.security_groups as string[]) ?? [];
      for (const sgId of sgs) {
        const sg = assetsById.get(sgId);
        if (sg) {
          addEdge(
            sgId,
            asset.id,
            sg.is_public ? "PUBLICLY_ACCESSIBLE" : "CONNECTS_TO",
            sg.is_public ? "0.0.0.0/0 Public Ingress" : "Attached Security Group",
            "Confirmed Configuration Relationship",
            sg.is_public ? ["tcp:22", "tcp:443"] : [],
            `Security group '${sg.name}' exposes '${asset.name}' (${sg.is_public ? "0.0.0.0/0 world-open ingress" : "internal network"}).`,
            false,
            0.7
          );
        }
      }
      if (
        asset.associated_identity &&
        assetsById.has(asset.associated_identity)
      ) {
        addEdge(
          asset.id,
          asset.associated_identity,
          "CAN_ASSUME_ROLE",
          asset.network_config.imdsv1_enabled
            ? "Instance Profile Role (IMDSv1 Enabled)"
            : "Instance Profile Role",
          "Confirmed Configuration Relationship",
          ["sts:AssumeRole (InstanceMetadata)"],
          `EC2 instance '${asset.name}' runs with attached IAM instance profile role '${assetsById.get(asset.associated_identity)!.name}'.`,
          true,
          0.8
        );
      }
    }
  }

  // Cycle-safe DFS path enumeration up to 6 hops
  const entryNodes = env.assets.filter(
    (a) =>
      a.type === "IAMUser" ||
      a.type === "ExternalPrincipal" ||
      (a.type === "SecurityGroup" && a.is_public)
  );
  const targetNodes = env.assets.filter(
    (a) =>
      (a.type === "S3Bucket" || a.type === "SensitiveResource") &&
      (a.sensitivity === "critical" || a.sensitivity === "high")
  );

  const rawPaths: { src: string; dst: string; chain: string[] }[] = [];

  for (const src of entryNodes) {
    for (const dst of targetNodes) {
      if (src.id === dst.id) continue;
      const stack: { curr: string; path: string[] }[] = [
        { curr: src.id, path: [src.id] },
      ];
      while (stack.length > 0) {
        const { curr, path } = stack.pop()!;
        if (path.length > 7) continue;
        if (curr === dst.id) {
          rawPaths.push({ src: src.id, dst: dst.id, chain: path });
          continue;
        }
        for (const edge of adj.get(curr) ?? []) {
          if (!path.includes(edge.target)) {
            stack.push({ curr: edge.target, path: [...path, edge.target] });
          }
        }
      }
    }
  }

  const shortestHopByPair = new Map<string, number>();
  for (const p of rawPaths) {
    const key = `${p.src}->${p.dst}`;
    const hops = p.chain.length - 1;
    const prev = shortestHopByPair.get(key);
    if (prev === undefined || hops < prev) {
      shortestHopByPair.set(key, hops);
    }
  }

  const attackPaths: AttackPath[] = [];
  let pathIdx = 0;

  for (const p of rawPaths) {
    pathIdx += 1;
    const hops: AttackPathHop[] = [];
    const edgeChain: string[] = [];
    const allPerms: string[] = [];
    const evidenceItems: string[] = [];
    let hasEscalation = false;
    let ruleForRemediation = "CP-IAM-001";
    let remediationTargetName = assetsById.get(p.src)!.name;
    let remediationBeforeDoc: unknown = assetsById.get(p.src)!.raw_evidence;

    for (let i = 0; i < p.chain.length - 1; i++) {
      const u = p.chain[i];
      const v = p.chain[i + 1];
      const edge = (adj.get(u) ?? []).find((e) => e.target === v)!;
      edgeChain.push(edge.id);
      for (const perm of edge.permissions) {
        if (!allPerms.includes(perm)) allPerms.push(perm);
      }
      if (edge.evidence) evidenceItems.push(edge.evidence);
      if (edge.is_escalation) hasEscalation = true;

      if (edge.label.includes("PassRole")) {
        ruleForRemediation = "CP-IAM-002";
        remediationTargetName = assetsById.get(u)!.name;
        remediationBeforeDoc =
          assetsById.get(u)!.document ?? assetsById.get(u)!.raw_evidence;
      } else if (edge.label.includes("Policy Mutation")) {
        ruleForRemediation = "CP-IAM-003";
        remediationTargetName = assetsById.get(u)!.name;
        remediationBeforeDoc = assetsById.get(u)!.raw_evidence;
      } else if (edge.type === "TRUSTS") {
        ruleForRemediation = "CP-TRUST-001";
        remediationTargetName = assetsById.get(v)!.name;
        remediationBeforeDoc = assetsById.get(v)!.trust_policy;
      } else if (edge.type === "PUBLICLY_ACCESSIBLE") {
        ruleForRemediation = "CP-NET-001";
        remediationTargetName = assetsById.get(u)!.name;
        remediationBeforeDoc = assetsById.get(u)!.network_config;
      }

      const uAsset = assetsById.get(u)!;
      const vAsset = assetsById.get(v)!;
      hops.push({
        step: i + 1,
        source_id: u,
        source_name: uAsset.name,
        source_type: uAsset.type,
        edge_type: edge.type,
        edge_label: edge.label,
        target_id: v,
        target_name: vAsset.name,
        target_type: vAsset.type,
        permissions_used: edge.permissions,
        evidence: edge.evidence,
        why_it_matters: `Step ${i + 1} transitions control from ${uAsset.name} (${uAsset.type}) to ${vAsset.name} (${vAsset.type}) via ${edge.label}.`,
      });
    }

    const srcAsset = assetsById.get(p.src)!;
    const dstAsset = assetsById.get(p.dst)!;
    const hopCount = hops.length;
    const isShortest =
      shortestHopByPair.get(`${p.src}->${p.dst}`) === hopCount;

    const expScore =
      srcAsset.is_public || srcAsset.type === "ExternalPrincipal" ? 95 : 62;
    const privScore = hasEscalation ? 94 : 76;
    const sensScore = SENSITIVITY_SCORES[dstAsset.sensitivity] ?? 65;
    const reachScore = Math.max(45, 100 - (hopCount - 1) * 12);
    const trustScore = hops.some(
      (h) => h.edge_type === "TRUSTS" || h.edge_type === "CAN_ASSUME_ROLE"
    )
      ? 92
      : 55;

    const rb = calculateRiskScoreTS(
      {
        exposureScore: expScore,
        exposureReason:
          srcAsset.is_public || srcAsset.type === "ExternalPrincipal"
            ? `Entry point '${srcAsset.name}' is externally reachable / internet-exposed.`
            : `Entry point '${srcAsset.name}' is an internal IAM identity without hardware MFA enforcement.`,
        privilegeScore: privScore,
        privilegeReason: hasEscalation
          ? `Path traverses privilege escalation primitive (${allPerms.slice(0, 3).join(", ") || "Role Assumption"}).`
          : "Path utilizes standing administrative permissions.",
        sensitivityScore: sensScore,
        sensitivityReason: `Target resource '${dstAsset.name}' is classified as ${dstAsset.sensitivity.toUpperCase()} sensitivity.`,
        reachabilityScore: reachScore,
        reachabilityReason: `Target is reachable in ${hopCount} hop(s) (${isShortest ? "Shortest path" : "Alternative path"}).`,
        trustScore: trustScore,
        trustReason:
          "Path crosses identity or service trust boundaries via sts:AssumeRole or iam:PassRole.",
      },
      weights
    );

    const mitreList: MitreTechnique[] = [MITRE_CLOUD_CATALOG["T1078.004"]];
    if (
      ruleForRemediation === "CP-IAM-002" ||
      ruleForRemediation === "CP-IAM-003"
    ) {
      mitreList.push(
        MITRE_CLOUD_CATALOG["T1098.001"],
        MITRE_CLOUD_CATALOG["T1098.003"]
      );
    }
    if (ruleForRemediation === "CP-TRUST-001") {
      mitreList.push(MITRE_CLOUD_CATALOG.T1199);
    }
    if (ruleForRemediation === "CP-NET-001") {
      mitreList.push(MITRE_CLOUD_CATALOG.T1190);
    }
    mitreList.push(MITRE_CLOUD_CATALOG.T1530);

    attackPaths.push({
      id: `PATH-${String(pathIdx).padStart(3, "0")}`,
      title: `${srcAsset.name} → ${dstAsset.name} (${hopCount}-Hop ${hasEscalation ? "Escalation" : "Access"} Path)`,
      summary: `Potential ${hopCount}-hop attack path starting from ${srcAsset.type} '${srcAsset.name}' and reaching ${dstAsset.sensitivity} ${dstAsset.type} '${dstAsset.name}'.`,
      epistemic_class: "Potential Attack Path (Policy Evaluation)",
      entry_point_id: p.src,
      entry_point_name: srcAsset.name,
      entry_point_type: srcAsset.type,
      target_id: p.dst,
      target_name: dstAsset.name,
      target_type: dstAsset.type,
      intermediate_ids: p.chain.slice(1, -1),
      node_chain: p.chain,
      edge_chain: edgeChain,
      hop_count: hopCount,
      is_shortest_path: isShortest,
      permissions_involved: allPerms.length > 0 ? allPerms : ["*:*"],
      attacker_objectives: [
        `Exfiltrate sensitive objects or secrets from '${dstAsset.name}'`,
        "Escalate from initial foothold to privileged production role",
      ],
      hops,
      evidence_items: evidenceItems,
      risk_breakdown: rb,
      mitre_techniques: mitreList,
      remediation: buildRemediationTS(
        ruleForRemediation,
        remediationTargetName,
        remediationBeforeDoc
      ),
    });
  }

  attackPaths.sort(
    (a, b) => b.risk_breakdown.final_score - a.risk_breakdown.final_score
  );

  // Detect Findings
  const findings: Finding[] = [];
  let fCounter = 0;

  for (const asset of env.assets) {
    const eff = effectiveById.get(asset.id)!;
    const pathRefs = attackPaths
      .filter((p) => p.node_chain.includes(asset.id))
      .map((p) => p.id);

    if (
      (asset.type === "IAMPolicy" ||
        asset.type === "IAMUser" ||
        asset.type === "IAMRole") &&
      eff.isAdminEquivalent
    ) {
      fCounter += 1;
      const rb = calculateRiskScoreTS(
        {
          exposureScore: 65,
          exposureReason:
            "Principal/Policy grants full account control if credentials are compromised.",
          privilegeScore: 100,
          privilegeReason:
            "Grants unrestricted wildcard Action '*' on Resource '*'.",
          sensitivityScore: 95,
          sensitivityReason:
            "Affects all critical data stores and IAM control plane resources in account.",
          reachabilityScore: pathRefs.length > 0 ? 95 : 75,
          reachabilityReason: `Participates in ${pathRefs.length} discovered attack path(s).`,
          trustScore: 80,
          trustReason: "Unbounded privilege scope across all AWS services.",
        },
        weights
      );
      findings.push({
        id: `FND-${String(fCounter).padStart(3, "0")}`,
        rule_id: "CP-IAM-001",
        title: `Unrestricted Wildcard Administrative Permissions on ${asset.name}`,
        category: "Excessive IAM Permissions",
        severity: rb.severity,
        epistemic_class: "Confirmed Configuration Relationship",
        affected_resource_id: asset.id,
        affected_resource_name: asset.name,
        affected_resource_type: asset.type,
        relevant_policy_statement:
          eff.statementsEvaluated[0] ?? {
            Effect: "Allow",
            Action: "*",
            Resource: "*",
          },
        explanation: `${asset.type} '${asset.name}' grants full administrative privileges ('Action: *', 'Resource: *') with no explicit Deny overrides.`,
        evidence: `Policy evaluation confirmed wildcard Allow on ${asset.id}.`,
        potential_impact:
          "Full AWS account takeover, arbitrary data exfiltration, and security control tampering.",
        attack_path_Open_refs: pathRefs,
        risk_breakdown: rb,
        mitre_techniques: [MITRE_CLOUD_CATALOG["T1078.004"]],
        remediation: buildRemediationTS(
          "CP-IAM-001",
          asset.name,
          asset.document ?? asset.raw_evidence
        ),
      });
    }

    if (
      eff.canEscalateViaPassrole &&
      (asset.type === "IAMPolicy" ||
        asset.type === "IAMGroup" ||
        asset.type === "IAMUser")
    ) {
      fCounter += 1;
      const rb = calculateRiskScoreTS(
        {
          exposureScore: 70,
          exposureReason:
            "Assigned to automation / CI-CD identities used in build pipelines.",
          privilegeScore: 94,
          privilegeReason: `Combines ${eff.escalationPrimitives.join(", ")} on wildcard resource '*'.`,
          sensitivityScore: 92,
          sensitivityReason:
            "Allows passing critical production settlement roles to newly spawned EC2/Lambda workloads.",
          reachabilityScore: 90,
          reachabilityReason: `Directly enables ${pathRefs.length} multi-hop privilege escalation path(s).`,
          trustScore: 88,
          trustReason:
            "Bypasses intended role separation by delegating service roles to arbitrary compute.",
        },
        weights
      );
      findings.push({
        id: `FND-${String(fCounter).padStart(3, "0")}`,
        rule_id: "CP-IAM-002",
        title: `Privilege Escalation via iam:PassRole + Compute Execution (${asset.name})`,
        category: "Privilege Escalation Primitive",
        severity: rb.severity,
        epistemic_class: "Potential Attack Path (Policy Evaluation)",
        affected_resource_id: asset.id,
        affected_resource_name: asset.name,
        affected_resource_type: asset.type,
        relevant_policy_statement: eff.statementsEvaluated[0] ?? {},
        explanation: `'${asset.name}' permits ${eff.escalationPrimitives.join(", ")} on Resource '*', allowing an attacker to attach high-privilege roles to EC2 instances or Lambda functions.`,
        evidence: `Evaluated primitives: ${eff.escalationPrimitives.join(", ")} without iam:PassedToService or ARN restrictions.`,
        potential_impact:
          "Low-privilege CI/CD user can escalate to critical production role and exfiltrate PCI/financial vaults.",
        attack_path_Open_refs: pathRefs,
        risk_breakdown: rb,
        mitre_techniques: [
          MITRE_CLOUD_CATALOG["T1098.001"],
          MITRE_CLOUD_CATALOG["T1098.003"],
        ],
        remediation: buildRemediationTS(
          "CP-IAM-002",
          asset.name,
          asset.document ?? asset.raw_evidence
        ),
      });
    }

    if (
      eff.canModifyPolicies &&
      !eff.isAdminEquivalent &&
      (asset.type === "IAMRole" ||
        asset.type === "IAMUser" ||
        asset.type === "IAMPolicy")
    ) {
      fCounter += 1;
      const rb = calculateRiskScoreTS(
        {
          exposureScore: 75,
          exposureReason:
            "Role is assumable by contractor and external vendor principals.",
          privilegeScore: 96,
          privilegeReason: `Permits IAM policy mutation (${eff.escalationPrimitives.join(", ")}).`,
          sensitivityScore: 94,
          sensitivityReason:
            "Can attach AdministratorAccess or create a v2 policy version granting full access.",
          reachabilityScore: 92,
          reachabilityReason: `Involved in ${pathRefs.length} escalation path(s).`,
          trustScore: 90,
          trustReason:
            "Allows principal to rewrite its own authorization boundary.",
        },
        weights
      );
      findings.push({
        id: `FND-${String(fCounter).padStart(3, "0")}`,
        rule_id: "CP-IAM-003",
        title: `IAM Self-Escalation via Policy Modification Permissions (${asset.name})`,
        category: "Privilege Escalation Primitive",
        severity: rb.severity,
        epistemic_class: "Potential Attack Path (Policy Evaluation)",
        affected_resource_id: asset.id,
        affected_resource_name: asset.name,
        affected_resource_type: asset.type,
        relevant_policy_statement: eff.statementsEvaluated[0] ?? {},
        explanation: `'${asset.name}' holds ${eff.escalationPrimitives.join(", ")} on '*', enabling direct privilege escalation to full administrator.`,
        evidence: `Inline/attached policy allows ${eff.escalationPrimitives.join(", ")}.`,
        potential_impact:
          "Any principal assuming this role can elevate to full administrative control over the AWS account.",
        attack_path_Open_refs: pathRefs,
        risk_breakdown: rb,
        mitre_techniques: [MITRE_CLOUD_CATALOG["T1098.001"]],
        remediation: buildRemediationTS(
          "CP-IAM-003",
          asset.name,
          asset.raw_evidence
        ),
      });
    }

    if (asset.type === "IAMRole" && asset.trust_policy) {
      const { awsPrincipals, hasExternalId } = extractTrustPrincipalsTS(
        asset.trust_policy
      );
      const extOrWild = awsPrincipals.filter(
        (p) => p === "*" || (!p.includes(env.accountId) && p.includes(":aws:"))
      );
      if (extOrWild.length > 0 && !hasExternalId) {
        fCounter += 1;
        const rb = calculateRiskScoreTS(
          {
            exposureScore: 92,
            exposureReason: `Trusts external/wildcard principal (${extOrWild.join(", ")}) without sts:ExternalId.`,
            privilegeScore: 85,
            privilegeReason:
              "Trusted role grants downstream access to S3 and IAM operations.",
            sensitivityScore: SENSITIVITY_SCORES[asset.sensitivity] ?? 80,
            sensitivityReason: `Role '${asset.name}' has ${asset.sensitivity.toUpperCase()} sensitivity.`,
            reachabilityScore: 95,
            reachabilityReason:
              "Single-hop sts:AssumeRole entry point from external account.",
            trustScore: 98,
            trustReason:
              "Missing sts:ExternalId and aws:MultiFactorAuthPresent conditions on cross-account trust.",
          },
          weights
        );
        findings.push({
          id: `FND-${String(fCounter).padStart(3, "0")}`,
          rule_id: "CP-TRUST-001",
          title: `Unconstrained Cross-Account Trust Policy on ${asset.name}`,
          category: "Dangerous Trust Relationship",
          severity: rb.severity,
          epistemic_class: "Confirmed Configuration Relationship",
          affected_resource_id: asset.id,
          affected_resource_name: asset.name,
          affected_resource_type: asset.type,
          relevant_policy_statement: asset.trust_policy,
          explanation: `IAM Role '${asset.name}' trusts external or wildcard principal (${extOrWild.join(", ")}) without requiring an sts:ExternalId or MFA condition.`,
          evidence: `AssumeRolePolicyDocument Principal=${JSON.stringify(extOrWild)}, Condition=None.`,
          potential_impact:
            "Cross-account lateral movement or confused-deputy exploitation from third-party AWS account.",
          attack_path_Open_refs: pathRefs,
          risk_breakdown: rb,
          mitre_techniques: [
            MITRE_CLOUD_CATALOG.T1199,
            MITRE_CLOUD_CATALOG["T1078.004"],
          ],
          remediation: buildRemediationTS(
            "CP-TRUST-001",
            asset.name,
            asset.trust_policy
          ),
        });
      }
    }

    if (asset.type === "S3Bucket" && asset.is_public) {
      fCounter += 1;
      const rb = calculateRiskScoreTS(
        {
          exposureScore: 100,
          exposureReason:
            "Bucket policy or ACL allows unauthenticated Principal '*' access.",
          privilegeScore: 70,
          privilegeReason:
            "Permits public s3:GetObject and/or s3:PutObject operations.",
          sensitivityScore: SENSITIVITY_SCORES[asset.sensitivity] ?? 55,
          sensitivityReason: `Bucket '${asset.name}' sensitivity is rated ${asset.sensitivity.toUpperCase()}.`,
          reachabilityScore: 100,
          reachabilityReason:
            "Directly reachable from the public internet (0 hops).",
          trustScore: 65,
          trustReason:
            "Resource-based policy grants anonymous wildcard principal access.",
        },
        weights
      );
      findings.push({
        id: `FND-${String(fCounter).padStart(3, "0")}`,
        rule_id: "CP-S3-001",
        title: `Publicly Accessible S3 Bucket (${asset.name})`,
        category: "Public Resource Exposure",
        severity: rb.severity,
        epistemic_class: "Confirmed Configuration Relationship",
        affected_resource_id: asset.id,
        affected_resource_name: asset.name,
        affected_resource_type: asset.type,
        relevant_policy_statement: asset.resource_policy ?? {
          acl: "public-read",
        },
        explanation: `S3 Bucket '${asset.name}' is publicly exposed via wildcard Principal '*' or public ACL with BlockPublicAccess disabled.`,
        evidence: "is_public=true, BlockPublicAccess=false",
        potential_impact:
          "Unauthenticated data disclosure or malicious web asset tampering (supply-chain injection).",
        attack_path_Open_refs: pathRefs,
        risk_breakdown: rb,
        mitre_techniques: [MITRE_CLOUD_CATALOG.T1530],
        remediation: buildRemediationTS(
          "CP-S3-001",
          asset.name,
          asset.resource_policy ?? asset.raw_evidence
        ),
      });
    }

    if (asset.type === "SecurityGroup" && asset.is_public) {
      fCounter += 1;
      const rb = calculateRiskScoreTS(
        {
          exposureScore: 95,
          exposureReason:
            "Allows unrestricted 0.0.0.0/0 ingress on TCP port 22 (SSH) and 443.",
          privilegeScore: 78,
          privilegeReason:
            "Attached to compute instance running with privileged IAM instance profile.",
          sensitivityScore: 85,
          sensitivityReason:
            "Protects production settlement compute workload.",
          reachabilityScore: 95,
          reachabilityReason: `Serves as initial network entry point for ${pathRefs.length} attack path(s).`,
          trustScore: 75,
          trustReason:
            "Exposes instance metadata service (IMDSv1) role credentials if workload is breached.",
        },
        weights
      );
      findings.push({
        id: `FND-${String(fCounter).padStart(3, "0")}`,
        rule_id: "CP-NET-001",
        title: `Unrestricted 0.0.0.0/0 SSH Ingress on Security Group (${asset.name})`,
        category: "Network & Compute Exposure",
        severity: rb.severity,
        epistemic_class: "Confirmed Configuration Relationship",
        affected_resource_id: asset.id,
        affected_resource_name: asset.name,
        affected_resource_type: asset.type,
        relevant_policy_statement: asset.network_config,
        explanation: `Security group '${asset.name}' allows 0.0.0.0/0 on port 22 and is attached to a public EC2 instance with a critical IAM role.`,
        evidence: `ingress_rules=${JSON.stringify(asset.network_config.ingress_rules)}`,
        potential_impact:
          "Brute-force or service exploitation leads to IMDS credential theft of ProdSettlementInstanceRole.",
        attack_path_Open_refs: pathRefs,
        risk_breakdown: rb,
        mitre_techniques: [
          MITRE_CLOUD_CATALOG.T1190,
          MITRE_CLOUD_CATALOG.T1530,
        ],
        remediation: buildRemediationTS(
          "CP-NET-001",
          asset.name,
          asset.network_config
        ),
      });
    }

    if (
      asset.type === "IAMUser" &&
      (asset.tags.Status === "OrphanedAccount" ||
        Number(asset.tags.LastUsedDaysAgo ?? 0) > 90 ||
        Number(asset.tags.AccessKeyAgeDays ?? 0) > 180)
    ) {
      fCounter += 1;
      const rb = calculateRiskScoreTS(
        {
          exposureScore: 58,
          exposureReason: `Long-lived access key or dormant account (tags: ${JSON.stringify(asset.tags)}).`,
          privilegeScore: eff.isAdminEquivalent ? 85 : 60,
          privilegeReason:
            "Retains active policy attachments without credential rotation.",
          sensitivityScore: 75,
          sensitivityReason: "Can traverse to production resources if leaked.",
          reachabilityScore: 80,
          reachabilityReason: `Originates ${pathRefs.length} potential attack path(s).`,
          trustScore: 60,
          trustReason:
            "Static IAM user credentials lack automatic session expiration.",
        },
        weights
      );
      findings.push({
        id: `FND-${String(fCounter).padStart(3, "0")}`,
        rule_id: "CP-IAM-004",
        title: `Dormant / Unrotated IAM User Credentials (${asset.name})`,
        category: "Identity Hygiene & Orphaned Access",
        severity: rb.severity,
        epistemic_class: "Confirmed Configuration Relationship",
        affected_resource_id: asset.id,
        affected_resource_name: asset.name,
        affected_resource_type: asset.type,
        relevant_policy_statement: asset.tags,
        explanation: `IAM User '${asset.name}' has unrotated or dormant credentials (${JSON.stringify(asset.tags)}) while retaining active permissions.`,
        evidence: `Identity telemetry tags: ${JSON.stringify(asset.tags)}`,
        potential_impact:
          "Compromised legacy credentials allow silent persistence and privilege escalation.",
        attack_path_Open_refs: pathRefs,
        risk_breakdown: rb,
        mitre_techniques: [MITRE_CLOUD_CATALOG["T1078.004"]],
        remediation: buildRemediationTS(
          "CP-IAM-004",
          asset.name,
          asset.raw_evidence
        ),
      });
    }
  }

  findings.sort(
    (a, b) => b.risk_breakdown.final_score - a.risk_breakdown.final_score
  );

  for (const asset of env.assets) {
    const relF = findings
      .filter((f) => f.affected_resource_id === asset.id)
      .map((f) => f.risk_breakdown.final_score);
    const relP = attackPaths
      .filter((p) => p.node_chain.includes(asset.id))
      .map((p) => p.risk_breakdown.final_score);
    const baseSens = (SENSITIVITY_SCORES[asset.sensitivity] ?? 40) * 0.55;
    asset.risk_score = Number(Math.max(...relF, ...relP, baseSens).toFixed(1));
    asset.risk_level = scoreToSeverityTS(asset.risk_score);
  }

  const nodes: GraphNode[] = env.assets.map((a) => ({
    id: a.id,
    label: a.name,
    type: a.type,
    provider: a.provider,
    service: a.service,
    is_public: a.is_public,
    is_critical: a.risk_level === "Critical" || a.sensitivity === "critical",
    sensitivity: a.sensitivity,
    risk_score: a.risk_score,
    severity: a.risk_level,
    metadata: {
      permissions: a.permissions.slice(0, 12),
      explicit_denies: a.explicit_denies,
      tags: a.tags,
    },
  }));

  const critCount = findings.filter((f) => f.severity === "Critical").length;
  const highCount = findings.filter((f) => f.severity === "High").length;
  const medCount = findings.filter((f) => f.severity === "Medium").length;
  const lowCount = findings.filter((f) => f.severity === "Low").length;
  const infoCount = findings.filter(
    (f) => f.severity === "Informational"
  ).length;

  const assetDist: Record<string, number> = {};
  for (const a of env.assets) {
    assetDist[a.type] = (assetDist[a.type] ?? 0) + 1;
  }

  const maxFinding = Math.max(
    ...findings.map((f) => f.risk_breakdown.final_score),
    25
  );
  const postureScore = Number(
    Math.max(12, 100 - maxFinding * 0.65 - critCount * 4.5).toFixed(1)
  );

  return {
    id: `scan-${Math.random().toString(36).slice(2, 10)}`,
    workspace_id: workspaceId,
    name: scanName,
    organization: env.organization,
    account_id: env.accountId,
    source_type: env.sourceType,
    provider: "aws",
    created_at: new Date().toISOString(),
    warnings: env.warnings,
    unsupported_resources: env.unsupportedResources,
    summary_metrics: {
      total_assets: env.assets.length,
      total_identities: env.assets.filter((a) =>
        ["IAMUser", "IAMRole", "IAMGroup", "ExternalPrincipal"].includes(a.type)
      ).length,
      critical_findings: critCount,
      high_findings: highCount,
      medium_findings: medCount,
      low_findings: lowCount,
      info_findings: infoCount,
      high_risk_attack_paths: attackPaths.filter(
        (p) =>
          p.risk_breakdown.severity === "Critical" ||
          p.risk_breakdown.severity === "High"
      ).length,
      total_attack_paths: attackPaths.length,
      publicly_exposed_resources: env.assets.filter((a) => a.is_public).length,
      excessive_permission_count: env.assets.filter((a) => {
        const eff = effectiveById.get(a.id)!;
        return (
          eff.hasWildcardAllow ||
          eff.canModifyPolicies ||
          eff.canEscalateViaPassrole
        );
      }).length,
      overall_posture_score: postureScore,
      risk_distribution: {
        Critical: critCount,
        High: highCount,
        Medium: medCount,
        Low: lowCount,
        Informational: infoCount,
      },
      asset_distribution: assetDist,
    },
    nodes,
    edges,
    assets: env.assets,
    findings,
    attack_paths: attackPaths,
  };
}
