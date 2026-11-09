import { describe, it, expect } from "vitest";
import {
  evaluateEffectivePermissionsTS,
  getNorthstarDemoEnvironment,
  runFullAnalysisTS,
  DEMO_WORKSPACE_ID,
} from "../../src/lib/engine/ts-analyzer";

describe("CloudPath TypeScript Engine Parity & Security Suite", () => {
  it("enforces explicit Deny overriding wildcard Allow (*:*)", () => {
    const eff = evaluateEffectivePermissionsTS([
      { Effect: "Allow", Action: "*", Resource: "*" },
      { Effect: "Deny", Action: ["s3:*", "sts:AssumeRole"], Resource: "*" },
    ]);
    expect(eff.isActionAllowed("ec2:RunInstances")).toBe(true);
    expect(eff.isActionAllowed("s3:GetObject")).toBe(false);
    expect(eff.isActionAllowed("sts:AssumeRole")).toBe(false);
  });

  it("detects iam:PassRole + compute execution escalation", () => {
    const eff = evaluateEffectivePermissionsTS([
      {
        Effect: "Allow",
        Action: ["iam:PassRole", "ec2:RunInstances"],
        Resource: "*",
      },
    ]);
    expect(eff.canEscalateViaPassrole).toBe(true);
    expect(eff.escalationPrimitives).toContain("iam:PassRole + ec2:RunInstances");
  });

  it("analyzes Northstar Financial Technologies demo environment and produces multi-hop attack paths", () => {
    const demo = getNorthstarDemoEnvironment();
    const result = runFullAnalysisTS(
      demo,
      "demo_environment",
      "Northstar Demo Scan",
      DEMO_WORKSPACE_ID
    );
    expect(result.summary_metrics.total_assets).toBeGreaterThanOrEqual(14);
    expect(result.attack_paths.length).toBeGreaterThanOrEqual(4);
    expect(result.findings.length).toBeGreaterThanOrEqual(8);

    for (const p of result.attack_paths) {
      expect(p.epistemic_class).not.toBe("Observed Security Incident");
      expect(p.risk_breakdown.final_score).toBeGreaterThan(0);
      expect(p.risk_breakdown.final_score).toBeLessThanOrEqual(100);
    }
  });

  it("parses Terraform HCL configurations and flags public S3 buckets", () => {
    const hcl = `
      resource "aws_iam_user" "deployer" {
        name = "ci-deployer"
      }
      resource "aws_iam_role" "admin_role" {
        name = "ProdAdminRole"
      }
      resource "aws_s3_bucket" "vault" {
        bucket = "prod-cardholder-vault"
        acl    = "public-read"
      }
    `;
    const res = runFullAnalysisTS(
      hcl,
      "terraform_hcl",
      "Terraform Audit",
      DEMO_WORKSPACE_ID,
      undefined,
      "main.tf"
    );
    expect(res.assets.some((a) => a.name === "prod-cardholder-vault")).toBe(true);
    expect(res.findings.some((f) => f.rule_id === "CP-S3-001")).toBe(true);
  });

  it("rejects malicious script injection payloads", () => {
    expect(() =>
      runFullAnalysisTS(
        "#!/bin/bash\nrm -rf /",
        "custom_json",
        "Malicious Upload",
        DEMO_WORKSPACE_ID
      )
    ).toThrow(/Security violation/);
  });
});
