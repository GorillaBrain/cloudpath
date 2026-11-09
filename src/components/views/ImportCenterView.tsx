"use client";

import React, { useState } from "react";
import {
  UploadCloud,
  FileCode2,
  CheckCircle2,
  AlertCircle,
  Sparkles,
  Play,
  Shield,
} from "lucide-react";
import { useCloudPath } from "@/context/CloudPathContext";
import { getNorthstarDemoEnvironment } from "@/lib/engine/ts-analyzer";

const SAMPLE_PRESETS: Record<
  string,
  { label: string; sourceType: string; filename: string; content: string }
> = {
  terraform_hcl: {
    label: "Terraform HCL (.tf) — CI/CD PassRole & Public S3 Vault",
    sourceType: "terraform_hcl",
    filename: "production_iam.tf",
    content: `resource "aws_iam_user" "github_actions_runner" {
  name = "github-actions-deployer"
}

resource "aws_iam_policy" "ci_passrole_policy" {
  name = "CIPassRoleAndComputePolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["iam:PassRole", "ec2:RunInstances", "lambda:CreateFunction", "s3:*"]
      Resource = "*"
    }]
  })
}

resource "aws_iam_role" "prod_database_admin" {
  name = "ProdVaultAdminRole"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_s3_bucket" "customer_pii_vault" {
  bucket = "acme-prod-customer-pii-vault"
  acl    = "public-read"
}

resource "aws_security_group" "public_ssh_sg" {
  name   = "bastion-world-open-sg"
  cidr   = "0.0.0.0/0"
}`,
  },
  iam_policy_json: {
    label: "AWS IAM Policy JSON — Explicit Deny vs Wildcard Allow",
    sourceType: "iam_policy_json",
    filename: "developer_power_policy.json",
    content: JSON.stringify(
      {
        PolicyName: "DeveloperEscalationPolicyWithExplicitDenyTest",
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "AllowComputeAndPassRole",
            Effect: "Allow",
            Action: [
              "iam:PassRole",
              "ec2:RunInstances",
              "iam:CreatePolicyVersion",
              "s3:GetObject",
            ],
            Resource: "*",
          },
          {
            Sid: "ExplicitDenyDirectBilling",
            Effect: "Deny",
            Action: ["aws-portal:*"],
            Resource: "*",
          },
        ],
      },
      null,
      2
    ),
  },
  iam_trust_policy_json: {
    label: "IAM Role Trust Policy JSON — Cross-Account Vendor Root Without ExternalId",
    sourceType: "iam_trust_policy_json",
    filename: "vendor_trust_policy.json",
    content: JSON.stringify(
      {
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "UnrestrictedThirdPartyVendorTrust",
            Effect: "Allow",
            Principal: {
              AWS: "arn:aws:iam::998877665544:root",
            },
            Action: "sts:AssumeRole",
          },
        ],
      },
      null,
      2
    ),
  },
  custom_json: {
    label: "Northstar Financial Technologies — Full Enterprise AWS Manifest",
    sourceType: "custom_json",
    filename: "northstar_enterprise_aws.json",
    content: JSON.stringify(getNorthstarDemoEnvironment(), null, 2),
  },
};

export function ImportCenterView() {
  const { runAnalysisJob, loadNorthstarDemo, setActiveTab, isAnalyzing } =
    useCloudPath();

  const [scanName, setScanName] = useState(
    "Uploaded Cloud Infrastructure Audit"
  );
  const [sourceType, setSourceType] = useState("terraform_hcl");
  const [filename, setFilename] = useState("production_iam.tf");
  const [rawContent, setRawContent] = useState(
    SAMPLE_PRESETS.terraform_hcl.content
  );
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const handlePresetLoad = (key: string) => {
    const preset = SAMPLE_PRESETS[key];
    if (!preset) return;
    setSourceType(preset.sourceType);
    setFilename(preset.filename);
    setRawContent(preset.content);
    setScanName(preset.label);
    setErrorMessage(null);
    setSuccessMessage(null);
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setErrorMessage(null);
    setSuccessMessage(null);

    if (file.size > 5 * 1024 * 1024) {
      setErrorMessage(
        "File rejected: Upload exceeds the 5 MB security size ceiling."
      );
      return;
    }

    const text = await file.text();
    setFilename(file.name);
    setRawContent(text);
    if (file.name.endsWith(".tf")) {
      setSourceType("terraform_hcl");
    } else {
      setSourceType("custom_json");
    }
    setScanName(`File Import: ${file.name}`);
  };

  const handleSubmitAnalysis = async () => {
    setErrorMessage(null);
    setSuccessMessage(null);
    try {
      const res = await runAnalysisJob({
        content: rawContent,
        sourceType,
        scanName,
        filename,
      });
      setSuccessMessage(
        `Analysis complete: Normalized ${res.summary_metrics.total_assets} assets, discovered ${res.summary_metrics.total_attack_paths} attack paths, and detected ${res.findings.length} findings.`
      );
    } catch (err) {
      setErrorMessage((err as Error).message);
    }
  };

  return (
    <div className="p-6 max-w-6xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="bg-[#11131A] p-5 rounded-lg border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-white">
            Cloud Environment Importer &amp; Static Analysis Sandbox
          </h2>
          <p className="text-xs text-slate-400">
            Import Terraform HCL (.tf), Terraform Plan JSON, AWS IAM Policy JSON, Role Trust Policies, AWS Config exports, or load the Northstar Financial demo.
          </p>
        </div>

        <button
          onClick={async () => {
            await loadNorthstarDemo();
            setActiveTab("dashboard");
          }}
          disabled={isAnalyzing}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-md bg-violet-500/20 hover:bg-violet-500/30 text-violet-200 border border-violet-500/40 text-xs font-semibold cursor-pointer"
        >
          <Sparkles className="w-4 h-4 text-violet-400" />
          Reload Northstar Financial Enterprise Demo
        </button>
      </div>

      {/* Security Guarantee Notice */}
      <div className="p-3.5 rounded-lg bg-emerald-500/10 border border-emerald-500/25 flex items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-2.5 text-emerald-200">
          <Shield className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>
            <strong>Zero-Credential Offline Analysis:</strong> CloudPath never
            requests live AWS access keys or secret tokens. Uploaded files are
            parsed strictly as untrusted static data (5 MB limit, zero code
            execution).
          </span>
        </div>
      </div>

      {errorMessage && (
        <div className="p-4 rounded-lg bg-red-500/15 border border-red-500/40 text-xs text-red-200 flex items-start gap-2.5">
          <AlertCircle className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
          <div>
            <div className="font-semibold text-red-300">
              Configuration Import Rejected
            </div>
            <p className="mt-0.5 font-mono">{errorMessage}</p>
          </div>
        </div>
      )}

      {successMessage && (
        <div className="p-4 rounded-lg bg-cyan-500/15 border border-cyan-500/40 text-xs text-cyan-100 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <CheckCircle2 className="w-4 h-4 text-cyan-400 shrink-0" />
            <span>{successMessage}</span>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => setActiveTab("graph")}
              className="px-3 py-1.5 rounded bg-cyan-500 text-slate-950 font-semibold text-xs cursor-pointer"
            >
              Open Attack Graph →
            </button>
            <button
              onClick={() => setActiveTab("dashboard")}
              className="px-3 py-1.5 rounded bg-slate-800 text-slate-200 text-xs cursor-pointer"
            >
              View Dashboard
            </button>
          </div>
        </div>
      )}

      <div className="grid lg:grid-cols-12 gap-6">
        {/* Left Format & Template Selector */}
        <div className="lg:col-span-5 space-y-4">
          <div className="p-4 rounded-lg bg-[#11131A] border border-slate-800 space-y-3">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              1. Select Configuration Format
            </h3>

            <div className="space-y-2 text-xs">
              <div>
                <label className="block text-slate-400 mb-1">
                  Analysis Job Name
                </label>
                <input
                  type="text"
                  value={scanName}
                  onChange={(e) => setScanName(e.target.value)}
                  className="w-full bg-[#161B29] border border-slate-700 rounded-md px-3 py-2 text-slate-100"
                />
              </div>

              <div>
                <label className="block text-slate-400 mb-1">
                  Supported Input Schema
                </label>
                <select
                  aria-label="Supported Input Schema"
                  value={sourceType}
                  onChange={(e) => setSourceType(e.target.value)}
                  className="w-full bg-[#161B29] border border-slate-700 rounded-md px-3 py-2 text-slate-100"
                >
                  <option value="terraform_hcl">
                    1. Terraform Configuration (.tf HCL)
                  </option>
                  <option value="terraform_plan_json">
                    2. Terraform Plan Export (.json)
                  </option>
                  <option value="iam_policy_json">
                    3. AWS IAM Policy Document (.json)
                  </option>
                  <option value="iam_trust_policy_json">
                    4. AWS IAM Role Trust Policy (.json)
                  </option>
                  <option value="aws_config_export">
                    5. AWS Config / IAM Authorization Export (.json)
                  </option>
                  <option value="custom_json">
                    6. CloudPath Custom Environment Manifest (.json)
                  </option>
                </select>
              </div>

              <div className="pt-2">
                <label className="block text-slate-400 mb-1.5">
                  Upload File From Disk (.tf / .json, max 5 MB)
                </label>
                <label className="flex flex-col items-center justify-center p-4 border-2 border-dashed border-slate-700 hover:border-cyan-500/60 rounded-lg bg-[#141824] cursor-pointer transition-colors">
                  <UploadCloud className="w-6 h-6 text-cyan-400 mb-1" />
                  <span className="text-xs text-slate-200 font-medium">
                    Click to select file ({filename})
                  </span>
                  <span className="text-[10px] text-slate-400 mt-0.5">
                    Validated statically in sandbox
                  </span>
                  <input
                    type="file"
                    accept=".tf,.json,.txt"
                    onChange={handleFileUpload}
                    className="hidden"
                  />
                </label>
              </div>
            </div>
          </div>

          <div className="p-4 rounded-lg bg-[#11131A] border border-slate-800 space-y-2.5">
            <h3 className="text-xs font-mono uppercase tracking-wider text-slate-400">
              2. Quick-Load Reference Templates
            </h3>
            {Object.entries(SAMPLE_PRESETS).map(([key, item]) => (
              <button
                key={key}
                onClick={() => handlePresetLoad(key)}
                className="w-full text-left p-2.5 rounded bg-[#161B29] hover:bg-slate-800 border border-slate-800 text-xs text-slate-200 flex items-center gap-2 cursor-pointer"
              >
                <FileCode2 className="w-4 h-4 text-cyan-400 shrink-0" />
                <span className="truncate">{item.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Right Code Editor & Run Button */}
        <div className="lg:col-span-7 rounded-lg bg-[#11131A] border border-slate-800 p-4 flex flex-col">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-slate-400">
              Configuration Payload Editor ({filename})
            </span>
            <button
              onClick={handleSubmitAnalysis}
              disabled={isAnalyzing}
              className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs cursor-pointer"
            >
              <Play className="w-3.5 h-3.5" />
              {isAnalyzing
                ? "Running Graph Analysis..."
                : "Execute Attack Path Analysis"}
            </button>
          </div>

          <textarea
            value={rawContent}
            onChange={(e) => setRawContent(e.target.value)}
            rows={18}
            spellCheck={false}
            className="w-full flex-1 bg-[#090A0F] border border-slate-800 rounded-md p-3.5 text-xs font-mono text-cyan-100 focus:outline-none focus:border-cyan-500"
          />
        </div>
      </div>
    </div>
  );
}
