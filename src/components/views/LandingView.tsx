"use client";

import React from "react";
import {
  Shield,
  Network,
  KeyRound,
  Lock,
  ArrowRight,
  Github,
  CheckCircle2,
  Terminal,
  Layers,
  AlertTriangle,
  FileCode2,
  Cpu,
} from "lucide-react";
import { useCloudPath } from "@/context/CloudPathContext";

export function LandingView() {
  const { setActiveTab, activeScan } = useCloudPath();

  return (
    <div className="min-h-screen bg-[#090A0F] text-slate-100">
      {/* Top Navbar */}
      <header className="border-b border-slate-800/80 bg-[#090A0F]/90 backdrop-blur sticky top-0 z-30">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-500/15 border border-cyan-500/40 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
            <span className="font-semibold tracking-tight text-white">
              CloudPath
            </span>
            <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/25">
              v1.0 Enterprise CSPM
            </span>
          </div>

          <div className="hidden md:flex items-center gap-6 text-xs text-slate-300">
            <a href="#capabilities" className="hover:text-white transition-colors">
              Core Capabilities
            </a>
            <a href="#architecture" className="hover:text-white transition-colors">
              Graph Engine Architecture
            </a>
            <a href="#security" className="hover:text-white transition-colors">
              Zero-Credential Security
            </a>
            <a
              href="https://github.com/GorillaBrain/cloudpath"
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center gap-1.5 text-slate-300 hover:text-white"
            >
              <Github className="w-3.5 h-3.5" />
              GitHub Repository
            </a>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => setActiveTab("import")}
              className="hidden sm:inline-flex px-3 py-1.5 rounded-md border border-slate-700 hover:border-slate-500 text-xs text-slate-200 transition-colors cursor-pointer"
            >
              Upload Config
            </button>
            <button
              onClick={() => setActiveTab("dashboard")}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs transition-colors cursor-pointer"
            >
              Launch Live Demo
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="max-w-7xl mx-auto px-6 pt-16 pb-14">
        <div className="grid lg:grid-cols-12 gap-10 items-center">
          <div className="lg:col-span-7 space-y-6">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#121624] border border-slate-800 text-xs text-cyan-300">
              <span className="w-2 h-2 rounded-full bg-cyan-400" />
              Cloud Identity Risk Intelligence &amp; Multi-Hop Attack Path Analysis
            </div>

            <h1 className="text-3xl sm:text-5xl font-bold tracking-tight text-white leading-[1.12]">
              Map how attackers traverse{" "}
              <span className="text-cyan-400">IAM permissions</span>,{" "}
              <span className="text-purple-400">trust policies</span>, and
              exposed cloud assets.
            </h1>

            <p className="text-sm sm:text-base text-slate-300 leading-relaxed max-w-2xl">
              CloudPath constructs a directed identity-to-resource graph from your
              Terraform HCL, Terraform Plan JSON, AWS IAM policies, and Config
              exports. Discover privilege escalation chains, evaluate explicit{" "}
              <code className="text-cyan-300 font-mono">Deny</code> semantics,
              calculate shortest paths to critical vaults, and generate
              least-privilege remediation diffs—100% offline with zero cloud
              credentials required.
            </p>

            <div className="flex flex-wrap items-center gap-3 pt-1">
              <button
                onClick={() => setActiveTab("graph")}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-md bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-sm transition-colors cursor-pointer"
              >
                <Network className="w-4 h-4" />
                Explore Interactive Attack Graph
              </button>
              <button
                onClick={() => setActiveTab("dashboard")}
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-md bg-[#141824] hover:bg-slate-800 text-slate-100 border border-slate-700 text-sm font-medium transition-colors cursor-pointer"
              >
                View Northstar Financial Demo ({activeScan.summary_metrics.total_attack_paths} Attack Paths)
              </button>
              <a
                href="https://github.com/GorillaBrain/cloudpath"
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-md bg-[#0E111B] hover:bg-slate-900 text-slate-300 border border-slate-800 text-sm transition-colors"
              >
                <Github className="w-4 h-4" />
                Source &amp; Docs
              </a>
            </div>

            {/* Live Engine Telemetry Strip */}
            <div className="pt-4 grid grid-cols-2 sm:grid-cols-4 gap-3">
              <div className="p-3 rounded-lg bg-[#10131C] border border-slate-800/90">
                <div className="text-[11px] font-mono text-slate-400">
                  DEMO ASSETS ANALYZED
                </div>
                <div className="text-xl font-bold text-white font-mono mt-0.5">
                  {activeScan.summary_metrics.total_assets}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-[#10131C] border border-slate-800/90">
                <div className="text-[11px] font-mono text-slate-400">
                  DISCOVERED PATHS
                </div>
                <div className="text-xl font-bold text-cyan-400 font-mono mt-0.5">
                  {activeScan.summary_metrics.total_attack_paths}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-[#10131C] border border-slate-800/90">
                <div className="text-[11px] font-mono text-slate-400">
                  CRITICAL FINDINGS
                </div>
                <div className="text-xl font-bold text-red-400 font-mono mt-0.5">
                  {activeScan.summary_metrics.critical_findings}
                </div>
              </div>
              <div className="p-3 rounded-lg bg-[#10131C] border border-slate-800/90">
                <div className="text-[11px] font-mono text-slate-400">
                  EVALUATION ENGINE
                </div>
                <div className="text-sm font-bold text-emerald-400 font-mono mt-1.5">
                  BFS / Dijkstra
                </div>
              </div>
            </div>
          </div>

          {/* Right Interactive Attack Chain Preview Card */}
          <div className="lg:col-span-5">
            <div className="rounded-xl bg-[#0F131E] border border-slate-800 p-5 space-y-4 shadow-2xl">
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-red-500" />
                  <span className="text-xs font-mono text-slate-300">
                    LIVE ENGINE TRACE • NORTHSTAR FINANCIAL
                  </span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/15 text-red-400 border border-red-500/30">
                  Risk Score: {activeScan.attack_paths[0]?.risk_breakdown.final_score ?? 88.2} / 100
                </span>
              </div>

              {/* Visual Chain Preview */}
              <div className="space-y-2.5">
                <div className="p-3 rounded-lg bg-[#151A28] border border-slate-700/80 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono text-cyan-400 uppercase block">
                      1. Compromised Entry Identity (IAMUser)
                    </span>
                    <span className="text-xs font-semibold text-white">
                      ci-deploy-assistant
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-slate-300">
                    Key Age: 214d
                  </span>
                </div>

                <div className="pl-6 flex items-center gap-2 text-[11px] font-mono text-amber-400">
                  <span>↓ MEMBER_OF → DevOpsAutomationGroup → ASSIGNED_POLICY</span>
                </div>

                <div className="p-3 rounded-lg bg-[#151A28] border border-orange-500/40 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono text-orange-400 uppercase block">
                      2. Privilege Escalation Primitive (IAMPolicy)
                    </span>
                    <span className="text-xs font-semibold text-white">
                      WorkloadComputePassRolePolicy
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-orange-500/20 text-orange-300">
                    iam:PassRole + ec2:RunInstances
                  </span>
                </div>

                <div className="pl-6 flex items-center gap-2 text-[11px] font-mono text-red-400">
                  <span>↓ CAN_ASSUME_ROLE (Workload Attachment)</span>
                </div>

                <div className="p-3 rounded-lg bg-[#151A28] border border-red-500/40 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono text-red-400 uppercase block">
                      3. Privileged Role (IAMRole)
                    </span>
                    <span className="text-xs font-semibold text-white">
                      ProdSettlementInstanceRole
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-500/20 text-red-300">
                    s3:* + kms:Decrypt
                  </span>
                </div>

                <div className="pl-6 flex items-center gap-2 text-[11px] font-mono text-purple-400">
                  <span>↓ CAN_ACCESS (Effective Allow, 0 Explicit Denies)</span>
                </div>

                <div className="p-3 rounded-lg bg-[#181224] border border-purple-500/50 flex items-center justify-between">
                  <div>
                    <span className="text-[10px] font-mono text-purple-300 uppercase block">
                      4. Crown-Jewel Data Store (S3Bucket)
                    </span>
                    <span className="text-xs font-semibold text-white">
                      northstar-pci-cardholder-vault
                    </span>
                  </div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/25 text-purple-200">
                    PCI-DSS Level 1
                  </span>
                </div>
              </div>

              <div className="pt-2 flex items-center justify-between border-t border-slate-800 text-xs">
                <span className="text-slate-400 text-[11px]">
                  Classification:{" "}
                  <strong className="text-cyan-300">
                    Potential Attack Path (Policy Evaluation)
                  </strong>
                </span>
                <button
                  onClick={() => setActiveTab("investigations")}
                  className="text-cyan-400 hover:text-cyan-300 font-medium inline-flex items-center gap-1 cursor-pointer"
                >
                  Inspect Evidence
                  <ArrowRight className="w-3 h-3" />
                </button>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Core Capabilities Grid */}
      <section
        id="capabilities"
        className="border-t border-slate-800/80 bg-[#0B0D14] py-16"
      >
        <div className="max-w-7xl mx-auto px-6 space-y-10">
          <div className="max-w-2xl">
            <div className="text-xs font-mono uppercase tracking-wider text-cyan-400">
              Engineering Capabilities
            </div>
            <h2 className="text-2xl font-bold text-white mt-1">
              Built for Cloud Security Engineers, Red/Purple Teams &amp; SecOps
            </h2>
          </div>

          <div className="grid md:grid-cols-3 gap-5">
            <div className="p-5 rounded-lg bg-[#11141F] border border-slate-800 space-y-2.5">
              <KeyRound className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">
                True AWS IAM Policy Semantics
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Evaluates explicit <code className="text-slate-200">Deny</code>{" "}
                overrides before <code className="text-slate-200">Allow</code>,
                wildcard action/resource matching,{" "}
                <code className="text-slate-200">iam:PassRole</code> combined
                with compute execution, and IAM self-mutation primitives.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#11141F] border border-slate-800 space-y-2.5">
              <Network className="w-5 h-5 text-purple-400" />
              <h3 className="text-sm font-semibold text-white">
                Multi-Hop Graph &amp; Shortest Path Discovery
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Models 11 node types and 9 relationship types in a directed
                multigraph. Uses cycle-safe BFS/DFS and Dijkstra’s algorithm to
                pinpoint shortest paths to crown-jewel assets.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#11141F] border border-slate-800 space-y-2.5">
              <Layers className="w-5 h-5 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">
                Explainable Weighted Risk Scoring (0–100)
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Transparent formula combining Exposure, Privilege Scope, Target
                Sensitivity, Hop Reachability, and Trust Boundary Risk—with
                customizable workspace weights and confidence intervals.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#11141F] border border-slate-800 space-y-2.5">
              <FileCode2 className="w-5 h-5 text-amber-400" />
              <h3 className="text-sm font-semibold text-white">
                Multi-Format Offline Config Importer
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Supports Terraform HCL (<code className="text-slate-200">.tf</code>),
                Terraform Plan JSON, AWS IAM Policy JSON, Role Trust Policy JSON,
                and AWS Config exports—with strict validation and zero code
                execution.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#11141F] border border-slate-800 space-y-2.5">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-sm font-semibold text-white">
                Epistemic Honesty &amp; MITRE ATT&amp;CK Mapping
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Strictly separates{" "}
                <em>Confirmed Configuration Relationships</em> and{" "}
                <em>Potential Attack Paths</em> from observed security
                incidents, mapped to MITRE ATT&amp;CK Cloud techniques.
              </p>
            </div>

            <div className="p-5 rounded-lg bg-[#11141F] border border-slate-800 space-y-2.5">
              <Terminal className="w-5 h-5 text-cyan-400" />
              <h3 className="text-sm font-semibold text-white">
                Before/After Least-Privilege Remediation Diffs
              </h3>
              <p className="text-xs text-slate-400 leading-relaxed">
                Every finding and attack path includes copy-ready IAM policy
                remediations, <code className="text-slate-200">sts:ExternalId</code>{" "}
                conditions, S3 PublicAccessBlock configs, and operational impact
                notes.
              </p>
            </div>
          </div>
        </div>
      </section>

      {/* Architecture & Security Overview */}
      <section
        id="architecture"
        className="border-t border-slate-800/80 py-16 max-w-7xl mx-auto px-6"
      >
        <div className="grid lg:grid-cols-2 gap-8">
          <div className="p-6 rounded-xl bg-[#10131D] border border-slate-800 space-y-4">
            <div className="flex items-center gap-2 text-cyan-400 text-xs font-mono uppercase">
              <Cpu className="w-4 h-4" />
              Technical Architecture
            </div>
            <h3 className="text-lg font-bold text-white">
              Modular Graph Pipeline
            </h3>
            <div className="space-y-2.5 text-xs text-slate-300 font-mono bg-[#0B0D14] p-4 rounded-lg border border-slate-800">
              <div>1. [Multi-Format Importer] → Static AST/Schema Validation (5 MB cap)</div>
              <div>2. [Asset Normalizer] → 11 Canonical Cloud Entity Types</div>
              <div>3. [IAM Policy Evaluator] → Explicit Deny Precedence + Escalation Primitives</div>
              <div>4. [NetworkX MultiDiGraph] → 9 Directed Relationship Edge Types</div>
              <div>5. [Path Traversal Engine] → Cycle-Safe BFS/DFS + Dijkstra Shortest Path</div>
              <div>6. [Risk &amp; Remediation Engine] → Weighted 0–100 Score + JSON/HCL Diffs</div>
            </div>
          </div>

          <div
            id="security"
            className="p-6 rounded-xl bg-[#10131D] border border-slate-800 space-y-4"
          >
            <div className="flex items-center gap-2 text-emerald-400 text-xs font-mono uppercase">
              <Lock className="w-4 h-4" />
              Security &amp; Privacy Guarantees
            </div>
            <h3 className="text-lg font-bold text-white">
              Zero Live Credentials. Strict Tenant Isolation.
            </h3>
            <ul className="space-y-2.5 text-xs text-slate-300">
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>
                  <strong>No AWS Keys Requested:</strong> CloudPath operates
                  exclusively on offline declarative configuration exports.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Zero Code Execution:</strong> Uploaded Terraform and
                  JSON files are parsed as untrusted text; shell scripts and
                  binaries are rejected immediately.
                </span>
              </li>
              <li className="flex items-start gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                <span>
                  <strong>Workspace Isolation &amp; RLS:</strong> Enforced via
                  Supabase Row Level Security and API workspace headers.
                </span>
              </li>
            </ul>
          </div>
        </div>
      </section>
    </div>
  );
}
