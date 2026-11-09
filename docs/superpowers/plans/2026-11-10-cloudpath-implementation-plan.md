# CloudPath — Implementation Plan & System Specification

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Design, engineer, test, document, and deploy **CloudPath**, a production-grade Cloud Attack Path Mapper & Identity Risk Intelligence Platform for AWS IAM, trust relationships, and cloud resource exposure.

**Architecture:**
- **Analysis Backend (`/backend`)**: Python 3.12+, FastAPI, Pydantic v2, NetworkX (`MultiDiGraph`). Provides offline, read-only parsing and normalization of Terraform HCL/JSON, AWS IAM policies, Trust policies, AWS Config exports, and custom cloud environment manifests. Builds directed identity-to-resource graphs, evaluates IAM policy semantics (explicit `Deny` precedence, wildcards, `iam:PassRole` + execution, `sts:AssumeRole`, policy modification privilege escalation, cross-account trust, S3/SG public exposure), executes BFS/DFS/Dijkstra shortest-path discovery, and computes transparent, weighted 0–100 risk scores with MITRE ATT&CK Cloud mappings and before/after remediation diffs.
- **Enterprise Frontend (`/src`)**: Next.js (App Router), TypeScript, Tailwind CSS, shadcn/ui design primitives, `@xyflow/react` (React Flow) for interactive graph exploration, Recharts for risk/asset telemetry, Lucide icons, and Supabase client for authentication, workspace isolation, and persistence.
- **Database & Security (`/supabase`)**: Supabase PostgreSQL with Row Level Security (RLS) migrations (`supabase/migrations/20261110000000_cloudpath_schema.sql`), plus deterministic workspace-isolated storage so both authenticated workspaces and the public **Northstar Financial Technologies** demonstration environment work seamlessly.

**Tech Stack:** Next.js 15+ (App Router), TypeScript, Tailwind CSS, React Flow (`@xyflow/react`), Recharts, Lucide React, Python 3.12+, FastAPI, Pydantic, NetworkX, Pytest, Vitest, Docker, GitHub Actions, Supabase, Vercel.

**Spec:** User Build Directive (`PROJECT BUILD DIRECTIVE: CLOUDPATH`)

## Global Constraints
- Never request live AWS access keys or secret credentials; analysis is 100% read-only on uploaded configurations.
- Never execute uploaded Terraform, shell scripts, binaries, or arbitrary code (`eval`/`exec`/`subprocess` on user input is strictly forbidden).
- Distinguish clearly between: (1) `CONFIRMED_CONFIGURATION` relationships, (2) `POTENTIAL_ATTACK_PATH` based on policy evaluation, (3) `HYPOTHETICAL_SCENARIO`, and (4) `OBSERVED_INCIDENT` (never claim a theoretical path was exploited).
- Account for explicit `Deny` overriding `Allow`, policy scope, principal conditions, and resource constraints.
- Normalize risk scores to `0–100` (`0–19` Informational, `20–39` Low, `40–59` Medium, `60–79` High, `80–100` Critical) with documented, user-configurable factor weights.
- All dashboard and demonstration metrics must be computed dynamically by the real analysis engine (no hardcoded attack graphs or fake numbers).

## Review Focus
1. **Explicit Deny Precedence**: An IAM identity has `AdministratorAccess` (`*:*`) in one policy statement, and an explicit `Deny` on `s3:*` or `sts:AssumeRole` in another statement or inline policy — the engine must suppress `CAN_ACCESS` / `CAN_ASSUME_ROLE` edges covered by the explicit `Deny`.
2. **Malformed / Hostile Uploads**: Oversized payloads (>5 MB), invalid JSON/HCL syntax, deeply nested objects, or YAML/script payloads masquerading as configs must be safely rejected with clear validation error messages and HTTP 400/413 status codes.
3. **Multi-Hop Privilege Escalation (`iam:PassRole` + `ec2:RunInstances` / `lambda:CreateFunction`)**: A low-privilege user without direct S3 access can pass an administrative role to a compute instance or Lambda function and reach a sensitive S3 bucket; the engine must discover this multi-hop path and classify each edge accurately.
4. **Cross-Workspace Isolation**: Requests belonging to Workspace A must never read or mutate scans, findings, or settings belonging to Workspace B.
5. **Cycle-Safe Graph Traversal**: Mutual role assumption (`RoleA` trusts `RoleB` and `RoleB` trusts `RoleA`) must not cause infinite loops during DFS/BFS path discovery or shortest-path calculation.

---

### Task 1: Backend Core Models, IAM Semantics Evaluator, and Multi-Format Importer (`Module A & B`)

**Files:**
- Create: `backend/__init__.py`
- Create: `backend/models.py`
- Create: `backend/iam_evaluator.py`
- Create: `backend/importer.py`
- Create: `backend/demo_environment.py`

**Interfaces:**
- Produces:
  - `CloudAsset`, `GraphNode`, `GraphEdge`, `Finding`, `AttackPath`, `RiskBreakdown`, `RemediationGuidance`, `ScanResult`, `RiskWeights` in `backend/models.py`
  - `evaluate_effective_permissions(statements: list[dict]) -> EffectivePermissions` in `backend/iam_evaluator.py`
  - `parse_cloud_input(content: str, format_hint: str | None = None, filename: str | None = None) -> ParsedEnvironment` in `backend/importer.py`
  - `get_northstar_demo_environment() -> dict` in `backend/demo_environment.py`

---

### Task 2: Graph Analysis Engine, Risk Scoring Engine, MITRE Mapping & Remediation (`Module C, E, F, G`)

**Files:**
- Create: `backend/graph_engine.py`
- Create: `backend/risk_engine.py`
- Create: `backend/remediation.py`
- Create: `backend/analyzer.py`

**Interfaces:**
- Consumes: `ParsedEnvironment`, `evaluate_effective_permissions`, `RiskWeights`
- Produces:
  - `build_cloud_graph(env: ParsedEnvironment) -> nx.MultiDiGraph`
  - `discover_attack_paths(G: nx.MultiDiGraph, assets: dict[str, CloudAsset], weights: RiskWeights) -> list[AttackPath]`
  - `detect_findings(env: ParsedEnvironment, G: nx.MultiDiGraph, paths: list[AttackPath], weights: RiskWeights) -> list[Finding]`
  - `calculate_risk_score(factors: RiskFactors, weights: RiskWeights) -> RiskBreakdown`
  - `run_full_analysis(content: str | dict, source_type: str, scan_name: str, workspace_id: str, weights: RiskWeights | None = None) -> ScanResult`

---

### Task 3: FastAPI Server, Workspace Security, Rate Limiting & Backend Pytest Suite

**Files:**
- Create: `backend/main.py`
- Create: `backend/security.py`
- Create: `backend/requirements.txt`
- Create: `Dockerfile`
- Create: `docker-compose.yml`
- Create: `tests/backend/test_engine.py`
- Create: `tests/backend/test_security.py`

---

### Task 4: Next.js Frontend Design System, TypeScript Engine Mirror & API Layer

**Files:**
- Create: `package.json`, `tsconfig.json`, `next.config.ts`, `postcss.config.mjs`
- Create: `src/types/cloudpath.ts`
- Create: `src/lib/engine/ts-analyzer.ts` (TypeScript parity mirror + FastAPI client connector so both Docker Python backend and Vercel serverless edge/API routes run identical graph & IAM semantics)
- Create: `src/lib/supabase/client.ts`
- Create: `src/context/CloudPathContext.tsx`
- Create: `src/app/api/analyze/route.ts`
- Create: `src/app/api/demo/route.ts`
- Create: `src/app/api/workspaces/route.ts`

---

### Task 5: Application Pages (9 Complete Views) & Interactive React Flow Attack Graph Explorer

**Files:**
- Create: `src/components/layout/AppShell.tsx`
- Create: `src/components/graph/AttackGraphCanvas.tsx`
- Create: `src/components/graph/CustomGraphNode.tsx`
- Create: `src/app/page.tsx` (1. Landing Page + App Router Workspace View)
- Create: `src/components/views/DashboardView.tsx` (2. Dashboard)
- Create: `src/components/views/AttackGraphView.tsx` (3. Attack Graph Explorer)
- Create: `src/components/views/FindingsView.tsx` (4. Findings Table & Remediation Diff)
- Create: `src/components/views/AssetsView.tsx` (5. Cloud Asset Inventory & Inspector)
- Create: `src/components/views/InvestigationsView.tsx` (6. Attack Path Investigations & MITRE ATT&CK)
- Create: `src/components/views/ReportsView.tsx` (7. PDF & JSON Reports)
- Create: `src/components/views/ImportCenterView.tsx` (8. Multi-Format Importer)
- Create: `src/components/views/SettingsView.tsx` (9. Workspace Settings, Auth, Risk Weights & Retention)

---

### Task 6: Frontend Test Suite, Documentation Suite, GitHub Repo & Vercel Production Deployment

**Files:**
- Create: `tests/frontend/analyzer.test.ts`
- Create: `README.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `ATTACK_PATH_ENGINE.md`, `RISK_SCORING.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `LICENSE`
- Create: `.github/workflows/ci.yml`
