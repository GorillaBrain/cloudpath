# Changelog

All notable changes to **CloudPath** are documented in this file.

## [1.0.0] — 2026-11-10

### Added
- **Multi-Format Cloud Environment Importer (`Module A`)**: Added static, zero-execution parsers for Terraform HCL (`.tf`), Terraform Plan JSON, AWS IAM Policy JSON, IAM Role Trust Policy JSON, AWS Config exports, and custom environment manifests with a 5 MB upload ceiling.
- **Cloud Asset Discovery & Inventory (`Module B`)**: Added normalization across 11 node types (`IAMUser`, `IAMRole`, `IAMGroup`, `IAMPolicy`, `S3Bucket`, `EC2Instance`, `SecurityGroup`, `VPC`, `ExternalPrincipal`, `SensitiveResource`, `TrustRelationship`).
- **Graph-Based Attack Path Analysis Engine (`Module C`)**: Implemented NetworkX `MultiDiGraph` construction, AWS IAM explicit `Deny` precedence evaluation, `iam:PassRole` + compute execution escalation detection, IAM policy mutation detection, cycle-safe BFS/DFS path discovery, and Dijkstra shortest-path calculation.
- **Interactive Attack Graph Explorer (`Module D`)**: Built custom React Flow visualization with node icons, severity badges, path isolation, critical path highlighting, search/filtering, and SVG export.
- **Transparent Risk Scoring Engine (`Module E`)**: Added configurable 5-factor weighted scoring (0–100) with per-factor justification and confidence intervals.
- **Attack Path Investigations & MITRE ATT&CK Mapping (`Module F`)**: Added hop-by-hop investigation dossiers mapped to MITRE ATT&CK Cloud (`T1078.004`, `T1098.001`, `T1098.003`, `T1199`, `T1190`, `T1530`).
- **Actionable Remediation Intelligence (`Module G`)**: Added side-by-side before/after JSON configuration diffs and operational impact guidance.
- **Northstar Financial Technologies Demo Environment**: Added realistic enterprise AWS environment generating 5 multi-hop attack paths and 8 findings dynamically through the analysis engine.
- **Supabase PostgreSQL Schema & Row Level Security**: Added migration `20261110000000_cloudpath_schema.sql` enforcing workspace isolation.
