# CloudPath — Threat Model & Security Controls

## 1. Threat Modeling Scope (STRIDE)

Because CloudPath ingests cloud infrastructure configurations from security teams, the platform itself is a high-value target and must treat all uploaded configurations as untrusted input.

| Threat Category | Attack Scenario | CloudPath Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Attacker attempts to impersonate another user or workspace via forged headers. | Supabase JWT authentication + PostgreSQL Row Level Security (RLS) + server-side validation that `X-Workspace-Id` matches `payload.workspace_id`. |
| **Tampering** | Malicious user attempts to overwrite or purge the public Northstar demonstration workspace. | Explicit guard in both FastAPI (`backend/main.py`) and RLS policies blocking mutation/deletion where `is_demo = TRUE`. |
| **Repudiation** | Unauthorized scan creation or workspace purge without audit trail. | `cloudpath_audit_logs` table records actor, workspace, action, and timestamp. |
| **Information Disclosure** | Cross-workspace data leakage (Workspace B querying a `scan_id` belonging to Workspace A). | Enforced `403 Forbidden` check in `GET /api/scans/{scan_id}` verified by automated test `test_api_workspace_isolation_and_security`. |
| **Denial of Service (DoS)** | Uploading a 500 MB JSON bomb or cyclic IAM role graph (`RoleA` $\leftrightarrow$ `RoleB`) to exhaust CPU/RAM. | Strict `5 MB` upload ceiling (`413 Payload Too Large`), sliding-window IP rate limiter (`429 Too Many Requests`), and cycle-safe simple-path traversal (`cutoff=6`). |
| **Elevation of Privilege / RCE** | Uploading a shell script, Python payload, or malicious Terraform provider plugin hoping the backend runs `terraform plan`. | **Zero execution policy**: CloudPath never runs `terraform`, `sh`, `eval`, or `subprocess` on uploaded files. Only static regex/JSON parsing is performed, and script shebangs/`<script>` tags are rejected with `400 Bad Request`. |

---

## 2. Cloud Credential Safety

- **No AWS Access Keys Accepted**: CloudPath v1.0 is intentionally designed as an **offline, read-only configuration analyzer**. It never prompts for `AWS_ACCESS_KEY_ID` or `AWS_SECRET_ACCESS_KEY`.
- **Least-Privilege Container Runtime**: The production `Dockerfile` runs under a non-root Linux user (`uid=1001`, `cloudpath`).
