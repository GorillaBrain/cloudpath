# Security Policy

## Supported Versions

| Version | Supported |
| :--- | :---: |
| `1.0.x` | ✅ Yes |

## Security Guarantees

1. **Zero Execution of Uploaded Files**: CloudPath parses Terraform HCL (`.tf`) and JSON files strictly as static text/data. It never executes `terraform`, shell scripts, or dynamic code evaluation on user uploads.
2. **No Live Cloud Credentials**: Never paste real production `AWS_SECRET_ACCESS_KEY` values or private cryptographic keys into uploaded files.
3. **Workspace Isolation**: All scans are scoped to an isolated `workspace_id` enforced at both the API layer and Supabase PostgreSQL Row Level Security (RLS).

## Reporting a Vulnerability

If you discover a security vulnerability in CloudPath:
1. Do **not** open a public GitHub issue containing live exploit payloads.
2. Open a security advisory on the [GitHub repository](https://github.com/GorillaBrain/cloudpath/security/advisories) with reproduction steps and affected component (`backend/` or `src/`).
3. We aim to triage and respond within 48 hours.
