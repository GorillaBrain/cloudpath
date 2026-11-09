# Contributing to CloudPath

Thank you for contributing to **CloudPath**! We welcome pull requests that expand cloud provider coverage (AWS, Azure Entra ID, GCP IAM), improve IAM condition evaluation, or add new privilege escalation detection rules.

## Development Workflow

1. **Fork & Clone** the repository:
   ```bash
   git clone https://github.com/GorillaBrain/cloudpath.git
   cd cloudpath
   ```
2. **Backend Setup & Tests (Python 3.12+)**:
   ```bash
   pip install -r backend/requirements.txt
   PYTHONPATH=. pytest tests/backend -v
   ```
3. **Frontend Setup & Tests (Node.js 20+)**:
   ```bash
   npm install --legacy-peer-deps
   npm test
   npm run build
   ```

## Engineering Guidelines

- **Every Graph Edge Requires Evidence**: Never add synthetic or decorative edges between cloud resources. Every edge in `backend/analyzer.py` and `src/lib/engine/ts-analyzer.ts` must cite the exact policy statement, trust principal, or network rule that created it.
- **Honor Explicit Deny**: Any new permission check must call `eff.is_action_allowed(action, resource)` so explicit `Deny` statements always take precedence over `Allow`.
- **Epistemic Clarity**: Never label static configuration findings as `Observed Security Incident`.
- **Test-Driven Development**: Include unit tests in `tests/backend/test_engine.py` and `tests/frontend/analyzer.test.ts` for every new detection rule or parser format.
