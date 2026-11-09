# CloudPath — Transparent Risk Scoring Methodology

## 1. Design Philosophy

CloudPath avoids opaque or arbitrary risk numbers. Every finding and attack path receives a deterministic **0–100 Risk Score** computed from five documented security factors, with user-configurable weights.

> [!IMPORTANT]
> **CVSS Distinction:** CloudPath Risk Scores measure **cloud identity reachability, privilege escalation potential, and blast radius** within an account's specific topology. They are not CVSS software vulnerability scores and must not be treated as interchangeable with CVE severity ratings.

---

## 2. Mathematical Formula

Given a normalized weight vector $\mathbf{w} = (w_{\text{exp}}, w_{\text{priv}}, w_{\text{sens}}, w_{\text{reach}}, w_{\text{trust}})$ where $\sum w_i = 1.00$:

$$\text{RiskScore} = \text{clamp}_{[0, 100]}\Big( w_{\text{exp}} \cdot F_{\text{exp}} + w_{\text{priv}} \cdot F_{\text{priv}} + w_{\text{sens}} \cdot F_{\text{sens}} + w_{\text{reach}} \cdot F_{\text{reach}} + w_{\text{trust}} \cdot F_{\text{trust}} \Big)$$

### Default Factor Weights
| Factor | Symbol | Default Weight | What It Measures |
| :--- | :---: | :---: | :--- |
| **Public & Network Exposure** | $F_{\text{exp}}$ | `0.25` | Whether the entry point or resource is exposed to `0.0.0.0/0`, Principal `*`, an external AWS account, or lacks MFA. |
| **Privilege & Escalation Scope** | $F_{\text{priv}}$ | `0.25` | Whether the path or policy grants `*:*`, `iam:PassRole` + compute execution, or IAM policy self-mutation (`iam:CreatePolicyVersion`). |
| **Target Resource Sensitivity** | $F_{\text{sens}}$ | `0.20` | Data classification of the destination asset (`Critical` = 96, `High` = 78, `Medium` = 50, `Low` = 25). |
| **Attack Path Reachability** | $F_{\text{reach}}$ | `0.15` | Hop distance from entry point to crown-jewel asset ($100 - 12 \times (\text{hops} - 1)$, bounded below by 45). |
| **Identity Trust Boundary Risk** | $F_{\text{trust}}$ | `0.15` | Whether the path crosses account or service trust boundaries without `sts:ExternalId` or MFA conditions. |

---

## 3. Severity Thresholds

| Score Range | Severity Level | Recommended SLA |
| :---: | :--- | :--- |
| **80.0 – 100.0** | **Critical** | Remediate within 24–48 hours (Immediate P1 escalation risk) |
| **60.0 – 79.9** | **High** | Remediate within 7 days |
| **40.0 – 59.9** | **Medium** | Remediate within 30 days |
| **20.0 – 39.9** | **Low** | Remediate during scheduled IAM hygiene review |
| **0.0 – 19.9** | **Informational** | Observation / Defense-in-depth hardening |

---

## 4. Confidence Levels & Epistemic Classification

Each `RiskBreakdown` includes a `confidence` score $\in [0.0, 1.0]$ and an explicit `EpistemicClass`:
- `Confirmed Configuration Relationship`: Directly declared in uploaded JSON/HCL (e.g., `PublicAccessBlock=false` or `Action: "*"`).
- `Potential Attack Path (Policy Evaluation)`: Multi-hop path inferred by evaluating IAM permissions and trust policies across connected entities.
- `Hypothetical Attack Scenario`: What-if simulation assuming initial credential compromise.
- `Observed Security Incident`: **Never emitted by static configuration analysis**—reserved exclusively for verified runtime telemetry.
