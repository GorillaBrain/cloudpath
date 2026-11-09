"""
Module E: Transparent & Explainable Risk Scoring Engine for CloudPath.
Implements a documented, user-configurable weighted scoring formula normalized to 0–100:
Risk Score = (w_exp * Exposure) + (w_priv * Privilege) + (w_sens * Sensitivity)
           + (w_reach * Reachability) + (w_trust * Trust)

Severity Mapping:
- 0–19: Informational
- 20–39: Low
- 40–59: Medium
- 60–79: High
- 80–100: Critical
"""

from __future__ import annotations
from dataclasses import dataclass
from backend.models import RiskBreakdown, RiskFactorScore, RiskWeights, SeverityLevel


@dataclass
class RiskInputFactors:
    exposure_score: float
    exposure_reason: str
    privilege_score: float
    privilege_reason: str
    sensitivity_score: float
    sensitivity_reason: str
    reachability_score: float
    reachability_reason: str
    trust_score: float
    trust_reason: str
    confidence: float = 0.95
    confidence_reason: str = "Evaluated from full static IAM policy & resource declarations."


def score_to_severity(score: float) -> SeverityLevel:
    if score >= 80.0:
        return SeverityLevel.CRITICAL
    if score >= 60.0:
        return SeverityLevel.HIGH
    if score >= 40.0:
        return SeverityLevel.MEDIUM
    if score >= 20.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFORMATIONAL


def calculate_risk_score(factors: RiskInputFactors, weights: RiskWeights | None = None) -> RiskBreakdown:
    w = (weights or RiskWeights()).normalized()

    exp_contrib = round(factors.exposure_score * w["exposure"], 2)
    priv_contrib = round(factors.privilege_score * w["privilege"], 2)
    sens_contrib = round(factors.sensitivity_score * w["sensitivity"], 2)
    reach_contrib = round(factors.reachability_score * w["reachability"], 2)
    trust_contrib = round(factors.trust_score * w["trust"], 2)

    raw_total = exp_contrib + priv_contrib + sens_contrib + reach_contrib + trust_contrib
    final_score = round(min(100.0, max(0.0, raw_total)), 1)
    severity = score_to_severity(final_score)

    formula_str = (
        f"Score ({final_score}) = "
        f"Exposure({factors.exposure_score:.0f} × {w['exposure']:.2f}) + "
        f"Privilege({factors.privilege_score:.0f} × {w['privilege']:.2f}) + "
        f"Sensitivity({factors.sensitivity_score:.0f} × {w['sensitivity']:.2f}) + "
        f"Reachability({factors.reachability_score:.0f} × {w['reachability']:.2f}) + "
        f"Trust({factors.trust_score:.0f} × {w['trust']:.2f})"
    )

    factor_list = [
        RiskFactorScore(
            factor="Public & Network Exposure",
            raw_score=round(factors.exposure_score, 1),
            weight=round(w["exposure"], 2),
            weighted_contribution=exp_contrib,
            justification=factors.exposure_reason,
        ),
        RiskFactorScore(
            factor="Privilege & Escalation Scope",
            raw_score=round(factors.privilege_score, 1),
            weight=round(w["privilege"], 2),
            weighted_contribution=priv_contrib,
            justification=factors.privilege_reason,
        ),
        RiskFactorScore(
            factor="Target Resource Sensitivity & Impact",
            raw_score=round(factors.sensitivity_score, 1),
            weight=round(w["sensitivity"], 2),
            weighted_contribution=sens_contrib,
            justification=factors.sensitivity_reason,
        ),
        RiskFactorScore(
            factor="Attack Path Reachability (Hop Distance)",
            raw_score=round(factors.reachability_score, 1),
            weight=round(w["reachability"], 2),
            weighted_contribution=reach_contrib,
            justification=factors.reachability_reason,
        ),
        RiskFactorScore(
            factor="Identity Trust Boundary Risk",
            raw_score=round(factors.trust_score, 1),
            weight=round(w["trust"], 2),
            weighted_contribution=trust_contrib,
            justification=factors.trust_reason,
        ),
    ]

    return RiskBreakdown(
        final_score=final_score,
        severity=severity,
        confidence=factors.confidence,
        confidence_reason=factors.confidence_reason,
        formula_summary=formula_str,
        factors=factor_list,
    )
