"""
SecureMailScope — Risk Scoring Engine
Deterministic composite risk score — NOT an official NIST/BIS/NTRO score.
"""
from __future__ import annotations

import logging
from typing import Any

from backend.models.session import Finding, FindingSeverity, RiskScore, TCPSession

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scoring Configuration (configurable weights)
# ---------------------------------------------------------------------------

DEFAULT_WEIGHTS: dict[str, float] = {
    "base_score": 100.0,
    # Deductions per finding
    "critical_deduction": 25.0,
    "high_deduction": 15.0,
    "medium_deduction": 7.0,
    "low_deduction": 2.0,
    # ML anomaly deduction
    "ml_anomaly_deduction": 5.0,
    # Positive adjustments
    "tls_13_bonus": 3.0,
    "forward_secrecy_bonus": 2.0,
    "valid_cert_bonus": 1.0,
}

RISK_LEVELS = [
    (85, "MINIMAL"),
    (70, "LOW"),
    (50, "MEDIUM"),
    (30, "HIGH"),
    (0,  "CRITICAL"),
]


def _risk_level(score: float) -> str:
    for threshold, label in RISK_LEVELS:
        if score >= threshold:
            return label
    return "CRITICAL"


def compute_risk_score(
    sessions: list[TCPSession],
    weights: dict[str, float] | None = None,
) -> RiskScore:
    """
    Compute the SecureMailScope Composite Risk Score across all sessions.
    
    The score starts at 100 and deductions are applied per finding.
    Positive controls (TLS 1.3, FS, valid certs) partially restore score.
    Score is clamped to [0, 100].
    """
    w = {**DEFAULT_WEIGHTS, **(weights or {})}
    score = w["base_score"]
    rationale: list[str] = []

    # Count findings
    crit = high = med = low = info = ml_count = 0
    for session in sessions:
        for finding in session.findings:
            if finding.is_ml_finding:
                ml_count += 1
            elif finding.severity == FindingSeverity.CRITICAL:
                crit += 1
            elif finding.severity == FindingSeverity.HIGH:
                high += 1
            elif finding.severity == FindingSeverity.MEDIUM:
                med += 1
            elif finding.severity == FindingSeverity.LOW:
                low += 1
            else:
                info += 1

    # Apply deductions
    if crit:
        d = crit * w["critical_deduction"]
        score -= d
        rationale.append(f"{crit} critical finding(s): -{d:.1f}")
    if high:
        d = high * w["high_deduction"]
        score -= d
        rationale.append(f"{high} high finding(s): -{d:.1f}")
    if med:
        d = med * w["medium_deduction"]
        score -= d
        rationale.append(f"{med} medium finding(s): -{d:.1f}")
    if low:
        d = low * w["low_deduction"]
        score -= d
        rationale.append(f"{low} low finding(s): -{d:.1f}")
    if ml_count:
        d = ml_count * w["ml_anomaly_deduction"]
        score -= d
        rationale.append(f"{ml_count} ML anomaly finding(s): -{d:.1f}")

    # Positive adjustments
    from backend.models.session import TLSVersion, ForwardSecrecyStatus
    for session in sessions:
        if session.tls_handshake:
            if session.tls_handshake.tls_version == TLSVersion.TLS_1_3:
                score += w["tls_13_bonus"]
                rationale.append(f"TLS 1.3 in session {session.session_id[-8:]}: +{w['tls_13_bonus']:.1f}")
            if session.tls_handshake.forward_secrecy == ForwardSecrecyStatus.YES:
                score += w["forward_secrecy_bonus"]

    score = max(0.0, min(100.0, score))

    return RiskScore(
        score=round(score, 1),
        level=_risk_level(score),
        rationale=rationale,
        critical_count=crit,
        high_count=high,
        medium_count=med,
        low_count=low,
        info_count=info,
        ml_anomaly_count=ml_count,
    )


def prioritize_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (critical first), then by category."""
    severity_order = {
        FindingSeverity.CRITICAL: 0,
        FindingSeverity.HIGH: 1,
        FindingSeverity.MEDIUM: 2,
        FindingSeverity.LOW: 3,
        FindingSeverity.INFO: 4,
    }
    return sorted(findings, key=lambda f: (severity_order.get(f.severity, 5), f.category.value))


def generate_recommendations(findings: list[Finding]) -> list[str]:
    """Deduplicate and prioritize recommendations from all findings."""
    seen: set[str] = set()
    recs: list[str] = []
    for finding in prioritize_findings(findings):
        rec = finding.recommendation.strip()
        if rec and rec not in seen:
            seen.add(rec)
            recs.append(rec)
    return recs
