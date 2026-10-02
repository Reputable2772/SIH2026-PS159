"""
Unit tests for Risk Scoring Engine and Posture Evaluation.
"""

from backend.models.session import (
    ApplicationProtocol,
    Evidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    ForwardSecrecyStatus,
    STARTTLSState,
    TCPSession,
    TLSHandshakeInfo,
    TLSVersion,
)
from backend.posture.engine import PostureRuleEngine
from backend.posture.scoring import (
    compute_risk_score,
    generate_recommendations,
    prioritize_findings,
)


def _make_dummy_session(
    session_id: str = "sess-01",
    findings: list[Finding] | None = None,
    tls_version: TLSVersion | None = None,
    forward_secrecy: ForwardSecrecyStatus = ForwardSecrecyStatus.UNKNOWN,
) -> TCPSession:
    handshake = None
    if tls_version or forward_secrecy != ForwardSecrecyStatus.UNKNOWN:
        handshake = TLSHandshakeInfo(
            tls_version=tls_version or TLSVersion.TLS_1_2,
            cipher_suite_name="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            forward_secrecy=forward_secrecy,
        )

    return TCPSession(
        session_id=session_id,
        src_ip="192.168.1.10",
        src_port=54321,
        dst_ip="192.168.1.25",
        dst_port=587,
        protocol=ApplicationProtocol.SMTP,
        findings=findings or [],
        tls_handshake=handshake,
    )


def _make_finding(
    severity: FindingSeverity,
    category: FindingCategory = FindingCategory.CIPHER_SUITE,
    is_ml: bool = False,
    rec: str = "Upgrade configuration",
) -> Finding:
    return Finding(
        id="f-test",
        severity=severity,
        category=category,
        title=f"Test {severity.value} finding",
        description="Test finding description",
        evidence=Evidence(session_id="sess-01"),
        recommendation=rec,
        is_ml_finding=is_ml,
    )


# ---------------------------------------------------------------------------
# Scoring Unit Tests
# ---------------------------------------------------------------------------


def test_clean_session_score():
    """A session with no findings should have a score of 100 and MINIMAL risk."""
    sess = _make_dummy_session()
    result = compute_risk_score([sess])
    assert result.score == 100.0
    assert result.level == "MINIMAL"
    assert result.critical_count == 0
    assert result.high_count == 0


def test_critical_deduction():
    """Critical findings should deduct 25 points each."""
    f1 = _make_finding(FindingSeverity.CRITICAL)
    sess = _make_dummy_session(findings=[f1])
    result = compute_risk_score([sess])
    assert result.score == 75.0
    assert result.critical_count == 1
    assert result.level == "LOW"


def test_multiple_deductions_cumulative():
    """Cumulative deductions for mixed severities."""
    findings = [
        _make_finding(FindingSeverity.CRITICAL),  # -25
        _make_finding(FindingSeverity.HIGH),  # -15
        _make_finding(FindingSeverity.MEDIUM),  # -7
        _make_finding(FindingSeverity.LOW),  # -2
    ]
    sess = _make_dummy_session(findings=findings)
    result = compute_risk_score([sess])
    # 100 - 25 - 15 - 7 - 2 = 51.0
    assert result.score == 51.0
    assert result.level == "MEDIUM"


def test_ml_anomaly_deduction():
    """ML anomaly findings should deduct 5 points each."""
    f_ml = _make_finding(FindingSeverity.MEDIUM, is_ml=True)
    sess = _make_dummy_session(findings=[f_ml])
    result = compute_risk_score([sess])
    assert result.score == 95.0
    assert result.ml_anomaly_count == 1


def test_tls13_and_forward_secrecy_bonuses():
    """Positive controls (TLS 1.3, FS) add bonus points up to clamp max."""
    findings = [_make_finding(FindingSeverity.HIGH)]  # 100 - 15 = 85
    sess = _make_dummy_session(
        findings=findings,
        tls_version=TLSVersion.TLS_1_3,
        forward_secrecy=ForwardSecrecyStatus.YES,
    )
    result = compute_risk_score([sess])
    # 85 + 3.0 (TLS 1.3) + 2.0 (FS) = 90.0
    assert result.score == 90.0
    assert result.level == "MINIMAL"


def test_score_clamping():
    """Score must not fall below 0 or exceed 100."""
    severe_findings = [_make_finding(FindingSeverity.CRITICAL) for _ in range(6)]
    sess = _make_dummy_session(findings=severe_findings)
    result = compute_risk_score([sess])
    assert result.score == 0.0
    assert result.level == "CRITICAL"

    # Perfect session with bonuses
    perfect_sess = _make_dummy_session(
        tls_version=TLSVersion.TLS_1_3,
        forward_secrecy=ForwardSecrecyStatus.YES,
    )
    result_perfect = compute_risk_score([perfect_sess])
    assert result_perfect.score == 100.0


def test_prioritize_findings():
    """Findings must sort with CRITICAL first, then HIGH, MEDIUM, LOW, INFO."""
    f_low = _make_finding(FindingSeverity.LOW)
    f_crit = _make_finding(FindingSeverity.CRITICAL)
    f_high = _make_finding(FindingSeverity.HIGH)
    f_info = _make_finding(FindingSeverity.INFO)

    sorted_f = prioritize_findings([f_low, f_crit, f_info, f_high])
    assert sorted_f[0].severity == FindingSeverity.CRITICAL
    assert sorted_f[1].severity == FindingSeverity.HIGH
    assert sorted_f[2].severity == FindingSeverity.LOW
    assert sorted_f[3].severity == FindingSeverity.INFO


def test_generate_recommendations_deduplication():
    """Recommendations should be deduplicated while preserving order."""
    f1 = _make_finding(FindingSeverity.CRITICAL, rec="Disable SSLv3/TLS 1.0")
    f2 = _make_finding(FindingSeverity.HIGH, rec="Disable SSLv3/TLS 1.0")
    f3 = _make_finding(FindingSeverity.MEDIUM, rec="Enable HSTS / Strict Transport")

    recs = generate_recommendations([f1, f2, f3])
    assert len(recs) == 2
    assert recs[0] == "Disable SSLv3/TLS 1.0"
    assert recs[1] == "Enable HSTS / Strict Transport"


# ---------------------------------------------------------------------------
# Posture Engine Tests
# ---------------------------------------------------------------------------


def test_posture_engine_weak_cipher_detection():
    engine = PostureRuleEngine()
    sess = _make_dummy_session()
    sess.tls_handshake = TLSHandshakeInfo(
        tls_version=TLSVersion.TLS_1_2,
        cipher_suite_name="TLS_RSA_WITH_RC4_128_SHA",
        forward_secrecy=ForwardSecrecyStatus.NO,
    )
    engine.evaluate(sess)
    cipher_findings = [f for f in sess.findings if f.category == FindingCategory.CIPHER_SUITE]
    assert len(cipher_findings) >= 1
    assert any("RC4" in f.title or "Weak Cipher" in f.title for f in cipher_findings)


def test_posture_engine_cleartext_traffic():
    engine = PostureRuleEngine()
    sess = _make_dummy_session()
    sess.tls_handshake = None
    sess.starttls_state = STARTTLSState.NONE
    engine.evaluate(sess)
    no_tls_findings = [f for f in sess.findings if f.category == FindingCategory.STARTTLS]
    assert len(no_tls_findings) >= 1
