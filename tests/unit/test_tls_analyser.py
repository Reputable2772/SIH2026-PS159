"""
Unit tests for TLS analyser and risk scoring.
"""
import pytest
from backend.tls.analyser import (
    parse_tls_version,
    resolve_cipher_name,
    is_weak_cipher,
    assess_forward_secrecy,
    get_key_exchange,
    TLSVersion,
    ForwardSecrecyStatus,
)
from backend.posture.scoring import compute_risk_score, _risk_level
from backend.models.session import (
    TCPSession, TLSHandshake, Finding, FindingSeverity, FindingCategory, Evidence,
    ApplicationProtocol, STARTTLSState, ForwardSecrecyStatus as FS,
)


# ---------------------------------------------------------------------------
# TLS Version Parsing
# ---------------------------------------------------------------------------

class TestTLSVersionParsing:
    def test_tls_13_numeric(self):
        assert parse_tls_version("772") == TLSVersion.TLS_1_3

    def test_tls_12_numeric(self):
        assert parse_tls_version("771") == TLSVersion.TLS_1_2

    def test_tls_10_numeric(self):
        assert parse_tls_version("769") == TLSVersion.TLS_1_0

    def test_tls_13_hex(self):
        assert parse_tls_version("0x0304") == TLSVersion.TLS_1_3

    def test_tls_12_hex(self):
        assert parse_tls_version("0x0303") == TLSVersion.TLS_1_2

    def test_ssl_30_hex(self):
        assert parse_tls_version("0x0300") == TLSVersion.SSL_3_0

    def test_unknown(self):
        assert parse_tls_version("garbage") == TLSVersion.UNKNOWN

    def test_none(self):
        assert parse_tls_version(None) == TLSVersion.UNKNOWN


# ---------------------------------------------------------------------------
# Cipher Suite Analysis
# ---------------------------------------------------------------------------

class TestCipherSuiteAnalysis:
    def test_rc4_is_weak(self):
        assert is_weak_cipher("TLS_RSA_WITH_RC4_128_SHA")

    def test_null_is_weak(self):
        assert is_weak_cipher("TLS_NULL_WITH_NULL_NULL")

    def test_3des_is_weak(self):
        assert is_weak_cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA")

    def test_aes_gcm_not_weak(self):
        assert not is_weak_cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

    def test_chacha20_not_weak(self):
        assert not is_weak_cipher("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256")

    def test_resolve_cipher_hex(self):
        assert resolve_cipher_name("0xc02f") == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"

    def test_resolve_cipher_already_name(self):
        assert resolve_cipher_name("TLS_AES_256_GCM_SHA384") == "TLS_AES_256_GCM_SHA384"


# ---------------------------------------------------------------------------
# Forward Secrecy
# ---------------------------------------------------------------------------

class TestForwardSecrecy:
    def test_tls_13_always_fs(self):
        result = assess_forward_secrecy("TLS_AES_128_GCM_SHA256", TLSVersion.TLS_1_3)
        assert result == ForwardSecrecyStatus.YES

    def test_ecdhe_has_fs(self):
        result = assess_forward_secrecy("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TLSVersion.TLS_1_2)
        assert result == ForwardSecrecyStatus.YES

    def test_rsa_no_fs(self):
        result = assess_forward_secrecy("TLS_RSA_WITH_AES_256_CBC_SHA", TLSVersion.TLS_1_2)
        assert result == ForwardSecrecyStatus.NO

    def test_dhe_has_fs(self):
        result = assess_forward_secrecy("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", TLSVersion.TLS_1_2)
        assert result == ForwardSecrecyStatus.YES


# ---------------------------------------------------------------------------
# Key Exchange Extraction
# ---------------------------------------------------------------------------

class TestKeyExchange:
    def test_ecdhe(self):
        assert get_key_exchange("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", TLSVersion.TLS_1_2) == "ECDHE"

    def test_dhe(self):
        assert get_key_exchange("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", TLSVersion.TLS_1_2) == "DHE"

    def test_rsa(self):
        assert get_key_exchange("TLS_RSA_WITH_AES_256_CBC_SHA", TLSVersion.TLS_1_2) == "RSA"

    def test_tls_13_ephemeral(self):
        kex = get_key_exchange("TLS_AES_256_GCM_SHA384", TLSVersion.TLS_1_3)
        assert "ephemeral" in (kex or "").lower() or "1.3" in (kex or "")


# ---------------------------------------------------------------------------
# Risk Scoring
# ---------------------------------------------------------------------------

def _make_session(findings_severity: list[str]) -> TCPSession:
    s = TCPSession(
        session_id="test:1",
        src_ip="1.2.3.4", src_port=12345,
        dst_ip="5.6.7.8", dst_port=25,
        protocol=ApplicationProtocol.SMTP,
        starttls_state=STARTTLSState.NO_TLS,
    )
    for sev in findings_severity:
        s.findings.append(Finding(
            id="test-id",
            severity=FindingSeverity(sev),
            category=FindingCategory.WEAK_CIPHER,
            title="Test finding",
            description="desc",
            evidence=Evidence(pcap_file="test.pcap", session_id="test:1"),
            recommendation="Fix it",
        ))
    return s


class TestRiskScoring:
    def test_clean_session_high_score(self):
        session = _make_session([])
        score = compute_risk_score([session])
        assert score.score >= 90

    def test_critical_finding_reduces_score(self):
        session = _make_session(["critical"])
        score = compute_risk_score([session])
        assert score.score < 80

    def test_multiple_criticals_low_score(self):
        session = _make_session(["critical", "critical", "critical"])
        score = compute_risk_score([session])
        assert score.score < 30

    def test_risk_level_critical(self):
        assert _risk_level(10) == "CRITICAL"

    def test_risk_level_high(self):
        assert _risk_level(45) == "HIGH"

    def test_risk_level_medium(self):
        assert _risk_level(60) == "MEDIUM"

    def test_risk_level_minimal(self):
        assert _risk_level(90) == "MINIMAL"

    def test_score_clamped(self):
        session = _make_session(["critical"] * 10)
        score = compute_risk_score([session])
        assert 0 <= score.score <= 100
