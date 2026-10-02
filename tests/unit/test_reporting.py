"""
Unit tests for Report Generation (JSON, HTML, PDF).
"""

import json
import tempfile
from pathlib import Path

import pytest

from backend.models.session import (
    AnalysisResult,
    ApplicationProtocol,
    CaptureMetadata,
    Evidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    ForwardSecrecyStatus,
    RiskScore,
    TCPSession,
    TLSHandshakeInfo,
    TLSVersion,
)
from backend.reporting.generator import (
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)


@pytest.fixture
def sample_analysis_result() -> AnalysisResult:
    """Fixture providing a realistic mock AnalysisResult."""
    finding = Finding(
        id="f-sample-01",
        severity=FindingSeverity.HIGH,
        category=FindingCategory.CIPHER_SUITE,
        title="Weak Cipher Suite Negotiated",
        description="Negotiated 3DES with RSA key exchange",
        evidence=Evidence(session_id="sess-01", field="tls.ciphersuite", observed_value="0x000a"),
        recommendation="Enforce AES-GCM or ChaCha20-Poly1305 ciphers",
        cve_references=["CVE-2016-2183"],
    )

    session = TCPSession(
        session_id="sess-01",
        src_ip="192.168.1.50",
        src_port=49152,
        dst_ip="10.0.0.25",
        dst_port=587,
        protocol=ApplicationProtocol.SMTP,
        findings=[finding],
        tls_handshake=TLSHandshakeInfo(
            tls_version=TLSVersion.TLS_1_2,
            cipher_suite_name="TLS_RSA_WITH_3DES_EDE_CBC_SHA",
            forward_secrecy=ForwardSecrecyStatus.NO,
        ),
    )

    capture = CaptureMetadata(
        pcap_filename="test_capture.pcap",
        sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        packet_count=42,
        duration_seconds=3.5,
    )

    score = RiskScore(
        score=85.0,
        level="LOW",
        rationale=["1 high finding(s): -15.0"],
        high_count=1,
    )

    return AnalysisResult(
        analysis_id="test-analysis-uuid",
        capture=capture,
        sessions=[session],
        all_findings=[finding],
        risk_score=score,
        recommendations=["Enforce AES-GCM or ChaCha20-Poly1305 ciphers"],
    )


# ---------------------------------------------------------------------------
# JSON Report Tests
# ---------------------------------------------------------------------------


def test_generate_json_report(sample_analysis_result):
    report_dict = generate_json_report(sample_analysis_result)

    assert "report_metadata" in report_dict
    assert report_dict["report_metadata"]["tool"] == "SecureMailScope"
    assert "disclaimer" in report_dict["report_metadata"]
    assert report_dict["analysis_id"] == "test-analysis-uuid"
    assert report_dict["risk_score"]["score"] == 85.0
    assert len(report_dict["all_findings"]) == 1

    # Verify JSON serializability
    json_str = json.dumps(report_dict)
    assert len(json_str) > 0


# ---------------------------------------------------------------------------
# HTML Report Tests
# ---------------------------------------------------------------------------


def test_generate_html_report(sample_analysis_result):
    html = generate_html_report(sample_analysis_result)

    assert "<!DOCTYPE html>" in html
    assert "SecureMailScope" in html
    assert "test_capture.pcap" in html
    assert "85.0" in html or "85" in html
    assert "Weak Cipher Suite Negotiated" in html
    assert "Enforce AES-GCM" in html


# ---------------------------------------------------------------------------
# PDF Report Tests
# ---------------------------------------------------------------------------


def test_generate_pdf_report(sample_analysis_result):
    pytest.importorskip("fpdf")
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        tmp_path = tmp.name

    try:
        out = generate_pdf_report(sample_analysis_result, tmp_path)
        assert Path(out).exists()
        with open(out, "rb") as f:
            header = f.read(5)
            assert header == b"%PDF-"
        assert Path(out).stat().st_size > 500
    finally:
        Path(tmp_path).unlink(missing_ok=True)
