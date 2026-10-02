"""
Unit tests for FastAPI REST API endpoints.
"""
import io
import pytest
from fastapi.testclient import TestClient

from backend.api.main import app, _analyses, _analysis_status
from backend.models.session import (
    AnalysisResult,
    ApplicationProtocol,
    CaptureMetadata,
    Evidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    RiskScore,
    TCPSession,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mock_analysis_in_db():
    aid = "test-api-analysis-01"
    finding = Finding(
        id="f-api-01",
        severity=FindingSeverity.CRITICAL,
        category=FindingCategory.STARTTLS,
        title="STARTTLS Stripping Suspected",
        description="STARTTLS command observed in plaintext without handshake",
        evidence=Evidence(session_id="sess-api-01"),
        recommendation="Enforce mandatory TLS",
    )
    session = TCPSession(
        session_id="sess-api-01",
        src_ip="10.0.0.1",
        src_port=50000,
        dst_ip="10.0.0.2",
        dst_port=25,
        protocol=ApplicationProtocol.SMTP,
        findings=[finding],
    )
    capture = CaptureMetadata(
        pcap_filename="test_api.pcap",
        sha256_hash="abcd1234efgh5678",
        packet_count=10,
        duration_seconds=1.2,
    )
    score = RiskScore(
        score=75.0,
        level="LOW",
        rationale=["1 critical finding"],
        critical_count=1,
    )
    result = AnalysisResult(
        analysis_id=aid,
        capture=capture,
        sessions=[session],
        all_findings=[finding],
        risk_score=score,
        recommendations=["Enforce mandatory TLS"],
    )

    _analyses[aid] = result
    _analysis_status[aid] = "done"

    yield aid

    _analyses.pop(aid, None)
    _analysis_status.pop(aid, None)


def test_health_endpoint(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data
    assert "tshark_available" in data


def test_list_analyses(client, mock_analysis_in_db):
    response = client.get("/api/analyses")
    assert response.status_code == 200
    items = response.json()
    assert any(item["analysis_id"] == mock_analysis_in_db for item in items)


def test_get_analysis(client, mock_analysis_in_db):
    response = client.get(f"/api/analysis/{mock_analysis_in_db}")
    assert response.status_code == 200
    data = response.json()
    assert data["analysis_id"] == mock_analysis_in_db
    assert data["risk_score"]["score"] == 75.0


def test_get_analysis_status(client, mock_analysis_in_db):
    response = client.get(f"/api/analysis/{mock_analysis_in_db}/status")
    assert response.status_code == 200
    assert response.json()["status"] == "done"


def test_get_sessions(client, mock_analysis_in_db):
    response = client.get(f"/api/analysis/{mock_analysis_in_db}/sessions")
    assert response.status_code == 200
    sessions = response.json()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "sess-api-01"


def test_get_findings_with_filters(client, mock_analysis_in_db):
    # Match severity
    res_crit = client.get(f"/api/analysis/{mock_analysis_in_db}/findings?severity=CRITICAL")
    assert res_crit.status_code == 200
    assert len(res_crit.json()) == 1

    # Non-matching severity
    res_low = client.get(f"/api/analysis/{mock_analysis_in_db}/findings?severity=LOW")
    assert res_low.status_code == 200
    assert len(res_low.json()) == 0


def test_report_json(client, mock_analysis_in_db):
    res = client.get(f"/api/analysis/{mock_analysis_in_db}/report/json")
    assert res.status_code == 200
    data = res.json()
    assert "report_metadata" in data


def test_report_html(client, mock_analysis_in_db):
    res = client.get(f"/api/analysis/{mock_analysis_in_db}/report/html")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SecureMailScope" in res.text


def test_report_pdf(client, mock_analysis_in_db):
    res = client.get(f"/api/analysis/{mock_analysis_in_db}/report/pdf")
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content.startswith(b"%PDF-")


def test_unknown_analysis_404(client):
    res = client.get("/api/analysis/non-existent-uuid")
    assert res.status_code == 404


def test_invalid_upload_suffix(client):
    file_content = b"fake content"
    files = {"file": ("malicious.exe", io.BytesIO(file_content), "application/octet-stream")}
    res = client.post("/api/analysis/upload", files=files)
    assert res.status_code == 400
    assert "Unsupported file type" in res.json()["detail"]
