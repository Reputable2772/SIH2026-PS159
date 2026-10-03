"""
Unit tests for FastAPI REST API endpoints.
"""

import io

import pytest
from fastapi.testclient import TestClient

from backend.api.main import _analyses, _analysis_status, app
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


def test_list_pcaps(client):
    res = client.get("/api/pcaps")
    assert res.status_code == 200
    items = res.json()
    assert isinstance(items, list)
    if items:
        first = items[0]
        assert "filename" in first
        assert "download_url" in first
        assert "analyse_url" in first
        assert "sha256_hash" in first


def test_download_pcap(client):
    res_list = client.get("/api/pcaps")
    items = res_list.json()
    if items:
        filename = items[0]["filename"]
        res_dl = client.get(f"/api/pcaps/{filename}")
        assert res_dl.status_code == 200
        assert len(res_dl.content) > 0


def test_download_pcap_not_found(client):
    res = client.get("/api/pcaps/non_existent_file.pcap")
    assert res.status_code == 404


def test_analyse_pcap_by_name(client):
    res_list = client.get("/api/pcaps")
    items = res_list.json()
    if items:
        filename = items[0]["filename"]
        res_an = client.post(f"/api/pcaps/{filename}/analyse")
        assert res_an.status_code == 200
        data = res_an.json()
        assert data["status"] == "pending"
        assert "analysis_id" in data


def test_docs_html_response(client):
    res = client.get("/docs", headers={"Accept": "text/html,application/xhtml+xml"})
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "SecureMailScope API" in res.text
    assert "Forensic API Reference" in res.text
    assert "/api/pcaps" in res.text


def test_docs_json_accept_header(client):
    res = client.get("/docs", headers={"Accept": "application/json"})
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]
    data = res.json()
    assert data["api"] == "SecureMailScope API"
    assert "endpoints" in data
    assert "models" in data
    assert any(ep["path"] == "/api/pcaps" for ep in data["endpoints"])


def test_docs_json_query_param(client):
    res = client.get("/docs?format=json")
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]
    data = res.json()
    assert "endpoints" in data
    assert "models" in data
    pcap_ep = next(ep for ep in data["endpoints"] if ep["path"] == "/api/pcaps")
    assert pcap_ep["response"]["model"] == "list[PcapEntry]"


def test_docs_json_direct_path(client):
    res = client.get("/docs.json")
    assert res.status_code == 200
    assert "application/json" in res.headers["content-type"]
    data = res.json()
    assert data["version"] == "0.1.0"

    res_api = client.get("/api/docs.json")
    assert res_api.status_code == 200
    assert res_api.json()["api"] == data["api"]


def test_docs_openapi_format(client):
    res = client.get("/docs?format=openapi")
    assert res.status_code == 200
    data = res.json()
    assert "openapi" in data
    assert "paths" in data
    # Verify our endpoints have rich schemas in OpenAPI paths
    assert "/api/pcaps" in data["paths"]
    assert "200" in data["paths"]["/api/pcaps"]["get"]["responses"]


def test_swagger_endpoint(client):
    res = client.get("/swagger")
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
