"""
SecureMailScope — FastAPI Backend
REST API exposing PCAP analysis, session data, and report generation.

All API endpoints, request/response models, and parameters are documented
directly beside the code using Python docstrings, FastAPI tags, and Pydantic Field descriptions.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import (
    BackgroundTasks,
    FastAPI,
    File,
    HTTPException,
    Query,
    Request,
    UploadFile,
)
from fastapi import (
    Path as FastPath,
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

from backend.models.session import AnalysisResult, Finding, TCPSession
from backend.pcap.pipeline import analyse_pcap
from backend.reporting.generator import (
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App Setup & Lifespan
# ---------------------------------------------------------------------------

_background_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for managing async background tasks."""
    yield
    for task in list(_background_tasks):
        task.cancel()


app = FastAPI(
    title="SecureMailScope API",
    description=(
        "AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications. "
        "Provides passive network traffic inspection, STARTTLS state machine validation, "
        "X.509 certificate auditing, and 16-D Isolation Forest anomaly detection for SMTP, IMAP, and POP3."
    ),
    version="0.1.0",
    docs_url=None,  # Handled dynamically by our /docs endpoint
    redoc_url=None,
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Dev mode; restrict in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory analysis store (sufficient for POC)
_analyses: dict[str, AnalysisResult] = {}
_analysis_status: dict[str, str] = {}  # "pending" | "running" | "done" | "error"
_analysis_errors: dict[str, str] = {}

# Demo PCAPs directory
DEMO_PCAPS_DIR = Path(__file__).parent.parent.parent / "demo_pcaps"
UPLOAD_DIR = Path(tempfile.gettempdir()) / "securemailscope_uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Pydantic Schemas (Documented Beside Code)
# ---------------------------------------------------------------------------


class AnalysisRequest(BaseModel):
    """Request payload to initiate analysis on a server-side PCAP file."""

    pcap_path: str = Field(
        ...,
        description="Local or relative filesystem path to the target PCAP capture file.",
        examples=["demo_pcaps/01_enterprise_secure_baseline.pcap"],
    )


class AnalysisStatus(BaseModel):
    """Execution status and tracking descriptor for an asynchronous analysis task."""

    analysis_id: str = Field(
        ...,
        description="Unique UUIDv4 identifier assigned to the analysis run.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    )
    status: str = Field(
        ...,
        description="Current execution lifecycle state: 'pending', 'running', 'done', or 'error'.",
        examples=["pending"],
    )
    error: str | None = Field(
        default=None,
        description="Error details if the analysis failed; None if pending, running, or successful.",
        examples=[None],
    )


class PcapEntry(BaseModel):
    """Forensic metadata descriptor for an available packet capture file."""

    filename: str = Field(
        ...,
        description="Basename of the packet capture file.",
        examples=["01_enterprise_secure_baseline.pcap"],
    )
    title: str = Field(
        ...,
        description="Human-readable scenario title.",
        examples=["Enterprise Secure Baseline"],
    )
    description: str = Field(
        ...,
        description="Detailed forensic description of the captured traffic scenario.",
        examples=[
            "Modern TLS 1.3 / 1.2, ECDHE Forward Secrecy, valid certificates across SMTP, IMAP, and POP3."
        ],
    )
    category: str = Field(
        ...,
        description="Scenario classification category ('secure_baseline', 'legacy_crypto', 'downgrade_attack', 'anomalies', 'network_transports').",
        examples=["secure_baseline"],
    )
    size_bytes: int = Field(
        ...,
        description="File size in bytes on disk.",
        examples=[142850],
    )
    sha256_hash: str = Field(
        ...,
        description="Cryptographic SHA-256 digest of the capture file.",
        examples=["3d9f10a8b2c45e6f1a890b1234567890abcdef1234567890abcdef1234567890"],
    )
    download_url: str = Field(
        ...,
        description="REST API URL to download the raw binary PCAP file.",
        examples=["/api/pcaps/01_enterprise_secure_baseline.pcap"],
    )
    analyse_url: str = Field(
        ...,
        description="REST API URL to trigger asynchronous analysis for this capture.",
        examples=["/api/pcaps/01_enterprise_secure_baseline.pcap/analyse"],
    )


class SessionSummaryItem(BaseModel):
    """Brief 5-tuple summary for an active TCP email session."""

    session_id: str = Field(
        ...,
        description="Unique TCP stream index identifier.",
        examples=["stream-0"],
    )
    protocol: str = Field(
        ...,
        description="Identified application protocol: 'SMTP', 'IMAP', 'POP3', or 'UNKNOWN'.",
        examples=["SMTP"],
    )
    src_ip: str = Field(..., description="Source IPv4 address.", examples=["192.168.1.100"])
    src_port: int = Field(..., description="Source TCP port.", examples=[49210])
    dst_ip: str = Field(..., description="Destination IPv4 address.", examples=["192.168.1.25"])
    dst_port: int = Field(..., description="Destination TCP port.", examples=[587])
    risk_level: str | None = Field(
        default=None,
        description="Session risk level: 'MINIMAL', 'LOW', 'MEDIUM', 'HIGH', or 'CRITICAL'.",
        examples=["MINIMAL"],
    )


class AnalysisSummaryItem(BaseModel):
    """Summary metrics overview for an in-memory or completed analysis run."""

    analysis_id: str = Field(
        ...,
        description="Unique UUIDv4 identifier of the analysis run.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    )
    status: str = Field(
        ...,
        description="Analysis execution status ('pending', 'running', 'done', 'error').",
        examples=["done"],
    )
    pcap: str | None = Field(
        default=None,
        description="Basename of the analyzed capture file.",
        examples=["01_enterprise_secure_baseline.pcap"],
    )
    risk_score: float | None = Field(
        default=None,
        description="Composite Posture Risk Score (0.0 to 100.0).",
        examples=[99.0],
    )
    risk_level: str | None = Field(
        default=None,
        description="Evaluated posture risk band ('MINIMAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL').",
        examples=["MINIMAL"],
    )
    analyzed_at: str | None = Field(
        default=None,
        description="ISO 8601 UTC timestamp of analysis completion.",
        examples=["2026-10-03T10:00:00Z"],
    )
    session_count: int = Field(
        default=0,
        description="Total reconstructed TCP email sessions.",
        examples=[3],
    )
    finding_count: int = Field(
        default=0,
        description="Total security findings emitted.",
        examples=[0],
    )
    packet_count: int = Field(
        default=0,
        description="Total packets processed in the capture.",
        examples=[86],
    )
    critical_count: int = Field(
        default=0,
        description="Count of CRITICAL severity findings.",
        examples=[0],
    )
    high_count: int = Field(
        default=0,
        description="Count of HIGH severity findings.",
        examples=[0],
    )
    sessions: list[SessionSummaryItem] = Field(
        default_factory=list,
        description="Brief summaries of reconstructed TCP sessions.",
    )


class HealthResponse(BaseModel):
    """System operational health and dependency status."""

    status: str = Field(..., description="API operational health status.", examples=["ok"])
    version: str = Field(..., description="SecureMailScope version.", examples=["0.1.0"])
    tshark_available: bool = Field(
        ...,
        description="Indicates whether the TShark binary was detected in PATH.",
        examples=[True],
    )
    analyses_cached: int = Field(
        ...,
        description="Count of analysis results currently cached in memory.",
        examples=[0],
    )


class DemoRunItem(BaseModel):
    """Dispatched demo analysis execution item."""

    analysis_id: str = Field(
        ...,
        description="UUID assigned to the demo analysis job.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    )
    pcap: str = Field(
        ...,
        description="Filename of the demo PCAP file.",
        examples=["01_enterprise_secure_baseline.pcap"],
    )


class DemoRunResponse(BaseModel):
    """Response payload when triggering batch analysis of all canonical demo PCAPs."""

    demo_analyses: list[DemoRunItem] = Field(..., description="List of queued demo analysis tasks.")


# ---------------------------------------------------------------------------
# Interactive & Dynamic Documentation Endpoint
# ---------------------------------------------------------------------------


@app.get(
    "/docs",
    include_in_schema=False,
    summary="Unified API documentation & shape specification",
)
async def api_docs(
    request: Request,
    format: str | None = Query(
        default=None,
        description="Format override: 'json' (OpenAPI schema for tools) or 'html' (interactive UI).",
    ),
):
    """
    Unified API documentation endpoint.

    - Returns OpenAPI JSON schema if format=json or Accept: application/json (for automated tools/agents).
    - Returns interactive Swagger UI for web browsers.
    """
    accept = request.headers.get("accept", "").lower()
    if format == "json" or ("application/json" in accept and "text/html" not in accept):
        return JSONResponse(app.openapi())

    from fastapi.openapi.docs import get_swagger_ui_html

    return get_swagger_ui_html(
        openapi_url=app.openapi_url or "/openapi.json",
        title=f"{app.title} - Documentation",
    )


# ---------------------------------------------------------------------------
# PCAP Upload & Analysis
# ---------------------------------------------------------------------------


@app.post(
    "/api/analysis/upload",
    response_model=AnalysisStatus,
    tags=["Analysis & Ingestion"],
    summary="Upload a PCAP capture file and start asynchronous analysis",
)
async def upload_and_analyse(
    file: UploadFile = File(
        ...,
        description="Packet capture file (.pcap, .pcapng, or .cap) to ingest.",
    ),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """
    Upload a raw packet capture file via multipart/form-data.

    Validates file extension (.pcap, .pcapng, .cap), saves to a temporary forensic
    upload directory, and schedules background stream reconstruction, protocol state
    machine analysis, cryptographic posture evaluation, and ML anomaly detection.

    Returns an `analysis_id` and initial `pending` status.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {suffix}")

    analysis_id = str(uuid.uuid4())
    pcap_path = UPLOAD_DIR / f"{analysis_id}{suffix}"

    content = await file.read()
    with open(pcap_path, "wb") as f:
        f.write(content)

    _analysis_status[analysis_id] = "pending"
    background_tasks.add_task(_run_analysis, analysis_id, str(pcap_path))

    return AnalysisStatus(analysis_id=analysis_id, status="pending")


@app.post(
    "/api/analysis/file",
    response_model=AnalysisStatus,
    tags=["Analysis & Ingestion"],
    summary="Trigger analysis of a PCAP by server filesystem path",
)
async def analyse_file(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """
    Trigger analysis of a PCAP located on the server filesystem.

    Checks DEMO_PCAPS_DIR, project root, and absolute paths. Dispatches
    background processing and returns immediately with a tracking ID.
    """
    pcap_path = Path(request.pcap_path)
    if not pcap_path.exists():
        alt_demo = DEMO_PCAPS_DIR / pcap_path.name
        if alt_demo.exists():
            pcap_path = alt_demo
        else:
            alt_repo = Path(__file__).parent.parent.parent / request.pcap_path
            if alt_repo.exists():
                pcap_path = alt_repo
            else:
                raise HTTPException(status_code=404, detail=f"PCAP not found: {request.pcap_path}")

    analysis_id = str(uuid.uuid4())
    _analysis_status[analysis_id] = "pending"
    background_tasks.add_task(_run_analysis, analysis_id, str(pcap_path))

    return AnalysisStatus(analysis_id=analysis_id, status="pending")


@app.get(
    "/api/analysis/{analysis_id}/status",
    response_model=AnalysisStatus,
    tags=["Analysis & Forensics"],
    summary="Query processing status of an analysis job",
)
async def get_analysis_status(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis to query.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
):
    """
    Poll execution state for an active or completed analysis run.

    Returns status ('pending', 'running', 'done', 'error') and any error message.
    """
    if analysis_id not in _analysis_status:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisStatus(
        analysis_id=analysis_id,
        status=_analysis_status[analysis_id],
        error=_analysis_errors.get(analysis_id),
    )


@app.get(
    "/api/analysis/{analysis_id}",
    response_model=AnalysisResult | AnalysisStatus,
    tags=["Analysis & Forensics"],
    summary="Retrieve complete forensic analysis result tree",
)
async def get_analysis(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis (prefix match supported).",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
):
    """
    Retrieve the complete forensic analysis data tree.

    Contains capture metadata, reconstructed TCP sessions, STARTTLS negotiation states,
    dissected TLS handshakes, X.509 certificate chains, ML anomaly scores, composite
    posture risk score, protocol summaries, all security findings, and prioritized recommendations.

    If the analysis is still pending or running, returns current status descriptor.
    """
    status = _analysis_status.get(analysis_id)
    if not status:
        for aid, st in _analysis_status.items():
            if aid.startswith(analysis_id):
                status = st
                break
    if status in ("pending", "running"):
        return AnalysisStatus(analysis_id=analysis_id, status=status)
    result = _get_result_or_404(analysis_id)
    return result


@app.get(
    "/api/analysis/{analysis_id}/sessions",
    response_model=list[TCPSession],
    tags=["Analysis & Forensics"],
    summary="Retrieve all reconstructed TCP email sessions in capture",
)
async def get_sessions(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis run.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
):
    """
    List all reconstructed TCP email conversations in the capture.

    Each session includes 5-tuple network coordinates, application protocol,
    STARTTLS state machine transitions, TLS handshake details (ciphers, version, FS, JA3),
    X.509 certificates, session-level findings, and 16-D Isolation Forest anomaly scores.
    """
    result = _get_result_or_404(analysis_id)
    return result.sessions


@app.get(
    "/api/analysis/{analysis_id}/sessions/{session_id}",
    response_model=TCPSession,
    tags=["Analysis & Forensics"],
    summary="Retrieve granular forensic parameters for a specific TCP stream",
)
async def get_session(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis run.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
    session_id: str = FastPath(
        ...,
        description="Session stream identifier (e.g. 'stream-0').",
        examples=["stream-0"],
    ),
):
    """
    Inspect detailed forensic telemetry for a single TCP stream.

    Provides raw protocol command banners, packet timing, TLS extension lists,
    certificate validity timestamps, and session-level risk deductions.
    """
    result = _get_result_or_404(analysis_id)
    for s in result.sessions:
        if s.session_id == session_id:
            return s
    raise HTTPException(status_code=404, detail="Session not found")


@app.get(
    "/api/analysis/{analysis_id}/findings",
    response_model=list[Finding],
    tags=["Analysis & Forensics"],
    summary="Query security findings with optional severity and category filters",
)
async def get_findings(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis run.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
    severity: str | None = Query(
        default=None,
        description="Filter by finding severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'.",
        examples=["CRITICAL"],
    ),
    category: str | None = Query(
        default=None,
        description="Filter by finding category: 'deprecated_tls', 'weak_cipher', 'weak_key', 'expired_certificate', 'starttls_anomaly', 'plaintext_auth', 'ml_anomaly'.",
        examples=["starttls_anomaly"],
    ),
):
    """
    Retrieve security findings across all sessions in the capture.

    Every finding includes traceable evidence provenance: packet numbers,
    observed field names, and values. Supports filtering by severity and category.
    """
    result = _get_result_or_404(analysis_id)
    findings = result.all_findings
    if severity:
        sev_lower = severity.lower()
        findings = [
            f
            for f in findings
            if f.severity.value.lower() == sev_lower or f.severity.name.lower() == sev_lower
        ]
    if category:
        cat_lower = category.lower()
        findings = [
            f
            for f in findings
            if f.category.value.lower() == cat_lower or f.category.name.lower() == cat_lower
        ]
    return findings


# ---------------------------------------------------------------------------
# Demo PCAPs & Direct Ingestion
# ---------------------------------------------------------------------------


PCAP_METADATA = {
    "01_enterprise_secure_baseline.pcap": {
        "title": "Enterprise Secure Baseline",
        "description": "Modern TLS 1.3 / 1.2, ECDHE Forward Secrecy, valid certificates across SMTP, IMAP, and POP3.",
        "category": "secure_baseline",
    },
    "02_legacy_cryptography_and_certs.pcap": {
        "title": "Legacy Cryptography & Expired Certs",
        "description": "Deprecated TLS 1.0/1.1, 3DES ciphers, expired X.509 certificates, and weak RSA key lengths.",
        "category": "legacy_crypto",
    },
    "03_starttls_downgrade_and_cleartext.pcap": {
        "title": "STARTTLS Downgrade & Cleartext Auth",
        "description": "Active STARTTLS 454 rejection, fallback to plaintext, and cleartext credential harvesting.",
        "category": "downgrade_attack",
    },
    "04_protocol_anomalies_and_fuzzing.pcap": {
        "title": "Protocol Anomalies & Pipeline Fuzzing",
        "description": "Command pipelining violations, malformed banners, buffer fuzzing, and ML outliers.",
        "category": "anomalies",
    },
    "05_realworld_network_transports.pcap": {
        "title": "Real-World Network Transports",
        "description": "Multi-stream packet capture featuring mixed cipher negotiation, cross-protocol flows, and network latency.",
        "category": "network_transports",
    },
}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _get_demo_pcaps() -> list[Path]:
    if not DEMO_PCAPS_DIR.exists():
        return []
    files: list[Path] = []
    for ext in ("*.pcap", "*.pcapng", "*.cap"):
        files.extend(DEMO_PCAPS_DIR.glob(ext))
    return sorted(files, key=lambda p: p.name)


def _build_pcap_entry(p: Path) -> dict:
    meta = PCAP_METADATA.get(p.name, {})
    return {
        "filename": p.name,
        "title": meta.get("title", p.name),
        "description": meta.get(
            "description", "Packet capture file for forensic email security analysis."
        ),
        "category": meta.get("category", "general"),
        "size_bytes": p.stat().st_size,
        "sha256_hash": _sha256_file(p),
        "download_url": f"/api/pcaps/{p.name}",
        "analyse_url": f"/api/pcaps/{p.name}/analyse",
    }


@app.get(
    "/api/pcaps",
    response_model=list[PcapEntry],
    tags=["PCAPs & Capture Management"],
    summary="List available PCAPs with metadata, checksums, and trigger URLs",
)
@app.get(
    "/api/demo/pcaps",
    response_model=list[PcapEntry],
    tags=["PCAPs & Capture Management"],
    include_in_schema=False,
)
async def list_pcaps():
    """
    Retrieve metadata, file sizes, SHA-256 digests, scenario categories,
    and analysis trigger URLs for all canonical benchmark PCAPs and stored capture files.
    """
    return [_build_pcap_entry(p) for p in _get_demo_pcaps()]


@app.get(
    "/api/pcaps/{filename}",
    tags=["PCAPs & Capture Management"],
    summary="Download raw binary PCAP capture file",
    response_class=FileResponse,
    responses={
        200: {
            "content": {"application/vnd.tcpdump.pcap": {}},
            "description": "Raw binary packet capture file.",
        },
        404: {"description": "PCAP file not found."},
    },
)
@app.get(
    "/api/demo/pcaps/{filename}",
    tags=["PCAPs & Capture Management"],
    include_in_schema=False,
)
async def download_pcap(
    filename: str = FastPath(
        ...,
        description="Name of the PCAP file to download (e.g. '01_enterprise_secure_baseline.pcap').",
        examples=["01_enterprise_secure_baseline.pcap"],
    ),
):
    """
    Download the raw binary packet capture file (.pcap or .pcapng) for offline
    inspection in Wireshark or external forensic tooling.
    """
    pcap_path = DEMO_PCAPS_DIR / filename
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {filename}")
    return FileResponse(
        str(pcap_path),
        media_type="application/vnd.tcpdump.pcap",
        filename=filename,
    )


@app.post(
    "/api/pcaps/{filename}/analyse",
    response_model=AnalysisStatus,
    tags=["PCAPs & Capture Management"],
    summary="Trigger asynchronous analysis of a stored PCAP from scratch",
)
@app.post(
    "/api/pcaps/{filename}/analyze",
    response_model=AnalysisStatus,
    tags=["PCAPs & Capture Management"],
    include_in_schema=False,
)
async def analyse_pcap_by_name(
    filename: str = FastPath(
        ...,
        description="Filename of the PCAP in the repository directory to re-analyze.",
        examples=["01_enterprise_secure_baseline.pcap"],
    ),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """
    Trigger a fresh analysis of an available PCAP file from scratch in the background.

    Runs the complete forensic pipeline: TShark extraction, TCP session reconstruction,
    STARTTLS state machine parsing, TLS handshake dissection, X.509 certificate hygiene checks,
    deterministic scoring, and Isolation Forest ML anomaly detection.

    Returns immediately with an `analysis_id` and `pending` status.
    """
    pcap_path = DEMO_PCAPS_DIR / filename
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {filename}")

    analysis_id = str(uuid.uuid4())
    _analysis_status[analysis_id] = "pending"
    background_tasks.add_task(_run_analysis, analysis_id, str(pcap_path))

    return AnalysisStatus(analysis_id=analysis_id, status="pending")


@app.post(
    "/api/pcaps/{filename}/analyse/sync",
    response_model=AnalysisResult,
    tags=["PCAPs & Capture Management"],
    summary="Trigger synchronous analysis of a PCAP (blocks until complete)",
)
@app.post(
    "/api/pcaps/{filename}/analyze/sync",
    response_model=AnalysisResult,
    tags=["PCAPs & Capture Management"],
    include_in_schema=False,
)
async def analyse_pcap_by_name_sync(
    filename: str = FastPath(
        ...,
        description="Filename of the PCAP to analyze synchronously.",
        examples=["01_enterprise_secure_baseline.pcap"],
    ),
):
    """
    Trigger synchronous analysis of an available PCAP from scratch.

    Blocks until the entire forensic pipeline finishes execution, and returns
    the complete `AnalysisResult` data tree immediately.
    """
    pcap_path = DEMO_PCAPS_DIR / filename
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {filename}")

    analysis_id = str(uuid.uuid4())
    _analysis_status[analysis_id] = "running"
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, analyse_pcap, str(pcap_path), analysis_id)
        _analyses[analysis_id] = result
        _analysis_status[analysis_id] = "done"
        return result
    except Exception as exc:
        _analysis_status[analysis_id] = "error"
        _analysis_errors[analysis_id] = str(exc)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}") from exc


@app.post(
    "/api/demo/run",
    response_model=DemoRunResponse,
    tags=["Analysis & Ingestion"],
    summary="Dispatch background analyses for all 5 canonical demo PCAPs",
)
async def run_demo(background_tasks: BackgroundTasks = BackgroundTasks()):
    """
    Run analysis on all 5 canonical demo PCAPs in demo_pcaps/.

    Dispatches background jobs for each scenario and returns the list of
    allocated analysis IDs.
    """
    all_pcaps = _get_demo_pcaps()
    if not all_pcaps:
        raise HTTPException(
            status_code=503, detail="Demo PCAPs not generated yet. Run: just gen-pcaps"
        )

    demo_ids = []
    for pcap in all_pcaps:
        aid = str(uuid.uuid4())
        _analysis_status[aid] = "pending"
        background_tasks.add_task(_run_analysis, aid, str(pcap))
        demo_ids.append(DemoRunItem(analysis_id=aid, pcap=pcap.name))

    return DemoRunResponse(demo_analyses=demo_ids)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@app.get(
    "/api/analysis/{analysis_id}/report/json",
    tags=["Forensic Reports"],
    summary="Download serialized machine-readable JSON forensic report",
    response_class=JSONResponse,
)
async def report_json(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis to generate JSON report for.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
):
    """
    Download a comprehensive, machine-readable JSON forensic report containing
    report metadata, capture SHA-256 hashes, session summaries, prioritized findings,
    and methodology disclaimers.
    """
    result = _get_result_or_404(analysis_id)
    return JSONResponse(generate_json_report(result))


@app.get(
    "/api/analysis/{analysis_id}/report/html",
    response_class=HTMLResponse,
    tags=["Forensic Reports"],
    summary="Render standalone dark-mode HTML forensic dashboard",
)
async def report_html(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis to render HTML dashboard for.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
):
    """
    Render a self-contained, publication-ready HTML dashboard report.
    Requires zero external CDN dependencies and features a high-contrast dark theme.
    """
    result = _get_result_or_404(analysis_id)
    html = generate_html_report(result)
    return HTMLResponse(html)


@app.get(
    "/api/analysis/{analysis_id}/report/pdf",
    tags=["Forensic Reports"],
    summary="Download compiled PDF executive forensic report",
    response_class=FileResponse,
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Compiled ReportLab PDF forensic executive report.",
        }
    },
)
async def report_pdf(
    analysis_id: str = FastPath(
        ...,
        description="UUID of the analysis to generate PDF report for.",
        examples=["f47ac10b-58cc-4372-a567-0e02b2c3d479"],
    ),
):
    """
    Streams a formal forensic PDF executive report dynamically compiled via ReportLab.
    Includes metric cards, risk breakdown tables, packet-level evidence, and guidance.
    """
    result = _get_result_or_404(analysis_id)
    pdf_path = UPLOAD_DIR / f"{analysis_id}_report.pdf"
    generate_pdf_report(result, str(pdf_path))
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"securemailscope_{analysis_id[:8]}.pdf",
    )


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------


@app.get(
    "/api/health",
    response_model=HealthResponse,
    tags=["System & Documentation"],
    summary="System operational health check",
)
async def health():
    """
    Operational health check verifying API readiness, software version,
    system TShark binary availability, and cached analysis counts.
    """
    import shutil

    return HealthResponse(
        status="ok",
        version="0.1.0",
        tshark_available=shutil.which("tshark") is not None,
        analyses_cached=len(_analyses),
    )


@app.get(
    "/api/analyses",
    response_model=list[AnalysisSummaryItem],
    tags=["Analysis & Forensics"],
    summary="List all cached analyses with summary metrics",
)
async def list_analyses():
    """
    List all active and cached analyses stored in memory.

    Provides high-level posture scores, risk bands, session counts, packet counts,
    and finding severity breakdowns.
    """
    return [
        AnalysisSummaryItem(
            analysis_id=aid,
            status=_analysis_status.get(aid, "unknown"),
            pcap=_analyses[aid].capture.pcap_filename if aid in _analyses else None,
            risk_score=_analyses[aid].risk_score.score if aid in _analyses else None,
            risk_level=_analyses[aid].risk_score.level if aid in _analyses else None,
            analyzed_at=_analyses[aid].capture.analyzed_at.isoformat()
            if aid in _analyses
            else None,
            session_count=len(_analyses[aid].sessions) if aid in _analyses else 0,
            finding_count=len(_analyses[aid].all_findings) if aid in _analyses else 0,
            packet_count=_analyses[aid].capture.packet_count if aid in _analyses else 0,
            critical_count=_analyses[aid].risk_score.critical_count if aid in _analyses else 0,
            high_count=_analyses[aid].risk_score.high_count if aid in _analyses else 0,
            sessions=[
                SessionSummaryItem(
                    session_id=s.session_id,
                    protocol=str(s.protocol),
                    src_ip=s.src_ip,
                    src_port=s.src_port,
                    dst_ip=s.dst_ip,
                    dst_port=s.dst_port,
                    risk_level=s.session_risk_level,
                )
                for s in _analyses[aid].sessions
            ]
            if aid in _analyses
            else [],
        )
        for aid in _analysis_status
    ]


# ---------------------------------------------------------------------------
# Background Task Helpers
# ---------------------------------------------------------------------------


def _get_result_or_404(analysis_id: str) -> AnalysisResult:
    if analysis_id in _analyses:
        return _analyses[analysis_id]
    for aid, res in _analyses.items():
        if aid.startswith(analysis_id):
            return res
    raise HTTPException(status_code=404, detail="Analysis not found or still running")


async def _run_analysis(analysis_id: str, pcap_path: str) -> None:
    """Background task executing the forensic pipeline."""
    _analysis_status[analysis_id] = "running"
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, analyse_pcap, pcap_path, analysis_id)
        _analyses[analysis_id] = result
        _analysis_status[analysis_id] = "done"
        logger.info("Analysis %s complete: score=%s", analysis_id, result.risk_score.score)
    except Exception as exc:
        logger.exception("Analysis %s failed", analysis_id)
        _analysis_status[analysis_id] = "error"
        _analysis_errors[analysis_id] = str(exc)
