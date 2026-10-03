"""
SecureMailScope — FastAPI Backend
REST API exposing PCAP analysis, session data, and report generation.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import tempfile
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from backend.models.session import AnalysisResult
from backend.pcap.pipeline import analyse_pcap
from backend.reporting.generator import (
    generate_html_report,
    generate_json_report,
    generate_pdf_report,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------

_background_tasks: set[asyncio.Task] = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager for background task management."""
    yield
    for task in list(_background_tasks):
        task.cancel()


app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version="0.1.0",
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
# Models
# ---------------------------------------------------------------------------


class AnalysisRequest(BaseModel):
    pcap_path: str


class AnalysisStatus(BaseModel):
    analysis_id: str
    status: str
    error: str | None = None


# ---------------------------------------------------------------------------
# PCAP Upload & Analysis
# ---------------------------------------------------------------------------


@app.post("/api/analysis/upload", response_model=AnalysisStatus)
async def upload_and_analyse(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """Upload a PCAP file and start analysis."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided")

    suffix = Path(file.filename).suffix.lower()
    if suffix not in (".pcap", ".pcapng", ".cap"):
        raise HTTPException(status_code=400, detail=f"Unsupported file type: {suffix}")

    analysis_id = str(uuid.uuid4())
    pcap_path = UPLOAD_DIR / f"{analysis_id}{suffix}"

    # Save upload
    content = await file.read()
    with open(pcap_path, "wb") as f:
        f.write(content)

    _analysis_status[analysis_id] = "pending"
    background_tasks.add_task(_run_analysis, analysis_id, str(pcap_path))

    return AnalysisStatus(analysis_id=analysis_id, status="pending")


@app.post("/api/analysis/file", response_model=AnalysisStatus)
async def analyse_file(
    request: AnalysisRequest,
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """Analyse a PCAP file by server-side path (for demo PCAPs)."""
    pcap_path = Path(request.pcap_path)
    if not pcap_path.exists():
        # Check DEMO_PCAPS_DIR
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


@app.get("/api/analysis/{analysis_id}/status", response_model=AnalysisStatus)
async def get_analysis_status(analysis_id: str):
    if analysis_id not in _analysis_status:
        raise HTTPException(status_code=404, detail="Analysis not found")
    return AnalysisStatus(
        analysis_id=analysis_id,
        status=_analysis_status[analysis_id],
        error=_analysis_errors.get(analysis_id),
    )


@app.get("/api/analysis/{analysis_id}")
async def get_analysis(analysis_id: str):
    status = _analysis_status.get(analysis_id)
    if not status:
        for aid, st in _analysis_status.items():
            if aid.startswith(analysis_id):
                status = st
                break
    if status in ("pending", "running"):
        return JSONResponse({"status": status, "analysis_id": analysis_id})
    result = _get_result_or_404(analysis_id)
    return result.model_dump(mode="json")


@app.get("/api/analysis/{analysis_id}/sessions")
async def get_sessions(analysis_id: str):
    result = _get_result_or_404(analysis_id)
    return [s.model_dump(mode="json") for s in result.sessions]


@app.get("/api/analysis/{analysis_id}/sessions/{session_id}")
async def get_session(analysis_id: str, session_id: str):
    result = _get_result_or_404(analysis_id)
    for s in result.sessions:
        if s.session_id == session_id:
            return s.model_dump(mode="json")
    raise HTTPException(status_code=404, detail="Session not found")


@app.get("/api/analysis/{analysis_id}/findings")
async def get_findings(
    analysis_id: str,
    severity: str | None = None,
    category: str | None = None,
):
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
    return [f.model_dump(mode="json") for f in findings]


# ---------------------------------------------------------------------------
# Demo PCAPs
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
        "description": meta.get("description", "Packet capture file for forensic email security analysis."),
        "category": meta.get("category", "general"),
        "size_bytes": p.stat().st_size,
        "sha256_hash": _sha256_file(p),
        "download_url": f"/api/pcaps/{p.name}",
        "analyse_url": f"/api/pcaps/{p.name}/analyse",
    }


@app.get("/api/pcaps")
@app.get("/api/demo/pcaps")
async def list_pcaps():
    """List available PCAP files with metadata, checksums, and analysis trigger URLs."""
    return [_build_pcap_entry(p) for p in _get_demo_pcaps()]


@app.get("/api/pcaps/{filename}")
@app.get("/api/demo/pcaps/{filename}")
async def download_pcap(filename: str):
    """Download raw PCAP capture file."""
    pcap_path = DEMO_PCAPS_DIR / filename
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {filename}")
    return FileResponse(
        str(pcap_path),
        media_type="application/vnd.tcpdump.pcap",
        filename=filename,
    )


@app.post("/api/pcaps/{filename}/analyse", response_model=AnalysisStatus)
@app.post("/api/pcaps/{filename}/analyze", response_model=AnalysisStatus)
async def analyse_pcap_by_name(
    filename: str,
    background_tasks: BackgroundTasks = BackgroundTasks(),
):
    """Trigger a fresh analysis of an available PCAP from scratch."""
    pcap_path = DEMO_PCAPS_DIR / filename
    if not pcap_path.exists() or not pcap_path.is_file():
        raise HTTPException(status_code=404, detail=f"PCAP not found: {filename}")

    analysis_id = str(uuid.uuid4())
    _analysis_status[analysis_id] = "pending"
    background_tasks.add_task(_run_analysis, analysis_id, str(pcap_path))

    return AnalysisStatus(analysis_id=analysis_id, status="pending")


@app.post("/api/pcaps/{filename}/analyse/sync")
@app.post("/api/pcaps/{filename}/analyze/sync")
async def analyse_pcap_by_name_sync(filename: str):
    """Trigger synchronous analysis of an available PCAP from scratch (returns complete result)."""
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
        return result.model_dump(mode="json")
    except Exception as exc:
        _analysis_status[analysis_id] = "error"
        _analysis_errors[analysis_id] = str(exc)
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")


@app.post("/api/demo/run")
async def run_demo(background_tasks: BackgroundTasks = BackgroundTasks()):
    """Run analysis on all available demo PCAPs."""
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
        demo_ids.append({"analysis_id": aid, "pcap": pcap.name})

    return {"demo_analyses": demo_ids}


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------


@app.get("/api/analysis/{analysis_id}/report/json")
async def report_json(analysis_id: str):
    result = _get_result_or_404(analysis_id)
    return JSONResponse(generate_json_report(result))


@app.get("/api/analysis/{analysis_id}/report/html")
async def report_html(analysis_id: str):
    from fastapi.responses import HTMLResponse

    result = _get_result_or_404(analysis_id)
    html = generate_html_report(result)
    return HTMLResponse(html)


@app.get("/api/analysis/{analysis_id}/report/pdf")
async def report_pdf(analysis_id: str):
    result = _get_result_or_404(analysis_id)
    pdf_path = UPLOAD_DIR / f"{analysis_id}_report.pdf"
    generate_pdf_report(result, str(pdf_path))
    return FileResponse(
        str(pdf_path),
        media_type="application/pdf",
        filename=f"securemailscope_{analysis_id[:8]}.pdf",
    )


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------


@app.get("/api/health")
async def health():
    import shutil

    return {
        "status": "ok",
        "version": "0.1.0",
        "tshark_available": shutil.which("tshark") is not None,
        "analyses_cached": len(_analyses),
    }


@app.get("/api/analyses")
async def list_analyses():
    return [
        {
            "analysis_id": aid,
            "status": _analysis_status.get(aid, "unknown"),
            "pcap": _analyses[aid].capture.pcap_filename if aid in _analyses else None,
            "risk_score": _analyses[aid].risk_score.score if aid in _analyses else None,
            "risk_level": _analyses[aid].risk_score.level if aid in _analyses else None,
            "analyzed_at": _analyses[aid].capture.analyzed_at.isoformat()
            if aid in _analyses
            else None,
            "session_count": len(_analyses[aid].sessions) if aid in _analyses else 0,
            "finding_count": len(_analyses[aid].all_findings) if aid in _analyses else 0,
            "packet_count": _analyses[aid].capture.packet_count if aid in _analyses else 0,
            "critical_count": _analyses[aid].risk_score.critical_count if aid in _analyses else 0,
            "high_count": _analyses[aid].risk_score.high_count if aid in _analyses else 0,
            "sessions": [
                {
                    "session_id": s.session_id,
                    "protocol": s.protocol,
                    "src_ip": s.src_ip,
                    "src_port": s.src_port,
                    "dst_ip": s.dst_ip,
                    "dst_port": s.dst_port,
                    "risk_level": s.session_risk_level,
                }
                for s in _analyses[aid].sessions
            ]
            if aid in _analyses
            else [],
        }
        for aid in _analysis_status
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_result_or_404(analysis_id: str) -> AnalysisResult:
    if analysis_id in _analyses:
        return _analyses[analysis_id]
    for aid, res in _analyses.items():
        if aid.startswith(analysis_id):
            return res
    raise HTTPException(status_code=404, detail="Analysis not found or still running")


async def _run_analysis(analysis_id: str, pcap_path: str) -> None:
    """Background task that runs the analysis pipeline."""
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
