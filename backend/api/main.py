"""
SecureMailScope — FastAPI Backend
REST API exposing PCAP analysis, session data, and report generation.
"""
from __future__ import annotations

import asyncio
import logging
import os
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.models.session import AnalysisResult
from backend.pcap.pipeline import analyse_pcap
from backend.reporting.generator import generate_html_report, generate_json_report, generate_pdf_report

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SecureMailScope API",
    description="AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications",
    version="0.1.0",
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
    error: Optional[str] = None


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
    if analysis_id not in _analyses:
        status = _analysis_status.get(analysis_id, "not_found")
        if status in ("pending", "running"):
            return JSONResponse({"status": status, "analysis_id": analysis_id})
        raise HTTPException(status_code=404, detail="Analysis not found or failed")
    result = _analyses[analysis_id]
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
    severity: Optional[str] = None,
    category: Optional[str] = None,
):
    result = _get_result_or_404(analysis_id)
    findings = result.all_findings
    if severity:
        sev_lower = severity.lower()
        findings = [
            f for f in findings
            if f.severity.value.lower() == sev_lower or f.severity.name.lower() == sev_lower
        ]
    if category:
        cat_lower = category.lower()
        findings = [
            f for f in findings
            if f.category.value.lower() == cat_lower or f.category.name.lower() == cat_lower
        ]
    return [f.model_dump(mode="json") for f in findings]


# ---------------------------------------------------------------------------
# Demo PCAPs
# ---------------------------------------------------------------------------

@app.get("/api/demo/pcaps")
async def list_demo_pcaps():
    """List available demo PCAP files."""
    if not DEMO_PCAPS_DIR.exists():
        return []
    pcaps = []
    for p in sorted(DEMO_PCAPS_DIR.glob("*.pcap")):
        pcaps.append({
            "filename": p.name,
            "path": str(p),
            "size_bytes": p.stat().st_size,
        })
    return pcaps


@app.post("/api/demo/run")
async def run_demo(background_tasks: BackgroundTasks = BackgroundTasks()):
    """Run analysis on all demo PCAPs."""
    if not DEMO_PCAPS_DIR.exists():
        raise HTTPException(status_code=503, detail="Demo PCAPs not generated yet. Run: just gen-pcaps")

    demo_ids = []
    for pcap in sorted(DEMO_PCAPS_DIR.glob("*.pcap")):
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
    return FileResponse(str(pdf_path), media_type="application/pdf",
                        filename=f"securemailscope_{analysis_id[:8]}.pdf")


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
        }
        for aid in _analysis_status
    ]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_result_or_404(analysis_id: str) -> AnalysisResult:
    if analysis_id not in _analyses:
        raise HTTPException(status_code=404, detail="Analysis not found or still running")
    return _analyses[analysis_id]


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
        logger.exception("Analysis %s failed: %s", analysis_id, exc)
        _analysis_status[analysis_id] = "error"
        _analysis_errors[analysis_id] = str(exc)
