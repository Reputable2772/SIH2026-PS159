"""
SecureMailScope — Report Generator
Produces JSON, HTML, and PDF forensic reports.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.models.session import AnalysisResult, FindingSeverity

logger = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


# ---------------------------------------------------------------------------
# JSON Report
# ---------------------------------------------------------------------------

def generate_json_report(result: AnalysisResult) -> dict[str, Any]:
    """Generate a machine-readable JSON report."""
    data = result.model_dump(mode="json")
    data["report_metadata"] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool": "SecureMailScope",
        "version": "0.1.0",
        "disclaimer": (
            "SecureMailScope Composite Risk Score is a prototype scoring methodology. "
            "It is NOT an official NIST, BIS, or NTRO score."
        ),
    }
    return data


# ---------------------------------------------------------------------------
# HTML Report
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureMailScope Forensic Report — {{ result.capture.pcap_filename }}</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --surface2: #1c2128;
    --border: #30363d; --text: #e6edf3; --text-muted: #8b949e;
    --critical: #da3633; --high: #e3b341; --medium: #f0883e;
    --low: #58a6ff; --info: #3fb950; --success: #2ea043;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
    line-height: 1.6; padding: 2rem; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 2rem; color: #58a6ff; margin-bottom: 0.25rem; }
  h2 { font-size: 1.3rem; color: var(--text); border-bottom: 1px solid var(--border);
    padding-bottom: 0.5rem; margin: 2rem 0 1rem; }
  h3 { font-size: 1.05rem; color: var(--text-muted); margin-bottom: 0.5rem; }
  .meta { color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; }
  .score-box { background: var(--surface); border: 1px solid var(--border); border-radius: 12px;
    padding: 2rem; display: flex; align-items: center; gap: 2rem; margin-bottom: 2rem; }
  .score-num { font-size: 4rem; font-weight: 700; }
  .score-level { font-size: 1.5rem; font-weight: 600; }
  .finding-counts { display: flex; gap: 1.5rem; flex-wrap: wrap; }
  .count-badge { padding: 0.4rem 0.8rem; border-radius: 6px; font-size: 0.85rem; font-weight: 600; }
  .sev-critical { background: #2d1011; color: var(--critical); border: 1px solid var(--critical); }
  .sev-high { background: #2d1f00; color: var(--high); border: 1px solid var(--high); }
  .sev-medium { background: #2d1c00; color: var(--medium); border: 1px solid var(--medium); }
  .sev-low { background: #0d1f3c; color: var(--low); border: 1px solid var(--low); }
  .sev-info { background: #0d2318; color: var(--info); border: 1px solid var(--info); }
  .card { background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
    padding: 1rem 1.2rem; margin-bottom: 1rem; }
  .finding-card { border-left: 4px solid; }
  .finding-critical { border-color: var(--critical); }
  .finding-high { border-color: var(--high); }
  .finding-medium { border-color: var(--medium); }
  .finding-low { border-color: var(--low); }
  .finding-info { border-color: var(--info); }
  .badge { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
    font-size: 0.75rem; font-weight: 700; text-transform: uppercase; margin-right: 0.5rem; }
  .tag-ml { background: #1f2d4a; color: #79c0ff; border: 1px solid #388bfd; }
  .recommendation { background: #0d2318; border: 1px solid var(--success); border-radius: 6px;
    padding: 0.75rem 1rem; margin: 0.5rem 0; color: #79e09a; font-size: 0.9rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th { background: var(--surface2); padding: 0.6rem 0.8rem; text-align: left;
    color: var(--text-muted); border-bottom: 1px solid var(--border); }
  td { padding: 0.5rem 0.8rem; border-bottom: 1px solid var(--border); }
  .limitation { background: #1c1f0d; border: 1px solid #3d4000; border-radius: 6px;
    padding: 0.75rem 1rem; margin-bottom: 0.5rem; color: #d4b12f; font-size: 0.88rem; }
  .tls13-note { background: #1a1f2d; border: 1px solid #388bfd; border-radius: 6px;
    padding: 0.75rem 1rem; color: #79c0ff; font-size: 0.85rem; }
  footer { margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border);
    color: var(--text-muted); font-size: 0.8rem; }
</style>
</head>
<body>
<div class="container">

<h1>🔒 SecureMailScope Forensic Report</h1>
<div class="meta">
  <strong>File:</strong> {{ result.capture.pcap_filename }} &nbsp;|&nbsp;
  <strong>SHA-256:</strong> <code>{{ result.capture.sha256_hash }}</code> &nbsp;|&nbsp;
  <strong>Analysed:</strong> {{ result.capture.analyzed_at.strftime('%Y-%m-%d %H:%M:%S UTC') }} &nbsp;|&nbsp;
  <strong>Tool:</strong> SecureMailScope v{{ result.capture.tool_version }}
</div>

<!-- Score -->
<div class="score-box">
  <div>
    <div style="color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.25rem;">SecureMailScope Composite Risk Score</div>
    <div class="score-num" style="color: {{ score_color }};">{{ result.risk_score.score }}</div>
    <div style="color: var(--text-muted); font-size: 0.8rem;">(prototype methodology — not an official NIST/BIS/NTRO score)</div>
  </div>
  <div>
    <div class="score-level" style="color: {{ score_color }};">{{ result.risk_score.level }} RISK</div>
    <div class="finding-counts" style="margin-top: 1rem;">
      <span class="count-badge sev-critical">{{ result.risk_score.critical_count }} Critical</span>
      <span class="count-badge sev-high">{{ result.risk_score.high_count }} High</span>
      <span class="count-badge sev-medium">{{ result.risk_score.medium_count }} Medium</span>
      <span class="count-badge sev-low">{{ result.risk_score.low_count }} Low</span>
      {% if result.risk_score.ml_anomaly_count %}
      <span class="count-badge" style="background:#1a1f2d;color:#79c0ff;border:1px solid #388bfd;">{{ result.risk_score.ml_anomaly_count }} ML Anomalies</span>
      {% endif %}
    </div>
  </div>
</div>

<!-- Capture Info -->
<h2>Capture Metadata</h2>
<div class="card">
  <table>
    <tr><th>File</th><td>{{ result.capture.pcap_filename }}</td></tr>
    <tr><th>SHA-256</th><td><code>{{ result.capture.sha256_hash }}</code></td></tr>
    <tr><th>Size</th><td>{{ result.capture.file_size_bytes | filesizeformat }}</td></tr>
    <tr><th>Packets</th><td>{{ result.capture.packet_count }}</td></tr>
    <tr><th>Duration</th><td>{{ "%.3f"|format(result.capture.capture_duration_seconds or 0) }}s</td></tr>
    <tr><th>Sessions Analysed</th><td>{{ result.sessions|length }}</td></tr>
    <tr><th>Processing Time</th><td>{{ "%.3f"|format(result.processing_time_seconds) }}s</td></tr>
  </table>
</div>

<!-- Protocol Summary -->
<h2>Protocol Summary</h2>
<div class="card">
  <table>
    <thead><tr><th>Protocol</th><th>Sessions</th></tr></thead>
    <tbody>
      <tr><td>SMTP</td><td>{{ result.protocol_summary.smtp_sessions }}</td></tr>
      <tr><td>IMAP</td><td>{{ result.protocol_summary.imap_sessions }}</td></tr>
      <tr><td>POP3</td><td>{{ result.protocol_summary.pop3_sessions }}</td></tr>
      <tr><td>TLS sessions total</td><td>{{ result.protocol_summary.tls_sessions }}</td></tr>
      <tr><td>Plaintext sessions</td><td>{{ result.protocol_summary.plaintext_sessions }}</td></tr>
      <tr><td>Forward Secrecy: YES</td><td>{{ result.protocol_summary.forward_secrecy_yes }}</td></tr>
      <tr><td>Forward Secrecy: NO</td><td>{{ result.protocol_summary.forward_secrecy_no }}</td></tr>
    </tbody>
  </table>
</div>

<!-- Findings -->
<h2>Security Findings</h2>
{% for finding in result.all_findings %}
<div class="card finding-card finding-{{ finding.severity.value }}">
  <div style="display:flex;align-items:center;gap:0.5rem;margin-bottom:0.5rem;">
    <span class="badge sev-{{ finding.severity.value }}">{{ finding.severity.value }}</span>
    {% if finding.is_ml_finding %}<span class="badge tag-ml">ML Anomaly</span>{% endif %}
    <strong>{{ finding.title }}</strong>
  </div>
  <p style="color: var(--text-muted); font-size: 0.9rem; margin-bottom: 0.5rem;">{{ finding.description }}</p>
  <div class="recommendation">💡 {{ finding.recommendation }}</div>
  <div style="font-size:0.78rem;color:var(--text-muted);margin-top:0.5rem;">
    Session: {{ finding.evidence.session_id }} &nbsp;|&nbsp;
    Category: {{ finding.category.value }}
    {% if finding.evidence.observed_value %} &nbsp;|&nbsp; Observed: <code>{{ finding.evidence.observed_value }}</code>{% endif %}
  </div>
</div>
{% endfor %}

<!-- Sessions -->
<h2>Session Summary</h2>
<div class="card">
  <table>
    <thead><tr>
      <th>Session</th><th>Protocol</th><th>Src</th><th>Dst</th>
      <th>TLS Version</th><th>Cipher</th><th>STARTTLS</th>
      <th>Risk</th><th>Anomaly</th>
    </tr></thead>
    <tbody>
    {% for s in result.sessions %}
    <tr>
      <td><code>{{ s.session_id[-8:] }}</code></td>
      <td>{{ s.protocol.value }}</td>
      <td>{{ s.src_ip }}:{{ s.src_port }}</td>
      <td>{{ s.dst_ip }}:{{ s.dst_port }}</td>
      <td>{{ s.tls_handshake.tls_version.value if s.tls_handshake else '—' }}</td>
      <td style="font-size:0.78rem;max-width:180px;word-break:break-all;">
        {{ s.tls_handshake.cipher_suite if s.tls_handshake else '—' }}
      </td>
      <td>{{ s.starttls_state.value }}</td>
      <td><span class="badge sev-{{ s.session_risk_level.lower() if s.session_risk_level else 'info' }}">
        {{ s.session_risk_score or '—' }}</span></td>
      <td>{{ '⚠️' if s.is_anomalous else ('—' if s.is_anomalous is not none else '?') }}</td>
    </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<!-- Recommendations -->
<h2>Recommendations</h2>
{% for rec in result.recommendations %}
<div class="recommendation">{{ loop.index }}. {{ rec }}</div>
{% endfor %}

<!-- Limitations -->
<h2>Limitations & Assumptions</h2>
{% for lim in result.limitations %}
<div class="limitation">⚠️ {{ lim }}</div>
{% endfor %}
<div class="tls13-note">
  <strong>TLS 1.3 Certificate Observability:</strong>
  In TLS 1.3, the Certificate message is encrypted (RFC 8446 §4.4.2). Passive capture without
  session keys cannot extract server X.509 certificates from TLS 1.3 sessions. This tool correctly
  reports this limitation rather than fabricating certificate data.
</div>

<footer>
  <p>Generated by SecureMailScope v0.1.0 — SIH 2026 Prototype (PS 26159)</p>
  <p>This is a prototype scoring methodology. NOT an official NIST/BIS/NTRO assessment.</p>
  <p>Generated: {{ now }}</p>
</footer>
</div>
</body>
</html>
"""


def generate_html_report(result: AnalysisResult) -> str:
    """Generate an HTML forensic report."""
    from jinja2 import Environment

    score = result.risk_score.score
    if score >= 85:
        score_color = "#2ea043"
    elif score >= 70:
        score_color = "#3fb950"
    elif score >= 50:
        score_color = "#f0883e"
    elif score >= 30:
        score_color = "#e3b341"
    else:
        score_color = "#da3633"

    env = Environment(autoescape=True)
    # Add custom filter
    env.filters["filesizeformat"] = lambda v: f"{int(v):,} bytes"

    template = env.from_string(HTML_TEMPLATE)
    return template.render(
        result=result,
        score_color=score_color,
        now=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )


# ---------------------------------------------------------------------------
# PDF Report
# ---------------------------------------------------------------------------

def _latin1_safe(s: str) -> str:
    """Sanitize strings for built-in PDF Helvetica font (latin-1 only)."""
    return (
        s.replace("—", "--")
        .replace("–", "-")
        .replace("’", "'")
        .replace("‘", "'")
        .replace("“", '"')
        .replace("”", '"')
        .replace("…", "...")
        .replace("•", "*")
        .encode("latin-1", "replace")
        .decode("latin-1")
    )


def generate_pdf_report(result: AnalysisResult, output_path: str) -> str:
    """Generate a PDF forensic report using fpdf2."""
    try:
        from fpdf import FPDF
    except ImportError:
        logger.error("fpdf2 not installed — PDF generation unavailable")
        raise

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(88, 166, 255)
    pdf.cell(0, 10, "SecureMailScope Forensic Report", new_x="LMARGIN", new_y="NEXT")

    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(139, 148, 158)
    pdf.cell(0, 5, _latin1_safe(f"File: {result.capture.pcap_filename}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _latin1_safe(f"SHA-256: {result.capture.sha256_hash}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _latin1_safe(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"), new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 5, _latin1_safe("SecureMailScope v0.1.0 -- SIH 2026 Prototype (PS 26159)"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Score
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 8, "Composite Risk Score (Prototype Methodology)", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 36)
    score = result.risk_score.score
    if score >= 70:
        pdf.set_text_color(46, 160, 67)
    elif score >= 50:
        pdf.set_text_color(240, 136, 62)
    else:
        pdf.set_text_color(218, 54, 51)
    pdf.cell(0, 14, _latin1_safe(f"{score} / 100  ({result.risk_score.level} RISK)"), new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(139, 148, 158)
    pdf.set_font("Helvetica", "I", 8)
    pdf.cell(0, 5, _latin1_safe("NOT an official NIST/BIS/NTRO score -- prototype methodology only."), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Finding counts
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 7, "Finding Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    rs = result.risk_score
    pdf.cell(0, 6, _latin1_safe(f"Critical: {rs.critical_count}  |  High: {rs.high_count}  |  Medium: {rs.medium_count}  |  Low: {rs.low_count}  |  ML Anomalies: {rs.ml_anomaly_count}"), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(4)

    # Capture metadata
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "Capture Metadata", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(139, 148, 158)
    rows = [
        ("File", result.capture.pcap_filename),
        ("Packets", str(result.capture.packet_count)),
        ("Sessions analysed", str(len(result.sessions))),
        ("Duration", f"{result.capture.capture_duration_seconds or 0:.3f}s"),
        ("File size", f"{result.capture.file_size_bytes:,} bytes"),
        ("Processing time", f"{result.processing_time_seconds:.3f}s"),
    ]
    for k, v in rows:
        pdf.cell(50, 5, _latin1_safe(k), border=0)
        pdf.set_text_color(230, 237, 243)
        pdf.cell(0, 5, _latin1_safe(v), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(139, 148, 158)
    pdf.ln(4)

    # Findings
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 7, "Security Findings", new_x="LMARGIN", new_y="NEXT")

    sev_colors = {
        "critical": (218, 54, 51),
        "high": (227, 179, 65),
        "medium": (240, 136, 62),
        "low": (88, 166, 255),
        "info": (63, 185, 80),
    }
    for finding in result.all_findings[:30]:  # PDF space limit
        c = sev_colors.get(finding.severity.value, (230, 237, 243))
        pdf.set_text_color(*c)
        pdf.set_font("Helvetica", "B", 9)
        label = f"[{finding.severity.value.upper()}{'  ML' if finding.is_ml_finding else ''}] {finding.title}"
        pdf.multi_cell(0, 5, _latin1_safe(label[:120]), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(139, 148, 158)
        pdf.set_font("Helvetica", "", 8)
        desc = finding.description[:300].replace("\n", " ")
        pdf.multi_cell(0, 4, _latin1_safe(desc), new_x="LMARGIN", new_y="NEXT")
        pdf.set_text_color(46, 160, 67)
        rec = finding.recommendation[:200].replace("\n", " ")
        pdf.multi_cell(0, 4, _latin1_safe(f"Rec: {rec}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # Recommendations
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 7, "Recommendations", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(121, 224, 154)
    for i, rec in enumerate(result.recommendations, 1):
        pdf.multi_cell(0, 5, _latin1_safe(f"{i}. {rec}"), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(1)

    # Limitations
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 7, "Limitations", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 8)
    pdf.set_text_color(212, 177, 47)
    for lim in result.limitations:
        pdf.multi_cell(0, 4, _latin1_safe(lim[:400]), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(2)

    # TLS 1.3 note
    pdf.ln(4)
    pdf.set_font("Helvetica", "B", 9)
    pdf.set_text_color(121, 192, 255)
    pdf.cell(0, 6, "TLS 1.3 Certificate Observability Limitation", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "I", 8)
    pdf.multi_cell(0, 4, _latin1_safe(
        "In TLS 1.3 (RFC 8446), the Certificate message is encrypted during the handshake. "
        "Passive PCAP analysis without session keys (SSLKEYLOGFILE) cannot extract server X.509 "
        "certificates from TLS 1.3 sessions. This report correctly identifies this limitation "
        "rather than fabricating certificate information. TLS version and cipher suite remain "
        "observable from the unencrypted ClientHello/ServerHello messages."
    ), new_x="LMARGIN", new_y="NEXT")

    pdf.output(output_path)
    return output_path
