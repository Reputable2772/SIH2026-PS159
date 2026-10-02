"""
SecureMailScope — Main Analysis Pipeline
Orchestrates PCAP → sessions → TLS → certificates → rules → ML → results.
"""
from __future__ import annotations

import logging
import time
import uuid
from pathlib import Path
from typing import Any, Optional

from backend.anomaly.detector import get_detector
from backend.certificates.analyser import (
    assess_cert_risk,
    extract_certs_from_tshark_stream,
    parse_certificate_der,
)
from backend.models.session import (
    AnalysisResult,
    ApplicationProtocol,
    CaptureMetadata,
    Evidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    ForwardSecrecyStatus,
    ObservabilityStatus,
    ProtocolSummary,
    STARTTLSState,
    TCPSession,
    TLSVersion,
)
from backend.pcap.extractor import (
    compute_sha256,
    extract_certificates_from_pcap,
    get_pcap_metadata,
    get_tcp_streams,
)
from backend.posture.engine import PostureRuleEngine
from backend.posture.scoring import (
    compute_risk_score,
    generate_recommendations,
    prioritize_findings,
)
from backend.protocols.identifier import (
    IMPLICIT_TLS_PORTS,
    identify_from_tshark_packets,
    identify_protocol_by_port,
)
from backend.protocols.starttls import make_starttls_machine
from backend.tls.analyser import (
    extract_tls_handshake,
    parse_tls_version,
)

logger = logging.getLogger(__name__)


def analyse_pcap(pcap_path: str, analysis_id: Optional[str] = None) -> AnalysisResult:
    """
    Full analysis pipeline for a single PCAP file.
    Returns a complete AnalysisResult with all sessions, findings, and scores.
    """
    start_time = time.perf_counter()
    if analysis_id is None:
        analysis_id = str(uuid.uuid4())

    logger.info("Starting analysis: %s → %s", pcap_path, analysis_id)

    # ── 1. Capture metadata ──────────────────────────────────────────────────
    meta_raw = get_pcap_metadata(pcap_path)
    capture = CaptureMetadata(
        pcap_path=pcap_path,
        pcap_filename=meta_raw.get("pcap_filename", Path(pcap_path).name),
        sha256_hash=meta_raw.get("sha256_hash", compute_sha256(pcap_path)),
        file_size_bytes=meta_raw.get("file_size_bytes", Path(pcap_path).stat().st_size),
        capture_duration_seconds=meta_raw.get("capture_duration_seconds"),
        packet_count=meta_raw.get("packet_count", 0),
        first_packet_time=meta_raw.get("first_packet_time"),
        last_packet_time=meta_raw.get("last_packet_time"),
    )

    # ── 2. Extract TCP streams ───────────────────────────────────────────────
    streams = get_tcp_streams(pcap_path)

    # ── 3. Build sessions ────────────────────────────────────────────────────
    sessions: list[TCPSession] = []
    for stream_id, packets in streams.items():
        session = _build_session(stream_id, packets, pcap_path, analysis_id)
        if session is not None:
            sessions.append(session)

    logger.info("Built %d sessions", len(sessions))

    # ── 4. Rule engine ───────────────────────────────────────────────────────
    rule_engine = PostureRuleEngine()
    sessions = rule_engine.evaluate_batch(sessions)

    # ── 5. ML anomaly detection ──────────────────────────────────────────────
    try:
        detector = get_detector()
        sessions = detector.score_sessions(sessions)
    except Exception as exc:
        logger.warning("ML scoring failed: %s", exc)

    # ── 6. Collect all findings ──────────────────────────────────────────────
    all_findings: list[Finding] = []
    for s in sessions:
        # Set pcap_file in evidence
        for f in s.findings:
            f.evidence.pcap_file = pcap_path
        all_findings.extend(s.findings)
    all_findings = prioritize_findings(all_findings)

    # ── 7. Risk scoring ──────────────────────────────────────────────────────
    risk_score = compute_risk_score(sessions)

    # Per-session risk scores
    for session in sessions:
        session_risk = compute_risk_score([session])
        session.session_risk_score = session_risk.score
        session.session_risk_level = session_risk.level

    # ── 8. Protocol summary ──────────────────────────────────────────────────
    proto_summary = _build_protocol_summary(sessions)

    # ── 9. Recommendations ──────────────────────────────────────────────────
    recommendations = generate_recommendations(all_findings)

    # ── 10. Limitations ─────────────────────────────────────────────────────
    limitations = _collect_limitations(sessions)

    elapsed = time.perf_counter() - start_time

    return AnalysisResult(
        analysis_id=analysis_id,
        capture=capture,
        sessions=sessions,
        risk_score=risk_score,
        protocol_summary=proto_summary,
        all_findings=all_findings,
        recommendations=recommendations,
        limitations=limitations,
        processing_time_seconds=round(elapsed, 3),
    )


# ---------------------------------------------------------------------------
# Session Builder
# ---------------------------------------------------------------------------

def _build_session(
    stream_id: str,
    packets: list[dict[str, Any]],
    pcap_path: str,
    analysis_id: str,
) -> Optional[TCPSession]:
    """Build a TCPSession from a stream's packet list."""
    if not packets:
        return None

    # Extract basic 5-tuple from first packets
    src_ip, src_port, dst_ip, dst_port = _extract_5tuple(packets)
    if not src_ip:
        return None

    session_id = f"{analysis_id[:8]}:{stream_id}"
    times = _extract_times(packets)

    session = TCPSession(
        session_id=session_id,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        start_time=min(times) if times else None,
        end_time=max(times) if times else None,
        duration_seconds=round(max(times) - min(times), 3) if len(times) > 1 else 0.0,
        packet_count=len(packets),
        bytes_transferred=sum(_pkt_len(p) for p in packets),
    )

    # Protocol identification
    session.protocol = identify_from_tshark_packets(packets)
    if session.protocol == ApplicationProtocol.UNKNOWN:
        session.protocol = identify_protocol_by_port(src_port, dst_port)

    # Skip non-email streams entirely
    if session.protocol == ApplicationProtocol.UNKNOWN:
        # Only keep if TLS handshake on interesting ports
        has_tls = any(
            p.get("_source", {}).get("layers", {}).get("tls.handshake.type")
            for p in packets
        )
        if not has_tls:
            return None

    # STARTTLS state machine
    is_implicit_tls = dst_port in IMPLICIT_TLS_PORTS or src_port in IMPLICIT_TLS_PORTS
    if is_implicit_tls:
        session.starttls_state = STARTTLSState.DIRECT_TLS
    else:
        machine = make_starttls_machine(session.protocol)
        for i, pkt in enumerate(packets):
            layers = pkt.get("_source", {}).get("layers", {})
            pkt_num_raw = layers.get("frame.number")
            pkt_num = int(pkt_num_raw) if pkt_num_raw else i
            machine.process_packet(pkt, pkt_num)
        session.starttls_state = machine.get_starttls_state()
        session.starttls_advertised_pkt = getattr(machine, "starttls_advertised_pkt", None)
        session.starttls_requested_pkt = getattr(machine, "starttls_requested_pkt", None)
        session.tls_start_pkt = getattr(machine, "tls_start_pkt", None)
        session.cleartext_auth_detected = getattr(machine, "cleartext_auth_detected", False)

        # Collect protocol banners (first few command lines only — never payload)
        session.protocol_banners = _collect_banners(packets, session.protocol)

    # TLS Handshake
    tls_hs = extract_tls_handshake(packets)
    if tls_hs:
        session.tls_handshake = tls_hs

        # Certificate extraction (TLS ≤ 1.2 only)
        if tls_hs.tls_version != TLSVersion.TLS_1_3:
            certs, obs, note = extract_certs_from_tshark_stream(packets)
            tls_hs.cert_observability = obs
            tls_hs.cert_observability_note = note

            # Try to extract certificate DER via tshark export
            # (best-effort; may be empty if not decoded)
            cert_ders = extract_certificates_from_pcap(pcap_path)
            for _fname, der in cert_ders.items():
                cert_info = parse_certificate_der(der)
                if cert_info:
                    tls_hs.certificates.append(cert_info)
                    tls_hs.cert_observability = ObservabilityStatus.OBSERVED
                    tls_hs.cert_observability_note = "Certificate extracted from capture."
                    # Add certificate-level findings
                    cert_signals = assess_cert_risk(cert_info)
                    for sig in cert_signals:
                        import uuid as _uuid
                        session.findings.append(Finding(
                            id=str(_uuid.uuid4()),
                            severity=FindingSeverity(sig["severity"]),
                            category=FindingCategory(sig["category"]),
                            title=sig["title"],
                            description=sig["detail"],
                            evidence=Evidence(
                                pcap_file=pcap_path,
                                session_id=session_id,
                                packet_numbers=[],
                                field="x509_certificate",
                                observed_value=sig.get("detail"),
                                extra={"cert_sha256": cert_info.fingerprint_sha256},
                            ),
                            recommendation=sig["recommendation"],
                        ))

    return session


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_5tuple(packets: list[dict]) -> tuple[str, int, str, int]:
    for pkt in packets[:5]:
        layers = pkt.get("_source", {}).get("layers", {})
        src_ip = layers.get("ip.src", "")
        dst_ip = layers.get("ip.dst", "")
        src_port_raw = layers.get("tcp.srcport")
        dst_port_raw = layers.get("tcp.dstport")
        if src_ip and dst_ip and src_port_raw and dst_port_raw:
            try:
                return src_ip, int(src_port_raw), dst_ip, int(dst_port_raw)
            except (ValueError, TypeError):
                continue
    return "", 0, "", 0


def _extract_times(packets: list[dict]) -> list[float]:
    times = []
    for pkt in packets:
        t = pkt.get("_source", {}).get("layers", {}).get("frame.time_epoch")
        if t:
            try:
                times.append(float(t))
            except (ValueError, TypeError):
                pass
    return times


def _pkt_len(pkt: dict) -> int:
    try:
        return int(pkt.get("_source", {}).get("layers", {}).get("tcp.len", 0))
    except (ValueError, TypeError):
        return 0


def _collect_banners(packets: list[dict], protocol: ApplicationProtocol) -> list[str]:
    """Extract first few protocol command lines (never user data/payload)."""
    banners: list[str] = []
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        if protocol == ApplicationProtocol.SMTP:
            for key in ("smtp.rsp.parameter", "smtp.req.command"):
                val = layers.get(key)
                if val:
                    banners.append(str(val)[:120])
        elif protocol == ApplicationProtocol.IMAP:
            for key in ("imap.response", "imap.request"):
                val = layers.get(key)
                if val:
                    banners.append(str(val)[:120])
        elif protocol == ApplicationProtocol.POP3:
            for key in ("pop.response", "pop.request"):
                val = layers.get(key)
                if val:
                    banners.append(str(val)[:120])
        if len(banners) >= 10:
            break
    return banners


def _build_protocol_summary(sessions: list[TCPSession]) -> ProtocolSummary:
    summary = ProtocolSummary()
    for s in sessions:
        if s.protocol == ApplicationProtocol.SMTP:
            summary.smtp_sessions += 1
        elif s.protocol == ApplicationProtocol.IMAP:
            summary.imap_sessions += 1
        elif s.protocol == ApplicationProtocol.POP3:
            summary.pop3_sessions += 1
        else:
            summary.unknown_sessions += 1

        if s.tls_handshake:
            summary.tls_sessions += 1
            ver = s.tls_handshake.tls_version.value
            summary.tls_versions[ver] = summary.tls_versions.get(ver, 0) + 1
            cipher = s.tls_handshake.cipher_suite or "Unknown"
            summary.cipher_suites[cipher] = summary.cipher_suites.get(cipher, 0) + 1
            fs = s.tls_handshake.forward_secrecy
            if fs == ForwardSecrecyStatus.YES:
                summary.forward_secrecy_yes += 1
            elif fs == ForwardSecrecyStatus.NO:
                summary.forward_secrecy_no += 1
            else:
                summary.forward_secrecy_unknown += 1

            if s.starttls_state in (STARTTLSState.NEGOTIATED,):
                summary.starttls_sessions += 1
        else:
            summary.plaintext_sessions += 1

    return summary


def _collect_limitations(sessions: list[TCPSession]) -> list[str]:
    limitations = []
    tls13_count = sum(
        1 for s in sessions
        if s.tls_handshake and s.tls_handshake.tls_version == TLSVersion.TLS_1_3
    )
    if tls13_count > 0:
        limitations.append(
            f"TLS 1.3 ({tls13_count} session(s)): Server X.509 certificates are encrypted "
            "in TLS 1.3 handshakes and cannot be extracted from passive traffic capture "
            "without session keys (SSLKEYLOGFILE). TLS version and cipher suite remain "
            "observable. This is technically correct behaviour — TLS 1.3 encrypts the "
            "Certificate message to protect server identity (RFC 8446 §4.4.2)."
        )

    no_tls = sum(1 for s in sessions if s.tls_handshake is None)
    if no_tls > 0:
        limitations.append(
            f"{no_tls} session(s) had no observable TLS handshake. "
            "These may be plaintext sessions, TLS sessions not captured from the start, "
            "or non-email traffic that matched port heuristics."
        )

    limitations.append(
        "Chain validation: Certificate chain completeness cannot be guaranteed from "
        "passive PCAP capture. Only certificates present in the capture are analysed."
    )
    limitations.append(
        "This tool performs passive analysis only. It does not connect to mail servers, "
        "perform active scanning, or modify network traffic."
    )
    return limitations
