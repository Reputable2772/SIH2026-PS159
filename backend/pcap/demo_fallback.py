"""
SecureMailScope — Demo Fallback Data
Pre-baked AnalysisResult objects for each canonical demo PCAP, used when
the real tshark analysis pipeline is unavailable (e.g. during permission
debugging on rootless Podman / Ubuntu). Each scenario is deliberately
distinct so the three demo cards show meaningfully different results.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

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
    RiskScore,
    STARTTLSState,
    TCPSession,
    TLSHandshake,
    TLSVersion,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DEMO_PCAPS_DIR = Path(__file__).parent.parent.parent / "demo_pcaps"


def _ev(session_id: str, field: str, value: str, pkts: list[int] | None = None) -> Evidence:
    return Evidence(
        session_id=session_id,
        field=field,
        observed_value=value,
        packet_numbers=pkts or [],
    )


def _finding(
    sid: str,
    severity: FindingSeverity,
    category: FindingCategory,
    title: str,
    description: str,
    recommendation: str,
    field: str = "",
    value: str = "",
    pkts: list[int] | None = None,
) -> Finding:
    return Finding(
        id=str(uuid.uuid4()),
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence=_ev(sid, field, value, pkts),
        recommendation=recommendation,
    )


# ---------------------------------------------------------------------------
# Scenario 01 — Enterprise Secure Baseline (MINIMAL risk)
# ---------------------------------------------------------------------------
# A well-configured mail environment: all sessions use TLS 1.3 with ECDHE,
# STARTTLS not needed (implicit TLS ports), forward secrecy everywhere.
# Only an INFO note about TLS 1.3 cert non-observability.

def _scenario_01(analysis_id: str, pcap_path: str) -> AnalysisResult:
    t0 = 1_736_985_600.0  # 2025-01-16 00:00 UTC

    def _sess(n: int, proto: ApplicationProtocol, dport: int) -> TCPSession:
        sid = f"{analysis_id[:8]}:{n}"
        s = TCPSession(
            session_id=sid,
            src_ip=f"10.0.1.{10 + n}",
            src_port=50_000 + n * 100,
            dst_ip="203.0.113.25",
            dst_port=dport,
            start_time=t0 + n * 45.0,
            end_time=t0 + n * 45.0 + 2.3,
            duration_seconds=2.3,
            packet_count=28 + n * 3,
            bytes_transferred=4_200 + n * 512,
            protocol=proto,
            starttls_state=STARTTLSState.DIRECT_TLS,
            tls_handshake=TLSHandshake(
                tls_version=TLSVersion.TLS_1_3,
                cipher_suite="TLS_AES_256_GCM_SHA384",
                cipher_suite_name="TLS_AES_256_GCM_SHA384",
                key_exchange="ECDHE",
                forward_secrecy=ForwardSecrecyStatus.YES,
                cert_observability=ObservabilityStatus.NOT_OBSERVABLE,
                cert_observability_note=(
                    "TLS 1.3 encrypts the Certificate message (RFC 8446 §4.4.2). "
                    "Certificates cannot be extracted from passive capture without "
                    "session keys."
                ),
                handshake_complete=True,
            ),
            findings=[
                _finding(
                    sid,
                    FindingSeverity.INFO,
                    FindingCategory.INFO,
                    "TLS 1.3 certificate not observable",
                    "This session uses TLS 1.3. The server certificate is encrypted "
                    "in the handshake and cannot be extracted from a passive capture "
                    "without SSLKEYLOGFILE. This is correct TLS 1.3 behaviour, not a flaw.",
                    "No action required. Provide an SSLKEYLOGFILE if certificate "
                    "inspection is needed for compliance purposes.",
                    "tls.handshake.type",
                    "TLS 1.3",
                )
            ],
        )
        return s

    sessions = [
        _sess(0, ApplicationProtocol.SMTP, 465),
        _sess(1, ApplicationProtocol.SMTP, 465),
        _sess(2, ApplicationProtocol.SMTP, 587),
        _sess(3, ApplicationProtocol.SMTP, 587),
        _sess(4, ApplicationProtocol.IMAP, 993),
        _sess(5, ApplicationProtocol.IMAP, 993),
        _sess(6, ApplicationProtocol.POP3, 995),
    ]

    all_findings = [f for s in sessions for f in s.findings]

    return AnalysisResult(
        analysis_id=analysis_id,
        capture=CaptureMetadata(
            pcap_path=pcap_path,
            pcap_filename=Path(pcap_path).name,
            sha256_hash="a1b2c3d4e5f6" * 5 + "a1b2",
            file_size_bytes=25_052,
            capture_duration_seconds=312.4,
            packet_count=196,
            first_packet_time=t0,
            last_packet_time=t0 + 312.4,
        ),
        sessions=sessions,
        risk_score=RiskScore(
            score=8.0,
            level="MINIMAL",
            rationale=[
                "All sessions use TLS 1.3 with ECDHE — maximum forward secrecy.",
                "No deprecated protocols, weak ciphers, or authentication issues detected.",
                "7 INFO findings only (TLS 1.3 cert non-observability — expected behaviour).",
            ],
            info_count=7,
        ),
        protocol_summary=ProtocolSummary(
            smtp_sessions=4,
            imap_sessions=2,
            pop3_sessions=1,
            tls_sessions=7,
            plaintext_sessions=0,
            tls_versions={"TLS 1.3": 7},
            cipher_suites={"TLS_AES_256_GCM_SHA384": 7},
            forward_secrecy_yes=7,
        ),
        all_findings=all_findings,
        recommendations=[
            "Maintain current TLS 1.3-only configuration.",
            "Consider providing SSLKEYLOGFILE in controlled test environments to enable "
            "certificate inspection for compliance audits.",
        ],
        limitations=[
            "TLS 1.3 (7 sessions): certificates are encrypted and cannot be extracted "
            "from passive traffic without session keys (SSLKEYLOGFILE). "
            "This is expected behaviour per RFC 8446 §4.4.2.",
            "This tool performs passive analysis only.",
        ],
        processing_time_seconds=1.24,
    )


# ---------------------------------------------------------------------------
# Scenario 02 — Legacy Cryptography and Certificates (HIGH risk)
# ---------------------------------------------------------------------------
# Legacy mail server still offering TLS 1.0/1.1, RC4 and 3DES cipher suites,
# RSA-only key exchange (no forward secrecy), and an expired SHA-1 cert.

def _scenario_02(analysis_id: str, pcap_path: str) -> AnalysisResult:
    t0 = 1_736_985_600.0

    def _sess(n: int, ver: TLSVersion, cipher: str, fs: ForwardSecrecyStatus) -> TCPSession:
        sid = f"{analysis_id[:8]}:{n}"
        findings: list[Finding] = []

        if ver in (TLSVersion.TLS_1_0, TLSVersion.TLS_1_1, TLSVersion.SSL_3_0):
            findings.append(_finding(
                sid, FindingSeverity.HIGH, FindingCategory.DEPRECATED_TLS,
                f"Deprecated TLS version: {ver.value}",
                f"The session negotiated {ver.value}, which is deprecated per RFC 8996. "
                f"Known attacks: BEAST (TLS 1.0), POODLE downgrade.",
                "Disable TLS 1.0 and TLS 1.1. Require TLS 1.2 minimum; prefer TLS 1.3.",
                "tls.handshake.version", ver.value, [3],
            ))

        if cipher in ("RC4-SHA", "RC4-MD5"):
            findings.append(_finding(
                sid, FindingSeverity.HIGH, FindingCategory.WEAK_CIPHER,
                f"Broken stream cipher: {cipher}",
                f"RC4 is cryptographically broken (RFC 7465). The cipher {cipher} must "
                "not be used. PCAP traffic protected by RC4 can be decrypted offline.",
                "Remove all RC4 cipher suites from your mail server TLS configuration.",
                "tls.handshake.ciphersuite", cipher, [5],
            ))
        elif cipher in ("DES-CBC3-SHA", "ECDHE-RSA-DES-CBC3-SHA"):
            findings.append(_finding(
                sid, FindingSeverity.HIGH, FindingCategory.WEAK_CIPHER,
                f"Weak cipher suite: {cipher} (3DES/SWEET32)",
                "Triple-DES has a 64-bit block size, vulnerable to the SWEET32 birthday "
                "attack after ~785 GB of data. NSS and Chrome have disabled 3DES.",
                "Replace 3DES cipher suites with AES-GCM or ChaCha20-Poly1305.",
                "tls.handshake.ciphersuite", cipher, [5],
            ))

        if fs == ForwardSecrecyStatus.NO:
            findings.append(_finding(
                sid, FindingSeverity.HIGH, FindingCategory.NO_FORWARD_SECRECY,
                "No forward secrecy — RSA key exchange",
                "The session uses static RSA key exchange. Any future compromise of "
                "the server's private key will decrypt all recorded sessions retroactively.",
                "Enable ECDHE or DHE cipher suites and disable static RSA key exchange.",
                "tls.handshake.ciphersuite", cipher, [5],
            ))

        # Expired/weak cert on first session
        if n == 0:
            findings.append(_finding(
                sid, FindingSeverity.CRITICAL, FindingCategory.EXPIRED_CERTIFICATE,
                "Server certificate expired 847 days ago",
                "The presented X.509 certificate expired on 2022-11-01. Clients may "
                "reject this certificate, and it provides no meaningful binding to the "
                "server's identity after expiry.",
                "Renew the server certificate immediately. Consider automating renewal "
                "with ACME/Let's Encrypt or a managed PKI.",
                "x509af.serialNumber", "1a:2b:3c:4d:5e:6f", [7],
            ))
            findings.append(_finding(
                sid, FindingSeverity.MEDIUM, FindingCategory.WEAK_SIGNATURE,
                "Certificate signed with SHA-1 (deprecated)",
                "SHA-1 collision attacks are computationally feasible (SHAttered, 2017). "
                "All major browser/OS trust stores have removed SHA-1 certificate support.",
                "Re-issue the certificate with SHA-256 or SHA-384 signature algorithm.",
                "x509af.subjectPublicKeyInfo_element", "sha1WithRSAEncryption", [7],
            ))
            findings.append(_finding(
                sid, FindingSeverity.HIGH, FindingCategory.WEAK_KEY,
                "RSA public key is only 1024 bits",
                "A 1024-bit RSA key is below NIST minimum (2048 bits as of 2011) and "
                "is considered breakable with state-level resources.",
                "Replace with an RSA-2048 (or larger) or ECDSA P-256 key.",
                "x509af.subjectPublicKeyInfo_element", "rsaEncryption/1024", [7],
            ))

        return TCPSession(
            session_id=sid,
            src_ip=f"192.168.10.{20 + n}",
            src_port=51_000 + n * 200,
            dst_ip="198.51.100.77",
            dst_port=25,
            start_time=t0 + n * 60.0,
            end_time=t0 + n * 60.0 + 5.8,
            duration_seconds=5.8,
            packet_count=45 + n * 5,
            bytes_transferred=6_800 + n * 900,
            protocol=ApplicationProtocol.SMTP,
            starttls_state=STARTTLSState.NEGOTIATED,
            starttls_advertised_pkt=2,
            starttls_requested_pkt=4,
            tls_start_pkt=6,
            tls_handshake=TLSHandshake(
                tls_version=ver,
                cipher_suite=cipher,
                cipher_suite_name=cipher,
                key_exchange="RSA",
                forward_secrecy=fs,
                cert_observability=ObservabilityStatus.OBSERVED,
                handshake_complete=True,
            ),
            findings=findings,
        )

    sessions = [
        _sess(0, TLSVersion.TLS_1_0, "RC4-SHA", ForwardSecrecyStatus.NO),
        _sess(1, TLSVersion.TLS_1_1, "DES-CBC3-SHA", ForwardSecrecyStatus.NO),
        _sess(2, TLSVersion.TLS_1_2, "DES-CBC3-SHA", ForwardSecrecyStatus.NO),
    ]

    all_findings = [f for s in sessions for f in s.findings]
    crit = sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH)
    med = sum(1 for f in all_findings if f.severity == FindingSeverity.MEDIUM)

    return AnalysisResult(
        analysis_id=analysis_id,
        capture=CaptureMetadata(
            pcap_path=pcap_path,
            pcap_filename=Path(pcap_path).name,
            sha256_hash="b2c3d4e5f6a7" * 5 + "b2c3",
            file_size_bytes=35_880,
            capture_duration_seconds=180.2,
            packet_count=173,
            first_packet_time=t0,
            last_packet_time=t0 + 180.2,
        ),
        sessions=sessions,
        risk_score=RiskScore(
            score=74.0,
            level="HIGH",
            rationale=[
                "1 CRITICAL finding: expired server certificate (847 days past expiry).",
                f"{high} HIGH findings: deprecated TLS versions (1.0/1.1), RC4 cipher, "
                "3DES (SWEET32), no forward secrecy, undersized RSA key.",
                f"{med} MEDIUM finding: SHA-1 signature algorithm on server certificate.",
                "All 3 SMTP sessions used static RSA key exchange — retroactive decryption "
                "possible if private key is ever compromised.",
            ],
            critical_count=crit,
            high_count=high,
            medium_count=med,
        ),
        protocol_summary=ProtocolSummary(
            smtp_sessions=3,
            tls_sessions=3,
            starttls_sessions=3,
            tls_versions={"TLS 1.0": 1, "TLS 1.1": 1, "TLS 1.2": 1},
            cipher_suites={"RC4-SHA": 1, "DES-CBC3-SHA": 2},
            forward_secrecy_no=3,
        ),
        all_findings=all_findings,
        recommendations=[
            "URGENT: Renew the expired server certificate. Current cert expired 847 days ago.",
            "Disable TLS 1.0 and TLS 1.1 immediately (RFC 8996).",
            "Remove RC4 (RFC 7465) and 3DES cipher suites.",
            "Enable ECDHE or DHE key exchange to achieve forward secrecy.",
            "Replace the 1024-bit RSA key with RSA-2048 or ECDSA P-256.",
            "Re-issue the certificate with a SHA-256 signature algorithm.",
        ],
        limitations=[
            "Chain validation: only the leaf certificate was present in the capture.",
            "This tool performs passive analysis only.",
        ],
        processing_time_seconds=2.87,
    )


# ---------------------------------------------------------------------------
# Scenario 03 — STARTTLS Downgrade and Cleartext Auth (CRITICAL risk)
# ---------------------------------------------------------------------------
# Active STARTTLS stripping: the server advertises STARTTLS but the client
# is blocked from upgrading (MITM removes the capability). One session has
# a cleartext AUTH LOGIN. Two more sessions fall back to suspicious cleartext.

def _scenario_03(analysis_id: str, pcap_path: str) -> AnalysisResult:
    t0 = 1_736_985_600.0

    # Session 0: STARTTLS properly negotiated (TLS 1.2) — control
    s0_id = f"{analysis_id[:8]}:0"
    s0 = TCPSession(
        session_id=s0_id,
        src_ip="10.10.5.30",
        src_port=52_100,
        dst_ip="203.0.113.90",
        dst_port=25,
        start_time=t0,
        end_time=t0 + 4.1,
        duration_seconds=4.1,
        packet_count=38,
        bytes_transferred=5_200,
        protocol=ApplicationProtocol.SMTP,
        starttls_state=STARTTLSState.NEGOTIATED,
        starttls_advertised_pkt=2,
        starttls_requested_pkt=4,
        tls_start_pkt=6,
        tls_handshake=TLSHandshake(
            tls_version=TLSVersion.TLS_1_2,
            cipher_suite="ECDHE-RSA-AES256-GCM-SHA384",
            cipher_suite_name="ECDHE-RSA-AES256-GCM-SHA384",
            key_exchange="ECDHE",
            forward_secrecy=ForwardSecrecyStatus.YES,
            cert_observability=ObservabilityStatus.OBSERVED,
            handshake_complete=True,
        ),
        findings=[],
    )

    # Session 1: STARTTLS capability stripped (downgrade attack)
    s1_id = f"{analysis_id[:8]}:1"
    s1 = TCPSession(
        session_id=s1_id,
        src_ip="10.10.5.31",
        src_port=52_200,
        dst_ip="203.0.113.90",
        dst_port=25,
        start_time=t0 + 90.0,
        end_time=t0 + 90.0 + 6.3,
        duration_seconds=6.3,
        packet_count=52,
        bytes_transferred=7_100,
        protocol=ApplicationProtocol.SMTP,
        starttls_state=STARTTLSState.SUSPICIOUS_FALLBACK,
        starttls_advertised_pkt=2,
        starttls_requested_pkt=None,
        tls_start_pkt=None,
        findings=[
            _finding(
                s1_id,
                FindingSeverity.CRITICAL,
                FindingCategory.STARTTLS_ANOMALY,
                "STARTTLS capability stripping detected",
                "The server advertised STARTTLS in its EHLO response (packet 2) but "
                "the capability was absent when the client re-queried (packet 8), "
                "suggesting a man-in-the-middle removed it. The session continued in "
                "cleartext. This is the canonical STARTTLS stripping attack.",
                "Enforce STARTTLS with MTA-STS (RFC 8461) so clients refuse cleartext "
                "fallback. Enable DANE (RFC 7672) for additional authentication.",
                "smtp.req.command",
                "EHLO → STARTTLS capability absent on re-query",
                [2, 8, 10],
            ),
        ],
    )

    # Session 2: AUTH LOGIN sent in cleartext (no TLS at all)
    s2_id = f"{analysis_id[:8]}:2"
    s2 = TCPSession(
        session_id=s2_id,
        src_ip="10.10.5.32",
        src_port=52_300,
        dst_ip="203.0.113.90",
        dst_port=25,
        start_time=t0 + 200.0,
        end_time=t0 + 200.0 + 8.7,
        duration_seconds=8.7,
        packet_count=61,
        bytes_transferred=9_400,
        protocol=ApplicationProtocol.SMTP,
        starttls_state=STARTTLSState.NO_TLS,
        cleartext_auth_detected=True,
        protocol_banners=[
            "220 mail.example.com ESMTP",
            "EHLO client.example.com",
            "250-mail.example.com",
            "250 AUTH LOGIN PLAIN",
            "AUTH LOGIN",
            "334 VXNlcm5hbWU6",  # Base64("Username:")
        ],
        findings=[
            _finding(
                s2_id,
                FindingSeverity.CRITICAL,
                FindingCategory.PLAINTEXT_AUTH,
                "Cleartext AUTH LOGIN over unencrypted SMTP",
                "SMTP AUTH LOGIN credentials were transmitted in plaintext with no TLS "
                "protection. Base64 encoding provides zero confidentiality — credentials "
                "are trivially recoverable from the PCAP. Any passive observer on the "
                "network path has access to these credentials.",
                "Require TLS before AUTH: configure the MTA to reject AUTH unless "
                "STARTTLS has been completed (smtpd_tls_auth_only=yes in Postfix). "
                "Audit for credential reuse.",
                "smtp.req.command",
                "AUTH LOGIN (cleartext)",
                [18, 20, 22],
            ),
            _finding(
                s2_id,
                FindingSeverity.CRITICAL,
                FindingCategory.STARTTLS_ANOMALY,
                "Mail session transmitted entirely in plaintext",
                "No TLS was negotiated in this session. STARTTLS was not advertised "
                "by the server. Email headers, message content, and authentication "
                "credentials are fully visible in the capture.",
                "Configure the server to advertise and enforce STARTTLS. Consider "
                "migrating to implicit TLS (port 465, RFC 8314).",
                "smtp.req.command",
                "No STARTTLS observed",
                [1, 2, 3],
            ),
        ],
    )

    # Session 3: STARTTLS advertised, client sends STARTTLS, server responds 454 (temp fail)
    s3_id = f"{analysis_id[:8]}:3"
    s3 = TCPSession(
        session_id=s3_id,
        src_ip="10.10.5.33",
        src_port=52_400,
        dst_ip="203.0.113.90",
        dst_port=25,
        start_time=t0 + 310.0,
        end_time=t0 + 310.0 + 3.2,
        duration_seconds=3.2,
        packet_count=29,
        bytes_transferred=3_900,
        protocol=ApplicationProtocol.SMTP,
        starttls_state=STARTTLSState.FAILED,
        starttls_advertised_pkt=2,
        starttls_requested_pkt=4,
        tls_start_pkt=None,
        findings=[
            _finding(
                s3_id,
                FindingSeverity.HIGH,
                FindingCategory.STARTTLS_ANOMALY,
                "STARTTLS negotiation failed (454 TLS not available)",
                "The server advertised STARTTLS but returned '454 TLS not available' "
                "when the client attempted to upgrade (packet 6). The session fell back "
                "to cleartext. This may indicate a misconfigured TLS certificate on the "
                "server or an active downgrade attack.",
                "Investigate the server TLS configuration. Ensure a valid certificate "
                "is installed and the TLS listener is correctly bound.",
                "smtp.rsp.code",
                "454",
                [4, 6],
            ),
        ],
    )

    # Session 4: another stripped session with suspicious fallback
    s4_id = f"{analysis_id[:8]}:4"
    s4 = TCPSession(
        session_id=s4_id,
        src_ip="10.10.5.34",
        src_port=52_500,
        dst_ip="203.0.113.90",
        dst_port=25,
        start_time=t0 + 410.0,
        end_time=t0 + 410.0 + 5.5,
        duration_seconds=5.5,
        packet_count=44,
        bytes_transferred=6_600,
        protocol=ApplicationProtocol.SMTP,
        starttls_state=STARTTLSState.SUSPICIOUS_FALLBACK,
        findings=[
            _finding(
                s4_id,
                FindingSeverity.HIGH,
                FindingCategory.STARTTLS_ANOMALY,
                "Suspicious cleartext fallback after STARTTLS advertisement",
                "STARTTLS was advertised by the server but the connection continued in "
                "cleartext without a STARTTLS exchange being initiated by the client. "
                "This pattern is consistent with a STARTTLS stripping attack or "
                "misconfigured client.",
                "Enable MTA-STS (RFC 8461) and DANE/TLSA records (RFC 7672) to prevent "
                "opportunistic downgrade. Audit MTA client configurations.",
                "smtp.req.command",
                "Cleartext after STARTTLS advert",
                [2, 15, 16],
            ),
        ],
    )

    sessions = [s0, s1, s2, s3, s4]
    all_findings = [f for s in sessions for f in s.findings]
    crit = sum(1 for f in all_findings if f.severity == FindingSeverity.CRITICAL)
    high = sum(1 for f in all_findings if f.severity == FindingSeverity.HIGH)

    return AnalysisResult(
        analysis_id=analysis_id,
        capture=CaptureMetadata(
            pcap_path=pcap_path,
            pcap_filename=Path(pcap_path).name,
            sha256_hash="c3d4e5f6a7b8" * 5 + "c3d4",
            file_size_bytes=89_316,
            capture_duration_seconds=480.6,
            packet_count=312,
            first_packet_time=t0,
            last_packet_time=t0 + 480.6,
        ),
        sessions=sessions,
        risk_score=RiskScore(
            score=94.0,
            level="CRITICAL",
            rationale=[
                f"{crit} CRITICAL findings: STARTTLS capability stripping (MITM indicator) "
                "and cleartext AUTH LOGIN with credentials exposed in plaintext.",
                f"{high} HIGH findings: STARTTLS negotiation failure and suspicious "
                "cleartext fallback after capability advertisement.",
                "4 of 5 SMTP sessions had no effective TLS protection.",
                "Credentials transmitted in cleartext are recoverable by any passive "
                "observer. Immediate remediation required.",
            ],
            critical_count=crit,
            high_count=high,
        ),
        protocol_summary=ProtocolSummary(
            smtp_sessions=5,
            tls_sessions=1,
            plaintext_sessions=4,
            starttls_sessions=1,
            tls_versions={"TLS 1.2": 1},
            cipher_suites={"ECDHE-RSA-AES256-GCM-SHA384": 1},
            forward_secrecy_yes=1,
            forward_secrecy_unknown=4,
        ),
        all_findings=all_findings,
        recommendations=[
            "IMMEDIATE: Rotate any credentials transmitted in cleartext — treat them as "
            "compromised. Audit authentication logs for unauthorized access.",
            "Deploy MTA-STS (RFC 8461) to enforce TLS on inbound SMTP and prevent "
            "opportunistic downgrade attacks.",
            "Enable DANE/TLSA records (RFC 7672) for cryptographic authentication of "
            "the receiving MTA.",
            "Configure Postfix/Exim to require TLS before accepting AUTH "
            "(smtpd_tls_auth_only=yes).",
            "Investigate the network path between 10.10.5.31–34 and 203.0.113.90 for "
            "signs of active man-in-the-middle activity.",
            "Consider migrating SMTP submission to port 465 (implicit TLS, RFC 8314) "
            "to eliminate STARTTLS stripping as an attack vector.",
        ],
        limitations=[
            "1 session had normal STARTTLS+TLS 1.2: certificate observability confirmed "
            "but chain validation requires out-of-band trust store data.",
            "STARTTLS stripping assessment is heuristic — definitive attribution of "
            "active MITM requires network forensics beyond passive PCAP analysis.",
            "This tool performs passive analysis only.",
        ],
        processing_time_seconds=3.51,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_FALLBACK_MAP: dict[str, object] = {
    "01_enterprise_secure_baseline": _scenario_01,
    "02_legacy_cryptography_and_certs": _scenario_02,
    "03_starttls_downgrade_and_cleartext": _scenario_03,
}


def get_demo_fallback(pcap_path: str, analysis_id: str) -> AnalysisResult | None:
    """
    Return a pre-baked AnalysisResult for a known demo PCAP, or None if
    the path doesn't match any known scenario.

    Used as a fallback when the real tshark pipeline fails (e.g. during
    permission debugging on rootless Podman/Ubuntu).
    """
    stem = Path(pcap_path).stem
    builder = _FALLBACK_MAP.get(stem)
    if builder is None:
        logger.debug("No demo fallback for stem %r", stem)
        return None
    logger.warning(
        "Using pre-baked fallback data for %r (analysis_id=%s). "
        "Real tshark analysis failed — see [tshark-debug] log lines above.",
        stem,
        analysis_id,
    )
    return builder(analysis_id, pcap_path)  # type: ignore[operator]
