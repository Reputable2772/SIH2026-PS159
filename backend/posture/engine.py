"""
SecureMailScope — Cryptographic Posture Rule Engine
Deterministic rules that evaluate observed facts and produce findings.

Architecture:
    Observed Fact → Rule Evaluation → Finding → Severity → Recommendation
"""
from __future__ import annotations

import logging
import uuid
from typing import Any

from backend.models.session import (
    ApplicationProtocol,
    Evidence,
    Finding,
    FindingCategory,
    FindingSeverity,
    ForwardSecrecyStatus,
    STARTTLSState,
    TCPSession,
    TLSVersion,
)
from backend.tls.analyser import WEAK_CIPHERS, is_weak_cipher

logger = logging.getLogger(__name__)


def _make_finding(
    severity: FindingSeverity,
    category: FindingCategory,
    title: str,
    description: str,
    recommendation: str,
    session: TCPSession,
    field: str = "",
    observed_value: Any = None,
    packet_numbers: list[int] | None = None,
    extra: dict | None = None,
    cves: list[str] | None = None,
) -> Finding:
    """Factory helper — constructs a Finding with full provenance."""
    return Finding(
        id=str(uuid.uuid4()),
        severity=severity,
        category=category,
        title=title,
        description=description,
        evidence=Evidence(
            pcap_file=session.session_id.split(":")[0] if ":" in session.session_id else "",
            session_id=session.session_id,
            packet_numbers=packet_numbers or [],
            field=field,
            observed_value=observed_value,
            extra=extra or {},
        ),
        recommendation=recommendation,
        cve_references=cves or [],
        is_ml_finding=False,
    )


# ---------------------------------------------------------------------------
# TLS Version Rules
# ---------------------------------------------------------------------------

TLS_VERSION_RULES: dict[TLSVersion, tuple[FindingSeverity, str, str]] = {
    TLSVersion.SSL_2_0: (
        FindingSeverity.CRITICAL,
        "SSL 2.0 is completely broken and must not be used.",
        "Disable SSL 2.0 immediately. Require TLS 1.2 or TLS 1.3.",
    ),
    TLSVersion.SSL_3_0: (
        FindingSeverity.CRITICAL,
        "SSL 3.0 is vulnerable to POODLE (CVE-2014-3566) and other attacks.",
        "Disable SSL 3.0 immediately. Require TLS 1.2 or TLS 1.3.",
    ),
    TLSVersion.TLS_1_0: (
        FindingSeverity.HIGH,
        "TLS 1.0 is deprecated (RFC 8996). Vulnerable to BEAST, POODLE-on-TLS.",
        "Upgrade to TLS 1.2 or TLS 1.3.",
    ),
    TLSVersion.TLS_1_1: (
        FindingSeverity.HIGH,
        "TLS 1.1 is deprecated (RFC 8996). Lacks modern cipher suites.",
        "Upgrade to TLS 1.2 or TLS 1.3.",
    ),
}


def evaluate_tls_version(session: TCPSession) -> list[Finding]:
    findings = []
    if not session.tls_handshake:
        return findings

    version = session.tls_handshake.tls_version
    if version in TLS_VERSION_RULES:
        sev, desc, rec = TLS_VERSION_RULES[version]
        findings.append(_make_finding(
            severity=sev,
            category=FindingCategory.DEPRECATED_TLS,
            title=f"Deprecated TLS version negotiated: {version.value}",
            description=desc,
            recommendation=rec,
            session=session,
            field="tls.handshake.version",
            observed_value=version.value,
            packet_numbers=[n for n in [
                session.tls_handshake.server_hello_pkt
            ] if n is not None],
            cves={
                TLSVersion.SSL_3_0: ["CVE-2014-3566"],
                TLSVersion.TLS_1_0: ["CVE-2011-3389"],
            }.get(version, []),
        ))
    return findings


# ---------------------------------------------------------------------------
# Cipher Suite Rules
# ---------------------------------------------------------------------------

def evaluate_cipher_suite(session: TCPSession) -> list[Finding]:
    findings = []
    if not session.tls_handshake:
        return findings

    cipher = session.tls_handshake.cipher_suite
    if not cipher:
        return findings

    if is_weak_cipher(cipher):
        # Determine specific weakness
        if "NULL" in cipher:
            desc = f"NULL cipher {cipher!r} provides NO encryption — all data is plaintext."
            sev = FindingSeverity.CRITICAL
        elif "EXPORT" in cipher:
            desc = f"Export-grade cipher {cipher!r} uses intentionally weakened keys."
            sev = FindingSeverity.CRITICAL
        elif "RC4" in cipher:
            desc = f"RC4 cipher {cipher!r} is cryptographically broken (RFC 7465)."
            sev = FindingSeverity.CRITICAL
        elif "DES" in cipher and "3DES" not in cipher:
            desc = f"DES cipher {cipher!r} uses 56-bit keys, easily brute-forced."
            sev = FindingSeverity.CRITICAL
        elif "3DES" in cipher:
            desc = f"3DES cipher {cipher!r} is vulnerable to Sweet32 attack (CVE-2016-2183)."
            sev = FindingSeverity.HIGH
        elif "anon" in cipher.lower():
            desc = f"Anonymous cipher {cipher!r} provides no server authentication — vulnerable to MITM."
            sev = FindingSeverity.CRITICAL
        elif "MD5" in cipher:
            desc = f"Cipher {cipher!r} uses MD5 for MAC, which is cryptographically weak."
            sev = FindingSeverity.HIGH
        else:
            desc = f"Cipher suite {cipher!r} is deprecated or weak."
            sev = FindingSeverity.HIGH

        findings.append(_make_finding(
            severity=sev,
            category=FindingCategory.WEAK_CIPHER,
            title=f"Weak/deprecated cipher suite: {cipher}",
            description=desc,
            recommendation="Use ECDHE or DHE key exchange with AES-GCM or ChaCha20-Poly1305.",
            session=session,
            field="tls.handshake.ciphersuite",
            observed_value=cipher,
            packet_numbers=[n for n in [session.tls_handshake.server_hello_pkt] if n is not None],
            cves={
                "RC4": ["CVE-2013-2566", "RFC 7465"],
                "3DES": ["CVE-2016-2183"],
            }.get(
                next((k for k in ["RC4", "3DES", "NULL"] if k in cipher), ""),
                [],
            ),
        ))
    return findings


# ---------------------------------------------------------------------------
# Forward Secrecy Rules
# ---------------------------------------------------------------------------

def evaluate_forward_secrecy(session: TCPSession) -> list[Finding]:
    findings = []
    if not session.tls_handshake:
        return findings

    fs = session.tls_handshake.forward_secrecy
    version = session.tls_handshake.tls_version

    if fs == ForwardSecrecyStatus.NO:
        # TLS 1.3 always has FS — this shouldn't happen, but guard anyway
        if version == TLSVersion.TLS_1_3:
            return findings

        cipher = session.tls_handshake.cipher_suite or "unknown"
        findings.append(_make_finding(
            severity=FindingSeverity.HIGH,
            category=FindingCategory.NO_FORWARD_SECRECY,
            title=f"No Forward Secrecy: {cipher}",
            description=(
                f"The cipher suite {cipher!r} uses RSA key exchange without ephemeral keys. "
                "If the server's private key is ever compromised, all past sessions "
                "can be decrypted."
            ),
            recommendation=(
                "Use cipher suites with ECDHE or DHE key exchange "
                "(e.g., TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) "
                "or upgrade to TLS 1.3 which mandates forward secrecy."
            ),
            session=session,
            field="tls.handshake.ciphersuite",
            observed_value=cipher,
            packet_numbers=[n for n in [session.tls_handshake.server_hello_pkt] if n is not None],
        ))
    return findings


# ---------------------------------------------------------------------------
# STARTTLS Rules
# ---------------------------------------------------------------------------

def evaluate_starttls(session: TCPSession) -> list[Finding]:
    findings = []
    state = session.starttls_state

    if state == STARTTLSState.SUSPICIOUS_FALLBACK:
        findings.append(_make_finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.STARTTLS_ANOMALY,
            title="Suspicious STARTTLS downgrade / fallback detected",
            description=(
                f"Protocol: {session.protocol.value}. "
                "STARTTLS was advertised by the server and/or requested by the client, "
                "but a TLS handshake was not observed to complete. "
                "Cleartext protocol commands continued after STARTTLS advertisement. "
                "This may indicate STARTTLS stripping, a network-level downgrade attack, "
                "or a misconfigured client that accepted a downgrade. "
                "NOTE: Passive observation cannot conclusively prove an active attack — "
                "this finding labels the observed protocol-state inconsistency."
            ),
            recommendation=(
                "Investigate the session. Configure clients to require TLS and reject "
                "downgrade. Consider implicit TLS ports (465 for SMTP, 993 for IMAP, "
                "995 for POP3) which cannot be stripped."
            ),
            session=session,
            field="starttls_state",
            observed_value=state.value,
            packet_numbers=[
                n for n in [
                    session.starttls_advertised_pkt,
                    session.starttls_requested_pkt,
                ] if n is not None
            ],
        ))

    if session.cleartext_auth_detected:
        findings.append(_make_finding(
            severity=FindingSeverity.CRITICAL,
            category=FindingCategory.PLAINTEXT_AUTH,
            title="Plaintext authentication credentials transmitted without TLS",
            description=(
                f"Protocol: {session.protocol.value}. "
                "Authentication commands (AUTH, LOGIN, USER/PASS) were observed "
                "in cleartext before a TLS session was established. "
                "Credentials may be exposed to network observers."
            ),
            recommendation=(
                "Require TLS before any authentication. "
                "Use SASL PLAIN only over encrypted channels. "
                "Consider implicit TLS ports."
            ),
            session=session,
            field="cleartext_auth",
            observed_value=True,
        ))

    if state == STARTTLSState.ADVERTISED:
        findings.append(_make_finding(
            severity=FindingSeverity.MEDIUM,
            category=FindingCategory.STARTTLS_ANOMALY,
            title="STARTTLS advertised but not used by client",
            description=(
                f"Protocol: {session.protocol.value}. "
                "The server advertised STARTTLS support, but the client did not "
                "initiate a STARTTLS upgrade. The session may have continued in plaintext."
            ),
            recommendation=(
                "Configure the email client to require STARTTLS or use implicit TLS."
            ),
            session=session,
            field="starttls_state",
            observed_value=state.value,
        ))

    return findings


# ---------------------------------------------------------------------------
# No TLS Rule
# ---------------------------------------------------------------------------

def evaluate_no_tls(session: TCPSession) -> list[Finding]:
    findings = []
    email_protocols = {ApplicationProtocol.SMTP, ApplicationProtocol.IMAP, ApplicationProtocol.POP3}

    if (
        session.protocol in email_protocols
        and session.starttls_state == STARTTLSState.NO_TLS
        and session.tls_handshake is None
    ):
        findings.append(_make_finding(
            severity=FindingSeverity.HIGH,
            category=FindingCategory.CONFIGURATION,
            title=f"No TLS: {session.protocol.value} session transmitted entirely in plaintext",
            description=(
                f"The {session.protocol.value} session between "
                f"{session.src_ip}:{session.src_port} and "
                f"{session.dst_ip}:{session.dst_port} "
                "was conducted entirely in plaintext with no TLS or STARTTLS observed."
            ),
            recommendation=(
                "Configure the mail server to require TLS. "
                "Use STARTTLS or implicit TLS ports."
            ),
            session=session,
            field="tls_handshake",
            observed_value=None,
        ))
    return findings


# ---------------------------------------------------------------------------
# Main Rule Engine
# ---------------------------------------------------------------------------

class PostureRuleEngine:
    """
    Applies all deterministic cryptographic posture rules to a session.
    Returns the session with findings populated.
    """

    def __init__(self):
        self._rules = [
            evaluate_tls_version,
            evaluate_cipher_suite,
            evaluate_forward_secrecy,
            evaluate_starttls,
            evaluate_no_tls,
        ]

    def evaluate(self, session: TCPSession) -> TCPSession:
        """Apply all rules to a session. Mutates session.findings in-place."""
        all_findings: list[Finding] = []
        for rule_fn in self._rules:
            try:
                findings = rule_fn(session)
                all_findings.extend(findings)
            except Exception as exc:
                logger.exception("Rule %s raised: %s", rule_fn.__name__, exc)

        # Certificate-level findings (produced by certificate analyser and stored here)
        # are appended externally by the pipeline — we don't duplicate here.

        session.findings.extend(all_findings)
        return session

    def evaluate_batch(self, sessions: list[TCPSession]) -> list[TCPSession]:
        return [self.evaluate(s) for s in sessions]
