"""
SecureMailScope — Core Data Models
All data flowing through the pipeline is typed with Pydantic models.
"""
from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class ApplicationProtocol(str, enum.Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


class TLSVersion(str, enum.Enum):
    SSL_2_0 = "SSL 2.0"
    SSL_3_0 = "SSL 3.0"
    TLS_1_0 = "TLS 1.0"
    TLS_1_1 = "TLS 1.1"
    TLS_1_2 = "TLS 1.2"
    TLS_1_3 = "TLS 1.3"
    UNKNOWN = "Unknown"


class STARTTLSState(str, enum.Enum):
    """STARTTLS negotiation state machine states."""
    NO_TLS = "no_tls"                          # Plaintext only
    NONE = "no_tls"                            # Alias for NO_TLS
    ADVERTISED = "advertised"                   # Server advertised STARTTLS
    REQUESTED = "requested"                     # Client sent STARTTLS command
    NEGOTIATED = "negotiated"                   # TLS handshake completed
    FAILED = "failed"                           # STARTTLS attempted but failed
    SUSPICIOUS_FALLBACK = "suspicious_fallback" # Cleartext after STARTTLS advert
    DIRECT_TLS = "direct_tls"                   # Implicit TLS (no STARTTLS)


class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, enum.Enum):
    DEPRECATED_TLS = "deprecated_tls"
    WEAK_CIPHER = "weak_cipher"
    WEAK_KEY = "weak_key"
    WEAK_SIGNATURE = "weak_signature"
    EXPIRED_CERTIFICATE = "expired_certificate"
    INVALID_CERTIFICATE = "invalid_certificate"
    NO_FORWARD_SECRECY = "no_forward_secrecy"
    STARTTLS_ANOMALY = "starttls_anomaly"
    PLAINTEXT_AUTH = "plaintext_auth"
    ML_ANOMALY = "ml_anomaly"
    CONFIGURATION = "configuration"
    INFO = "info"

    # Aliases
    CIPHER_SUITE = "weak_cipher"
    STARTTLS = "starttls_anomaly"


class ForwardSecrecyStatus(str, enum.Enum):
    YES = "yes"                    # Forward secrecy confirmed
    NO = "no"                      # Forward secrecy absent
    UNKNOWN = "unknown"            # Cannot determine from capture


class ObservabilityStatus(str, enum.Enum):
    """Whether a piece of data was actually observed in the capture."""
    OBSERVED = "observed"
    NOT_OBSERVABLE = "not_observable"
    PARTIALLY_OBSERVABLE = "partially_observable"


# ---------------------------------------------------------------------------
# Evidence Provenance
# ---------------------------------------------------------------------------

class Evidence(BaseModel):
    """Traceable evidence for a finding — answers 'why did we flag this?'"""
    pcap_file: str = ""
    session_id: str
    packet_numbers: list[int] = Field(default_factory=list)
    field: Optional[str] = None
    observed_value: Optional[Any] = None
    extra: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class Finding(BaseModel):
    """A single deterministic security finding produced by the rule engine."""
    id: str
    severity: FindingSeverity
    category: FindingCategory
    title: str
    description: str
    evidence: Evidence
    recommendation: str
    cve_references: list[str] = Field(default_factory=list)
    is_ml_finding: bool = False  # True for ML-generated anomalies


# ---------------------------------------------------------------------------
# X.509 Certificate Models
# ---------------------------------------------------------------------------

class PublicKeyInfo(BaseModel):
    algorithm: str                 # RSA, EC, DSA, Ed25519, …
    key_size_bits: Optional[int] = None   # RSA/DSA key size; None for curves
    curve: Optional[str] = None    # EC named curve
    public_exponent: Optional[int] = None  # RSA e
    observability: ObservabilityStatus = ObservabilityStatus.OBSERVED


class CertificateInfo(BaseModel):
    """Parsed X.509 certificate — only fields verifiably extracted from PCAP."""
    fingerprint_sha256: str
    subject_cn: Optional[str] = None
    subject_dn: Optional[str] = None
    issuer_cn: Optional[str] = None
    issuer_dn: Optional[str] = None
    san: list[str] = Field(default_factory=list)
    not_before: Optional[datetime] = None
    not_after: Optional[datetime] = None
    is_expired: Optional[bool] = None
    days_until_expiry: Optional[int] = None
    is_self_signed: Optional[bool] = None
    signature_algorithm: Optional[str] = None
    public_key: Optional[PublicKeyInfo] = None
    serial_number: Optional[str] = None
    version: Optional[int] = None
    observability: ObservabilityStatus = ObservabilityStatus.OBSERVED
    # TLS 1.3: certificate may not be observable
    extraction_note: Optional[str] = None
    raw_der_b64: Optional[str] = None   # base64-encoded DER for export


# ---------------------------------------------------------------------------
# TLS Handshake
# ---------------------------------------------------------------------------

class TLSHandshake(BaseModel):
    """Observable TLS handshake data extracted from a session."""
    tls_version: TLSVersion = TLSVersion.UNKNOWN
    cipher_suite: Optional[str] = None
    cipher_suite_hex: Optional[str] = None
    key_exchange: Optional[str] = None           # DHE, ECDHE, RSA, …
    forward_secrecy: ForwardSecrecyStatus = ForwardSecrecyStatus.UNKNOWN

    # Client Hello fields
    client_offered_ciphers: list[str] = Field(default_factory=list)
    client_tls_extensions: list[str] = Field(default_factory=list)
    client_hello_version: Optional[str] = None

    # Server Hello fields
    server_hello_version: Optional[str] = None
    server_tls_extensions: list[str] = Field(default_factory=list)

    # Certificate chain (may be empty for TLS 1.3 without keys)
    certificates: list[CertificateInfo] = Field(default_factory=list)
    cert_observability: ObservabilityStatus = ObservabilityStatus.OBSERVED
    cert_observability_note: Optional[str] = None

    # JA3 fingerprint (client)
    ja3_hash: Optional[str] = None
    ja3_string: Optional[str] = None

    # Packet numbers for evidence tracing
    client_hello_pkt: Optional[int] = None
    server_hello_pkt: Optional[int] = None
    handshake_complete: bool = False
    cipher_suite_name: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def _sync_cipher_suite_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "cipher_suite_name" in data and "cipher_suite" not in data:
                data["cipher_suite"] = data["cipher_suite_name"]
            elif "cipher_suite" in data and "cipher_suite_name" not in data:
                data["cipher_suite_name"] = data["cipher_suite"]
        return data


# Alias for backward compatibility / alternate naming
TLSHandshakeInfo = TLSHandshake


# ---------------------------------------------------------------------------
# TCP Session
# ---------------------------------------------------------------------------

class TCPSession(BaseModel):
    """Reconstructed TCP session with application-layer context."""
    session_id: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    duration_seconds: Optional[float] = None
    packet_count: int = 0
    bytes_transferred: int = 0

    # Application layer
    protocol: ApplicationProtocol = ApplicationProtocol.UNKNOWN
    starttls_state: STARTTLSState = STARTTLSState.NO_TLS
    starttls_advertised_pkt: Optional[int] = None
    starttls_requested_pkt: Optional[int] = None
    tls_start_pkt: Optional[int] = None

    # Plaintext command snippets (only SMTP/IMAP/POP3 command lines — never payload content)
    protocol_banners: list[str] = Field(default_factory=list)
    cleartext_auth_detected: bool = False

    # TLS
    tls_handshake: Optional[TLSHandshake] = None

    # Findings for this session
    findings: list[Finding] = Field(default_factory=list)

    # ML anomaly
    anomaly_score: Optional[float] = None
    is_anomalous: Optional[bool] = None
    anomaly_features: dict[str, Any] = Field(default_factory=dict)

    # Risk score for this session
    session_risk_score: Optional[float] = None
    session_risk_level: Optional[str] = None


# ---------------------------------------------------------------------------
# PCAP Analysis Result
# ---------------------------------------------------------------------------

class CaptureMetadata(BaseModel):
    pcap_path: str = ""
    pcap_filename: str = ""
    sha256_hash: str = ""
    file_size_bytes: int = 0
    capture_duration_seconds: Optional[float] = None
    duration_seconds: Optional[float] = None
    packet_count: int = 0
    first_packet_time: Optional[float] = None
    last_packet_time: Optional[float] = None
    analyzed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tool_version: str = "0.1.0"

    @model_validator(mode="before")
    @classmethod
    def _sync_duration_fields(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "duration_seconds" in data and "capture_duration_seconds" not in data:
                data["capture_duration_seconds"] = data["duration_seconds"]
            elif "capture_duration_seconds" in data and "duration_seconds" not in data:
                data["duration_seconds"] = data["capture_duration_seconds"]
        return data


class RiskScore(BaseModel):
    """SecureMailScope Composite Risk Score — prototype scoring methodology."""
    score: float = Field(ge=0.0, le=100.0)
    level: str           # CRITICAL / HIGH / MEDIUM / LOW / MINIMAL
    rationale: list[str] = Field(default_factory=list)
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    ml_anomaly_count: int = 0


class ProtocolSummary(BaseModel):
    smtp_sessions: int = 0
    imap_sessions: int = 0
    pop3_sessions: int = 0
    unknown_sessions: int = 0
    tls_sessions: int = 0
    plaintext_sessions: int = 0
    starttls_sessions: int = 0
    tls_versions: dict[str, int] = Field(default_factory=dict)
    cipher_suites: dict[str, int] = Field(default_factory=dict)
    forward_secrecy_yes: int = 0
    forward_secrecy_no: int = 0
    forward_secrecy_unknown: int = 0


class AnalysisResult(BaseModel):
    """Top-level result of a PCAP analysis run."""
    analysis_id: str
    capture: CaptureMetadata
    sessions: list[TCPSession] = Field(default_factory=list)
    risk_score: RiskScore
    protocol_summary: ProtocolSummary = Field(default_factory=ProtocolSummary)
    all_findings: list[Finding] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    processing_time_seconds: float = 0.0
