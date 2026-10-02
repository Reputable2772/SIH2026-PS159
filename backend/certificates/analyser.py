"""
SecureMailScope — X.509 Certificate Analyser
Extracts and validates certificates observable in the PCAP.
Handles TLS 1.3 observability limitation explicitly.
"""
from __future__ import annotations

import base64
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import (
    dh,
    dsa,
    ec,
    ed25519,
    ed448,
    rsa,
)
from cryptography.x509.oid import ExtensionOID, NameOID

from backend.models.session import CertificateInfo, ObservabilityStatus, PublicKeyInfo

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Certificate Parsing
# ---------------------------------------------------------------------------

def parse_certificate_der(der_bytes: bytes) -> Optional[CertificateInfo]:
    """
    Parse a DER-encoded X.509 certificate.
    Returns None if parsing fails.
    All fields are explicitly marked with observability status.
    """
    try:
        cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as exc:
        logger.warning("Failed to parse certificate DER: %s", exc)
        return None

    now = datetime.now(timezone.utc)

    # Fingerprint (always computable from DER)
    fp = cert.fingerprint(hashes.SHA256()).hex()

    # Subject
    subject_cn = _get_name_attr(cert.subject, NameOID.COMMON_NAME)
    subject_dn = cert.subject.rfc4514_string()

    # Issuer
    issuer_cn = _get_name_attr(cert.issuer, NameOID.COMMON_NAME)
    issuer_dn = cert.issuer.rfc4514_string()

    # Validity
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc
    is_expired = now > not_after
    days_until_expiry = (not_after - now).days

    # Self-signed check
    is_self_signed = cert.subject == cert.issuer

    # SAN
    san_names: list[str] = []
    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        for name in san_ext.value:
            if isinstance(name, x509.DNSName):
                san_names.append(f"DNS:{name.value}")
            elif isinstance(name, x509.IPAddress):
                san_names.append(f"IP:{name.value}")
            elif isinstance(name, x509.RFC822Name):
                san_names.append(f"email:{name.value}")
    except x509.ExtensionNotFound:
        pass

    # Signature algorithm
    sig_alg = cert.signature_algorithm_oid.dotted_string
    try:
        sig_alg = cert.signature_hash_algorithm.name + "With" + cert.public_key().__class__.__name__
    except Exception:
        sig_alg = str(cert.signature_algorithm_oid.dotted_string)

    # Public key
    pub_key = _parse_public_key(cert.public_key())

    # Serial number
    serial = format(cert.serial_number, "x")

    return CertificateInfo(
        fingerprint_sha256=fp,
        subject_cn=subject_cn,
        subject_dn=subject_dn,
        issuer_cn=issuer_cn,
        issuer_dn=issuer_dn,
        san=san_names,
        not_before=not_before,
        not_after=not_after,
        is_expired=is_expired,
        days_until_expiry=days_until_expiry,
        is_self_signed=is_self_signed,
        signature_algorithm=sig_alg,
        public_key=pub_key,
        serial_number=serial,
        version=cert.version.value,
        observability=ObservabilityStatus.OBSERVED,
        raw_der_b64=base64.b64encode(der_bytes).decode(),
    )


def _get_name_attr(name: x509.Name, oid: x509.ObjectIdentifier) -> Optional[str]:
    try:
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None
    except Exception:
        return None


def _parse_public_key(pub_key: Any) -> PublicKeyInfo:
    if isinstance(pub_key, rsa.RSAPublicKey):
        return PublicKeyInfo(
            algorithm="RSA",
            key_size_bits=pub_key.key_size,
            public_exponent=pub_key.public_numbers().e,
        )
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        curve_name = pub_key.curve.name
        return PublicKeyInfo(
            algorithm="EC",
            key_size_bits=pub_key.key_size,
            curve=curve_name,
        )
    if isinstance(pub_key, dsa.DSAPublicKey):
        return PublicKeyInfo(
            algorithm="DSA",
            key_size_bits=pub_key.key_size,
        )
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return PublicKeyInfo(algorithm="Ed25519", key_size_bits=256)
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return PublicKeyInfo(algorithm="Ed448", key_size_bits=448)
    return PublicKeyInfo(algorithm="Unknown")


# ---------------------------------------------------------------------------
# Certificate extraction from tshark output
# ---------------------------------------------------------------------------

def extract_certs_from_tshark_stream(
    stream_packets: list[dict[str, Any]],
) -> tuple[list[CertificateInfo], ObservabilityStatus, Optional[str]]:
    """
    Try to extract certificates from a stream's tshark packets.

    Returns:
        (certs, observability_status, note)

    For TLS 1.3, certs will be empty with NOT_OBSERVABLE status and explanation.
    For TLS ≤ 1.2, certs may be populated if tshark decoded the Certificate message.
    """
    from backend.tls.analyser import parse_tls_version, TLSVersion

    tls_version = TLSVersion.UNKNOWN
    cert_ders: list[bytes] = []
    has_cert_message = False

    for pkt in stream_packets:
        layers = pkt.get("_source", {}).get("layers", {})
        hs_type = layers.get("tls.handshake.type")

        # Track negotiated version
        if hs_type == "2":  # ServerHello
            sv = layers.get("tls.handshake.extensions.supported_version")
            raw_ver = layers.get("tls.handshake.version")
            ver_str = str(sv) if sv else str(raw_ver)
            tls_version = parse_tls_version(ver_str)

        if hs_type == "11":  # Certificate message
            has_cert_message = True
            # tshark represents cert bytes in x509af fields — extract from JSON
            # The DER bytes aren't directly in JSON; we rely on tshark export-objects
            # or the presence of x509 fields as a signal that a certificate is present.
            # Actual DER extraction is done via tshark --export-objects tls in extractor.py

    # Check for TLS 1.3 — certs encrypted
    if tls_version == TLSVersion.TLS_1_3:
        note = (
            "TLS 1.3 session detected. Certificate messages are encrypted by default "
            "in TLS 1.3 (RFC 8446 §4.4.2). Without the session master secret "
            "(SSLKEYLOGFILE/NSS key log), server certificates cannot be extracted "
            "from passive traffic capture. Observable data: TLS version, cipher suite, "
            "key exchange type. This limitation demonstrates technically correct "
            "passive analysis."
        )
        return [], ObservabilityStatus.NOT_OBSERVABLE, note

    if has_cert_message:
        # Signal that a certificate message was seen but we may not have DER bytes
        # from this path — the pcap/extractor.py export-objects approach handles DER
        return [], ObservabilityStatus.PARTIALLY_OBSERVABLE, (
            "Certificate message observed in stream. "
            "DER bytes extracted via tshark export-objects if available."
        )

    return [], ObservabilityStatus.NOT_OBSERVABLE, "No TLS Certificate message observed in stream."


def create_not_observable_cert_placeholder(tls_version: str) -> None:
    """Explicitly do NOT create a placeholder certificate for TLS 1.3.
    Callers should check observability and display the note in the UI instead."""
    pass  # intentionally empty — we never fabricate certificate data


# ---------------------------------------------------------------------------
# Certificate Risk Assessment
# ---------------------------------------------------------------------------

MIN_RSA_KEY_BITS = 2048
MIN_DSA_KEY_BITS = 2048
MIN_EC_KEY_BITS = 224

WEAK_SIGNATURE_ALGORITHMS = {
    "md5", "md2", "sha1", "md5withrsa", "sha1withrsa", "sha1withecdsa",
    "md5withrsa encryption",
}

SOON_EXPIRY_DAYS = 30


def assess_cert_risk(cert: CertificateInfo) -> list[dict[str, Any]]:
    """
    Produce a list of raw risk signals from a certificate.
    Each signal is {severity, category, title, detail, recommendation}.
    """
    signals = []

    # Expiry
    if cert.is_expired:
        signals.append({
            "severity": "critical",
            "category": "expired_certificate",
            "title": "Certificate is expired",
            "detail": f"Not valid after: {cert.not_after}",
            "recommendation": "Replace the certificate immediately.",
        })
    elif cert.days_until_expiry is not None and cert.days_until_expiry <= SOON_EXPIRY_DAYS:
        signals.append({
            "severity": "high",
            "category": "invalid_certificate",
            "title": f"Certificate expiring soon ({cert.days_until_expiry} days)",
            "detail": f"Not valid after: {cert.not_after}",
            "recommendation": "Renew the certificate before expiry.",
        })

    # Weak public key
    if cert.public_key:
        pk = cert.public_key
        if pk.algorithm == "RSA" and pk.key_size_bits and pk.key_size_bits < MIN_RSA_KEY_BITS:
            signals.append({
                "severity": "high",
                "category": "weak_key",
                "title": f"Weak RSA key ({pk.key_size_bits} bits)",
                "detail": f"Key size {pk.key_size_bits} < {MIN_RSA_KEY_BITS} minimum.",
                "recommendation": f"Use RSA keys of at least {MIN_RSA_KEY_BITS} bits.",
            })
        if pk.algorithm == "DSA" and pk.key_size_bits and pk.key_size_bits < MIN_DSA_KEY_BITS:
            signals.append({
                "severity": "high",
                "category": "weak_key",
                "title": f"Weak DSA key ({pk.key_size_bits} bits)",
                "detail": f"Key size {pk.key_size_bits} < {MIN_DSA_KEY_BITS} minimum.",
                "recommendation": f"Migrate to ECDSA (P-256 or better) or RSA ≥ {MIN_RSA_KEY_BITS} bits.",
            })
        if pk.algorithm == "EC" and pk.key_size_bits and pk.key_size_bits < MIN_EC_KEY_BITS:
            signals.append({
                "severity": "high",
                "category": "weak_key",
                "title": f"Weak EC key ({pk.key_size_bits} bits on {pk.curve})",
                "detail": f"Key size {pk.key_size_bits} < {MIN_EC_KEY_BITS} minimum.",
                "recommendation": "Use P-256 or stronger EC curves.",
            })
        # RSA public exponent check
        if pk.algorithm == "RSA" and pk.public_exponent == 3:
            signals.append({
                "severity": "high",
                "category": "weak_key",
                "title": "RSA public exponent e=3 (low exponent attack risk)",
                "detail": "RSA with e=3 has known attack vectors.",
                "recommendation": "Use e=65537 (0x10001).",
            })

    # Weak signature algorithm
    if cert.signature_algorithm:
        sig_lower = cert.signature_algorithm.lower()
        for weak in WEAK_SIGNATURE_ALGORITHMS:
            if weak in sig_lower:
                signals.append({
                    "severity": "high",
                    "category": "weak_signature",
                    "title": f"Weak signature algorithm: {cert.signature_algorithm}",
                    "detail": f"Algorithm {cert.signature_algorithm} is deprecated.",
                    "recommendation": "Use SHA-256 or stronger signature algorithms.",
                })
                break

    # Self-signed
    if cert.is_self_signed:
        signals.append({
            "severity": "medium",
            "category": "invalid_certificate",
            "title": "Certificate is self-signed",
            "detail": "No trusted CA issued this certificate.",
            "recommendation": "Obtain a certificate from a trusted Certificate Authority.",
        })

    return signals
