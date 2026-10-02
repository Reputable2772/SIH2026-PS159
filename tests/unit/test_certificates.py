"""
Unit tests for certificate analyser.
"""
import base64
import pytest
from datetime import datetime, timezone, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from backend.certificates.analyser import (
    parse_certificate_der,
    assess_cert_risk,
)


def _make_cert_der(
    cn: str = "test.local",
    days_valid: int = 365,
    key_size: int = 2048,
    expired: bool = False,
) -> bytes:
    """Generate a minimal self-signed DER certificate for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    now = datetime.now(timezone.utc)
    if expired:
        not_before = now - timedelta(days=400)
        not_after = now - timedelta(days=35)  # expired 35 days ago
    else:
        not_before = now
        not_after = now + timedelta(days=days_valid)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn)]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


class TestCertificateParsing:

    def test_parse_valid_cert(self):
        der = _make_cert_der("valid.local")
        cert = parse_certificate_der(der)
        assert cert is not None
        assert cert.subject_cn == "valid.local"
        assert cert.is_self_signed is True
        assert cert.is_expired is False
        assert cert.public_key is not None
        assert cert.public_key.algorithm == "RSA"
        assert cert.public_key.key_size_bits == 2048

    def test_parse_expired_cert(self):
        der = _make_cert_der("expired.local", expired=True)
        cert = parse_certificate_der(der)
        assert cert is not None
        assert cert.is_expired is True
        assert cert.days_until_expiry < 0

    def test_san_extraction(self):
        der = _make_cert_der("san.local")
        cert = parse_certificate_der(der)
        assert cert is not None
        assert any("san.local" in s for s in cert.san)

    def test_fingerprint_deterministic(self):
        der = _make_cert_der("fp.local")
        c1 = parse_certificate_der(der)
        c2 = parse_certificate_der(der)
        assert c1.fingerprint_sha256 == c2.fingerprint_sha256

    def test_invalid_der_returns_none(self):
        cert = parse_certificate_der(b"not a certificate")
        assert cert is None


class TestCertificateRiskAssessment:

    def test_expired_is_critical(self):
        der = _make_cert_der("expired.local", expired=True)
        cert = parse_certificate_der(der)
        risks = assess_cert_risk(cert)
        sevs = [r["severity"] for r in risks]
        assert "critical" in sevs

    def test_valid_cert_no_critical(self):
        der = _make_cert_der("valid.local", key_size=2048)
        cert = parse_certificate_der(der)
        risks = assess_cert_risk(cert)
        assert not any(r["severity"] == "critical" for r in risks)

    def test_weak_rsa_key_flagged(self):
        der = _make_cert_der("weak.local", key_size=1024)
        cert = parse_certificate_der(der)
        risks = assess_cert_risk(cert)
        cats = [r["category"] for r in risks]
        assert "weak_key" in cats

    def test_self_signed_flagged(self):
        der = _make_cert_der("self.local")
        cert = parse_certificate_der(der)
        risks = assess_cert_risk(cert)
        cats = [r["category"] for r in risks]
        assert "invalid_certificate" in cats
