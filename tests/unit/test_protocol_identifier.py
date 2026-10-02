"""
Unit tests for protocol identification.
"""

from backend.protocols.identifier import (
    ApplicationProtocol,
    identify_protocol,
    identify_protocol_by_payload,
    identify_protocol_by_port,
)


def test_smtp_port_25():
    assert identify_protocol_by_port(12345, 25) == ApplicationProtocol.SMTP


def test_smtp_port_587():
    assert identify_protocol_by_port(12345, 587) == ApplicationProtocol.SMTP


def test_smtp_port_465():
    assert identify_protocol_by_port(12345, 465) == ApplicationProtocol.SMTP


def test_imap_port_143():
    assert identify_protocol_by_port(12345, 143) == ApplicationProtocol.IMAP


def test_imap_port_993():
    assert identify_protocol_by_port(12345, 993) == ApplicationProtocol.IMAP


def test_pop3_port_110():
    assert identify_protocol_by_port(12345, 110) == ApplicationProtocol.POP3


def test_pop3_port_995():
    assert identify_protocol_by_port(12345, 995) == ApplicationProtocol.POP3


def test_unknown_port():
    assert identify_protocol_by_port(12345, 8080) == ApplicationProtocol.UNKNOWN


def test_smtp_payload_detection():
    payload = b"220 mail.example.com ESMTP Postfix\r\nEHLO test\r\n250-STARTTLS\r\n"
    assert identify_protocol_by_payload(payload) == ApplicationProtocol.SMTP


def test_imap_payload_detection():
    payload = b"* OK [CAPABILITY IMAP4rev1 STARTTLS AUTH=PLAIN] Dovecot ready.\r\n"
    assert identify_protocol_by_payload(payload) == ApplicationProtocol.IMAP


def test_pop3_payload_detection():
    payload = b"+OK Dovecot ready.\r\nUSER test@example.com\r\n"
    assert identify_protocol_by_payload(payload) == ApplicationProtocol.POP3


def test_combined_identification_prefers_port():
    # Port should win over payload
    payload = b"+OK POP3 server"
    result = identify_protocol(12345, 25, payload)
    assert result == ApplicationProtocol.SMTP  # Port 25 wins


def test_combined_identification_falls_back_to_payload():
    payload = b"220 smtp.example.com ESMTP\r\n"
    result = identify_protocol(12345, 9999, payload)
    assert result == ApplicationProtocol.SMTP
