"""
Unit tests for STARTTLS state machine.
"""
import pytest
from backend.protocols.starttls import SMTPSTARTTLSMachine, IMAPSTARTTLSMachine, POP3STARTTLSMachine
from backend.models.session import STARTTLSState


def _make_smtp_pkt(cmd=None, rsp_code=None, rsp_param=None, hs_type=None, pkt_num=1):
    layers = {}
    if cmd: layers["smtp.req.command"] = cmd
    if rsp_code: layers["smtp.rsp.code"] = rsp_code
    if rsp_param: layers["smtp.rsp.parameter"] = rsp_param
    if hs_type: layers["tls.handshake.type"] = hs_type
    layers["frame.number"] = str(pkt_num)
    return {"_source": {"layers": layers}}


class TestSMTPSTARTTLSMachine:

    def test_clean_starttls_negotiation(self):
        m = SMTPSTARTTLSMachine()
        packets = [
            _make_smtp_pkt(rsp_code="220", pkt_num=1),
            _make_smtp_pkt(cmd="EHLO", pkt_num=2),
            _make_smtp_pkt(rsp_code="250", rsp_param="STARTTLS", pkt_num=3),
            _make_smtp_pkt(cmd="STARTTLS", pkt_num=4),
            _make_smtp_pkt(rsp_code="220", pkt_num=5),
            _make_smtp_pkt(hs_type="1", pkt_num=6),  # ClientHello
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.NEGOTIATED
        assert m.starttls_advertised_pkt is not None
        assert m.starttls_requested_pkt is not None
        assert m.tls_start_pkt is not None

    def test_starttls_not_used(self):
        """Server offers STARTTLS but client sends MAIL instead."""
        m = SMTPSTARTTLSMachine()
        packets = [
            _make_smtp_pkt(rsp_code="220", pkt_num=1),
            _make_smtp_pkt(cmd="EHLO", pkt_num=2),
            _make_smtp_pkt(rsp_code="250", rsp_param="STARTTLS", pkt_num=3),
            _make_smtp_pkt(cmd="MAIL", pkt_num=4),  # Skip STARTTLS!
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        state = m.get_starttls_state()
        assert state in (STARTTLSState.SUSPICIOUS_FALLBACK, STARTTLSState.ADVERTISED)

    def test_starttls_rejected_fallback(self):
        """Server advertises STARTTLS but rejects the STARTTLS command."""
        m = SMTPSTARTTLSMachine()
        packets = [
            _make_smtp_pkt(rsp_code="220", pkt_num=1),
            _make_smtp_pkt(cmd="EHLO", pkt_num=2),
            _make_smtp_pkt(rsp_code="250", rsp_param="STARTTLS", pkt_num=3),
            _make_smtp_pkt(cmd="STARTTLS", pkt_num=4),
            _make_smtp_pkt(rsp_code="454", pkt_num=5),  # Rejected
            _make_smtp_pkt(cmd="MAIL", pkt_num=6),       # Continues plaintext
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.SUSPICIOUS_FALLBACK

    def test_no_tls_session(self):
        """Plain SMTP with no TLS or STARTTLS."""
        m = SMTPSTARTTLSMachine()
        packets = [
            _make_smtp_pkt(rsp_code="220", pkt_num=1),
            _make_smtp_pkt(cmd="EHLO", pkt_num=2),
            _make_smtp_pkt(rsp_code="250", pkt_num=3),  # No STARTTLS in response
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.NO_TLS
        assert not m.cleartext_auth_detected

    def test_cleartext_auth_detected(self):
        """AUTH before STARTTLS should be flagged."""
        m = SMTPSTARTTLSMachine()
        packets = [
            _make_smtp_pkt(rsp_code="220", pkt_num=1),
            _make_smtp_pkt(cmd="EHLO", pkt_num=2),
            _make_smtp_pkt(rsp_code="250", rsp_param="STARTTLS", pkt_num=3),
            _make_smtp_pkt(cmd="AUTH", pkt_num=4),  # Auth before STARTTLS!
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.cleartext_auth_detected


class TestSTARTTLSEventLog:

    def test_events_recorded(self):
        m = SMTPSTARTTLSMachine()
        packets = [
            _make_smtp_pkt(rsp_code="220", pkt_num=1),
            _make_smtp_pkt(cmd="EHLO", pkt_num=2),
            _make_smtp_pkt(rsp_code="250", rsp_param="STARTTLS", pkt_num=3),
            _make_smtp_pkt(cmd="STARTTLS", pkt_num=4),
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        kinds = [e.kind for e in m.events]
        assert "advertised" in kinds
        assert "requested" in kinds
