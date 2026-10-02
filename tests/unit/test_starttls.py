"""
Unit tests for STARTTLS state machine.
"""

from backend.models.session import STARTTLSState
from backend.protocols.starttls import IMAPSTARTTLSMachine, POP3STARTTLSMachine, SMTPSTARTTLSMachine


def _make_smtp_pkt(cmd=None, rsp_code=None, rsp_param=None, hs_type=None, pkt_num=1):
    layers = {}
    if cmd:
        layers["smtp.req.command"] = cmd
    if rsp_code:
        layers["smtp.rsp.code"] = rsp_code
    if rsp_param:
        layers["smtp.rsp.parameter"] = rsp_param
    if hs_type:
        layers["tls.handshake.type"] = hs_type
    layers["frame.number"] = str(pkt_num)
    return {"_source": {"layers": layers}}


def _make_imap_pkt(req=None, rsp=None, hs_type=None, pkt_num=1):
    layers = {}
    if req:
        layers["imap.request"] = req
    if rsp:
        layers["imap.response"] = rsp
    if hs_type:
        layers["tls.handshake.type"] = hs_type
    layers["frame.number"] = str(pkt_num)
    return {"_source": {"layers": layers}}


def _make_pop3_pkt(req=None, rsp=None, hs_type=None, pkt_num=1):
    layers = {}
    if req:
        layers["pop.request"] = req
    if rsp:
        layers["pop.response"] = rsp
    if hs_type:
        layers["tls.handshake.type"] = hs_type
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
            _make_smtp_pkt(cmd="MAIL", pkt_num=6),  # Continues plaintext
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


class TestIMAPSTARTTLSMachine:
    def test_clean_starttls_negotiation(self):
        m = IMAPSTARTTLSMachine()
        packets = [
            _make_imap_pkt(rsp="* OK IMAP4rev1 Service Ready", pkt_num=1),
            _make_imap_pkt(req="A001 CAPABILITY", pkt_num=2),
            _make_imap_pkt(rsp="* CAPABILITY IMAP4rev1 STARTTLS", pkt_num=3),
            _make_imap_pkt(req="A002 STARTTLS", pkt_num=4),
            _make_imap_pkt(rsp="A002 OK Begin TLS negotiation now", pkt_num=5),
            _make_imap_pkt(hs_type="1", pkt_num=6),
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.NEGOTIATED
        assert not m.cleartext_auth_detected

    def test_cleartext_login_after_advertised(self):
        m = IMAPSTARTTLSMachine()
        packets = [
            _make_imap_pkt(rsp="* OK IMAP4rev1 Service Ready", pkt_num=1),
            _make_imap_pkt(rsp="* CAPABILITY IMAP4rev1 STARTTLS", pkt_num=2),
            _make_imap_pkt(req="A001 LOGIN user pass", pkt_num=3),
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.SUSPICIOUS_FALLBACK
        assert m.cleartext_auth_detected


class TestPOP3STARTTLSMachine:
    def test_clean_stls_negotiation(self):
        m = POP3STARTTLSMachine()
        packets = [
            _make_pop3_pkt(rsp="+OK POP3 server ready", pkt_num=1),
            _make_pop3_pkt(req="CAPA", pkt_num=2),
            _make_pop3_pkt(rsp="+OK Capability list follows\r\nSTLS", pkt_num=3),
            _make_pop3_pkt(req="STLS", pkt_num=4),
            _make_pop3_pkt(rsp="+OK Begin TLS negotiation", pkt_num=5),
            _make_pop3_pkt(hs_type="1", pkt_num=6),
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.NEGOTIATED
        assert not m.cleartext_auth_detected

    def test_cleartext_user_pass_after_advertised(self):
        m = POP3STARTTLSMachine()
        packets = [
            _make_pop3_pkt(rsp="+OK POP3 server ready", pkt_num=1),
            _make_pop3_pkt(rsp="+OK Capability: STLS", pkt_num=2),
            _make_pop3_pkt(req="USER alice", pkt_num=3),
        ]
        for i, p in enumerate(packets):
            m.process_packet(p, i + 1)

        assert m.get_starttls_state() == STARTTLSState.SUSPICIOUS_FALLBACK
        assert m.cleartext_auth_detected
