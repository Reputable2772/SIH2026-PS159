"""
SecureMailScope — STARTTLS State Machine
Explicit state machine for STARTTLS negotiation across SMTP, IMAP, POP3.
"""

from __future__ import annotations

import enum
import logging
from dataclasses import dataclass
from typing import Any

from backend.models.session import ApplicationProtocol, STARTTLSState

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal state machine states
# ---------------------------------------------------------------------------


class _SMTPState(enum.Enum):
    INIT = "init"
    BANNER = "banner"
    EHLO = "ehlo"
    EHLO_RESP = "ehlo_resp"
    STARTTLS_CAPABLE = "starttls_capable"
    STARTTLS_SENT = "starttls_sent"
    STARTTLS_OK = "starttls_ok"
    TLS_ACTIVE = "tls_active"
    PLAINTEXT_CONTINUE = "plaintext_continue"  # suspicious
    DONE = "done"


class _IMAPState(enum.Enum):
    INIT = "init"
    CAPABILITY = "capability"
    STARTTLS_CAPABLE = "starttls_capable"
    STARTTLS_SENT = "starttls_sent"
    TLS_ACTIVE = "tls_active"
    PLAINTEXT_CONTINUE = "plaintext_continue"
    DONE = "done"


class _POP3State(enum.Enum):
    INIT = "init"
    GREETING = "greeting"
    STLS_CAPABLE = "stls_capable"
    STLS_SENT = "stls_sent"
    TLS_ACTIVE = "tls_active"
    PLAINTEXT_CONTINUE = "plaintext_continue"
    DONE = "done"


# ---------------------------------------------------------------------------
# Events emitted by the state machine
# ---------------------------------------------------------------------------


@dataclass
class STARTTLSEvent:
    kind: str  # "advertised", "requested", "tls_started", "fallback_detected",
    # "cleartext_auth", "tls_failed"
    packet_number: int | None = None
    detail: str = ""


# ---------------------------------------------------------------------------
# SMTP STARTTLS State Machine
# ---------------------------------------------------------------------------


class SMTPSTARTTLSMachine:
    """
    Tracks SMTP STARTTLS state across a session's packet sequence.

    Transitions:
        INIT → BANNER (220 greeting)
        BANNER → EHLO_RESP (after EHLO/HELO)
        EHLO_RESP → STARTTLS_CAPABLE (250-STARTTLS in response)
        STARTTLS_CAPABLE → STARTTLS_SENT (client sends STARTTLS)
        STARTTLS_SENT → STARTTLS_OK (server 220 response)
        STARTTLS_OK → TLS_ACTIVE (ClientHello observed)
        [If cleartext commands continue after STARTTLS capable] → PLAINTEXT_CONTINUE
    """

    def __init__(self):
        self._state = _SMTPState.INIT
        self.events: list[STARTTLSEvent] = []
        self.starttls_advertised_pkt: int | None = None
        self.starttls_requested_pkt: int | None = None
        self.tls_start_pkt: int | None = None
        self.cleartext_auth_detected: bool = False

    def process_packet(self, pkt: dict[str, Any], pkt_num: int) -> None:
        layers = pkt.get("_source", {}).get("layers", {})

        raw_cmd = layers.get("smtp.req.command") or ""
        if isinstance(raw_cmd, list):
            smtp_cmd = str(raw_cmd[0]).upper().strip() if raw_cmd else ""
        else:
            smtp_cmd = str(raw_cmd).upper().strip()

        raw_code = layers.get("smtp.response.code") or layers.get("smtp.rsp.code") or ""
        if isinstance(raw_code, list):
            smtp_rsp_codes = [str(c).strip() for c in raw_code]
            smtp_rsp_code = smtp_rsp_codes[0] if smtp_rsp_codes else ""
        else:
            smtp_rsp_codes = [str(raw_code).strip()]
            smtp_rsp_code = str(raw_code).strip()

        raw_rsp_param = layers.get("smtp.rsp.parameter") or ""
        if isinstance(raw_rsp_param, list):
            smtp_rsp_param = " ".join(str(p) for p in raw_rsp_param).upper()
        else:
            smtp_rsp_param = str(raw_rsp_param).upper()

        # Detect TLS ClientHello (indicates TLS negotiation started)
        hs_type = layers.get("tls.handshake.type")
        if hs_type == "1":  # ClientHello
            self.tls_start_pkt = pkt_num
            self._state = _SMTPState.TLS_ACTIVE
            return

        if self._state == _SMTPState.INIT:
            if "220" in smtp_rsp_codes or smtp_rsp_code == "220":
                self._state = _SMTPState.BANNER

        elif self._state == _SMTPState.BANNER:
            if smtp_cmd in ("EHLO", "HELO"):
                self._state = _SMTPState.EHLO_RESP

        elif self._state == _SMTPState.EHLO_RESP:
            if ("250" in smtp_rsp_codes or smtp_rsp_code == "250") and "STARTTLS" in smtp_rsp_param:
                self._state = _SMTPState.STARTTLS_CAPABLE
                self.starttls_advertised_pkt = pkt_num
                self.events.append(
                    STARTTLSEvent(
                        "advertised", pkt_num, "Server advertised STARTTLS in EHLO response"
                    )
                )
            elif smtp_cmd in ("AUTH", "MAIL", "RCPT"):
                # Client sent auth/mail before STARTTLS — plaintext auth
                self._state = _SMTPState.PLAINTEXT_CONTINUE
                self.cleartext_auth_detected = True
                self.events.append(
                    STARTTLSEvent(
                        "cleartext_auth", pkt_num, f"Cleartext {smtp_cmd} before TLS negotiation"
                    )
                )

        elif self._state == _SMTPState.STARTTLS_CAPABLE:
            if smtp_cmd == "STARTTLS":
                self._state = _SMTPState.STARTTLS_SENT
                self.starttls_requested_pkt = pkt_num
                self.events.append(STARTTLSEvent("requested", pkt_num, "Client sent STARTTLS"))
            elif smtp_cmd in ("AUTH", "MAIL", "RCPT", "DATA"):
                # Suspicious: STARTTLS available but client didn't use it
                self._state = _SMTPState.PLAINTEXT_CONTINUE
                self.cleartext_auth_detected = smtp_cmd in ("AUTH", "MAIL")
                self.events.append(
                    STARTTLSEvent(
                        "fallback_detected",
                        pkt_num,
                        f"Client sent {smtp_cmd} without STARTTLS — possible downgrade",
                    )
                )

        elif self._state == _SMTPState.STARTTLS_SENT:
            if "220" in smtp_rsp_codes or smtp_rsp_code == "220":
                self._state = _SMTPState.STARTTLS_OK
                self.events.append(STARTTLSEvent("tls_started", pkt_num, "Server ready for TLS"))
            elif any(c.startswith(("4", "5")) for c in smtp_rsp_codes):
                self._state = _SMTPState.PLAINTEXT_CONTINUE
                self.events.append(
                    STARTTLSEvent(
                        "tls_failed", pkt_num, f"STARTTLS rejected by server ({smtp_rsp_code})"
                    )
                )

    def get_starttls_state(self) -> STARTTLSState:
        if self._state == _SMTPState.TLS_ACTIVE:
            if self.starttls_requested_pkt:
                return STARTTLSState.NEGOTIATED
            return STARTTLSState.DIRECT_TLS
        if self._state == _SMTPState.STARTTLS_CAPABLE:
            return STARTTLSState.ADVERTISED
        if self._state == _SMTPState.STARTTLS_SENT:
            return STARTTLSState.REQUESTED
        if self._state == _SMTPState.PLAINTEXT_CONTINUE:
            if self.starttls_advertised_pkt:
                return STARTTLSState.SUSPICIOUS_FALLBACK
            return STARTTLSState.NO_TLS
        if self._state in (_SMTPState.BANNER, _SMTPState.EHLO_RESP, _SMTPState.INIT):
            return STARTTLSState.NO_TLS
        return STARTTLSState.NO_TLS


# ---------------------------------------------------------------------------
# IMAP STARTTLS State Machine
# ---------------------------------------------------------------------------


def _normalize_text(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, list):
        return " ".join(str(v) for v in val).upper().strip()
    return str(val).upper().strip()


class IMAPSTARTTLSMachine:
    """IMAP STARTTLS state machine."""

    def __init__(self):
        self._state = _IMAPState.INIT
        self.events: list[STARTTLSEvent] = []
        self.starttls_advertised_pkt: int | None = None
        self.starttls_requested_pkt: int | None = None
        self.tls_start_pkt: int | None = None
        self.cleartext_auth_detected: bool = False

    def process_packet(self, pkt: dict[str, Any], pkt_num: int) -> None:
        layers = pkt.get("_source", {}).get("layers", {})
        imap_req = _normalize_text(layers.get("imap.request"))
        imap_rsp = _normalize_text(layers.get("imap.response"))

        hs_type = layers.get("tls.handshake.type")
        if hs_type == "1":
            self.tls_start_pkt = pkt_num
            self._state = _IMAPState.TLS_ACTIVE
            return

        if "STARTTLS" in imap_rsp or "STARTTLS" in imap_req:
            if "CAPABILITY" in imap_rsp and "STARTTLS" in imap_rsp:
                self._state = _IMAPState.STARTTLS_CAPABLE
                self.starttls_advertised_pkt = pkt_num
                self.events.append(
                    STARTTLSEvent("advertised", pkt_num, "IMAP CAPABILITY includes STARTTLS")
                )
            elif "STARTTLS" in imap_req:
                self._state = _IMAPState.STARTTLS_SENT
                self.starttls_requested_pkt = pkt_num
                self.events.append(STARTTLSEvent("requested", pkt_num, "Client sent IMAP STARTTLS"))

        if self._state == _IMAPState.STARTTLS_CAPABLE:
            if "LOGIN" in imap_req or "AUTHENTICATE" in imap_req:
                self._state = _IMAPState.PLAINTEXT_CONTINUE
                self.cleartext_auth_detected = True
                self.events.append(
                    STARTTLSEvent(
                        "cleartext_auth", pkt_num, "IMAP LOGIN/AUTHENTICATE before STARTTLS"
                    )
                )

    def get_starttls_state(self) -> STARTTLSState:
        if self._state == _IMAPState.TLS_ACTIVE:
            return (
                STARTTLSState.NEGOTIATED
                if self.starttls_requested_pkt
                else STARTTLSState.DIRECT_TLS
            )
        if self._state == _IMAPState.STARTTLS_CAPABLE:
            return STARTTLSState.ADVERTISED
        if self._state == _IMAPState.STARTTLS_SENT:
            return STARTTLSState.REQUESTED
        if self._state == _IMAPState.PLAINTEXT_CONTINUE:
            return (
                STARTTLSState.SUSPICIOUS_FALLBACK
                if self.starttls_advertised_pkt
                else STARTTLSState.NO_TLS
            )
        return STARTTLSState.NO_TLS


# ---------------------------------------------------------------------------
# POP3 STARTTLS State Machine
# ---------------------------------------------------------------------------


class POP3STARTTLSMachine:
    """POP3 STLS (STARTTLS equivalent) state machine."""

    def __init__(self):
        self._state = _POP3State.INIT
        self.events: list[STARTTLSEvent] = []
        self.starttls_advertised_pkt: int | None = None
        self.starttls_requested_pkt: int | None = None
        self.tls_start_pkt: int | None = None
        self.cleartext_auth_detected: bool = False

    def process_packet(self, pkt: dict[str, Any], pkt_num: int) -> None:
        layers = pkt.get("_source", {}).get("layers", {})
        pop_req = _normalize_text(layers.get("pop.request"))
        pop_rsp = _normalize_text(layers.get("pop.response"))

        hs_type = layers.get("tls.handshake.type")
        if hs_type == "1":
            self.tls_start_pkt = pkt_num
            self._state = _POP3State.TLS_ACTIVE
            return

        if self._state == _POP3State.INIT and pop_rsp.startswith("+OK"):
            self._state = _POP3State.GREETING

        if "STLS" in pop_rsp or "STARTTLS" in pop_rsp:
            self._state = _POP3State.STLS_CAPABLE
            self.starttls_advertised_pkt = pkt_num
            self.events.append(STARTTLSEvent("advertised", pkt_num, "POP3 CAPA includes STLS"))

        if pop_req.startswith("STLS"):
            self._state = _POP3State.STLS_SENT
            self.starttls_requested_pkt = pkt_num
            self.events.append(STARTTLSEvent("requested", pkt_num, "Client sent POP3 STLS"))

        if self._state == _POP3State.STLS_CAPABLE:
            if pop_req.startswith(("USER", "PASS", "AUTH")):
                self._state = _POP3State.PLAINTEXT_CONTINUE
                self.cleartext_auth_detected = True
                self.events.append(
                    STARTTLSEvent("cleartext_auth", pkt_num, "POP3 USER/PASS/AUTH before STLS")
                )

    def get_starttls_state(self) -> STARTTLSState:
        if self._state == _POP3State.TLS_ACTIVE:
            return (
                STARTTLSState.NEGOTIATED
                if self.starttls_requested_pkt
                else STARTTLSState.DIRECT_TLS
            )
        if self._state == _POP3State.STLS_CAPABLE:
            return STARTTLSState.ADVERTISED
        if self._state == _POP3State.STLS_SENT:
            return STARTTLSState.REQUESTED
        if self._state == _POP3State.PLAINTEXT_CONTINUE:
            return (
                STARTTLSState.SUSPICIOUS_FALLBACK
                if self.starttls_advertised_pkt
                else STARTTLSState.NO_TLS
            )
        return STARTTLSState.NO_TLS


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------


def make_starttls_machine(protocol: ApplicationProtocol):
    """Return the appropriate STARTTLS machine for the protocol."""
    if protocol == ApplicationProtocol.SMTP:
        return SMTPSTARTTLSMachine()
    if protocol == ApplicationProtocol.IMAP:
        return IMAPSTARTTLSMachine()
    if protocol == ApplicationProtocol.POP3:
        return POP3STARTTLSMachine()
    return SMTPSTARTTLSMachine()  # fallback
