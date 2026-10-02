"""
SecureMailScope — Protocol Identification
Identifies SMTP, IMAP, POP3 from TCP sessions.
"""
from __future__ import annotations

import logging
import re
from typing import Any

from backend.models.session import ApplicationProtocol

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Well-known port → protocol mapping
# ---------------------------------------------------------------------------

WELL_KNOWN_PORTS: dict[int, ApplicationProtocol] = {
    25:   ApplicationProtocol.SMTP,   # SMTP
    465:  ApplicationProtocol.SMTP,   # SMTPS (implicit TLS)
    587:  ApplicationProtocol.SMTP,   # SMTP submission
    2525: ApplicationProtocol.SMTP,   # Alt SMTP
    143:  ApplicationProtocol.IMAP,   # IMAP
    993:  ApplicationProtocol.IMAP,   # IMAPS (implicit TLS)
    110:  ApplicationProtocol.POP3,   # POP3
    995:  ApplicationProtocol.POP3,   # POP3S (implicit TLS)
}

# Ports where TLS is implicit (no STARTTLS needed)
IMPLICIT_TLS_PORTS: set[int] = {465, 993, 995}

# ---------------------------------------------------------------------------
# Payload pattern matching
# ---------------------------------------------------------------------------

# SMTP: server banner, EHLO, MAIL FROM, etc.
SMTP_PATTERNS = [
    re.compile(rb"^220[ -].*SMTP", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^EHLO\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^HELO\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^MAIL FROM:", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^250[ -]", re.MULTILINE),
]

# IMAP: server capability banner, LOGIN, SELECT
IMAP_PATTERNS = [
    re.compile(rb"\* OK.*IMAP", re.IGNORECASE),
    re.compile(rb"\* CAPABILITY", re.IGNORECASE),
    re.compile(rb"[A-Z0-9]+ LOGIN", re.IGNORECASE),
    re.compile(rb"[A-Z0-9]+ SELECT", re.IGNORECASE),
    re.compile(rb"[A-Z0-9]+ STARTTLS", re.IGNORECASE),
]

# POP3: server greeting, USER, PASS, STLS
POP3_PATTERNS = [
    re.compile(rb"^\+OK", re.MULTILINE),
    re.compile(rb"^USER\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^PASS\b", re.MULTILINE | re.IGNORECASE),
    re.compile(rb"^STLS\b", re.MULTILINE | re.IGNORECASE),
]


def identify_protocol_by_port(src_port: int, dst_port: int) -> ApplicationProtocol:
    """Fast port-based identification."""
    proto = WELL_KNOWN_PORTS.get(dst_port) or WELL_KNOWN_PORTS.get(src_port)
    return proto or ApplicationProtocol.UNKNOWN


def identify_protocol_by_payload(payload: bytes) -> ApplicationProtocol:
    """Deep-inspection pattern matching against cleartext payload bytes."""
    if not payload:
        return ApplicationProtocol.UNKNOWN

    smtp_score = sum(1 for p in SMTP_PATTERNS if p.search(payload))
    imap_score = sum(1 for p in IMAP_PATTERNS if p.search(payload))
    pop3_score = sum(1 for p in POP3_PATTERNS if p.search(payload))

    scores = {
        ApplicationProtocol.SMTP: smtp_score,
        ApplicationProtocol.IMAP: imap_score,
        ApplicationProtocol.POP3: pop3_score,
    }
    best = max(scores, key=scores.__getitem__)
    if scores[best] > 0:
        return best
    return ApplicationProtocol.UNKNOWN


def identify_protocol(
    src_port: int,
    dst_port: int,
    payload_sample: bytes = b"",
) -> ApplicationProtocol:
    """
    Combined protocol identification:
    1. Port-based (fast, reliable)
    2. Payload deep inspection (fallback for non-standard ports)
    """
    proto = identify_protocol_by_port(src_port, dst_port)
    if proto != ApplicationProtocol.UNKNOWN:
        return proto
    return identify_protocol_by_payload(payload_sample)


def identify_from_tshark_packets(packets: list[dict[str, Any]]) -> ApplicationProtocol:
    """
    Identify protocol from tshark extracted packet data.
    Uses both port and tshark-detected protocol layers.
    """
    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})

        # tshark protocol detection via dissector layers
        if "smtp" in layers or layers.get("smtp.req.command") or layers.get("smtp.rsp.code") or layers.get("smtp.response.code"):
            return ApplicationProtocol.SMTP
        if "imap" in layers or layers.get("imap.request") or layers.get("imap.response"):
            return ApplicationProtocol.IMAP
        if "pop" in layers or layers.get("pop.request") or layers.get("pop.response"):
            return ApplicationProtocol.POP3

        # Port fallback
        src_port = layers.get("tcp.srcport")
        dst_port = layers.get("tcp.dstport")
        if src_port or dst_port:
            try:
                proto = identify_protocol_by_port(
                    int(src_port or 0), int(dst_port or 0)
                )
                if proto != ApplicationProtocol.UNKNOWN:
                    return proto
            except (ValueError, TypeError):
                pass

    return ApplicationProtocol.UNKNOWN
