"""
SecureMailScope — TLS Handshake Analyser
Extracts TLS version, cipher suite, key exchange, and JA3 fingerprint
from tshark-decoded packet data.
"""
from __future__ import annotations

import logging
import re
from typing import Any, Optional

from backend.models.session import (
    ForwardSecrecyStatus,
    ObservabilityStatus,
    TLSHandshake,
    TLSVersion,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# TLS Version Mapping
# ---------------------------------------------------------------------------

# Maps tshark-reported version strings / hex values to our enum
TLS_VERSION_MAP: dict[str, TLSVersion] = {
    "0x0002": TLSVersion.SSL_2_0,
    "0x0300": TLSVersion.SSL_3_0,
    "0x0301": TLSVersion.TLS_1_0,
    "0x0302": TLSVersion.TLS_1_1,
    "0x0303": TLSVersion.TLS_1_2,
    "0x0304": TLSVersion.TLS_1_3,
    # tshark string representations
    "ssl 2.0": TLSVersion.SSL_2_0,
    "ssl 3.0": TLSVersion.SSL_3_0,
    "tls 1.0": TLSVersion.TLS_1_0,
    "tls 1.1": TLSVersion.TLS_1_1,
    "tls 1.2": TLSVersion.TLS_1_2,
    "tls 1.3": TLSVersion.TLS_1_3,
    # Numeric strings from tshark JSON
    "769": TLSVersion.TLS_1_0,
    "770": TLSVersion.TLS_1_1,
    "771": TLSVersion.TLS_1_2,
    "772": TLSVersion.TLS_1_3,
    "768": TLSVersion.SSL_3_0,
}


def parse_tls_version(raw: Any) -> TLSVersion:
    if raw is None:
        return TLSVersion.UNKNOWN
    s = str(raw).strip().lower()
    v = TLS_VERSION_MAP.get(s)
    if v:
        return v
    # Try hex
    v = TLS_VERSION_MAP.get(s.replace("0x", "0x").lower())
    if v:
        return v
    return TLSVersion.UNKNOWN


# ---------------------------------------------------------------------------
# Cipher Suite Database
# ---------------------------------------------------------------------------
# Maps IANA cipher suite name / hex to key-exchange and FS status.
# This is not exhaustive but covers the most common suites.

# Cipher hex values that provide forward secrecy
FS_CIPHER_PREFIXES = (
    "TLS_ECDHE_",
    "TLS_DHE_",
    "TLS_CECPQ",
)

# Cipher hex values that are known weak/deprecated
WEAK_CIPHERS = {
    # NULL ciphers
    "TLS_NULL_WITH_NULL_NULL",
    "TLS_RSA_WITH_NULL_MD5",
    "TLS_RSA_WITH_NULL_SHA",
    "TLS_RSA_WITH_NULL_SHA256",
    # Export ciphers
    "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    "TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
    # RC4
    "TLS_RSA_WITH_RC4_128_MD5",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    # DES/3DES
    "TLS_RSA_WITH_DES_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    # Anonymous DH
    "TLS_DH_anon_WITH_RC4_128_MD5",
    "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    # MD5 MACs
    "TLS_RSA_WITH_RC4_128_MD5",
    # Weak RSA key exchange (no FS)
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA256",
}

# Cipher hex → name lookup (subset; tshark usually provides the name directly)
CIPHER_HEX_NAMES: dict[str, str] = {
    "0x0000": "TLS_NULL_WITH_NULL_NULL",
    "0x0001": "TLS_RSA_WITH_NULL_MD5",
    "0x0004": "TLS_RSA_WITH_RC4_128_MD5",
    "0x0005": "TLS_RSA_WITH_RC4_128_SHA",
    "0x000a": "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "0x002f": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "0x0035": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "0x003c": "TLS_RSA_WITH_AES_128_CBC_SHA256",
    "0x003d": "TLS_RSA_WITH_AES_256_CBC_SHA256",
    "0x009c": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "0x009d": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "0x009e": "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "0x009f": "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xc02b": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "0xc02c": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "0xc02f": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "0xc030": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "0xcca8": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "0xcca9": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "0x1301": "TLS_AES_128_GCM_SHA256",
    "0x1302": "TLS_AES_256_GCM_SHA384",
    "0x1303": "TLS_CHACHA20_POLY1305_SHA256",
}


def resolve_cipher_name(raw: Any) -> Optional[str]:
    """Resolve a cipher suite value to its IANA name."""
    if raw is None:
        return None
    s = str(raw).strip()
    # Already a name
    if s.startswith("TLS_") or s.startswith("SSL_"):
        return s
    # Try hex lookup
    hex_s = s.lower()
    if not hex_s.startswith("0x"):
        hex_s = "0x" + hex_s
    name = CIPHER_HEX_NAMES.get(hex_s)
    if name:
        return name
    return f"UNKNOWN({s})"


def is_weak_cipher(cipher_name: Optional[str]) -> bool:
    """Return True if the cipher is known to be weak/deprecated."""
    if not cipher_name:
        return False
    return cipher_name in WEAK_CIPHERS or cipher_name.startswith("UNKNOWN")


def get_key_exchange(cipher_name: Optional[str], tls_version: TLSVersion) -> Optional[str]:
    """Extract key exchange from cipher name."""
    if not cipher_name:
        return None
    if tls_version == TLSVersion.TLS_1_3:
        # TLS 1.3 always uses ephemeral key exchange; cipher name doesn't encode it
        return "ECDHE/DHE (TLS 1.3 always ephemeral)"
    if "ECDHE" in cipher_name:
        return "ECDHE"
    if "DHE" in cipher_name or "EDH" in cipher_name:
        return "DHE"
    if "RSA" in cipher_name:
        return "RSA"
    if "DH_anon" in cipher_name or "ANON" in cipher_name.upper():
        return "DH_anon"
    if "PSK" in cipher_name:
        return "PSK"
    return None


def assess_forward_secrecy(cipher_name: Optional[str], tls_version: TLSVersion) -> ForwardSecrecyStatus:
    """Determine forward secrecy status from cipher/TLS version."""
    if tls_version == TLSVersion.TLS_1_3:
        # TLS 1.3 mandates ephemeral key exchange → always FS
        return ForwardSecrecyStatus.YES
    if not cipher_name:
        return ForwardSecrecyStatus.UNKNOWN
    if any(cipher_name.startswith(p) for p in FS_CIPHER_PREFIXES):
        return ForwardSecrecyStatus.YES
    if "RSA_WITH" in cipher_name or "RSA_EXPORT" in cipher_name:
        return ForwardSecrecyStatus.NO
    return ForwardSecrecyStatus.UNKNOWN


# ---------------------------------------------------------------------------
# JA3 Fingerprinting
# ---------------------------------------------------------------------------

def compute_ja3(
    tls_version: int,
    cipher_suites: list[int],
    extensions: list[int],
    elliptic_curves: list[int],
    ec_point_formats: list[int],
) -> tuple[str, str]:
    """
    Compute JA3 fingerprint from raw TLS ClientHello fields.
    Returns (ja3_string, md5_hash).
    """
    import hashlib

    # Filter GREASE values (0xXAXA pattern)
    def no_grease(lst: list[int]) -> list[int]:
        return [x for x in lst if not (x & 0x0f == 0x0a and (x >> 8) & 0x0f == 0x0a)]

    ciphers_str = "-".join(str(c) for c in no_grease(cipher_suites))
    exts_str = "-".join(str(e) for e in no_grease(extensions))
    curves_str = "-".join(str(c) for c in no_grease(elliptic_curves))
    formats_str = "-".join(str(f) for f in ec_point_formats)

    ja3_str = f"{tls_version},{ciphers_str},{exts_str},{curves_str},{formats_str}"
    ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()  # noqa: S324
    return ja3_str, ja3_hash


# ---------------------------------------------------------------------------
# Handshake Extractor
# ---------------------------------------------------------------------------

def extract_tls_handshake(stream_packets: list[dict[str, Any]]) -> Optional[TLSHandshake]:
    """
    Extract a TLSHandshake object from a stream's packet list.
    Handles TLS 1.3 certificate observability limitation correctly.
    """
    handshake = TLSHandshake()
    has_tls = False
    client_hello_seen = False
    server_hello_seen = False

    offered_ciphers_raw: list[str] = []
    client_extensions_raw: list[str] = []
    server_extensions_raw: list[str] = []
    supported_versions: list[str] = []

    for pkt in stream_packets:
        layers = pkt.get("_source", {}).get("layers", {})
        hs_type = layers.get("tls.handshake.type")
        pkt_num_raw = layers.get("frame.number")
        pkt_num = int(pkt_num_raw) if pkt_num_raw else None

        if hs_type is None and not layers.get("tls.record.version"):
            continue

        has_tls = True
        if isinstance(hs_type, list):
            hs_types = [str(x) for x in hs_type]
        elif hs_type is not None:
            hs_types = [str(hs_type)]
        else:
            hs_types = []

        if "1" in hs_types:  # ClientHello
            client_hello_seen = True
            handshake.client_hello_pkt = pkt_num

            # Version from ClientHello legacy_version (may be 0x0303 for TLS 1.3)
            raw_ver = layers.get("tls.handshake.version")
            handshake.client_hello_version = str(raw_ver) if raw_ver else None

            # Offered ciphers
            raw_ciphers = layers.get("tls.handshake.ciphersuites")
            if raw_ciphers:
                if isinstance(raw_ciphers, list):
                    offered_ciphers_raw = [str(c) for c in raw_ciphers]
                else:
                    offered_ciphers_raw = [str(raw_ciphers)]

            # Extensions
            raw_exts = layers.get("tls.handshake.extension.type")
            if raw_exts:
                if isinstance(raw_exts, list):
                    client_extensions_raw = [str(e) for e in raw_exts]
                else:
                    client_extensions_raw = [str(raw_exts)]

            # Supported versions extension (indicates TLS 1.3 support)
            sv = layers.get("tls.handshake.extensions.supported_version")
            if sv:
                if isinstance(sv, list):
                    supported_versions = [str(v) for v in sv]
                else:
                    supported_versions = [str(sv)]

        if "2" in hs_types:  # ServerHello
            server_hello_seen = True
            handshake.server_hello_pkt = pkt_num

            raw_ver = layers.get("tls.handshake.version")
            handshake.server_hello_version = str(raw_ver) if raw_ver else None

            # Negotiated cipher
            raw_cipher = layers.get("tls.handshake.ciphersuite")
            cipher_name = resolve_cipher_name(raw_cipher)
            handshake.cipher_suite = cipher_name
            handshake.cipher_suite_hex = str(raw_cipher) if raw_cipher else None

            # Extensions
            raw_exts = layers.get("tls.handshake.extension.type")
            if raw_exts:
                if isinstance(raw_exts, list):
                    server_extensions_raw = [str(e) for e in raw_exts]
                else:
                    server_extensions_raw = [str(raw_exts)]

            # Determine negotiated TLS version:
            # For TLS 1.3, ServerHello may advertise 0x0303 but supported_versions
            # extension contains 0x0304. tshark usually resolves this.
            sv = layers.get("tls.handshake.extensions.supported_version")
            if sv:
                sv_str = str(sv) if not isinstance(sv, list) else str(sv[-1])
                handshake.tls_version = parse_tls_version(sv_str)
            else:
                handshake.tls_version = parse_tls_version(raw_ver)

        if "11" in hs_types or "20" in hs_types:  # Certificate or Finished
            handshake.handshake_complete = True

        # JA3 from tshark if available
        ja3_hash = layers.get("tls.handshake.ja3")
        ja3_str = layers.get("tls.handshake.ja3_full")
        if ja3_hash:
            handshake.ja3_hash = str(ja3_hash)
        if ja3_str:
            handshake.ja3_string = str(ja3_str)

    if not has_tls:
        return None

    # Resolve offered ciphers to names
    handshake.client_offered_ciphers = [
        resolve_cipher_name(c) or c for c in offered_ciphers_raw
    ]
    handshake.client_tls_extensions = client_extensions_raw
    handshake.server_tls_extensions = server_extensions_raw

    # Key exchange and forward secrecy
    handshake.key_exchange = get_key_exchange(handshake.cipher_suite, handshake.tls_version)
    handshake.forward_secrecy = assess_forward_secrecy(handshake.cipher_suite, handshake.tls_version)

    # TLS 1.3 certificate observability note
    if handshake.tls_version == TLSVersion.TLS_1_3:
        handshake.cert_observability = ObservabilityStatus.NOT_OBSERVABLE
        handshake.cert_observability_note = (
            "TLS 1.3: Certificate messages are encrypted in the handshake. "
            "Without the session keys (SSLKEYLOGFILE), certificate contents "
            "cannot be extracted from this capture. This is by design — "
            "TLS 1.3 encrypts the certificate to protect server identity. "
            "TLS version and cipher suite are still observable from the unencrypted "
            "ClientHello and ServerHello messages."
        )

    return handshake
