"""
SecureMailScope — PCAP Ingestion Layer
Wraps tshark for reliable protocol/TLS dissection, with dpkt fallback.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# PCAP File Utilities
# ---------------------------------------------------------------------------

def compute_sha256(path: str) -> str:
    """Compute SHA-256 of a file in a streaming fashion."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def find_tshark() -> Optional[str]:
    """Locate tshark binary."""
    for candidate in ["tshark", "/run/current-system/sw/bin/tshark"]:
        result = subprocess.run(
            ["which", candidate], capture_output=True, text=True
        )
        if result.returncode == 0:
            return result.stdout.strip()
    # Try absolute common NixOS locations
    for path in ["/run/current-system/sw/bin/tshark", "/usr/bin/tshark"]:
        if os.path.exists(path):
            return path
    return None


TSHARK_BIN = find_tshark()


# ---------------------------------------------------------------------------
# TShark Extraction
# ---------------------------------------------------------------------------

# Fields we extract from tshark. Keep this list stable; adding fields here
# automatically propagates to the raw packet records.
TSHARK_FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "tcp.len",
    "tcp.flags",
    "tls.record.version",
    "tls.handshake.type",
    "tls.handshake.version",
    "tls.handshake.ciphersuite",
    "tls.handshake.ciphersuites",
    "tls.handshake.extensions_server_name",
    "tls.handshake.extensions.supported_version",
    "tls.handshake.extension.type",
    "tls.handshake.extensions_ec_point_format",
    "tls.handshake.extensions_supported_groups",
    "tls.handshake.ja3",
    "tls.handshake.ja3_full",
    # Certificate fields — only available for TLS < 1.3 (or if SSLKEYLOGFILE provided)
    "tls.handshake.certificates_length",
    "x509af.subjectPublicKeyInfo_element",
    "x509ce.dNSName",
    "x509sat.uTF8String",
    # SMTP
    "smtp.req.command",
    "smtp.response.code",
    "smtp.rsp.parameter",
    "smtp.req.parameter",
    # IMAP
    "imap.request",
    "imap.response",
    # POP3
    "pop.request",
    "pop.response",
]


def run_tshark(
    pcap_path: str,
    extra_filters: str = "",
    fields: Optional[list[str]] = None,
) -> list[dict[str, Any]]:
    """
    Run tshark on a PCAP, returning a list of packet records as dicts.
    Uses JSON output (-T json) for reliable parsing.
    """
    if TSHARK_BIN is None:
        raise RuntimeError(
            "tshark not found. Ensure wireshark-cli is available in the Nix devshell."
        )

    if fields is None:
        fields = TSHARK_FIELDS

    cmd = [
        TSHARK_BIN,
        "-r", pcap_path,
        "-T", "json",
        "--no-duplicate-keys",
    ]
    for f in fields:
        cmd += ["-e", f]
    if extra_filters:
        cmd += ["-Y", extra_filters]

    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

    if result.returncode not in (0, 1):  # tshark returns 1 on some warnings
        logger.error("tshark stderr: %s", result.stderr[:2000])
        raise RuntimeError(f"tshark failed (rc={result.returncode}): {result.stderr[:500]}")

    raw = result.stdout.strip()
    if not raw or raw == "[]":
        return []

    try:
        packets = json.loads(raw)
    except json.JSONDecodeError as exc:
        logger.warning("tshark JSON parse error: %s — attempting recovery", exc)
        # tshark sometimes emits partial JSON; try to recover
        try:
            packets = json.loads(raw.rsplit(",", 1)[0] + "]")
        except Exception:
            return []

    # Normalize layers: flatten 1-element lists produced by tshark -e
    for p in packets:
        layers = p.get("_source", {}).get("layers", {})
        norm = {}
        for k, v in layers.items():
            if isinstance(v, list) and len(v) == 1:
                norm[k] = v[0]
            else:
                norm[k] = v
        if "smtp.response.code" in norm and "smtp.rsp.code" not in norm:
            norm["smtp.rsp.code"] = norm["smtp.response.code"]
        p.setdefault("_source", {})["layers"] = norm

    return packets


def extract_field(pkt: dict, *keys: str, default: Any = None) -> Any:
    """Navigate nested tshark JSON to extract a field value."""
    layers = pkt.get("_source", {}).get("layers", {})

    def _search(d: Any, target: str) -> Any:
        if isinstance(d, dict):
            if target in d:
                return d[target]
            for v in d.values():
                res = _search(v, target)
                if res is not None:
                    return res
        return None

    for key in keys:
        val = _search(layers, key)
        if val is not None:
            return val
    return default


def extract_field_list(pkt: dict, key: str) -> list[str]:
    """Extract a field that may be a string or list, searching nested layers."""
    val = extract_field(pkt, key)
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v) for v in val]
    return [str(val)]


# ---------------------------------------------------------------------------
# Stream-Level PCAP Grouping (via tshark tcp.stream)
# ---------------------------------------------------------------------------

def get_tcp_streams(pcap_path: str) -> dict[str, list[dict]]:
    """
    Extract all packets grouped by TCP stream index.
    Returns {stream_id: [packet, ...]} dict.
    """
    packets = run_tshark(pcap_path)
    streams: dict[str, list[dict]] = {}

    for pkt in packets:
        stream_id = extract_field(pkt, "tcp.stream")
        if stream_id is None:
            continue
        stream_id = str(stream_id)
        if stream_id not in streams:
            streams[stream_id] = []
        streams[stream_id].append(pkt)

    logger.info("Found %d TCP streams in %s", len(streams), pcap_path)
    return streams


# ---------------------------------------------------------------------------
# Certificate DER extraction
# ---------------------------------------------------------------------------

def extract_certificates_from_pcap(pcap_path: str) -> dict[str, bytes]:
    """
    Use tshark to extract raw certificate DER bytes from the PCAP.
    Returns {stream_id: [der_bytes, ...]} for streams containing certificates.

    This works for TLS ≤ 1.2 where the Certificate message is plaintext.
    For TLS 1.3, tshark cannot extract certs without keys; we handle this
    gracefully by returning an empty result for those streams.
    """
    if TSHARK_BIN is None:
        return {}

    with tempfile.TemporaryDirectory() as tmpdir:
        cmd = [
            TSHARK_BIN,
            "-r", pcap_path,
            "--export-objects", f"x509af,{tmpdir}",
            "-q",
        ]
        try:
            subprocess.run(cmd, capture_output=True, timeout=60)
        except Exception as exc:
            logger.warning("Certificate export failed: %s", exc)

        certs: dict[str, bytes] = {}
        for fname in os.listdir(tmpdir):
            fpath = os.path.join(tmpdir, fname)
            with open(fpath, "rb") as f:
                certs[fname] = f.read()
        return certs


# ---------------------------------------------------------------------------
# PCAP metadata
# ---------------------------------------------------------------------------

def get_pcap_metadata(pcap_path: str) -> dict[str, Any]:
    """Extract high-level capture metadata using tshark capinfos."""
    capinfos_bin = TSHARK_BIN.replace("tshark", "capinfos") if TSHARK_BIN else None

    meta: dict[str, Any] = {
        "pcap_path": pcap_path,
        "pcap_filename": os.path.basename(pcap_path),
        "sha256_hash": compute_sha256(pcap_path),
        "file_size_bytes": os.path.getsize(pcap_path),
    }

    if capinfos_bin and os.path.exists(capinfos_bin):
        result = subprocess.run(
            [capinfos_bin, "-M", pcap_path],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k = k.strip().lower().replace(" ", "_")
                v = v.strip()
                meta[k] = v

    # Fallback: use tshark to count packets and get time range
    packets = run_tshark(pcap_path)
    if packets:
        times = []
        for pkt in packets:
            t = extract_field(pkt, "frame.time_epoch")
            if t:
                try:
                    times.append(float(t))
                except (ValueError, TypeError):
                    pass
        if times:
            meta["first_packet_time"] = min(times)
            meta["last_packet_time"] = max(times)
            meta["capture_duration_seconds"] = max(times) - min(times)
        meta["packet_count"] = len(packets)

    return meta
