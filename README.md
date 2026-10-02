# SecureMailScope

**AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications**

> SIH 2026 · Problem Statement 26159 · Passive Network Forensic Framework

---

## Overview

SecureMailScope is a passive network forensic framework that analyses captured network traffic (PCAP files) containing SMTP, IMAP, and POP3 email protocols. It extracts TLS handshake data, analyses cryptographic configurations, detects weak or deprecated settings, and uses an ML anomaly detector to flag unusual TLS sessions.

**This is a working proof-of-concept, not a production tool.**

---

## Architecture

```
PCAP Input (.pcap / .pcapng)
        │
        ▼
Packet/Stream Extraction Layer (tshark)
        │
    ┌───┴───────────────────────┐
    ▼           ▼               ▼
SMTP/IMAP/  TCP Session     TLS Handshake
POP3 ID     Reconstruction  Analysis
    │           │               │
    └───────────┴───────────────┘
                │
        Cryptographic Posture Engine
                │
    ┌───────────┴───────────────┐
    ▼           ▼               ▼
Rule Findings  ML Anomaly   Certificate
/ Weak Crypto  Detection     Analysis
    │           │               │
    └───────────┴───────────────┘
                │
        Risk Aggregation + Prioritization
                │
        Dashboard / Reports (JSON HTML PDF)
```

## Feature Status

| Feature | Status |
|---|---|
| PCAP upload & analysis | ✅ Implemented |
| SMTP/IMAP/POP3 identification | ✅ Implemented |
| TCP session reconstruction | ✅ Implemented (via tshark) |
| STARTTLS state machine | ✅ Implemented |
| TLS version extraction | ✅ Implemented |
| Cipher suite analysis | ✅ Implemented |
| Forward Secrecy assessment | ✅ Implemented |
| TLS 1.3 cert limitation handling | ✅ Implemented (correctly) |
| X.509 certificate extraction | ✅ Implemented (TLS ≤ 1.2) |
| Certificate risk analysis | ✅ Implemented |
| Deterministic rule engine | ✅ Implemented |
| ML anomaly detection (Isolation Forest) | ✅ Implemented |
| Risk scoring | ✅ Implemented |
| JSON reports | ✅ Implemented |
| HTML reports | ✅ Implemented |
| PDF reports | ✅ Implemented |
| Dashboard (React) | ✅ Implemented |
| Demo PCAPs + generation scripts | ✅ Implemented |
| Benchmark suite | ✅ Implemented |
| Offline demo mode | ✅ Implemented |
| Chain certificate validation | 🚧 Planned |
| JA3S fingerprinting | 🚧 Planned |
| PCAP streaming (large files) | 🚧 Planned |

---

## Prerequisites

- NixOS with flakes enabled
- `direnv` installed and allowed (`direnv allow`)

---

## Setup

```bash
# Clone / enter directory
cd /path/to/Prototype

# Enter Nix dev environment (direnv does this automatically)
nix develop
# OR
direnv allow

# Verify environment
just check
```

---

## Running

### Backend API

```bash
just backend
# API available at http://localhost:8000
# Docs at http://localhost:8000/docs
```

### Frontend Dashboard

```bash
just frontend-install   # First time only
just frontend
# Dashboard at http://localhost:5173
```

---

## Generating Test PCAPs

```bash
just gen-pcaps
```

This creates synthetic PCAPs in `demo_pcaps/`:

| PCAP | Scenario | Expected Findings |
|---|---|---|
| `01_secure_tls12.pcap` | Secure TLS 1.2 SMTP | None |
| `02_legacy_tls10.pcap` | Deprecated TLS 1.0 | deprecated_tls |
| `03_weak_cipher.pcap` | RSA key exchange (no FS) | weak_cipher, no_forward_secrecy |
| `04_expired_cert.pcap` | Expired certificate | expired_certificate |
| `05_starttls_fallback.pcap` | STARTTLS rejected → cleartext | starttls_anomaly |
| `06_anomalous_handshake.pcap` | Weak 1024-bit key | weak_key |
| `07_plaintext_smtp.pcap` | No TLS at all | configuration (no_tls) |

---

## Running the Demo

```bash
just demo
```

Analyses all demo PCAPs offline, shows results, and generates a PDF report.

---

## Benchmark

```bash
just benchmark
```

Produces precision/recall/F1 metrics for both rule engine and ML anomaly detection.

---

## Tests

```bash
just test
```

---

## Analysing a Custom PCAP

```bash
just analyse my_capture.pcap
```

Or use the API:

```bash
curl -X POST http://localhost:8000/api/analysis/upload \
  -F "file=@my_capture.pcap"
```

---

## TLS 1.3 Certificate Limitation

> **Important technical note**

In TLS 1.3 (RFC 8446), the Certificate message is encrypted during the handshake. A passive observer cannot extract server X.509 certificates from TLS 1.3 traffic without the session master secrets (SSLKEYLOGFILE).

SecureMailScope **correctly handles this limitation**:
- It detects and reports the TLS 1.3 session
- It reports TLS version and cipher suite (observable from ClientHello/ServerHello)
- It explicitly states that certificate information is not available
- It does NOT fabricate certificate data

This is a feature demonstrating technical correctness, not a bug.

---

## Scoring Disclaimer

The **SecureMailScope Composite Risk Score** is a prototype scoring methodology developed for SIH 2026.

It is **NOT** an official NIST, BIS, NTRO, or any regulatory score.

Do not use for compliance or regulatory purposes.

---

## Known Limitations

1. **TLS 1.3 certificates**: Not observable from passive capture (see above)
2. **Chain validation**: Only certificates present in the capture can be validated
3. **Passive only**: No active scanning or connection to mail servers
4. **TLS session keys**: Cannot decrypt TLS application data without keys
5. **Large PCAPs**: Processing is sequential; streaming support planned

---

## Security Assumptions

- Traffic is analysed passively from PCAPs; no active network connections are made
- Certificate analysis is limited to what is observable in the capture
- No claim of attack proof is made — suspicious sequences are labeled as such
- All findings include evidence provenance (PCAP, session, packet number, observed value)

---

## Directory Structure

```
.
├── flake.nix              — Nix development environment
├── pyproject.toml         — Python project config
├── justfile               — Task runner
├── backend/
│   ├── api/main.py        — FastAPI backend
│   ├── pcap/              — PCAP ingestion + pipeline
│   ├── protocols/         — SMTP/IMAP/POP3 + STARTTLS state machine
│   ├── tls/               — TLS handshake analyser
│   ├── certificates/      — X.509 certificate analyser
│   ├── posture/           — Rule engine + risk scoring
│   ├── anomaly/           — ML anomaly detection
│   ├── reporting/         — JSON/HTML/PDF report generation
│   └── models/            — Pydantic data models
├── frontend/              — React dashboard (Vite)
├── demo_pcaps/            — Synthetic test PCAPs
├── benchmark/             — Evaluation suite
├── scripts/               — PCAP generation + demo
├── tests/                 — Unit + integration tests
├── docs/                  — Architecture + protocol docs
└── evidence/              — SIH PPT evidence
```
