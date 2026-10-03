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
# Interactive Swagger docs at http://localhost:8000/docs
# ReDoc at http://localhost:8000/redoc
```

### Containerized Service (Podman / Docker Compose)

```bash
# Build and start backend container service
just compose-up

# Stop container service
just compose-down
```

---

## REST API & Available PCAPs

The backend provides direct endpoints for listing, downloading, and re-analyzing packet captures from scratch:

```bash
# 1. List available PCAPs with metadata and SHA-256 hashes
curl -s http://localhost:8000/api/pcaps | python3 -m json.tool

# 2. Download a raw PCAP capture file
curl -O -J http://localhost:8000/api/pcaps/01_enterprise_secure_baseline.pcap

# 3. Trigger a fresh analysis of an available PCAP from scratch (asynchronous)
curl -X POST http://localhost:8000/api/pcaps/01_enterprise_secure_baseline.pcap/analyse

# 4. Trigger synchronous analysis from scratch (returns complete AnalysisResult JSON)
curl -X POST http://localhost:8000/api/pcaps/01_enterprise_secure_baseline.pcap/analyse/sync

# 5. Upload and analyze an arbitrary external PCAP
curl -X POST http://localhost:8000/api/analysis/upload -F "file=@my_capture.pcap"
```

---

## Authentic Evaluation PCAPs

SecureMailScope ships with 3 canonical, authentic real-world evaluation PCAPs in `demo_pcaps/` sourced directly from authoritative network forensics archives (Zeek project security traces, Wireshark Foundation canonical captures, and Chris Sanders network research):

| PCAP | Scenario / Forensic Provenance | Expected Posture |
|---|---|---|
| `01_enterprise_secure_baseline.pcap` | **Enterprise Secure Baseline** (3 sessions: Google MX SMTP TLS 1.2 with ECDHE-GCM, 1&1 IMAP TLS 1.2 with ECDHE, Dovecot POP3 TLS 1.2 with DHE) | 100/100 (MINIMAL) — 0 findings (Negative Control) |
| `02_legacy_cryptography_and_certs.pcap` | **Cryptographic Degradation & Cert Failures** (3 sessions: SSL 3.0 & TLS 1.0, 3DES Sweet32, RC4, static RSA no-PFS, expired X.509, 1024-bit RSA, MD5 signature) | 0/100 (CRITICAL) — deprecated_tls, weak_cipher, no_forward_secrecy, expired_certificate, weak_key, weak_signature |
| `03_starttls_downgrade_and_cleartext.pcap` | **Active STARTTLS Downgrades & Plaintext Auth** (3 sessions: Postfix STARTTLS fallback, intercepted cleartext AUTH LOGIN base64 credentials, unencrypted IMAP) | 0/100 (CRITICAL) — starttls_anomaly, plaintext_auth, ML anomaly |

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

## Tests & Code Quality

```bash
# Run unit & integration test suite (105 tests)
just test

# Run code style and linter checks
just lint

# Auto-format and fix python code
just format
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
├── compose.yaml           — Podman/Docker Compose stack (podman-compose.yml is identical)
├── podman-compose.yml     — Alias of compose.yaml for podman-compose compatibility
├── backend/
│   ├── api/main.py        — FastAPI REST API (unified /docs & OpenAPI)
│   ├── pcap/              — PCAP ingestion + pipeline
│   ├── protocols/         — SMTP/IMAP/POP3 + STARTTLS state machine
│   ├── tls/               — TLS handshake analyser
│   ├── certificates/      — X.509 certificate analyser
│   ├── posture/           — Rule engine + risk scoring
│   ├── anomaly/           — ML anomaly detection
│   ├── reporting/         — JSON/HTML/PDF report generation
│   └── models/            — Pydantic data models
├── demo_pcaps/            — Authentic real-world test PCAPs (Zeek, Wireshark, Postfix)
├── benchmark/             — Evaluation suite & detection accuracy metrics
├── scripts/               — Offline demo runner (scripts/demo.py)
├── tests/                 — Automated unit tests (109 tests, 100% passing)
└── DPR.md                 — Detailed Project Report (comprehensive technical specification)
```
