# SecureMailScope — Architecture Documentation

## System Architecture

SecureMailScope is designed as a modular passive forensic analysis pipeline.

### Design Principles

1. **Passive only** — reads PCAP files; never connects to live services
2. **Evidence provenance** — every finding traces back to a specific packet/field
3. **No data fabrication** — only reports what is actually observable in the capture
4. **Explicit observability** — clearly labels data as OBSERVED / NOT_OBSERVABLE / PARTIALLY_OBSERVABLE
5. **Deterministic scoring** — rule engine produces predictable, reproducible findings

---

## Module Map

```
backend/
├── models/session.py          ← Core data types (Pydantic)
│
├── pcap/
│   ├── extractor.py           ← tshark wrapper, stream extraction
│   └── pipeline.py            ← Main orchestration pipeline
│
├── protocols/
│   ├── identifier.py          ← SMTP/IMAP/POP3 identification (port + payload)
│   └── starttls.py            ← Explicit STARTTLS state machines
│
├── tls/
│   └── analyser.py            ← TLS handshake, JA3, cipher DB, forward secrecy
│
├── certificates/
│   └── analyser.py            ← X.509 parsing, risk assessment
│
├── posture/
│   ├── engine.py              ← Deterministic rule engine
│   └── scoring.py             ← Risk scoring, finding prioritization
│
├── anomaly/
│   └── detector.py            ← Isolation Forest ML anomaly detector
│
├── reporting/
│   └── generator.py           ← JSON/HTML/PDF report generation
│
└── api/
    └── main.py                ← FastAPI REST API
```

---

## Data Flow

```
1. PCAP File
      │
      ▼ pcap/extractor.py
2. tshark JSON output → TCP stream groups {stream_id: [packets]}
      │
      ▼ pcap/pipeline.py → _build_session()
3. TCPSession objects
      │
      ├──▶ protocols/identifier.py → ApplicationProtocol (SMTP/IMAP/POP3)
      │
      ├──▶ protocols/starttls.py → STARTTLSState + events
      │
      └──▶ tls/analyser.py → TLSHandshake
                │
                └──▶ certificates/analyser.py → [CertificateInfo]
      │
      ▼ posture/engine.py
4. Findings (deterministic rule evaluation)
      │
      ▼ anomaly/detector.py
5. ML anomaly scores + anomaly findings
      │
      ▼ posture/scoring.py
6. RiskScore + prioritized findings + recommendations
      │
      ▼ reporting/generator.py
7. JSON / HTML / PDF reports
```

---

## TLS 1.3 Observability

| Data | TLS ≤ 1.2 | TLS 1.3 |
|------|-----------|---------|
| TLS Version | ✅ Observable | ✅ Observable |
| Cipher Suite | ✅ Observable | ✅ Observable (from ServerHello) |
| Key Exchange | ✅ Observable | ✅ Always ephemeral |
| Forward Secrecy | ✅ Observable | ✅ Always YES |
| Server Certificate | ✅ Observable | ❌ Encrypted (RFC 8446 §4.4.2) |
| Certificate validity | ✅ If cert observable | ❌ Not extractable |
| SNI | ✅ Observable | ✅ Observable (unless ECH) |

---

## STARTTLS State Machine

```
                  ┌─────────────────────────────┐
                  │         SMTP Example         │
                  └─────────────────────────────┘

TCP Connect ──▶ INIT
                  │
             220 banner
                  │
               BANNER
                  │
             EHLO/HELO
                  │
             EHLO_RESP
                  ├──── 250-STARTTLS ────▶ STARTTLS_CAPABLE ──┐
                  │                                             │
                  │                                    STARTTLS cmd
                  │                                             │
                  │                                    STARTTLS_SENT
                  │                                             │
                  │                             220 ready ──▶ STARTTLS_OK
                  │                             4xx/5xx ──▶ PLAINTEXT_CONTINUE ⚠
                  │
                  │ (no 250-STARTTLS or direct commands)
                  │
                  ▼
             [PLAINTEXT_CONTINUE] ⚠ or NO_TLS
```

Suspicious conditions detected:
- STARTTLS advertised → client sends cleartext AUTH/MAIL without STARTTLS
- STARTTLS requested → server returns 4xx/5xx → client continues plaintext
- Session ends without TLS after STARTTLS advertisement

---

## Risk Scoring Methodology

The **SecureMailScope Composite Risk Score** (not a regulatory score):

```
Base Score: 100

Deductions:
  Critical finding:   -25 each
  High finding:       -15 each
  Medium finding:     -7 each
  Low finding:        -2 each
  ML anomaly:         -5 each

Positive adjustments:
  TLS 1.3 session:    +3 each
  Forward Secrecy:    +2 each

Final score: clamped to [0, 100]

Risk levels:
  [85-100]: MINIMAL
  [70-84]:  LOW
  [50-69]:  MEDIUM
  [30-49]:  HIGH
  [0-29]:   CRITICAL
```

---

## ML Anomaly Detection

### Algorithm: Isolation Forest

- **Input**: 16-dimensional feature vector from TLS/session metadata
- **No payload content used**
- **Training**: Synthetic benign session data (deterministic, reproducible)
- **Output**: Anomaly score [0.0, 1.0] + binary classification

### Feature Vector

| Feature | Description |
|---------|-------------|
| tls_version_num | Numeric TLS version |
| cipher_strength_cat | 1=null/export, 2=weak, 3=medium, 4=strong |
| key_exchange_cat | 1=RSA, 2=DHE, 3=ECDHE, 4=anon |
| forward_secrecy | 0/1 |
| cert_observable | 0/1 |
| cert_expired | 0/1 |
| cert_self_signed | 0/1 |
| cert_key_bits_norm | key_bits / 4096 |
| sig_alg_weak | 0/1 |
| starttls_state_cat | 0=none to 4=suspicious |
| cleartext_auth | 0/1 |
| protocol_cat | 1=SMTP, 2=IMAP, 3=POP3 |
| offered_cipher_count | normalized 0-1 |
| extension_count | normalized 0-1 |
| session_duration_norm | duration/300 |
| packet_count_norm | count/100 |

### Important Distinction

```
Deterministic Finding              ML Behavioural Anomaly
─────────────────────              ──────────────────────
Based on known-bad patterns        Based on statistical deviation
Evidence: specific packet/field    Evidence: feature vector
Deterministic/reproducible         Probabilistic
High confidence                    Lower confidence
Example: "TLS 1.0 negotiated"      Example: "Unusual cipher preference"
```
