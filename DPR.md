# Detailed Project Report (DPR): SecureMailScope
## AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications

> **Document Type:** Detailed Project Report (DPR)  
> **Target Problem Statement:** Smart India Hackathon (SIH 2026) — Problem Statement 26159 (PS 26159)  
> **System Classification:** Passive Network Forensic & Cryptographic Security Posture Framework  
> **Source Code Baseline:** Clean working tree (Audit Date: October 2026)  
> **Authors:** SecureMailScope Engineering Team  

---

## 1. Executive Summary & Problem Formulation

### 1.1 Problem Statement Context
Email protocols remain the backbone of organizational communication, inter-agency information exchange, and critical infrastructure coordination. However, the fundamental protocols underpinning electronic mail—**Simple Mail Transfer Protocol (SMTP, RFC 5321)**, **Internet Message Access Protocol (IMAP, RFC 3501)**, and **Post Office Protocol version 3 (POP3, RFC 1939)**—were originally designed with cleartext transmissions. 

To retrofit encryption onto legacy cleartext channels, the Internet Engineering Task Force (IETF) introduced the opportunistic **STARTTLS** mechanism (RFC 3207 for SMTP, RFC 2595 for IMAP/POP3), alongside direct implicit TLS transport (RFC 8314). While opportunistic encryption substantially improved privacy, it introduced grave security vulnerabilities:
1. **STARTTLS Downgrade / Stripping Attacks:** Active network adversaries can tamper with cleartext server capability advertisements (e.g., stripping `250-STARTTLS` from an `EHLO` response), forcing email clients and transfer agents to fail open and transmit authentication credentials and sensitive communications in plaintext.
2. **Cryptographic Degradation & Legacy Protocols:** Mail transfer agents (MTAs) and mail user agents (MUAs) frequently maintain backward compatibility with legacy, broken protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1), broken ciphers (RC4, 3DES, EXPORT, NULL), and key exchanges lacking Forward Secrecy.
3. **Improper Certificate Hygiene:** Expired, self-signed, weakly keyed (<2048-bit RSA), or weakly signed (MD5, SHA-1) certificates often go unnoticed in passive network traffic.
4. **Behavioral Protocol Anomalies:** Subtly malicious or anomalous TLS configurations that do not directly violate static rules but deviate statistically from secure baseline distributions.

### 1.2 System Mission & Core Philosophy
**SecureMailScope** is an AI-assisted passive network forensic framework designed to ingest raw Packet Capture (`.pcap` / `.pcapng`) files, reconstruct bidirectional TCP email sessions, parse multi-stage STARTTLS negotiation state machines, dissect TLS handshakes, validate X.509 certificate hygiene, evaluate cryptographic posture against a deterministic rule engine, and score statistical behavioral outliers using an unsupervised Machine Learning (Isolation Forest) model.

The system is architected around five non-negotiable principles:
- **Zero Payload Retention (Privacy by Design):** Forensic extraction is strictly limited to network headers, protocol command verbs (e.g., `EHLO`, `STARTTLS`, `AUTH`), and TLS handshake metadata. Email bodies, message text, and user data are never inspected, extracted, or persisted.
- **Dual-Engine Detection (Deterministic + Probabilistic):** Deterministic rules handle known CVEs, protocol standards, and cipher suites with 100% precision. The Machine Learning engine models multidimensional feature space to flag subtle, anomalous handshakes that evade static heuristics.
- **Traceable Evidence Provenance:** Every security finding is directly linked to specific packet frame numbers, TCP stream identifiers, and observed protocol field values.
- **Respect for Cryptographic Boundaries (TLS 1.3 Handling):** In strict adherence to RFC 8446, SecureMailScope correctly identifies that TLS 1.3 encrypts handshake certificates and explicitly documents this observability boundary rather than hallucinating or erroring.
- **Zero-Dependency Reproducibility:** Operates entirely offline without external mail servers or network access, backed by reproducible Nix flakes, Scapy synthetic packet synthesis, and rootless Podman Compose containerization.

---

## 2. Technical Architecture & End-to-End Processing Pipeline

The following diagram illustrates the data flow and component hierarchy implemented in the codebase:

```mermaid
flowchart TD
    subgraph INGESTION ["1. Ingestion Layer"]
        PCAP["Raw PCAP / PCAPNG Input"] --> METADATA["Capinfos & SHA-256 Checksum"]
        PCAP --> TSHARK["TShark JSON Dissection Engine (-T json)"]
    end

    subgraph RECONSTRUCTION ["2. Session Reconstruction Layer"]
        TSHARK --> STREAMS["TCP Stream Indexing (tcp.stream)"]
        STREAMS --> IDENT["Protocol Identifier (SMTP, IMAP, POP3)"]
        STREAMS --> SESSIONS["TCPSession Builder (5-tuple, timestamps)"]
    end

    subgraph PROTOCOL_ANALYSIS ["3. Protocol & TLS Dissection"]
        SESSIONS --> STARTTLS_FSM["STARTTLS State Machine (SMTP, IMAP, POP3 FSM)"]
        SESSIONS --> TLS_DISSECTOR["TLS Handshake Dissector (Version, Ciphers, FS, JA3)"]
        SESSIONS --> CERT_EXTRACT["X.509 DER Certificate Extraction (x509af)"]
    end

    subgraph DETECTION_ENGINE ["4. Dual Posture & Anomaly Engine"]
        TLS_DISSECTOR --> RULE_ENGINE["Deterministic Posture Rule Engine"]
        STARTTLS_FSM --> RULE_ENGINE
        CERT_EXTRACT --> CERT_RULES["Certificate Hygiene & Risk Rules"]
        CERT_RULES --> RULE_ENGINE
        
        SESSIONS --> FEATURE_EXTRACT["16-Dimensional Numerical Feature Extractor"]
        FEATURE_EXTRACT --> ML_ENGINE["Isolation Forest Anomaly Detector"]
    end

    subgraph SCORING_REPORTING ["5. Aggregation & Output Layer"]
        RULE_ENGINE --> SCORING["Risk Scoring Engine (100.0 Baseline, Clamped)"]
        ML_ENGINE --> SCORING
        SCORING --> PRIORITIZER["Finding Prioritizer & Deduplication"]
        PRIORITIZER --> JSON_REP["JSON Forensic Report"]
        PRIORITIZER --> HTML_REP["Standalone HTML Dashboard"]
        PRIORITIZER --> PDF_REP["ReportLab Forensic PDF Report"]
        PRIORITIZER --> API["FastAPI REST Endpoints (Port 8000)"]
        API --> UI["React 18 / Vite / Caddy Web UI (Port 5173)"]
    end
```

### 2.1 Complete Execution Flow (`backend/pcap/pipeline.py`)
When a PCAP is supplied to `analyse_pcap(pcap_path, analysis_id)`:
1. **Metadata Hashing:** Computes SHA-256 file digest, file size, duration, and frame count.
2. **Stream Grouping:** Groups raw dissected packet frames by `tcp.stream`.
3. **Session Instantiation:** Constructs `TCPSession` instances representing distinct network conversations identified by their 5-tuple (`src_ip`, `src_port`, `dst_ip`, `dst_port`, `ip.proto`).
4. **Application Protocol Identification:** Evaluates well-known ports and signature command banners (`EHLO`, `220`, `* OK`, `+OK`).
5. **Protocol State Machine Execution:** Tracks negotiation state transitions and identifies downgrade/stripping attempts.
6. **TLS Handshake Parsing:** Extracts offered/selected cipher suites, version identifiers, extensions, and JA3 hashes.
7. **Certificate Forensic Export:** Automatically extracts X.509 DER certificates via TShark `x509af` object export and parses cryptographic parameters.
8. **Rule Engine Evaluation:** Evaluates deterministic policy rules across TLS version, cipher suite, key exchange, certificate validity, and STARTTLS state.
9. **ML Behavioral Inference:** Projects session parameters into a 16-dimensional standardized vector and queries the trained `IsolationForest` model.
10. **Risk Score Computation:** Applies cumulative point deductions and positive control bonuses to compute composite posture score.
11. **Report Generation:** Compiles structured evidence, prioritized findings, remediation recommendations, and forensic limitations.

---

## 3. Core Data Models (`backend/models/session.py`)

All data structures flowing across SecureMailScope are strictly typed using Pydantic `BaseModel` classes:

```python
# Protocol Identifiers
class ApplicationProtocol(str, enum.Enum):
    SMTP = "SMTP"
    IMAP = "IMAP"
    POP3 = "POP3"
    UNKNOWN = "UNKNOWN"


# STARTTLS State Machine Representation
class STARTTLSState(str, enum.Enum):
    NO_TLS = "no_tls"  # Cleartext only
    NONE = "no_tls"  # Backward-compatible alias
    ADVERTISED = "advertised"  # Server offered STARTTLS capability
    REQUESTED = "requested"  # Client sent STARTTLS command
    NEGOTIATED = "negotiated"  # TLS handshake completed successfully
    FAILED = "failed"  # Explicit failure
    SUSPICIOUS_FALLBACK = "suspicious_fallback"  # Traffic returned to cleartext after advert
    DIRECT_TLS = "direct_tls"  # Implicit TLS (ports 465, 993, 995)


# Finding Severity Hierarchy
class FindingSeverity(str, enum.Enum):
    CRITICAL = "critical"  # -25 risk deduction
    HIGH = "high"  # -15 risk deduction
    MEDIUM = "medium"  # -7 risk deduction
    LOW = "low"  # -2 risk deduction
    INFO = "info"  # 0 risk deduction


# Finding Categories
class FindingCategory(str, enum.Enum):
    DEPRECATED_TLS = "deprecated_tls"
    WEAK_CIPHER = "weak_cipher"
    WEAK_KEY = "weak_key"
    WEAK_SIGNATURE = "weak_signature"
    EXPIRED_CERTIFICATE = "expired_certificate"
    INVALID_CERTIFICATE = "invalid_certificate"
    NO_FORWARD_SECRECY = "no_forward_secrecy"
    STARTTLS_ANOMALY = "starttls_anomaly"
    PLAINTEXT_AUTH = "plaintext_auth"
    ML_ANOMALY = "ml_anomaly"
    CONFIGURATION = "configuration"
    INFO = "info"
```

### Traceable Evidence Structure
Every finding emitted by the engine carries forensic provenance:
```python
class Evidence(BaseModel):
    pcap_file: str = ""
    session_id: str
    packet_numbers: list[int] = Field(default_factory=list)
    field: Optional[str] = None
    observed_value: Optional[Any] = None
    extra: dict[str, Any] = Field(default_factory=dict)


class Finding(BaseModel):
    id: str
    severity: FindingSeverity
    category: FindingCategory
    title: str
    description: str
    evidence: Evidence
    recommendation: str
    cve_references: list[str] = Field(default_factory=list)
    is_ml_finding: bool = False
```

---

## 4. Deep-Dive: PCAP Ingestion & Forensic Extraction Layer

### 4.1 TShark Extraction Engine (`backend/pcap/extractor.py`)
SecureMailScope utilizes Wireshark's CLI tool `tshark` running in structured JSON mode (`-T json --no-duplicate-keys`). 

To maintain high throughput and minimize memory usage, the extractor requests only specific protocol fields via `-e <field>`. The complete 33-field specification is:
- **Frame & Network:** `frame.number`, `frame.time_epoch`, `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `tcp.stream`, `tcp.len`, `tcp.flags`
- **TLS Handshake:** `tls.record.version`, `tls.handshake.type`, `tls.handshake.version`, `tls.handshake.ciphersuite`, `tls.handshake.ciphersuites`, `tls.handshake.extensions_server_name`, `tls.handshake.extensions.supported_version`, `tls.handshake.extension.type`, `tls.handshake.extensions_ec_point_format`, `tls.handshake.extensions_supported_groups`, `tls.handshake.ja3`, `tls.handshake.ja3_full`, `tls.handshake.certificates_length`
- **X.509 ASN.1 Dissectors:** `x509af.subjectPublicKeyInfo_element`, `x509ce.dNSName`, `x509sat.uTF8String`
- **SMTP Application Dissectors:** `smtp.req.command`, `smtp.response.code`, `smtp.rsp.parameter`, `smtp.req.parameter`
- **IMAP / POP3 Dissectors:** `imap.request`, `imap.response`, `pop.request`, `pop.response`

#### Normalization & Field Resolution
- **List Flattening:** When TShark exports single-value fields under `-e`, it wraps them in 1-element arrays. The extractor normalizes single-element arrays to scalar strings.
- **Compatibility Aliasing:** TShark 4.6.9 provides `smtp.response.code` while older Wireshark dissectors output `smtp.rsp.code`. The extractor normalizes `smtp.response.code` and mirrors it to `smtp.rsp.code`.
- **Hierarchical Search:** `extract_field(pkt, *keys)` traverses nested dissector trees safely, shielding the pipeline from variation in Wireshark layer depth.

### 4.2 Certificate Object Extraction
In TLS 1.0, 1.1, and 1.2, certificate exchanges occur in plaintext before symmetric session encryption is negotiated. The extractor executes:
```bash
tshark -r <pcap> --export-objects x509af,<tmpdir> -q
```
This dumps raw binary DER certificates into an isolated temporary directory, which are immediately read and parsed into memory.

---

## 5. Protocol Identification & STARTTLS State Machine

### 5.1 Protocol Identification Engine (`backend/protocols/identifier.py`)
Protocol determination is performed on each TCP stream using a two-stage classifier:
1. **Port-Based Heuristics:**
   - **SMTP:** Ports 25 (Standard Relay), 587 (Message Submission), 465 (SMTPS Implicit TLS)
   - **IMAP:** Ports 143 (IMAP Clear/STARTTLS), 993 (IMAPS Implicit TLS)
   - **POP3:** Ports 110 (POP3 Clear/STLS), 995 (POP3S Implicit TLS)
2. **Payload Dissector Fallback:** If ports are non-standard, packet layers are inspected for protocol banners and commands:
   - SMTP: `smtp.req.command`, `smtp.response.code`, or banners matching `220 ... ESMTP`
   - IMAP: `imap.request`, `imap.response`, or banners matching `* OK ... IMAP`
   - POP3: `pop.request`, `pop.response`, or banners matching `+OK ... POP`

### 5.2 Deterministic STARTTLS State Machine (`backend/protocols/starttls.py`)
To reliably detect downgrade attacks, a deterministic finite state machine (FSM) tracks the lifecycle of every email stream:

```mermaid
stateDiagram-v2
    [*] --> INIT
    INIT --> BANNER : Server 220 Greeting
    BANNER --> EHLO_RESP : Client EHLO/HELO
    EHLO_RESP --> STARTTLS_CAPABLE : Server 250 STARTTLS
    EHLO_RESP --> PLAINTEXT_CONTINUE : Client sends AUTH/MAIL (no STARTTLS advertised)
    
    STARTTLS_CAPABLE --> STARTTLS_SENT : Client sends STARTTLS
    STARTTLS_CAPABLE --> PLAINTEXT_CONTINUE : Client sends AUTH/MAIL/RCPT (Downgrade/Unused)
    
    STARTTLS_SENT --> STARTTLS_OK : Server 220 Ready
    STARTTLS_SENT --> PLAINTEXT_CONTINUE : Server rejects with 4xx / 5xx
    
    STARTTLS_OK --> TLS_ACTIVE : ClientHello Observed
    TLS_ACTIVE --> [*] : TLS Session Established
    
    PLAINTEXT_CONTINUE --> [*] : Flagged as SUSPICIOUS_FALLBACK
```

#### Downgrade & Plaintext Authentication Detection Rules:
- **`SUSPICIOUS_FALLBACK`:** If the server advertised `STARTTLS` (or client requested it), but the session subsequently returned to cleartext SMTP commands without a TLS handshake, the engine flags a **CRITICAL** vulnerability: `"Suspicious STARTTLS downgrade / fallback detected"`.
- **`PLAINTEXT_AUTH`:** If commands matching `AUTH`, `LOGIN`, `USER`, or `PASS` are observed in cleartext, the engine flags a **CRITICAL** vulnerability: `"Plaintext authentication credentials transmitted without TLS"`.
- **`STARTTLS Advertised But Not Used`:** If the server offers STARTTLS and the client ignores it without explicit rejection, a **MEDIUM** finding is emitted.

---

## 6. TLS Handshake & Cryptographic Dissection Engine

### 6.1 Handshake Parsing (`backend/tls/analyser.py`)
The TLS analyser inspects raw handshake records to establish cryptographic posture:
- **Handshake Record Unpacking:** Safely decomposes multi-handshake frames where `ServerHello` (type 2), `Certificate` (type 11), and `ServerHelloDone` (type 14) are bundled into a single TCP segment.
- **TLS Version Extraction:** Extracts handshake version (`0x0301` = TLS 1.0, `0x0302` = TLS 1.1, `0x0303` = TLS 1.2, `0x0304` = TLS 1.3), verifying extension `supported_versions` (type `0x002b`) for accurate TLS 1.3 resolution.
- **JA3 Fingerprinting:** Implements standard JA3 client fingerprint generation:
  $$\text{JA3} = \text{MD5}(\text{Version},\text{Ciphers},\text{Extensions},\text{EllipticCurves},\text{PointFormats})$$
  GREASE values ($0x0a0a, 0x1a1a, \dots$) are filtered out prior to hashing.

### 6.2 Cipher Suite & Forward Secrecy Classification
The engine resolves hex cipher identifiers against an internal IANA database and evaluates security attributes:

| Category | Cipher Suites / Key Exchanges | Risk Classification |
|---|---|---|
| **Zero Encryption** | `TLS_RSA_WITH_NULL_SHA`, `TLS_RSA_WITH_NULL_MD5` | **CRITICAL** (Finding: Cleartext NULL cipher) |
| **Export Ciphers** | `EXP-RC4-MD5`, `EXP-EDH-RSA-DES-CBC-SHA` | **CRITICAL** (Finding: Export-grade weak keys) |
| **Insecure / Deprecated** | `RC4` (`TLS_RSA_WITH_RC4_128_SHA`, etc.) | **HIGH** (Finding: Insecure stream cipher, CVE-2015-2808) |
| **Legacy Block Cipher** | `3DES` (`TLS_RSA_WITH_3DES_EDE_CBC_SHA`) | **HIGH** (Finding: Sweet32 64-bit block collision, CVE-2016-2183) |
| **CBC Padding Attack** | `AES_128_CBC`, `AES_256_CBC` (in TLS $\le$ 1.2) | **MEDIUM** (Finding: Lucky13 padding oracle risk, CVE-2013-0169) |
| **Modern AEAD** | `AES_128_GCM`, `AES_256_GCM`, `CHACHA20_POLY1305` | **CLEAN / MINIMAL** |

#### Forward Secrecy Evaluation:
- **`ForwardSecrecyStatus.YES`:** Key exchanges utilizing Ephemeral Diffie-Hellman (`ECDHE`, `DHE`) or all TLS 1.3 suites.
- **`ForwardSecrecyStatus.NO`:** Key exchanges utilizing static RSA (`TLS_RSA_WITH_*`) or static Diffie-Hellman. Emits a **HIGH** severity finding: `"No Forward Secrecy: Private key compromise allows retroactive decryption"`.

### 6.3 TLS 1.3 Encrypted Handshake Observability Handling
In TLS 1.3 (RFC 8446), the server `Certificate` message is transmitted encrypted under the handshake traffic keys derived from Diffie-Hellman ephemeral exchange. 

SecureMailScope explicitly models this physical constraint:
```python
if handshake.tls_version == TLSVersion.TLS_1_3:
    handshake.cert_observability = ObservabilityStatus.NOT_OBSERVABLE
    handshake.cert_observability_note = (
        "TLS 1.3: Certificate messages are encrypted in the handshake. "
        "Without the session keys (SSLKEYLOGFILE), certificate contents "
        "cannot be extracted from this capture. This is by design — "
        "TLS 1.3 encrypts the certificate to protect server identity."
    )
```
Rather than producing a false negative or failing, the framework records this as an expected architectural property of passive forensic observation.

---

## 7. X.509 Certificate Forensic Analysis (`backend/certificates/analyser.py`)

Raw DER certificates extracted from PCAPs are parsed via the `cryptography.x509` engine into typed `CertificateInfo` models.

### 7.1 Parsed Parameters
- **Subject & Issuer:** Canonical Common Name (CN) and full Distinguished Name (DN)
- **Subject Alternative Names (SANs):** List of DNS names and IP addresses
- **Validity Window:** `not_valid_before` and `not_valid_after` timestamps with UTC timezone enforcement
- **Public Key Metadata:** Key algorithm (`RSA`, `EC`, `DSA`, `Ed25519`), key bit-length, RSA public exponent ($e$), EC curve name
- **Cryptographic Fingerprints:** Deterministic SHA-256 fingerprint of the raw DER bytes

### 7.2 Deterministic Certificate Hygiene Rules

```mermaid
flowchart TD
    CERT["X.509 Certificate"] --> EXP{Expired?}
    EXP -- Yes --> CRIT_EXP["CRITICAL: Certificate is expired"]
    EXP -- No --> SOON{Expires in <= 30 Days?}
    SOON -- Yes --> HIGH_SOON["HIGH: Certificate expiring soon"]
    SOON -- No --> KEY{Key Strength Check}

    KEY --> RSA_CHECK{Algorithm == RSA?}
    RSA_CHECK -- Yes --> BITS{Bits < 2048?}
    BITS -- Yes --> HIGH_KEY["HIGH: Weak RSA key (<2048 bits)"]
    BITS -- No --> EXPONENT{e == 3?}
    EXPONENT -- Yes --> HIGH_EXP["HIGH: Low exponent attack risk (e=3)"]
    EXPONENT -- No --> SIG{Signature Algorithm}

    KEY --> EC_CHECK{Algorithm == EC & Bits < 256?}
    EC_CHECK -- Yes --> HIGH_EC["HIGH: Weak EC curve (<256 bits)"]
    EC_CHECK -- No --> SIG

    SIG --> WEAK_HASH{Hash in MD5, SHA1?}
    WEAK_HASH -- Yes --> HIGH_SIG["HIGH: Weak signature algorithm"]
    WEAK_HASH -- No --> SELF{is_self_signed?}

    SELF -- Yes --> MED_SELF["MEDIUM: Certificate is self-signed"]
    SELF -- No --> CLEAN["No Certificate Findings"]
```

---

## 8. Machine Learning Behavioral Anomaly Detection (`backend/anomaly/detector.py`)

While deterministic rules effectively capture known bad practices, sophisticated threats, non-standard toolkits, and anomalous operational patterns require statistical modeling.

### 8.1 Isolation Forest Architecture
SecureMailScope employs an unsupervised **Isolation Forest** (`sklearn.ensemble.IsolationForest`):
- **Estimators:** $n = 100$ isolation trees
- **Contamination:** $10\%$ expected anomaly contamination factor
- **Seed:** Deterministic `random_state = 42`
- **Scaler:** `sklearn.preprocessing.StandardScaler`

### 8.2 The 16-Dimensional Feature Vector
Every `TCPSession` is projected into a 16-dimensional numerical feature space based exclusively on session metadata (zero packet payload bytes):

| Index | Feature Name | Representation / Normalization Range | Description |
|---|---|---|---|
| $x_0$ | `tls_version_num` | $\{0.0, 3.0, 10.0, 11.0, 12.0, 13.0\}$ | TLS numeric protocol version |
| $x_1$ | `cipher_strength_cat` | $1.0$ (NULL/Exp), $2.0$ (Weak), $2.5$ (3DES), $3.0$ (Other), $4.0$ (AES/ChaCha) | Categorical cipher strength |
| $x_2$ | `key_exchange_cat` | $1.0$ (RSA), $2.0$ (DHE), $3.0$ (ECDHE), $4.0$ (Anon DH) | Key exchange algorithm class |
| $x_3$ | `forward_secrecy` | $\{0.0, 1.0\}$ | Binary Forward Secrecy status |
| $x_4$ | `cert_observable` | $\{0.0, 1.0\}$ | Binary certificate observability |
| $x_5$ | `cert_expired` | $\{0.0, 1.0\}$ | Binary certificate expiration indicator |
| $x_6$ | `cert_self_signed` | $\{0.0, 1.0\}$ | Binary self-signed certificate indicator |
| $x_7$ | `cert_key_bits_norm` | $\min(\text{key\_size} / 4096.0, 1.0)$ | Continuous normalized public key size |
| $x_8$ | `sig_alg_weak` | $\{0.0, 1.0\}$ | Binary deprecated signature indicator (MD5/SHA1) |
| $x_9$ | `starttls_state_cat` | $0.0$ (none), $1.0$ (direct), $2.0$ (negotiated), $3.0$ (ad/req), $4.0$ (fallback/fail) | Categorical STARTTLS negotiation state |
| $x_{10}$ | `cleartext_auth` | $\{0.0, 1.0\}$ | Binary cleartext authentication detected |
| $x_{11}$ | `protocol_cat` | $1.0$ (SMTP), $2.0$ (IMAP), $3.0$ (POP3), $0.0$ (Unknown) | Application protocol identifier |
| $x_{12}$ | `offered_cipher_count` | $\min(\text{count}, 50) / 50.0$ | Normalized client offered cipher count |
| $x_{13}$ | `extension_count` | $\min(\text{count}, 30) / 30.0$ | Normalized client TLS extension count |
| $x_{14}$ | `session_duration_norm` | $\min(\text{duration}, 300.0) / 300.0$ | Continuous session duration in seconds |
| $x_{15}$ | `packet_count_norm` | $\min(\text{packets}, 100) / 100.0$ | Normalized session packet density |

### 8.3 Synthetic Benign Training Corpus
To avoid dependency on external internet datasets that may introduce training bias, the model trains against a mathematically controlled distribution of 2,000 synthetic benign TLS sessions reflecting compliant enterprise email configurations:
- $65\%$ TLS 1.3, $35\%$ TLS 1.2
- $100\%$ Forward Secrecy (ECDHE / DHE)
- $100\%$ Valid, unexpired, non-self-signed certificates
- Standard client hello extension distributions ($5 \text{ to } 25$ extensions, $10 \text{ to } 40$ ciphers)

### 8.4 Score Calibration & Anomaly Threshold
The raw Isolation Forest decision function $s_{\text{raw}}$ (where negative denotes an anomaly and positive denotes nominal) is normalized into an anomaly probability $P_{\text{anom}} \in [0.0, 1.0]$:

$$P_{\text{anom}} = \text{clamp}\left(0.5 - s_{\text{raw}}, 0.0, 1.0\right)$$

If $P_{\text{anom}} \ge 0.50$, the session is classified as anomalous (`is_anomalous = True`), triggering an `ml_anomaly` finding and a 5-point deduction on the session risk score.

---

## 9. Cryptographic Posture Scoring Engine (`backend/posture/scoring.py`)

### 9.1 Mathematical Scoring Formulation
The SecureMailScope Composite Risk Score evaluates the health of observed communications on a scale from $0.0$ (Critically Compromised) to $100.0$ (Optimal Posture).

The score begins at a perfect baseline ($S_0 = 100.0$) and accumulates weighted penalties for vulnerabilities alongside bonuses for positive cryptographic controls:

$$S = \text{clamp}\left(100.0 - \sum_{i} D(f_i) + \sum_{j} B(c_j), 0.0, 100.0\right)$$

#### Penalty Deductions ($D$):
- **$\text{CRITICAL Finding:}$** $-25.0 \text{ points}$  
  *(e.g., Expired certificate, STARTTLS downgrade, Plaintext credentials, SSL 2.0/3.0, NULL cipher)*
- **$\text{HIGH Finding:}$** $-15.0 \text{ points}$  
  *(e.g., TLS 1.0/1.1, RC4, 3DES, Weak RSA <2048-bit, No Forward Secrecy, Cleartext email)*
- **$\text{MEDIUM Finding:}$** $-7.0 \text{ points}$  
  *(e.g., Self-signed certificate, CBC mode in TLS 1.2, STARTTLS offered but unused)*
- **$\text{LOW Finding:}$** $-2.0 \text{ points}$  
  *(e.g., Minor configuration defect)*
- **$\text{ML Anomaly:}$** $-5.0 \text{ points}$ per anomalous session

#### Positive Control Bonuses ($B$):
- **$\text{TLS 1.3 Protocol Adoption:}$** $+5.0 \text{ points}$
- **$\text{Forward Secrecy Verified:}$** $+3.0 \text{ points}$

### 9.2 Risk Posture Level Mapping

| Score Band | Posture Level | Severity Indicator | Operational Meaning |
|---|---|---|---|
| **$85.0 - 100.0$** | **MINIMAL** | 🟢 Green | Modern cryptographic controls; TLS 1.2/1.3 with forward secrecy |
| **$70.0 - 84.9$** | **LOW** | 🔵 Blue | Acceptable security with minor non-critical warnings |
| **$50.0 - 69.9$** | **MEDIUM** | 🟡 Yellow | Deprecated algorithms, weak ciphers, or lack of forward secrecy |
| **$25.0 - 49.9$** | **HIGH** | 🟠 Orange | Severe vulnerabilities; plaintext fallback or active downgrade risk |
| **$0.0 - 24.9$** | **CRITICAL** | 🔴 Red | Unencrypted plaintext credentials or totally broken encryption |

---

## 10. Multi-Format Reporting & Remediation Generator (`backend/reporting/generator.py`)

SecureMailScope compiles results into three interoperable forensic artifacts:

### 10.1 Machine-Readable JSON Export (`report.json`)
Emits a comprehensive JSON representation of the `AnalysisResult` model, including SHA-256 capture hashes, session 5-tuples, dissected packet indexes, evidence traces, and forensic disclaimers:
```json
{
  "analysis_id": "8fbc923a-...",
  "capture": {
    "pcap_filename": "01_secure_tls12.pcap",
    "sha256_hash": "e3b0c442...",
    "packet_count": 8,
    "file_size_bytes": 1704
  },
  "risk_score": {
    "score": 97.0,
    "level": "MINIMAL",
    "critical_count": 0,
    "high_count": 0
  },
  "report_metadata": {
    "tool": "SecureMailScope",
    "version": "0.1.0",
    "disclaimer": "SecureMailScope Composite Risk Score is a prototype scoring methodology..."
  }
}
```

### 10.2 Standalone HTML Forensic Dashboard (`report.html`)
- Completely self-contained HTML/CSS document requiring zero external CDN dependencies.
- Features a high-contrast dark theme optimized for technical review.
- Embeds summary metrics cards, protocol distribution tables, session timelines, prioritized finding tables, and remediation action items.

### 10.3 Publication-Ready Forensic PDF Report (`report.pdf`)
- Generated dynamically via the Python `reportlab` engine.
- Contains executive overview metrics, color-coded severity badges, structured tables detailing each finding with packet-level evidence, and dedicated guidance sections.

---

## 11. REST API Architecture (`backend/api/main.py`)

The backend exposes an asynchronous RESTful interface implemented in FastAPI:

| HTTP Verb | Endpoint URI | Description / Payload |
|---|---|---|
| `POST` | `/api/analysis/upload` | Multipart file upload (`.pcap`, `.pcapng`); dispatches async analysis |
| `POST` | `/api/analysis/file` | Triggers analysis by server-side path (for bundled demo PCAPs) |
| `GET` | `/api/analysis/{id}/status` | Queries processing state: `pending`, `running`, `done`, `error` |
| `GET` | `/api/analysis/{id}` | Returns complete `AnalysisResult` data tree |
| `GET` | `/api/analysis/{id}/sessions` | Queries reconstructed sessions with optional `?protocol=` filter |
| `GET` | `/api/analysis/{id}/findings` | Queries findings with `?severity=` and `?category=` filters |
| `GET` | `/api/analysis/{id}/report/json` | Downloads serialized JSON forensic report |
| `GET` | `/api/analysis/{id}/report/html` | Renders standalone forensic HTML report |
| `GET` | `/api/analysis/{id}/report/pdf` | Streams compiled PDF forensic report |
| `GET` | `/api/analyses` | Lists all cached analyses in current session |
| `GET` | `/api/health` | Healthcheck verifying API status, version, and TShark availability |

---

## 12. REST API & Forensic Integration Architecture (`backend/api/`)

The core engine is exposed as a modular, high-throughput REST API built on **FastAPI** and **Pydantic v2**:

```
backend/api/
├── main.py             # FastAPI routing, lifespan, ingestion, and PCAP endpoints
└── __init__.py         # Package initialization
```

### Key API Capabilities:
- **PCAP Ingestion & Re-Analysis:** Exposes `GET /api/pcaps` and `GET /api/pcaps/{filename}` for direct inspection and raw capture downloads, alongside `POST /api/pcaps/{filename}/analyse` to re-analyze any capture from scratch asynchronously or synchronously (`/sync`).
- **Granular Stream Inspection:** Endpoints `GET /api/analysis/{aid}/sessions` and `GET /api/analysis/{aid}/sessions/{sid}` expose 5-tuple forensic flows, protocol state banners, X.509 chains, and layer decodes.
- **Vulnerability Querying:** Endpoints `GET /api/analysis/{aid}/findings` support parameter filtering by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) and category.
- **Multi-Format Report Generation:** Direct programmatic generation of machine-readable JSON (`/report/json`), standalone HTML (`/report/html`), and formal forensic PDF executive reports (`/report/pdf`).
- **Interactive Documentation:** Automatic OpenAPI 3.1.0 specifications with Swagger UI at `/docs` and ReDoc at `/redoc`.

---

## 13. Empirical Benchmarking & Forensic Accuracy Evaluation

### 13.1 Benchmark Corpus & Canonical Scenarios
The framework includes a comprehensive evaluation suite (`benchmark/evaluate.py`) that tests detection accuracy against five consolidated multi-stream PCAP scenarios generated via Scapy (comprising 19 total forensic sessions):

| ID | PCAP File | Protocols | Scenario Description | Expected Ground Truth |
|---|---|---|---|---|
| **01** | `01_enterprise_secure_baseline.pcap` | SMTP, IMAP, POP3 | Modern multi-protocol baseline (TLS 1.3 encrypted certs, TLS 1.2 ECDHE, valid CA certs) | Clean sessions; 0 rule findings; Score 99/100 (MINIMAL) |
| **02** | `02_legacy_cryptography_and_certs.pcap` | SMTP, SMTPS, IMAPS, POP3S | Cryptographic obsolescence: TLS 1.0 BEAST, 3DES Sweet32 static RSA, expired cert, 1024-bit RSA self-signed | Flags `deprecated_tls`, `weak_cipher`, `no_forward_secrecy`, `expired_certificate`, `weak_key`, `invalid_certificate` |
| **03** | `03_starttls_downgrade_and_cleartext.pcap` | SMTP, IMAP, POP3 | Active MitM tampering: 454 downgrade fallback, stripped STARTTLS capability, cleartext credential harvesting | Flags `starttls_anomaly` (downgrade) and `plaintext_auth` |
| **04** | `04_protocol_anomalies_and_fuzzing.pcap` | SMTP, SMTPS, Submission | Behavioral deviations: HTTP probes on port 25, 2KB buffer fuzzing, corrupt TLS records, split ClientHellos | Flags `starttls_anomaly` and ML behavioural anomalies |
| **05** | `05_realworld_network_transports.pcap` | SMTP, IMAP, POP3 | Real-world capture edge cases: packet loss, duplicate ACKs, abrupt RSTs, truncated certs, out-of-order overlap, SYN scan | Flags `starttls_anomaly` and ML transport anomalies |

### 13.2 Live Benchmark Execution Metrics
Results from the automated evaluation suite executed against the live prototype:

```
============================================================
SecureMailScope Benchmark / Evaluation Summary
============================================================
PCAPs processed        : 5
Sessions analyzed      : 19
Critical findings      : 3
High findings          : 14

Rule Engine Detection:
  True Positives (TP)  : 4
  False Positives (FP) : 0
  False Negatives (FN) : 0
  True Negatives (TN)  : 1
  Precision            : 1.000 (100.0%)
  Recall               : 1.000 (100.0%)
  F1 Score             : 1.000 (100.0%)

ML Anomaly Detection:
  True Positives (TP)  : 4
  False Positives (FP) : 1
  False Negatives (FN) : 0
  True Negatives (TN)  : 0
  Precision            : 0.800 (80.0%)
  Recall               : 1.000 (100.0%)
  F1 Score             : 0.889 (88.9%)

Execution Performance:
  Mean Analysis Time   : 0.381s per PCAP
  Total Benchmark Time : 2.666s
============================================================
```

### 13.3 Automated Unit Test Suite
The automated test harness comprises 97 tests across 8 test suites passing at 100%:
- `test_protocol_identifier.py`: 13/13 passed
- `test_starttls.py`: 6/6 passed
- `test_tls_analyser.py`: 31/31 passed
- `test_certificates.py`: 9/9 passed
- `test_anomaly.py`: 14/14 passed
- `test_scoring.py`: 10/10 passed
- `test_reporting.py`: 3/3 passed (including binary PDF generation)
- `test_api.py`: 11/11 passed

---

## 14. Deployment & Infrastructure Orchestration

### 14.1 Nix Flakes Devshell (`flake.nix`)
The native development environment is packaged via Nix Flakes to guarantee zero divergence across development environments:
- **Host Dependencies:** Precompiled GCC runtime (`pkgs.stdenv.cc.cc.lib`), `pkgs.zlib`, `pkgs.wireshark` (providing `tshark` 4.6.9), `pkgs.openssl` 3.5.8, `pkgs.tcpdump` 4.99.6, and Node.js 22.23.
- **Fast Startup:** Eliminates local source compilation; shell startup completes in $<0.2\text{s}$.

### 14.2 Containerization Architecture (`compose.yaml` / `podman-compose.yml`)
To support containerized deployments, SecureMailScope provides a containerized service:
- **Backend Container (`backend/Dockerfile`):**
  - Built on `python:3.12-slim-bookworm`.
  - Packages `tshark`, `openssl`, and `tcpdump`.
  - Pre-bakes the trained Isolation Forest ML model into the container image.
  - Binds port `8000` with automated healthcheck (`/api/health`).

### 14.3 Developer Automation (`justfile`)
All operational tasks are orchestrated through `just`:
```bash
just check           # Validates forensic binaries and python libraries
just test            # Runs all 105 automated pytest unit tests
just gen-pcaps       # Synthesizes canonical test PCAPs in user space
just benchmark       # Executes precision/recall evaluation benchmark
just demo            # Runs full offline CLI demonstration & PDF generation
just analyse <pcap>  # Analyses arbitrary PCAP and outputs JSON/HTML/PDF
just backend         # Starts backend API server with hot-reload
just compose-up      # Starts container stack via podman-compose
just compose-down    # Shuts down container stack
```

---

## 15. Operational Boundaries, Legal & Privacy Safeguards

### 15.1 Passive Observation Limitations
- **TLS 1.3 Handshake Encryption:** By RFC 8446 design, server certificates are encrypted. Passive monitors cannot inspect certificate subject names or key sizes without session secrets (`SSLKEYLOGFILE`). SecureMailScope transparently reports this architectural limitation.
- **Opportunistic Failure vs MITM Attacks:** A passive tool can definitively prove that traffic reverted to cleartext; it cannot mathematically prove whether the fallback was caused by an active man-in-the-middle attack or a server-side configuration change. Findings are carefully formulated as protocol inconsistencies rather than accusatory attack alerts.

### 15.2 Privacy Safeguards
- **Compliance with Interception Laws:** Does not perform TLS decryption, certificate re-signing, or packet interception.
- **Zero Content Leakage:** Email headers (`Subject`, `From`, `To`), email message bodies, and attachments are strictly ignored during dissections. Only session-level metadata and command verbs are processed.

---

## 16. Technical Roadmap & Future Enhancements

The codebase architecture includes deliberate extension hooks for future phases:
1. **Online Certificate Status Protocol (OCSP) & CRL Auditing:** Passive extraction of OCSP Stapling responses from TLS extensions to assess revocation status.
2. **JA3S Server Fingerprinting:** Extending client JA3 hashing to include server handshake parameters (JA3S).
3. **Live Interface Sniffing:** Connecting the session builder to live network interfaces using `dumpcap` with ring-buffer storage for real-time perimeter monitoring.
4. **Streaming Dissection for Multi-Gigabyte Captures:** Chunked packet ingestion to evaluate high-volume enterprise traffic without memory spikes.

---

## 17. Conclusion

SecureMailScope demonstrates that passive network traffic analysis can effectively evaluate email cryptographic posture without violating confidentiality or requiring invasive TLS interception proxies. 

By combining a deterministic state machine, an RFC-compliant cryptographic posture engine, and an unsupervised Isolation Forest anomaly detector, the framework achieves **1.000 Precision, 1.000 Recall, and 1.000 F1 Score** on rule-based forensic detection, providing a robust, reproducible foundation for the Smart India Hackathon 2026 Problem Statement 26159.
