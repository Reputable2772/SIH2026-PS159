"""
SecureMailScope — Interactive & Machine-Readable API Documentation Engine
Generates detailed endpoint schemas, data shapes, and standalone HTML/JSON documentation.
"""

from __future__ import annotations

import json
from typing import Any

# ---------------------------------------------------------------------------
# Machine-Readable API Shape Catalog
# ---------------------------------------------------------------------------

API_SPEC_CATALOG: dict[str, Any] = {
    "api": "SecureMailScope API",
    "version": "0.1.0",
    "title": "SecureMailScope — AI-Assisted Cryptographic Posture Assessment API",
    "description": (
        "Passive network forensic framework for email protocol analysis (SMTP, IMAP, POP3), "
        "STARTTLS state machine tracking, X.509 certificate hygiene auditing, deterministic "
        "cryptographic posture scoring, and 16-dimensional Isolation Forest ML anomaly detection."
    ),
    "base_url": "/",
    "openapi_url": "/openapi.json",
    "documentation_url": "/docs",
    "endpoints": [
        # --- PCAP Management & Triggers ---
        {
            "id": "list_pcaps",
            "group": "PCAPs & Capture Management",
            "method": "GET",
            "path": "/api/pcaps",
            "aliases": ["/api/demo/pcaps"],
            "summary": "List available PCAPs with metadata and checksums",
            "description": (
                "Retrieves metadata, file sizes, SHA-256 digests, scenario categories, "
                "and analysis URLs for all canonical benchmark PCAPs and stored capture files."
            ),
            "parameters": [],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "list[PcapEntry]",
                "shape": [
                    {
                        "filename": "string (e.g. '01_enterprise_secure_baseline.pcap')",
                        "title": "string (Scenario title)",
                        "description": "string (Detailed scenario description)",
                        "category": "string ('secure_baseline' | 'legacy_crypto' | 'downgrade_attack' | 'anomalies' | 'network_transports')",
                        "size_bytes": "integer (File size in bytes)",
                        "sha256_hash": "string (64-character lowercase hex SHA-256)",
                        "download_url": "string (Path to download raw capture)",
                        "analyse_url": "string (Path to trigger async analysis)",
                    }
                ],
                "example": [
                    {
                        "filename": "01_enterprise_secure_baseline.pcap",
                        "title": "Enterprise Secure Baseline",
                        "description": "Modern TLS 1.3 / 1.2, ECDHE Forward Secrecy, valid certificates across SMTP, IMAP, and POP3.",
                        "category": "secure_baseline",
                        "size_bytes": 142850,
                        "sha256_hash": "3d9f10a8b2c45e6f1a890b1234567890abcdef1234567890abcdef1234567890",
                        "download_url": "/api/pcaps/01_enterprise_secure_baseline.pcap",
                        "analyse_url": "/api/pcaps/01_enterprise_secure_baseline.pcap/analyse",
                    }
                ],
            },
            "curl_example": "curl -s http://localhost:8000/api/pcaps",
        },
        {
            "id": "download_pcap",
            "group": "PCAPs & Capture Management",
            "method": "GET",
            "path": "/api/pcaps/{filename}",
            "aliases": ["/api/demo/pcaps/{filename}"],
            "summary": "Download raw PCAP capture file",
            "description": "Downloads the raw binary packet capture file (.pcap or .pcapng) for offline inspection in Wireshark or external forensic tooling.",
            "parameters": [
                {
                    "name": "filename",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "Name of the target PCAP file (e.g. '01_enterprise_secure_baseline.pcap').",
                    "example": "01_enterprise_secure_baseline.pcap",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/vnd.tcpdump.pcap",
                "model": "binary",
                "shape": "Raw pcap binary octet stream",
                "example": "<binary pcap bytes>",
            },
            "curl_example": "curl -O http://localhost:8000/api/pcaps/01_enterprise_secure_baseline.pcap",
        },
        {
            "id": "analyse_pcap_by_name",
            "group": "PCAPs & Capture Management",
            "method": "POST",
            "path": "/api/pcaps/{filename}/analyse",
            "aliases": ["/api/pcaps/{filename}/analyze"],
            "summary": "Trigger asynchronous PCAP analysis from scratch",
            "description": (
                "Dispatches a background forensic analysis job for an existing PCAP. "
                "Returns immediately with a newly generated analysis_id and 'pending' status."
            ),
            "parameters": [
                {
                    "name": "filename",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "Name of the PCAP file in the storage directory.",
                    "example": "01_enterprise_secure_baseline.pcap",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "AnalysisStatus",
                "shape": {
                    "analysis_id": "string (UUIDv4)",
                    "status": "string ('pending' | 'running' | 'done' | 'error')",
                    "error": "string | null",
                },
                "example": {
                    "analysis_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                    "status": "pending",
                    "error": None,
                },
            },
            "curl_example": "curl -X POST http://localhost:8000/api/pcaps/01_enterprise_secure_baseline.pcap/analyse",
        },
        {
            "id": "analyse_pcap_by_name_sync",
            "group": "PCAPs & Capture Management",
            "method": "POST",
            "path": "/api/pcaps/{filename}/analyse/sync",
            "aliases": ["/api/pcaps/{filename}/analyze/sync"],
            "summary": "Trigger synchronous PCAP analysis (blocking until complete)",
            "description": (
                "Executes the full forensic pipeline synchronously and blocks until completion. "
                "Returns the complete AnalysisResult data tree."
            ),
            "parameters": [
                {
                    "name": "filename",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "Name of the PCAP file to analyze synchronously.",
                    "example": "01_enterprise_secure_baseline.pcap",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "AnalysisResult",
                "shape": "Complete AnalysisResult object (see Models section)",
                "example": {
                    "analysis_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                    "capture": {
                        "pcap_filename": "01_enterprise_secure_baseline.pcap",
                        "sha256_hash": "3d9f10a8b2c45e6f1a890b1234567890abcdef1234567890abcdef1234567890",
                        "packet_count": 86,
                        "file_size_bytes": 142850,
                    },
                    "risk_score": {
                        "score": 99.0,
                        "level": "MINIMAL",
                        "critical_count": 0,
                        "high_count": 0,
                        "medium_count": 0,
                        "low_count": 0,
                    },
                    "sessions": [],
                    "all_findings": [],
                },
            },
            "curl_example": "curl -X POST http://localhost:8000/api/pcaps/01_enterprise_secure_baseline.pcap/analyse/sync",
        },
        # --- Analysis Ingestion ---
        {
            "id": "upload_and_analyse",
            "group": "Analysis & Ingestion",
            "method": "POST",
            "path": "/api/analysis/upload",
            "summary": "Upload and analyze PCAP capture file",
            "description": "Upload a raw .pcap, .pcapng, or .cap file via multipart/form-data. Dispatches background processing and returns an analysis tracking ID.",
            "parameters": [],
            "request_body": {
                "content_type": "multipart/form-data",
                "fields": {
                    "file": "binary (PCAP file content, .pcap / .pcapng / .cap)",
                },
            },
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "AnalysisStatus",
                "shape": {
                    "analysis_id": "string (UUIDv4)",
                    "status": "string ('pending' | 'running' | 'done' | 'error')",
                    "error": "string | null",
                },
                "example": {
                    "analysis_id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                    "status": "pending",
                    "error": None,
                },
            },
            "curl_example": "curl -F 'file=@sample.pcap' http://localhost:8000/api/analysis/upload",
        },
        {
            "id": "analyse_file",
            "group": "Analysis & Ingestion",
            "method": "POST",
            "path": "/api/analysis/file",
            "summary": "Analyze PCAP by server-side file path",
            "description": "Trigger analysis of a PCAP file by providing a local or relative filesystem path on the host.",
            "parameters": [],
            "request_body": {
                "content_type": "application/json",
                "shape": {
                    "pcap_path": "string (Path to target PCAP file)",
                },
                "example": {"pcap_path": "demo_pcaps/01_enterprise_secure_baseline.pcap"},
            },
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "AnalysisStatus",
                "shape": {
                    "analysis_id": "string (UUIDv4)",
                    "status": "string ('pending' | 'running' | 'done' | 'error')",
                    "error": "string | null",
                },
                "example": {
                    "analysis_id": "b2c3d4e5-f6a7-8901-bcde-f12345678901",
                    "status": "pending",
                    "error": None,
                },
            },
            "curl_example": 'curl -X POST http://localhost:8000/api/analysis/file -H "Content-Type: application/json" -d \'{"pcap_path": "demo_pcaps/01_enterprise_secure_baseline.pcap"}\'',
        },
        {
            "id": "run_demo",
            "group": "Analysis & Ingestion",
            "method": "POST",
            "path": "/api/demo/run",
            "summary": "Run analysis across all canonical demo PCAPs",
            "description": "Dispatches background analysis jobs for all canonical evaluation scenarios in demo_pcaps/.",
            "parameters": [],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "DemoRunResponse",
                "shape": {
                    "demo_analyses": [
                        {
                            "analysis_id": "string (UUIDv4)",
                            "pcap": "string (PCAP filename)",
                        }
                    ]
                },
                "example": {
                    "demo_analyses": [
                        {
                            "analysis_id": "8fbc923a-...",
                            "pcap": "01_enterprise_secure_baseline.pcap",
                        },
                        {
                            "analysis_id": "9acd112b-...",
                            "pcap": "02_legacy_cryptography_and_certs.pcap",
                        },
                    ]
                },
            },
            "curl_example": "curl -X POST http://localhost:8000/api/demo/run",
        },
        # --- Analysis Results & Forensics ---
        {
            "id": "get_analysis_status",
            "group": "Analysis & Forensics",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/status",
            "summary": "Check analysis processing status",
            "description": "Polls processing state ('pending', 'running', 'done', 'error') for an active or completed analysis.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "AnalysisStatus",
                "shape": {
                    "analysis_id": "string",
                    "status": "string ('pending' | 'running' | 'done' | 'error')",
                    "error": "string | null",
                },
                "example": {
                    "analysis_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                    "status": "done",
                    "error": None,
                },
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/status",
        },
        {
            "id": "get_analysis",
            "group": "Analysis & Forensics",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}",
            "summary": "Retrieve complete analysis result",
            "description": "Returns the complete forensic analysis data tree including capture metadata, reconstructed sessions, risk score, protocol summary, all findings, and recommendations.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis (prefix match supported).",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "AnalysisResult | AnalysisStatus",
                "shape": {
                    "analysis_id": "string",
                    "capture": {
                        "pcap_filename": "string",
                        "sha256_hash": "string",
                        "packet_count": "integer",
                        "file_size_bytes": "integer",
                        "duration_seconds": "float",
                        "analyzed_at": "string (ISO 8601 UTC)",
                    },
                    "risk_score": {
                        "score": "float (0.0 to 100.0)",
                        "level": "string ('MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL')",
                        "rationale": "list[string]",
                        "critical_count": "integer",
                        "high_count": "integer",
                        "medium_count": "integer",
                        "low_count": "integer",
                        "ml_anomaly_count": "integer",
                    },
                    "protocol_summary": {
                        "smtp_sessions": "integer",
                        "imap_sessions": "integer",
                        "pop3_sessions": "integer",
                        "tls_sessions": "integer",
                        "plaintext_sessions": "integer",
                        "tls_versions": "dict[string, integer]",
                        "cipher_suites": "dict[string, integer]",
                        "forward_secrecy_yes": "integer",
                        "forward_secrecy_no": "integer",
                    },
                    "sessions": "list[TCPSession]",
                    "all_findings": "list[Finding]",
                    "recommendations": "list[string]",
                    "limitations": "list[string]",
                    "processing_time_seconds": "float",
                },
                "example": {
                    "analysis_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                    "risk_score": {
                        "score": 99.0,
                        "level": "MINIMAL",
                        "critical_count": 0,
                        "high_count": 0,
                    },
                    "recommendations": ["Enforce TLS 1.3 across all mail endpoints."],
                },
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479",
        },
        {
            "id": "get_sessions",
            "group": "Analysis & Forensics",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/sessions",
            "summary": "Get reconstructed TCP sessions",
            "description": "Returns list of all reconstructed TCP email conversations in the capture with 5-tuples, STARTTLS state machine status, TLS handshakes, X.509 certs, and ML anomaly features.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "list[TCPSession]",
                "shape": [
                    {
                        "session_id": "string",
                        "src_ip": "string",
                        "src_port": "integer",
                        "dst_ip": "string",
                        "dst_port": "integer",
                        "protocol": "string ('SMTP' | 'IMAP' | 'POP3' | 'UNKNOWN')",
                        "starttls_state": "string ('no_tls' | 'advertised' | 'requested' | 'negotiated' | 'failed' | 'suspicious_fallback' | 'direct_tls')",
                        "cleartext_auth_detected": "boolean",
                        "tls_handshake": "TLSHandshake | null",
                        "findings": "list[Finding]",
                        "is_anomalous": "boolean | null",
                        "anomaly_score": "float | null",
                        "session_risk_score": "float | null",
                        "session_risk_level": "string | null",
                    }
                ],
                "example": [
                    {
                        "session_id": "stream-0",
                        "src_ip": "192.168.1.100",
                        "src_port": 49210,
                        "dst_ip": "192.168.1.25",
                        "dst_port": 587,
                        "protocol": "SMTP",
                        "starttls_state": "negotiated",
                        "session_risk_score": 100.0,
                        "session_risk_level": "MINIMAL",
                    }
                ],
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/sessions",
        },
        {
            "id": "get_session_by_id",
            "group": "Analysis & Forensics",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/sessions/{session_id}",
            "summary": "Get specific reconstructed TCP session",
            "description": "Returns full granular forensic parameters, raw banners, packet timestamps, and TLS extension decodes for a single TCP stream.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                },
                {
                    "name": "session_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "Identifier of the TCP session (e.g. 'stream-0').",
                    "example": "stream-0",
                },
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "TCPSession",
                "shape": "TCPSession object (see Models section)",
                "example": {
                    "session_id": "stream-0",
                    "src_ip": "192.168.1.100",
                    "src_port": 49210,
                    "dst_ip": "192.168.1.25",
                    "dst_port": 587,
                    "protocol": "SMTP",
                    "starttls_state": "negotiated",
                },
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/sessions/stream-0",
        },
        {
            "id": "get_findings",
            "group": "Analysis & Forensics",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/findings",
            "summary": "Query forensic security findings with filters",
            "description": "Returns security findings across all sessions in the capture. Supports filtering by severity (CRITICAL, HIGH, MEDIUM, LOW) and category.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                },
                {
                    "name": "severity",
                    "in": "query",
                    "type": "string | null",
                    "required": False,
                    "description": "Filter by severity: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'.",
                    "example": "CRITICAL",
                },
                {
                    "name": "category",
                    "in": "query",
                    "type": "string | null",
                    "required": False,
                    "description": "Filter by category: 'deprecated_tls', 'weak_cipher', 'weak_key', 'expired_certificate', 'starttls_anomaly', 'plaintext_auth', 'ml_anomaly'.",
                    "example": "starttls_anomaly",
                },
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "list[Finding]",
                "shape": [
                    {
                        "id": "string",
                        "severity": "string ('critical' | 'high' | 'medium' | 'low' | 'info')",
                        "category": "string",
                        "title": "string",
                        "description": "string",
                        "evidence": {
                            "session_id": "string",
                            "packet_numbers": "list[integer]",
                            "field": "string | null",
                            "observed_value": "any | null",
                            "extra": "dict[string, any]",
                        },
                        "recommendation": "string",
                        "cve_references": "list[string]",
                        "is_ml_finding": "boolean",
                    }
                ],
                "example": [
                    {
                        "id": "f-starttls-downgrade-stream-0",
                        "severity": "critical",
                        "category": "starttls_anomaly",
                        "title": "STARTTLS Downgrade / Stripping Detected",
                        "description": "STARTTLS was advertised by server, but session reverted to unencrypted cleartext SMTP commands without TLS.",
                        "evidence": {
                            "session_id": "stream-0",
                            "packet_numbers": [4, 6],
                            "field": "smtp.req.command",
                            "observed_value": "AUTH PLAIN",
                        },
                        "recommendation": "Enforce mandatory TLS (Reject plaintext fallback; implement MTA-STS / DANE).",
                        "cve_references": ["RFC 3207", "CVE-2014-3566"],
                        "is_ml_finding": False,
                    }
                ],
            },
            "curl_example": "curl -s 'http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/findings?severity=CRITICAL'",
        },
        {
            "id": "list_analyses",
            "group": "Analysis & Forensics",
            "method": "GET",
            "path": "/api/analyses",
            "summary": "List all active and cached analyses with summary metrics",
            "description": "Returns overview summary of all analysis runs stored in memory, including risk scores, posture levels, stream counts, and finding counts.",
            "parameters": [],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "list[AnalysisSummaryItem]",
                "shape": [
                    {
                        "analysis_id": "string",
                        "status": "string ('pending' | 'running' | 'done' | 'error')",
                        "pcap": "string | null",
                        "risk_score": "float | null",
                        "risk_level": "string | null",
                        "analyzed_at": "string (ISO 8601) | null",
                        "session_count": "integer",
                        "finding_count": "integer",
                        "packet_count": "integer",
                        "critical_count": "integer",
                        "high_count": "integer",
                        "sessions": "list[SessionSummaryItem]",
                    }
                ],
                "example": [
                    {
                        "analysis_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                        "status": "done",
                        "pcap": "01_enterprise_secure_baseline.pcap",
                        "risk_score": 99.0,
                        "risk_level": "MINIMAL",
                        "session_count": 3,
                        "finding_count": 0,
                    }
                ],
            },
            "curl_example": "curl -s http://localhost:8000/api/analyses",
        },
        # --- Reporting ---
        {
            "id": "report_json",
            "group": "Forensic Reports",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/report/json",
            "summary": "Download machine-readable JSON forensic report",
            "description": "Returns standardized JSON report artifact with analysis metadata, methodology disclaimers, and prioritized remediation directives.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "dict[string, any]",
                "shape": "Comprehensive JSON report with report_metadata, capture, sessions, findings, and score",
                "example": {
                    "report_metadata": {
                        "tool": "SecureMailScope",
                        "version": "0.1.0",
                        "disclaimer": "SecureMailScope Composite Risk Score is a prototype scoring methodology...",
                    },
                    "analysis_id": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                },
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/report/json",
        },
        {
            "id": "report_html",
            "group": "Forensic Reports",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/report/html",
            "summary": "Render standalone dark-mode HTML forensic dashboard",
            "description": "Generates a completely self-contained, publication-ready HTML dashboard report requiring zero external CDN dependencies.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "text/html",
                "model": "html",
                "shape": "HTML5 document string",
                "example": "<!DOCTYPE html><html>...</html>",
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/report/html > report.html",
        },
        {
            "id": "report_pdf",
            "group": "Forensic Reports",
            "method": "GET",
            "path": "/api/analysis/{analysis_id}/report/pdf",
            "summary": "Download compiled PDF executive forensic report",
            "description": "Streams binary PDF executive report compiled on the fly using Python ReportLab with tables, risk charts, and finding breakdowns.",
            "parameters": [
                {
                    "name": "analysis_id",
                    "in": "path",
                    "type": "string",
                    "required": True,
                    "description": "UUID of the analysis.",
                    "example": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/pdf",
                "model": "binary",
                "shape": "Binary PDF document stream",
                "example": "%PDF-1.4 ...",
            },
            "curl_example": "curl -s http://localhost:8000/api/analysis/f47ac10b-58cc-4372-a567-0e02b2c3d479/report/pdf -o report.pdf",
        },
        # --- System & Docs ---
        {
            "id": "health",
            "group": "System & Health",
            "method": "GET",
            "path": "/api/health",
            "summary": "System operational health check",
            "description": "Verifies API responsiveness, software version, TShark binary availability in system PATH, and cached analysis count.",
            "parameters": [],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json",
                "model": "HealthResponse",
                "shape": {
                    "status": "string ('ok')",
                    "version": "string (e.g. '0.1.0')",
                    "tshark_available": "boolean",
                    "analyses_cached": "integer",
                },
                "example": {
                    "status": "ok",
                    "version": "0.1.0",
                    "tshark_available": True,
                    "analyses_cached": 1,
                },
            },
            "curl_example": "curl -s http://localhost:8000/api/health",
        },
        {
            "id": "docs",
            "group": "System & Health",
            "method": "GET",
            "path": "/docs",
            "aliases": ["/api/docs", "/docs.json", "/api/docs.json"],
            "summary": "Interactive & machine-readable documentation & shape catalog",
            "description": (
                "Self-documenting schema endpoint. Returns rich structured JSON shape specifications "
                "for automated tools, coding agents, and SDK generators (?format=json or Accept: application/json), "
                "or interactive dark-mode HTML documentation for web browsers."
            ),
            "parameters": [
                {
                    "name": "format",
                    "in": "query",
                    "type": "string | null",
                    "required": False,
                    "description": "Explicit format override: 'json' (machine shape spec), 'html' (interactive UI), or 'openapi' (raw OpenAPI 3.1 JSON).",
                    "example": "json",
                }
            ],
            "request_body": None,
            "response": {
                "status_code": 200,
                "content_type": "application/json | text/html",
                "model": "ApiDocsCatalog | HTMLResponse",
                "shape": "Complete API catalog with parameter schemas, shapes, models, and examples",
                "example": {
                    "api": "SecureMailScope API",
                    "version": "0.1.0",
                    "endpoints": "list[EndpointSpec]",
                    "models": "dict[string, ModelSpec]",
                },
            },
            "curl_example": "curl -s http://localhost:8000/docs?format=json",
        },
    ],
    "models": {
        "PcapEntry": {
            "type": "object",
            "description": "Metadata descriptor for an available packet capture file.",
            "properties": {
                "filename": {"type": "string", "description": "Basename of PCAP file"},
                "title": {"type": "string", "description": "Human-readable scenario title"},
                "description": {
                    "type": "string",
                    "description": "Forensic description of scenario",
                },
                "category": {
                    "type": "string",
                    "description": "Scenario category classification",
                },
                "size_bytes": {"type": "integer", "description": "Size in bytes"},
                "sha256_hash": {
                    "type": "string",
                    "description": "SHA-256 cryptographic file checksum",
                },
                "download_url": {"type": "string", "description": "Endpoint to download raw file"},
                "analyse_url": {
                    "type": "string",
                    "description": "Endpoint to trigger async analysis",
                },
            },
            "required": [
                "filename",
                "title",
                "description",
                "category",
                "size_bytes",
                "sha256_hash",
                "download_url",
                "analyse_url",
            ],
        },
        "AnalysisStatus": {
            "type": "object",
            "description": "Status descriptor for an asynchronous PCAP analysis job.",
            "properties": {
                "analysis_id": {"type": "string", "description": "Unique UUIDv4 identifier"},
                "status": {
                    "type": "string",
                    "enum": ["pending", "running", "done", "error"],
                    "description": "Current processing state",
                },
                "error": {
                    "type": "string | null",
                    "description": "Error details if processing failed",
                },
            },
            "required": ["analysis_id", "status"],
        },
        "AnalysisSummaryItem": {
            "type": "object",
            "description": "Summary metrics for a cached analysis run.",
            "properties": {
                "analysis_id": {"type": "string"},
                "status": {"type": "string"},
                "pcap": {"type": "string | null"},
                "risk_score": {"type": "number | null"},
                "risk_level": {"type": "string | null"},
                "analyzed_at": {"type": "string | null"},
                "session_count": {"type": "integer"},
                "finding_count": {"type": "integer"},
                "packet_count": {"type": "integer"},
                "critical_count": {"type": "integer"},
                "high_count": {"type": "integer"},
                "sessions": {"type": "array", "items": {"$ref": "#/models/SessionSummaryItem"}},
            },
        },
        "SessionSummaryItem": {
            "type": "object",
            "description": "Brief 5-tuple summary for an active TCP session.",
            "properties": {
                "session_id": {"type": "string"},
                "protocol": {"type": "string"},
                "src_ip": {"type": "string"},
                "src_port": {"type": "integer"},
                "dst_ip": {"type": "string"},
                "dst_port": {"type": "integer"},
                "risk_level": {"type": "string | null"},
            },
        },
        "HealthResponse": {
            "type": "object",
            "description": "System operational status response.",
            "properties": {
                "status": {"type": "string", "example": "ok"},
                "version": {"type": "string", "example": "0.1.0"},
                "tshark_available": {"type": "boolean", "example": True},
                "analyses_cached": {"type": "integer", "example": 0},
            },
            "required": ["status", "version", "tshark_available", "analyses_cached"],
        },
        "DemoRunResponse": {
            "type": "object",
            "description": "Response when launching canonical benchmark demo analyses.",
            "properties": {
                "demo_analyses": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "analysis_id": {"type": "string"},
                            "pcap": {"type": "string"},
                        },
                    },
                }
            },
        },
        "AnalysisResult": {
            "type": "object",
            "description": "Top-level forensic analysis result containing all session data, findings, and posture score.",
            "properties": {
                "analysis_id": {"type": "string", "description": "Unique analysis run ID"},
                "capture": {"$ref": "#/models/CaptureMetadata"},
                "sessions": {"type": "array", "items": {"$ref": "#/models/TCPSession"}},
                "risk_score": {"$ref": "#/models/RiskScore"},
                "protocol_summary": {"$ref": "#/models/ProtocolSummary"},
                "all_findings": {"type": "array", "items": {"$ref": "#/models/Finding"}},
                "recommendations": {"type": "array", "items": {"type": "string"}},
                "limitations": {"type": "array", "items": {"type": "string"}},
                "processing_time_seconds": {"type": "number"},
            },
        },
        "TCPSession": {
            "type": "object",
            "description": "Reconstructed TCP conversation flow with protocol state and TLS telemetry.",
            "properties": {
                "session_id": {"type": "string", "description": "Unique stream identifier"},
                "src_ip": {"type": "string"},
                "src_port": {"type": "integer"},
                "dst_ip": {"type": "string"},
                "dst_port": {"type": "integer"},
                "protocol": {"type": "string", "enum": ["SMTP", "IMAP", "POP3", "UNKNOWN"]},
                "starttls_state": {
                    "type": "string",
                    "enum": [
                        "no_tls",
                        "advertised",
                        "requested",
                        "negotiated",
                        "failed",
                        "suspicious_fallback",
                        "direct_tls",
                    ],
                },
                "cleartext_auth_detected": {"type": "boolean"},
                "protocol_banners": {"type": "array", "items": {"type": "string"}},
                "tls_handshake": {"$ref": "#/models/TLSHandshake"},
                "findings": {"type": "array", "items": {"$ref": "#/models/Finding"}},
                "is_anomalous": {"type": "boolean | null"},
                "anomaly_score": {"type": "number | null"},
                "session_risk_score": {"type": "number | null"},
                "session_risk_level": {"type": "string | null"},
            },
        },
        "TLSHandshake": {
            "type": "object",
            "description": "Dissected TLS handshake parameters.",
            "properties": {
                "tls_version": {
                    "type": "string",
                    "enum": [
                        "SSL 2.0",
                        "SSL 3.0",
                        "TLS 1.0",
                        "TLS 1.1",
                        "TLS 1.2",
                        "TLS 1.3",
                        "Unknown",
                    ],
                },
                "cipher_suite": {"type": "string | null"},
                "cipher_suite_hex": {"type": "string | null"},
                "key_exchange": {"type": "string | null"},
                "forward_secrecy": {"type": "string", "enum": ["yes", "no", "unknown"]},
                "client_offered_ciphers": {"type": "array", "items": {"type": "string"}},
                "client_tls_extensions": {"type": "array", "items": {"type": "string"}},
                "certificates": {"type": "array", "items": {"$ref": "#/models/CertificateInfo"}},
                "cert_observability": {
                    "type": "string",
                    "enum": ["observed", "not_observable", "partially_observable"],
                },
                "cert_observability_note": {"type": "string | null"},
                "ja3_hash": {"type": "string | null"},
                "handshake_complete": {"type": "boolean"},
            },
        },
        "Finding": {
            "type": "object",
            "description": "Forensic vulnerability or compliance deviation.",
            "properties": {
                "id": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "category": {
                    "type": "string",
                    "enum": [
                        "deprecated_tls",
                        "weak_cipher",
                        "weak_key",
                        "weak_signature",
                        "expired_certificate",
                        "invalid_certificate",
                        "no_forward_secrecy",
                        "starttls_anomaly",
                        "plaintext_auth",
                        "ml_anomaly",
                        "configuration",
                        "info",
                    ],
                },
                "title": {"type": "string"},
                "description": {"type": "string"},
                "evidence": {"$ref": "#/models/Evidence"},
                "recommendation": {"type": "string"},
                "cve_references": {"type": "array", "items": {"type": "string"}},
                "is_ml_finding": {"type": "boolean"},
            },
        },
        "Evidence": {
            "type": "object",
            "description": "Traceable forensic provenance for a finding.",
            "properties": {
                "session_id": {"type": "string"},
                "pcap_file": {"type": "string"},
                "packet_numbers": {"type": "array", "items": {"type": "integer"}},
                "field": {"type": "string | null"},
                "observed_value": {"type": "any | null"},
                "extra": {"type": "object"},
            },
        },
        "CertificateInfo": {
            "type": "object",
            "description": "Parsed X.509 certificate metadata.",
            "properties": {
                "fingerprint_sha256": {"type": "string"},
                "subject_cn": {"type": "string | null"},
                "issuer_cn": {"type": "string | null"},
                "san": {"type": "array", "items": {"type": "string"}},
                "not_before": {"type": "string (ISO 8601) | null"},
                "not_after": {"type": "string (ISO 8601) | null"},
                "is_expired": {"type": "boolean | null"},
                "days_until_expiry": {"type": "integer | null"},
                "is_self_signed": {"type": "boolean | null"},
                "signature_algorithm": {"type": "string | null"},
                "serial_number": {"type": "string | null"},
            },
        },
        "RiskScore": {
            "type": "object",
            "description": "SecureMailScope Composite Risk Score.",
            "properties": {
                "score": {"type": "number", "minimum": 0.0, "maximum": 100.0},
                "level": {
                    "type": "string",
                    "enum": ["MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                },
                "rationale": {"type": "array", "items": {"type": "string"}},
                "critical_count": {"type": "integer"},
                "high_count": {"type": "integer"},
                "medium_count": {"type": "integer"},
                "low_count": {"type": "integer"},
                "ml_anomaly_count": {"type": "integer"},
            },
        },
    },
}


# ---------------------------------------------------------------------------
# Interactive HTML Documentation Renderer
# ---------------------------------------------------------------------------


def render_docs_html(spec: dict[str, Any] = API_SPEC_CATALOG) -> str:
    """Renders a self-contained, aesthetic, dark-mode interactive HTML API reference."""
    endpoints = spec.get("endpoints", [])
    models = spec.get("models", {})

    # Group endpoints by group
    groups: dict[str, list[dict[str, Any]]] = {}
    for ep in endpoints:
        grp = ep.get("group", "General")
        groups.setdefault(grp, []).append(ep)

    nav_links_html = []
    content_html = []

    for grp, eps in groups.items():
        nav_links_html.append(f'<div class="nav-group-title">{grp}</div>')
        for ep in eps:
            ep_id = ep["id"]
            method = ep["method"]
            path = ep["path"]
            nav_links_html.append(
                f'<a href="#{ep_id}" class="nav-item">'
                f'<span class="badge badge-{method.lower()}">{method}</span>'
                f'<span class="nav-path">{path}</span>'
                f"</a>"
            )

            # Build endpoint section
            params = ep.get("parameters", [])
            params_html = ""
            if params:
                params_rows = "".join(
                    f"<tr>"
                    f"<td><code>{p['name']}</code></td>"
                    f'<td><span class="type-tag">{p.get("type", "string")}</span></td>'
                    f'<td><span class="badge badge-{"req" if p.get("required") else "opt"}">{"Required" if p.get("required") else "Optional"}</span></td>'
                    f"<td>{p.get('description', '')}</td>"
                    f"</tr>"
                    for p in params
                )
                params_html = f"""
                <div class="section-block">
                    <div class="section-label">Parameters</div>
                    <table class="spec-table">
                        <thead><tr><th>Name</th><th>Type</th><th>Requirement</th><th>Description</th></tr></thead>
                        <tbody>{params_rows}</tbody>
                    </table>
                </div>
                """

            # Request Body
            req_body = ep.get("request_body")
            req_body_html = ""
            if req_body:
                ct = req_body.get("content_type", "application/json")
                shape_str = json.dumps(req_body.get("shape", req_body.get("fields", {})), indent=2)
                example_str = (
                    json.dumps(req_body.get("example"), indent=2) if req_body.get("example") else ""
                )
                example_block = (
                    f'<div class="code-sublabel">Example Payload:</div><pre><code>{example_str}</code></pre>'
                    if example_str
                    else ""
                )
                req_body_html = f"""
                <div class="section-block">
                    <div class="section-label">Request Body <span class="content-type">({ct})</span></div>
                    <div class="code-sublabel">Shape Definition:</div>
                    <pre><code>{shape_str}</code></pre>
                    {example_block}
                </div>
                """

            # Response
            resp = ep.get("response", {})
            status_code = resp.get("status_code", 200)
            resp_ct = resp.get("content_type", "application/json")
            resp_model = resp.get("model", "Object")
            resp_shape = resp.get("shape", {})
            resp_shape_str = (
                json.dumps(resp_shape, indent=2)
                if isinstance(resp_shape, (dict, list))
                else str(resp_shape)
            )
            resp_example = resp.get("example", {})
            resp_example_str = (
                json.dumps(resp_example, indent=2)
                if isinstance(resp_example, (dict, list))
                else str(resp_example)
            )

            aliases_html = ""
            if ep.get("aliases"):
                alias_badges = " ".join(f"<code>{a}</code>" for a in ep["aliases"])
                aliases_html = f'<div class="endpoint-aliases">Aliases: {alias_badges}</div>'

            curl_cmd = ep.get("curl_example", f"curl http://localhost:8000{path}")

            content_html.append(
                f"""
                <article class="endpoint-card" id="{ep_id}">
                    <div class="endpoint-header">
                        <span class="badge badge-{method.lower()} method-lg">{method}</span>
                        <h3 class="endpoint-path">{path}</h3>
                        <span class="badge badge-status">HTTP {status_code}</span>
                    </div>
                    {aliases_html}
                    <div class="endpoint-summary">{ep.get("summary", "")}</div>
                    <p class="endpoint-desc">{ep.get("description", "")}</p>

                    {params_html}
                    {req_body_html}

                    <div class="section-block">
                        <div class="section-label">
                            Response Shape
                            <span class="content-type">({resp_ct})</span>
                            <span class="model-tag">Model: {resp_model}</span>
                        </div>
                        <div class="code-sublabel">Schema & Shape:</div>
                        <pre><code>{resp_shape_str}</code></pre>
                        <div class="code-sublabel">Concrete Example:</div>
                        <pre><code>{resp_example_str}</code></pre>
                    </div>

                    <div class="section-block">
                        <div class="section-label">Curl Execution</div>
                        <div class="curl-box">
                            <pre><code>{curl_cmd}</code></pre>
                            <button class="copy-btn" onclick="copyText('{curl_cmd}')">Copy</button>
                        </div>
                    </div>
                </article>
                """
            )

    # Models section
    models_nav = '<div class="nav-group-title">Data Models & Schemas</div>'
    models_content = []
    for m_name, m_spec in models.items():
        m_slug = f"model-{m_name.lower()}"
        models_nav += f'<a href="#{m_slug}" class="nav-item"><span class="badge badge-model">TYPE</span><span class="nav-path">{m_name}</span></a>'
        props = m_spec.get("properties", {})
        props_rows = "".join(
            f'<tr><td><code>{p_name}</code></td><td><span class="type-tag">{p_info.get("type", p_info.get("$ref", "any"))}</span></td><td>{p_info.get("description", "")}</td></tr>'
            for p_name, p_info in props.items()
        )
        models_content.append(
            f"""
            <article class="endpoint-card model-card" id="{m_slug}">
                <div class="endpoint-header">
                    <span class="badge badge-model method-lg">MODEL</span>
                    <h3 class="endpoint-path">{m_name}</h3>
                </div>
                <p class="endpoint-desc">{m_spec.get("description", "")}</p>
                <table class="spec-table">
                    <thead><tr><th>Property</th><th>Type</th><th>Description</th></tr></thead>
                    <tbody>{props_rows}</tbody>
                </table>
            </article>
            """
        )

    nav_links_joined = "\n".join(nav_links_html) + "\n" + models_nav
    endpoints_joined = "\n".join(content_html)
    models_joined = "\n".join(models_content)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope API Documentation & Shape Reference</title>
    <style>
        :root {{
            --bg-canvas: #080c14;
            --bg-card: #0f172a;
            --bg-card-hover: #1e293b;
            --bg-code: #030712;
            --border-color: #1e293b;
            --border-highlight: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-cyan: #06b6d4;
            --accent-blue: #3b82f6;
            --accent-emerald: #10b981;
            --accent-amber: #f59e0b;
            --accent-rose: #f43f5e;
            --accent-violet: #8b5cf6;
            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Inter", Helvetica, Arial, sans-serif;
            --font-mono: "JetBrains Mono", "SF Mono", Consolas, "Liberation Mono", Menlo, monospace;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            background: var(--bg-canvas);
            color: var(--text-main);
            font-family: var(--font-sans);
            line-height: 1.6;
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }}
        /* Header */
        header {{
            background: #0b1120;
            border-bottom: 1px solid var(--border-color);
            position: sticky;
            top: 0;
            z-index: 100;
            padding: 1rem 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        .brand {{
            display: flex;
            align-items: center;
            gap: 1rem;
        }}
        .brand-logo {{
            width: 34px;
            height: 34px;
            background: linear-gradient(135deg, var(--accent-cyan), var(--accent-blue));
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 800;
            color: #030712;
            font-size: 1.1rem;
        }}
        .brand-title {{
            font-size: 1.15rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }}
        .brand-version {{
            font-size: 0.75rem;
            color: var(--accent-cyan);
            background: rgba(6, 182, 212, 0.1);
            border: 1px solid rgba(6, 182, 212, 0.25);
            padding: 0.15rem 0.5rem;
            border-radius: 4px;
            margin-left: 0.5rem;
            font-family: var(--font-mono);
        }}
        .header-actions {{
            display: flex;
            gap: 0.75rem;
            align-items: center;
        }}
        .btn {{
            font-size: 0.85rem;
            font-weight: 500;
            padding: 0.45rem 0.85rem;
            border-radius: 6px;
            text-decoration: none;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            gap: 0.4rem;
        }}
        .btn-outline {{
            background: rgba(255, 255, 255, 0.05);
            color: var(--text-main);
            border: 1px solid var(--border-color);
        }}
        .btn-outline:hover {{
            background: rgba(255, 255, 255, 0.1);
            border-color: var(--accent-cyan);
            color: var(--accent-cyan);
        }}
        .btn-primary {{
            background: var(--accent-cyan);
            color: #030712;
            border: 1px solid var(--accent-cyan);
            font-weight: 600;
        }}
        .btn-primary:hover {{
            background: #22d3ee;
        }}

        /* Main Workspace Layout */
        .workspace {{
            display: flex;
            flex: 1;
        }}
        .sidebar {{
            width: 320px;
            background: #090e1a;
            border-right: 1px solid var(--border-color);
            position: sticky;
            top: 65px;
            height: calc(100vh - 65px);
            overflow-y: auto;
            padding: 1.5rem 1rem;
        }}
        .search-box {{
            margin-bottom: 1.25rem;
        }}
        .search-box input {{
            width: 100%;
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            color: var(--text-main);
            padding: 0.5rem 0.75rem;
            font-size: 0.85rem;
            outline: none;
        }}
        .search-box input:focus {{
            border-color: var(--accent-cyan);
        }}
        .nav-group-title {{
            font-size: 0.72rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--text-muted);
            font-weight: 700;
            margin: 1.25rem 0 0.5rem 0.25rem;
        }}
        .nav-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.4rem 0.5rem;
            border-radius: 6px;
            color: #cbd5e1;
            text-decoration: none;
            font-size: 0.82rem;
            transition: background 0.15s ease;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        .nav-item:hover {{
            background: var(--bg-card-hover);
            color: #fff;
        }}
        .nav-path {{
            font-family: var(--font-mono);
            overflow: hidden;
            text-overflow: ellipsis;
        }}

        /* Content Area */
        .content {{
            flex: 1;
            padding: 2.5rem 3.5rem;
            max-width: 1100px;
            overflow-y: auto;
        }}
        .overview-hero {{
            margin-bottom: 3rem;
            padding-bottom: 2rem;
            border-bottom: 1px solid var(--border-color);
        }}
        .overview-hero h1 {{
            font-size: 2.1rem;
            font-weight: 800;
            letter-spacing: -0.03em;
            margin-bottom: 0.75rem;
        }}
        .overview-hero p {{
            font-size: 1.05rem;
            color: var(--text-muted);
            max-width: 800px;
        }}
        .badge-bar {{
            display: flex;
            gap: 0.6rem;
            margin-top: 1.25rem;
        }}
        .spec-pill {{
            font-size: 0.8rem;
            font-family: var(--font-mono);
            background: rgba(255, 255, 255, 0.04);
            border: 1px solid var(--border-color);
            padding: 0.25rem 0.65rem;
            border-radius: 9999px;
            color: #cbd5e1;
        }}

        /* Endpoint Cards */
        .endpoint-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 1.75rem;
            margin-bottom: 2rem;
            scroll-margin-top: 90px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.25);
        }}
        .endpoint-header {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 0.75rem;
        }}
        .endpoint-path {{
            font-family: var(--font-mono);
            font-size: 1.15rem;
            font-weight: 700;
            color: #f1f5f9;
        }}
        .endpoint-aliases {{
            font-size: 0.78rem;
            color: var(--text-muted);
            margin-bottom: 0.75rem;
            font-family: var(--font-mono);
        }}
        .endpoint-summary {{
            font-size: 1rem;
            font-weight: 600;
            color: #e2e8f0;
            margin-bottom: 0.35rem;
        }}
        .endpoint-desc {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-bottom: 1.25rem;
        }}

        /* Badges */
        .badge {{
            font-family: var(--font-mono);
            font-size: 0.7rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 4px;
            text-transform: uppercase;
        }}
        .method-lg {{
            font-size: 0.85rem;
            padding: 0.3rem 0.65rem;
        }}
        .badge-get {{ background: rgba(16, 185, 129, 0.15); color: var(--accent-emerald); border: 1px solid rgba(16, 185, 129, 0.3); }}
        .badge-post {{ background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.3); }}
        .badge-model {{ background: rgba(139, 92, 246, 0.15); color: var(--accent-violet); border: 1px solid rgba(139, 92, 246, 0.3); }}
        .badge-status {{ background: rgba(255, 255, 255, 0.05); color: #94a3b8; border: 1px solid var(--border-color); margin-left: auto; }}
        .badge-req {{ background: rgba(244, 63, 94, 0.15); color: var(--accent-rose); border: 1px solid rgba(244, 63, 94, 0.3); }}
        .badge-opt {{ background: rgba(148, 163, 184, 0.1); color: var(--text-muted); border: 1px solid var(--border-color); }}
        .type-tag {{ font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-cyan); }}
        .model-tag {{ font-family: var(--font-mono); font-size: 0.8rem; color: var(--accent-violet); margin-left: 0.5rem; }}

        /* Sections & Tables */
        .section-block {{
            margin-top: 1.25rem;
            padding-top: 1rem;
            border-top: 1px solid var(--border-color);
        }}
        .section-label {{
            font-size: 0.82rem;
            text-transform: uppercase;
            letter-spacing: 0.06em;
            color: #94a3b8;
            font-weight: 700;
            margin-bottom: 0.65rem;
            display: flex;
            align-items: center;
        }}
        .content-type {{
            font-family: var(--font-mono);
            font-size: 0.75rem;
            color: #64748b;
            margin-left: 0.5rem;
            text-transform: none;
        }}
        .code-sublabel {{
            font-size: 0.75rem;
            color: #64748b;
            font-weight: 600;
            margin: 0.6rem 0 0.25rem 0.2rem;
            font-family: var(--font-mono);
        }}
        .spec-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85rem;
            margin-bottom: 0.75rem;
        }}
        .spec-table th, .spec-table td {{
            padding: 0.6rem 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}
        .spec-table th {{
            color: var(--text-muted);
            font-weight: 600;
            font-size: 0.75rem;
            text-transform: uppercase;
        }}
        pre {{
            background: var(--bg-code);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 0.85rem 1rem;
            overflow-x: auto;
            font-family: var(--font-mono);
            font-size: 0.82rem;
            color: #e2e8f0;
            margin-bottom: 0.75rem;
        }}
        code {{
            font-family: var(--font-mono);
        }}
        .curl-box {{
            position: relative;
        }}
        .curl-box pre {{
            margin-bottom: 0;
            padding-right: 5rem;
        }}
        .copy-btn {{
            position: absolute;
            top: 8px;
            right: 8px;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--border-color);
            color: #cbd5e1;
            border-radius: 4px;
            padding: 0.25rem 0.6rem;
            font-size: 0.72rem;
            cursor: pointer;
            font-family: var(--font-mono);
            transition: all 0.2s ease;
        }}
        .copy-btn:hover {{
            background: var(--accent-cyan);
            color: #030712;
            border-color: var(--accent-cyan);
        }}

        /* Toast */
        #toast {{
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            background: var(--accent-cyan);
            color: #030712;
            font-weight: 600;
            padding: 0.6rem 1.2rem;
            border-radius: 6px;
            font-size: 0.85rem;
            display: none;
            box-shadow: 0 4px 15px rgba(6, 182, 212, 0.4);
            z-index: 1000;
        }}
    </style>
</head>
<body>
    <header>
        <div class="brand">
            <div class="brand-logo">SM</div>
            <div class="brand-title">SecureMailScope API<span class="brand-version">v0.1.0</span></div>
        </div>
        <div class="header-actions">
            <a href="/docs?format=json" class="btn btn-outline" target="_blank">Raw JSON Spec</a>
            <a href="/openapi.json" class="btn btn-outline" target="_blank">OpenAPI 3.1</a>
            <a href="/redoc" class="btn btn-outline" target="_blank">ReDoc</a>
            <a href="/api/health" class="btn btn-outline" target="_blank">Health</a>
        </div>
    </header>

    <div class="workspace">
        <aside class="sidebar">
            <div class="search-box">
                <input type="text" id="endpointSearch" placeholder="Filter endpoints & models..." onkeyup="filterEndpoints()">
            </div>
            <nav id="sidebarNav">
                {nav_links_joined}
            </nav>
        </aside>

        <main class="content">
            <section class="overview-hero">
                <h1>Forensic API Reference & Shape Catalog</h1>
                <p>
                    Interactive specifications and data contract shapes for tools, AI agents, and security automation
                    consuming the SecureMailScope passive network forensic service.
                </p>
                <div class="badge-bar">
                    <span class="spec-pill">RFC 5321 (SMTP)</span>
                    <span class="spec-pill">RFC 3501 (IMAP)</span>
                    <span class="spec-pill">RFC 1939 (POP3)</span>
                    <span class="spec-pill">RFC 8446 (TLS 1.3)</span>
                    <span class="spec-pill">Isolation Forest (16-D ML)</span>
                    <span class="spec-pill">ReportLab Forensic PDF</span>
                </div>
            </section>

            <section id="endpointsList">
                {endpoints_joined}
            </section>

            <section id="modelsList">
                <div class="overview-hero" style="margin-top: 4rem;">
                    <h1>Core Data Models & Pydantic Schemas</h1>
                    <p>Internal type definitions flowing through forensic state machines and analysis pipelines.</p>
                </div>
                {models_joined}
            </section>
        </main>
    </div>

    <div id="toast">Copied to clipboard!</div>

    <script>
        function copyText(txt) {{
            navigator.clipboard.writeText(txt).then(() => {{
                const toast = document.getElementById('toast');
                toast.style.display = 'block';
                setTimeout(() => {{ toast.style.display = 'none'; }}, 2000);
            }});
        }}

        function filterEndpoints() {{
            const val = document.getElementById('endpointSearch').value.toLowerCase();
            const items = document.querySelectorAll('.nav-item');
            const cards = document.querySelectorAll('.endpoint-card');

            items.forEach(el => {{
                const match = el.textContent.toLowerCase().includes(val);
                el.style.display = match ? 'flex' : 'none';
            }});

            cards.forEach(card => {{
                const match = card.textContent.toLowerCase().includes(val);
                card.style.display = match ? 'block' : 'none';
            }});
        }}
    </script>
</body>
</html>"""
