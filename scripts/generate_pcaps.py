#!/usr/bin/env python3
"""
SecureMailScope — Synthetic PCAP Generator (Scapy Engine)
Generates 5 consolidated multi-session PCAP files covering all protocols,
cryptographic baselines, legacy algorithms, certificate failures, active attacks,
protocol fuzzing, and real-world network transport edge cases.

Consolidated Scenarios (5 Files Total):
  01_enterprise_secure_baseline.pcap       – TLS 1.2/1.3, ECDHE, AES-GCM, Valid Certs, IMAPS/POP3S/SMTP
  02_legacy_cryptography_and_certs.pcap    – TLS 1.0, 3DES, Static RSA (No FS), Expired Cert, 1024-bit RSA
  03_starttls_downgrade_and_cleartext.pcap – MITM 454 Fallback, Stripped STARTTLS, Plaintext Auth
  04_protocol_anomalies_and_fuzzing.pcap   – HTTP Probes, Buffer Fuzzing, Corrupt TLS Records, Split Hello
  05_realworld_network_transports.pcap     – Packet Loss, RST, Truncated Certs, TCP Out-of-Order, SYN Scan
"""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from scapy.all import IP, TCP, Ether, wrpcap
from scapy.layers.tls.all import (
    TLS,
    ServerName,
    TLS_Ext_ServerName,
    TLS_Ext_SupportedVersion_CH,
    TLS_Ext_SupportedVersion_SH,
    TLSCertificate,
    TLSClientHello,
    TLSServerHello,
    TLSServerHelloDone,
)

DEMO_DIR = Path(__file__).parent.parent / "demo_pcaps"
CERTS_DIR = DEMO_DIR / "_certs"


# ---------------------------------------------------------------------------
# Certificate Generation
# ---------------------------------------------------------------------------


def setup_ca() -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    CERTS_DIR.mkdir(parents=True, exist_ok=True)
    ca_key_path = CERTS_DIR / "ca.key"
    ca_crt_path = CERTS_DIR / "ca.crt"

    if ca_key_path.exists() and ca_crt_path.exists():
        ca_key = serialization.load_pem_private_key(ca_key_path.read_bytes(), password=None)
        ca_cert = x509.load_pem_x509_certificate(ca_crt_path.read_bytes())
        return ca_key, ca_cert

    ca_key = rsa.generate_private_key(65537, 2048)
    ca_subject = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "SecureMailScope Root CA")]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.UTC))
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(
        ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    ca_crt_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_key, ca_cert


def generate_cert(
    name: str,
    cn: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    key_size: int = 2048,
    expired: bool = False,
    serial_number: int = 100,
) -> bytes:
    key_path = CERTS_DIR / f"{name}.key"
    crt_path = CERTS_DIR / f"{name}.crt"

    key = rsa.generate_private_key(65537, key_size)
    subj = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])

    if expired:
        nb = datetime.datetime(2019, 1, 1, tzinfo=datetime.UTC)
        na = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    else:
        nb = datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC)
        na = datetime.datetime(2028, 1, 1, tzinfo=datetime.UTC)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(nb)
        .not_valid_after(na)
        .sign(ca_key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.public_bytes(serialization.Encoding.DER)


def generate_self_signed_cert(
    name: str,
    cn: str,
    key_size: int = 1024,
    hash_algo=hashes.SHA256(),
    serial_number: int = 999,
) -> bytes:
    key_path = CERTS_DIR / f"{name}.key"
    crt_path = CERTS_DIR / f"{name}.crt"

    key = rsa.generate_private_key(65537, key_size)
    subj = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])

    nb = datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC)
    na = datetime.datetime(2030, 1, 1, tzinfo=datetime.UTC)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subj)
        .issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(serial_number)
        .not_valid_before(nb)
        .not_valid_after(na)
        .sign(key, hash_algo)
    )

    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert.public_bytes(serialization.Encoding.DER)


# ---------------------------------------------------------------------------
# Stream Tracker Helper (guarantees zero TCP seq/ack gaps)
# ---------------------------------------------------------------------------


class TCPStreamTracker:
    def __init__(
        self,
        sport: int,
        dport: int,
        cli_ip: str = "192.168.1.100",
        srv_ip: str = "192.168.1.10",
        base_c: int = 1000,
        base_s: int = 2000,
    ):
        self.sport = sport
        self.dport = dport
        self.cli_ip = cli_ip
        self.srv_ip = srv_ip
        self.seq_c = base_c
        self.seq_s = base_s
        self.pkts: list[Any] = []

        self.eth_c2s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        self.eth_s2c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
        self.ip_c2s = IP(src=cli_ip, dst=srv_ip)
        self.ip_s2c = IP(src=srv_ip, dst=cli_ip)

        # 3-way handshake
        self.pkts.append(
            self.eth_c2s / self.ip_c2s / TCP(sport=sport, dport=dport, flags="S", seq=self.seq_c)
        )
        self.pkts.append(
            self.eth_s2c
            / self.ip_s2c
            / TCP(sport=dport, dport=sport, flags="SA", seq=self.seq_s, ack=self.seq_c + 1)
        )
        self.seq_c += 1
        self.seq_s += 1
        self.pkts.append(
            self.eth_c2s
            / self.ip_c2s
            / TCP(sport=sport, dport=dport, flags="A", seq=self.seq_c, ack=self.seq_s)
        )

    def send_c2s(self, payload: bytes | Any, flags="PA"):
        raw = bytes(payload)
        self.pkts.append(
            self.eth_c2s
            / self.ip_c2s
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags=flags,
                seq=self.seq_c,
                ack=self.seq_s,
            )
            / payload
        )
        self.seq_c += len(raw)

    def send_s2c(self, payload: bytes | Any, flags="PA"):
        raw = bytes(payload)
        self.pkts.append(
            self.eth_s2c
            / self.ip_s2c
            / TCP(
                sport=self.dport,
                dport=self.sport,
                flags=flags,
                seq=self.seq_s,
                ack=self.seq_c,
            )
            / payload
        )
        self.seq_s += len(raw)

    def ack_c2s(self):
        self.pkts.append(
            self.eth_c2s
            / self.ip_c2s
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags="A",
                seq=self.seq_c,
                ack=self.seq_s,
            )
        )

    def ack_s2c(self):
        self.pkts.append(
            self.eth_s2c
            / self.ip_s2c
            / TCP(
                sport=self.dport,
                dport=self.sport,
                flags="A",
                seq=self.seq_s,
                ack=self.seq_c,
            )
        )

    def rst_c2s(self):
        self.pkts.append(
            self.eth_c2s
            / self.ip_c2s
            / TCP(
                sport=self.sport,
                dport=self.dport,
                flags="R",
                seq=self.seq_c,
                ack=self.seq_s,
            )
        )

    def rst_s2c(self):
        self.pkts.append(
            self.eth_s2c
            / self.ip_s2c
            / TCP(
                sport=self.dport,
                dport=self.sport,
                flags="R",
                seq=self.seq_s,
                ack=self.seq_c,
            )
        )


# ---------------------------------------------------------------------------
# Consolidated Scenario 1: Enterprise Secure Baseline
# ---------------------------------------------------------------------------


def scenario_01_enterprise_secure_baseline(ca_key, ca_cert):
    """
    01_enterprise_secure_baseline.pcap
    Multi-session capture of modern, compliant enterprise email services:
      - Stream 1: SMTP Submission (Port 587) with STARTTLS & TLS 1.3 (RFC 8446 Encrypted Certs)
      - Stream 2: IMAPS (Port 993) Direct TLS 1.2 with ECDHE-RSA-AES256-GCM + Valid CA Cert
      - Stream 3: POP3S (Port 995) Direct TLS 1.2 with ECDHE-RSA-AES128-GCM + Clean Session
    """
    print("  [01] Generating 01_enterprise_secure_baseline.pcap ...")
    pkts = []

    # Stream 1: SMTP Submission 587 with STARTTLS + TLS 1.3
    t1 = TCPStreamTracker(51001, 587, cli_ip="10.0.1.50", srv_ip="10.0.1.10")
    t1.send_s2c(b"220 smtp.corp.enterprise.com ESMTP Postfix\r\n")
    t1.send_c2s(b"EHLO mail-client.corp.enterprise.com\r\n")
    t1.send_s2c(b"250-smtp.corp.enterprise.com\r\n250-STARTTLS\r\n250-8BITMIME\r\n250 OK\r\n")
    t1.send_c2s(b"STARTTLS\r\n")
    t1.send_s2c(b"220 2.0.0 Ready to start TLS\r\n")

    ch1 = TLS(
        msg=[
            TLSClientHello(
                version=0x0303,
                ciphers=[0x1302, 0x1301, 0x1303, 0xC02F, 0xC030],
                ext=[
                    TLS_Ext_ServerName(
                        servernames=[ServerName(servername=b"smtp.corp.enterprise.com")]
                    ),
                    TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303]),
                ],
            )
        ]
    )
    t1.send_c2s(ch1)
    sh1 = TLS(
        msg=[
            TLSServerHello(
                version=0x0303,
                cipher=0x1302,  # TLS_AES_256_GCM_SHA384
                ext=[TLS_Ext_SupportedVersion_SH(version=0x0304)],
            )
        ]
    )
    t1.send_s2c(sh1)
    # Encrypted TLS 1.3 records (RFC 8446 §4.4.2 encrypted certificates)
    t1.send_s2c(b"\x17\x03\x03\x00\x60" + (b"\x13\x37" * 48))
    pkts.extend(t1.pkts)

    # Stream 2: IMAPS 993 Direct TLS 1.2
    cert_imap = generate_cert(
        "imap_secure", "imap.corp.enterprise.com", ca_key, ca_cert, 2048, serial_number=201
    )
    t2 = TCPStreamTracker(51002, 993, cli_ip="10.0.1.51", srv_ip="10.0.1.10")
    ch2 = TLS(
        msg=[
            TLSClientHello(
                version=0x0303,
                ciphers=[0xC030, 0xC02F, 0xCCA8],
                ext=[
                    TLS_Ext_ServerName(
                        servernames=[ServerName(servername=b"imap.corp.enterprise.com")]
                    )
                ],
            )
        ]
    )
    t2.send_c2s(ch2)
    sh2 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC030),
            TLSCertificate(certs=[(len(cert_imap), cert_imap)]),
            TLSServerHelloDone(),
        ]
    )
    t2.send_s2c(sh2)
    pkts.extend(t2.pkts)

    # Stream 3: POP3S 995 Direct TLS 1.2
    cert_pop = generate_cert(
        "pop_secure", "pop.corp.enterprise.com", ca_key, ca_cert, 2048, serial_number=202
    )
    t3 = TCPStreamTracker(51003, 995, cli_ip="10.0.1.52", srv_ip="10.0.1.10")
    ch3 = TLS(
        msg=[
            TLSClientHello(
                version=0x0303,
                ciphers=[0xC02F, 0xCCA8],
                ext=[
                    TLS_Ext_ServerName(
                        servernames=[ServerName(servername=b"pop.corp.enterprise.com")]
                    )
                ],
            )
        ]
    )
    t3.send_c2s(ch3)
    sh3 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert_pop), cert_pop)]),
            TLSServerHelloDone(),
        ]
    )
    t3.send_s2c(sh3)
    pkts.extend(t3.pkts)

    wrpcap(str(DEMO_DIR / "01_enterprise_secure_baseline.pcap"), pkts)


# ---------------------------------------------------------------------------
# Consolidated Scenario 2: Legacy Cryptography & Certificate Failures
# ---------------------------------------------------------------------------


def scenario_02_legacy_cryptography_and_certs(ca_key, ca_cert):
    """
    02_legacy_cryptography_and_certs.pcap
    Multi-session capture of cryptographic vulnerabilities and hygiene failures:
      - Stream 1: SMTP (Port 25) with Deprecated TLS 1.0 (BEAST CVE-2011-3389)
      - Stream 2: SMTPS (Port 465) with 3DES & Static RSA (No Forward Secrecy, Sweet32)
      - Stream 3: IMAPS (Port 993) with Expired X.509 Certificate
      - Stream 4: POP3S (Port 995) with Self-Signed Certificate & Weak 1024-bit RSA Key
    """
    print("  [02] Generating 02_legacy_cryptography_and_certs.pcap ...")
    pkts = []

    # Stream 1: SMTP 25 with Deprecated TLS 1.0
    cert_legacy = generate_cert(
        "legacy_tls10", "mail.legacy.org", ca_key, ca_cert, 2048, serial_number=101
    )
    t1 = TCPStreamTracker(52001, 25, cli_ip="10.0.2.50", srv_ip="10.0.2.10")
    t1.send_s2c(b"220 mail.legacy.org ESMTP\r\n")
    t1.send_c2s(b"EHLO legacy-client\r\n")
    t1.send_s2c(b"250-mail.legacy.org\r\n250-STARTTLS\r\n250 OK\r\n")
    t1.send_c2s(b"STARTTLS\r\n")
    t1.send_s2c(b"220 2.0.0 Ready to start TLS\r\n")
    ch1 = TLS(msg=[TLSClientHello(version=0x0301, ciphers=[0x002F, 0x0035])])
    t1.send_c2s(ch1)
    sh1 = TLS(
        msg=[
            TLSServerHello(version=0x0301, cipher=0x002F),  # TLS_RSA_WITH_AES_128_CBC_SHA
            TLSCertificate(certs=[(len(cert_legacy), cert_legacy)]),
            TLSServerHelloDone(),
        ]
    )
    t1.send_s2c(sh1)
    pkts.extend(t1.pkts)

    # Stream 2: SMTPS 465 with 3DES & Static RSA (No FS)
    cert_weak_cipher = generate_cert(
        "weak_3des", "secure.legacy.org", ca_key, ca_cert, 2048, serial_number=102
    )
    t2 = TCPStreamTracker(52002, 465, cli_ip="10.0.2.51", srv_ip="10.0.2.10")
    ch2 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x000A])])  # 3DES
    t2.send_c2s(ch2)
    sh2 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0x000A),  # TLS_RSA_WITH_3DES_EDE_CBC_SHA
            TLSCertificate(certs=[(len(cert_weak_cipher), cert_weak_cipher)]),
            TLSServerHelloDone(),
        ]
    )
    t2.send_s2c(sh2)
    pkts.extend(t2.pkts)

    # Stream 3: IMAPS 993 with Expired Certificate
    cert_expired = generate_cert(
        "expired_imap", "imap.legacy.org", ca_key, ca_cert, 2048, expired=True, serial_number=103
    )
    t3 = TCPStreamTracker(52003, 993, cli_ip="10.0.2.52", srv_ip="10.0.2.10")
    ch3 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F])])
    t3.send_c2s(ch3)
    sh3 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert_expired), cert_expired)]),
            TLSServerHelloDone(),
        ]
    )
    t3.send_s2c(sh3)
    pkts.extend(t3.pkts)

    # Stream 4: POP3S 995 with Self-Signed Certificate & Weak 1024-bit RSA
    cert_self_signed = generate_self_signed_cert(
        "self_signed_1024", "pop.legacy.org", key_size=1024, serial_number=104
    )
    t4 = TCPStreamTracker(52004, 995, cli_ip="10.0.2.53", srv_ip="10.0.2.10")
    ch4 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x0035, 0x002F])])
    t4.send_c2s(ch4)
    sh4 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0x0035),
            TLSCertificate(certs=[(len(cert_self_signed), cert_self_signed)]),
            TLSServerHelloDone(),
        ]
    )
    t4.send_s2c(sh4)
    pkts.extend(t4.pkts)

    wrpcap(str(DEMO_DIR / "02_legacy_cryptography_and_certs.pcap"), pkts)


# ---------------------------------------------------------------------------
# Consolidated Scenario 3: STARTTLS Downgrade & Cleartext Exfiltration
# ---------------------------------------------------------------------------


def scenario_03_starttls_downgrade_and_cleartext():
    """
    03_starttls_downgrade_and_cleartext.pcap
    Multi-session capture of active tampering and unencrypted authentication:
      - Stream 1: SMTP (Port 25) STARTTLS Stripping & 454 Fallback to Cleartext AUTH LOGIN
      - Stream 2: IMAP (Port 143) STARTTLS Stripped from CAPABILITY -> Cleartext LOGIN
      - Stream 3: POP3 (Port 110) Unencrypted Cleartext Authentication & Credential Spray
    """
    print("  [03] Generating 03_starttls_downgrade_and_cleartext.pcap ...")
    pkts = []

    # Stream 1: SMTP 25 STARTTLS MITM Fallback & Cleartext Auth
    t1 = TCPStreamTracker(53001, 25, cli_ip="10.0.3.50", srv_ip="10.0.3.10")
    t1.send_s2c(b"220 mail.victim-corp.com ESMTP\r\n")
    t1.send_c2s(b"EHLO dev-workstation\r\n")
    t1.send_s2c(b"250-mail.victim-corp.com\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
    t1.send_c2s(b"STARTTLS\r\n")
    # MITM or failing server injects 454
    t1.send_s2c(b"454 4.7.0 TLS not available due to temporary reason\r\n")
    # Client falls back open to cleartext authentication
    t1.send_c2s(b"AUTH LOGIN\r\n")
    t1.send_s2c(b"334 VXNlcm5hbWU6\r\n")
    t1.send_c2s(b"dXNlckBleGFtcGxlLmNvbQ==\r\n")
    t1.send_s2c(b"334 UGFzc3dvcmQ6\r\n")
    t1.send_c2s(b"UGFzc3dvcmQxMjM=\r\n")
    t1.send_s2c(b"235 2.7.0 Authentication successful\r\n")
    pkts.extend(t1.pkts)

    # Stream 2: IMAP 143 with STARTTLS Stripped from Greeting
    t2 = TCPStreamTracker(53002, 143, cli_ip="10.0.3.51", srv_ip="10.0.3.10")
    t2.send_s2c(b"* OK [CAPABILITY IMAP4rev1 LITERAL+ SASL-IR] IMAP4rev1 Server Ready\r\n")
    t2.send_c2s(b"a001 LOGIN finance-cfo@victim-corp.com UltraSecretCFO2026!\r\n")
    t2.send_s2c(b"a001 OK [CAPABILITY IMAP4rev1] Logged in\r\n")
    pkts.extend(t2.pkts)

    # Stream 3: POP3 110 Plaintext Credential Spray
    t3 = TCPStreamTracker(53003, 110, cli_ip="10.0.3.52", srv_ip="10.0.3.10")
    t3.send_s2c(b"+OK POP3 server ready <1896.697@victim-corp.com>\r\n")
    t3.send_c2s(b"USER ceo\r\n")
    t3.send_s2c(b"+OK password required\r\n")
    t3.send_c2s(b"PASS 123456\r\n")
    t3.send_s2c(b"-ERR invalid password\r\n")
    t3.send_c2s(b"USER admin@victim-corp.com\r\n")
    t3.send_s2c(b"+OK password required\r\n")
    t3.send_c2s(b"PASS Spring2026!\r\n")
    t3.send_s2c(b"+OK Logged in, 1 messages\r\n")
    pkts.extend(t3.pkts)

    wrpcap(str(DEMO_DIR / "03_starttls_downgrade_and_cleartext.pcap"), pkts)


# ---------------------------------------------------------------------------
# Consolidated Scenario 4: Protocol Anomalies & Malformed Payloads
# ---------------------------------------------------------------------------


def scenario_04_protocol_anomalies_and_fuzzing():
    """
    04_protocol_anomalies_and_fuzzing.pcap
    Multi-session capture of behavioral anomalies, fuzzing attacks, and corrupt records:
      - Stream 1: Malformed HTTP Probe on SMTP Port 25 (Protocol Desync)
      - Stream 2: Oversized Buffer / Command Fuzzing on SMTP Port 25
      - Stream 3: Corrupted TLS Record Layer on Port 465 (Invalid ContentType 0xFF)
      - Stream 4: TLS Split / Fragmented ClientHello Handshake on Port 587
    """
    print("  [04] Generating 04_protocol_anomalies_and_fuzzing.pcap ...")
    pkts = []

    # Stream 1: Malformed HTTP Probe on SMTP 25
    t1 = TCPStreamTracker(54001, 25, cli_ip="10.0.4.50", srv_ip="10.0.4.10")
    t1.send_s2c(b"220 mail.probe-target.org ESMTP Postfix\r\n")
    t1.send_c2s(
        b"GET / HTTP/1.1\r\nHost: mail.probe-target.org\r\nUser-Agent: WebScanner/1.0\r\n\r\n"
    )
    t1.send_s2c(
        b'500 5.5.1 Command unrecognized: "GET / HTTP/1.1"\r\n500 5.5.1 Command unrecognized\r\n'
    )
    t1.rst_s2c()
    pkts.extend(t1.pkts)

    # Stream 2: Buffer Fuzzing & Oversized Commands on Port 25
    t2 = TCPStreamTracker(54002, 25, cli_ip="10.0.4.51", srv_ip="10.0.4.10")
    t2.send_s2c(b"220 mail.probe-target.org ESMTP Postfix\r\n")
    fuzz_payload = b"EHLO " + (b"A" * 2048) + b"\r\n"
    t2.send_c2s(fuzz_payload)
    t2.send_s2c(b"501 5.5.2 Line too long\r\n")
    t2.rst_s2c()
    pkts.extend(t2.pkts)

    # Stream 3: Corrupted TLS Record Layer on Port 465
    t3 = TCPStreamTracker(54003, 465, cli_ip="10.0.4.52", srv_ip="10.0.4.10")
    ch3 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    t3.send_c2s(ch3)
    sh3 = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xC02F), TLSServerHelloDone()])
    t3.send_s2c(sh3)
    # Corrupt record with invalid content-type 0xFF and illegal length
    corrupted_record = b"\xff\x03\x03\xff\xff" + (b"\xde\xad\xbe\xef" * 16)
    t3.send_c2s(corrupted_record)
    t3.rst_s2c()
    pkts.extend(t3.pkts)

    # Stream 4: TLS Split / Fragmented ClientHello on Port 587
    t4 = TCPStreamTracker(54004, 587, cli_ip="10.0.4.53", srv_ip="10.0.4.10")
    t4.send_s2c(b"220 mail.probe-target.org ESMTP Ready\r\n")
    t4.send_c2s(b"EHLO split-test\r\n")
    t4.send_s2c(b"250-STARTTLS\r\n250 OK\r\n")
    t4.send_c2s(b"STARTTLS\r\n")
    t4.send_s2c(b"220 Ready\r\n")
    ch4_bytes = bytes(
        TLS(
            msg=[
                TLSClientHello(
                    version=0x0303,
                    ciphers=[0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0x009C, 0x009D, 0x002F, 0x0035],
                )
            ]
        )
    )
    # Split across 2 TCP segments
    part1 = ch4_bytes[:24]
    part2 = ch4_bytes[24:]
    t4.send_c2s(part1)
    t4.send_c2s(part2)
    sh4 = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xC02F), TLSServerHelloDone()])
    t4.send_s2c(sh4)
    pkts.extend(t4.pkts)

    wrpcap(str(DEMO_DIR / "04_protocol_anomalies_and_fuzzing.pcap"), pkts)


# ---------------------------------------------------------------------------
# Consolidated Scenario 5: Real-World Network Transports & Edge Cases
# ---------------------------------------------------------------------------


def scenario_05_realworld_network_transports(ca_key, ca_cert):
    """
    05_realworld_network_transports.pcap
    Multi-session capture of packet loss, retransmissions, resets, and truncated handshakes:
      - Stream 1: Midstream Truncated TLS with Packet Loss, Duplicate ACKs & TCP RST
      - Stream 2: Truncated Certificate Handshake Cutoff Mid-Stream (MTU drop)
      - Stream 3: Out-of-Order TCP Segments with Overlapping Byte Ranges
      - Stream 4: Half-Open TCP SYN Probes / Port Scan
      - Stream 5: SMTP Pipelining Command Desync (Commands Sent Prior to 220 Banner)
    """
    print("  [05] Generating 05_realworld_network_transports.pcap ...")
    pkts = []

    # Stream 1: Midstream Truncated TLS with Loss, Retransmissions & RST
    t1 = TCPStreamTracker(55001, 587, cli_ip="10.0.5.50", srv_ip="10.0.5.10")
    t1.send_s2c(b"220 mail.tap-capture.org ESMTP\r\n")
    t1.send_c2s(b"EHLO mta-relay.corp\r\n")
    t1.send_s2c(b"250-STARTTLS\r\n250 OK\r\n")
    t1.send_c2s(b"STARTTLS\r\n")
    t1.send_s2c(b"220 2.0.0 Ready to start TLS\r\n")
    ch1 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    t1.send_c2s(ch1)
    sh1 = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xC02F)])
    t1.send_s2c(sh1)
    # Simulate packet loss: Client sends duplicate ACK asking for missing data
    t1.ack_c2s()
    # Server retransmits ServerHello
    t1.send_s2c(sh1)
    # Abrupt RST injection
    t1.rst_c2s()
    pkts.extend(t1.pkts)

    # Stream 2: Truncated Certificate Handshake Cutoff Mid-Stream (Port 993)
    cert_trunc = generate_cert(
        "trunc_cert", "imap.tap-capture.org", ca_key, ca_cert, 2048, serial_number=502
    )
    t2 = TCPStreamTracker(55002, 993, cli_ip="10.0.5.51", srv_ip="10.0.5.10")
    ch2 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F])])
    t2.send_c2s(ch2)
    sh2 = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xC02F)])
    t2.send_s2c(sh2)
    # Server starts sending certificate but packet is truncated mid-payload
    full_cert_record = bytes(TLS(msg=[TLSCertificate(certs=[(len(cert_trunc), cert_trunc)])]))
    truncated_chunk = full_cert_record[:64]  # Cut off mid-handshake
    t2.send_s2c(truncated_chunk)
    pkts.extend(t2.pkts)

    # Stream 3: Out-of-Order TCP Segments with Overlapping Byte Ranges (Port 995)
    cert_ooo = generate_cert(
        "ooo_cert", "pop.tap-capture.org", ca_key, ca_cert, 2048, serial_number=503
    )
    t3 = TCPStreamTracker(55003, 995, cli_ip="10.0.5.52", srv_ip="10.0.5.10")
    ch3 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F])])
    t3.send_c2s(ch3)
    sh3 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert_ooo), cert_ooo)]),
            TLSServerHelloDone(),
        ]
    )
    # Out of order: deliver segment 2 first, then segment 1
    sh3_bytes = bytes(sh3)
    seg1 = sh3_bytes[:40]
    seg2 = sh3_bytes[30:]  # Overlapping bytes
    # Send seg2 first
    pkts_t3 = list(t3.pkts)
    eth_s2c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    ip_s2c = IP(src="10.0.5.10", dst="10.0.5.52")
    pkts_t3.append(
        eth_s2c
        / ip_s2c
        / TCP(sport=995, dport=55003, flags="PA", seq=t3.seq_s + 30, ack=t3.seq_c)
        / seg2
    )
    pkts_t3.append(
        eth_s2c
        / ip_s2c
        / TCP(sport=995, dport=55003, flags="PA", seq=t3.seq_s, ack=t3.seq_c)
        / seg1
    )
    pkts.extend(pkts_t3)

    # Stream 4: Half-Open TCP SYN Probe / Scan (Port 25)
    eth_scan = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ip_scan = IP(src="10.0.5.99", dst="10.0.5.10")
    eth_srv = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    ip_srv = IP(src="10.0.5.10", dst="10.0.5.99")
    pkts.append(eth_scan / ip_scan / TCP(sport=61025, dport=25, flags="S", seq=5000))
    pkts.append(eth_srv / ip_srv / TCP(sport=25, dport=61025, flags="SA", seq=7000, ack=5001))
    pkts.append(eth_scan / ip_scan / TCP(sport=61025, dport=25, flags="R", seq=5001, ack=0))

    # Stream 5: SMTP Pipelining Command Desync (Commands Sent Prior to 220 Banner)
    t5 = TCPStreamTracker(55005, 25, cli_ip="10.0.5.55", srv_ip="10.0.5.10")
    # Client sends commands immediately without waiting for banner
    desync_payload = b"EHLO spam-bot.net\r\nMAIL FROM:<stealth@botnet.org>\r\nRCPT TO:<admin@target.org>\r\nDATA\r\n"
    t5.send_c2s(desync_payload)
    # Server sends banner belatedly, then error
    t5.send_s2c(
        b"220 mail.tap-capture.org ESMTP Ready\r\n503 5.5.1 Error: send HELO/EHLO first\r\n"
    )
    pkts.extend(t5.pkts)

    wrpcap(str(DEMO_DIR / "05_realworld_network_transports.pcap"), pkts)


# ---------------------------------------------------------------------------
# Main Runner
# ---------------------------------------------------------------------------


def main():
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("SecureMailScope — Synthetic PCAP Generator (5 Consolidated Files)")
    print("=" * 60)

    # Clean up any existing pcaps
    for ext in ("*.pcap", "*.pcapng", "*.cap"):
        for old_file in DEMO_DIR.glob(ext):
            try:
                old_file.unlink()
            except Exception as e:
                print(f"  Warning deleting {old_file.name}: {e}")

    ca_key, ca_cert = setup_ca()

    scenario_01_enterprise_secure_baseline(ca_key, ca_cert)
    scenario_02_legacy_cryptography_and_certs(ca_key, ca_cert)
    scenario_03_starttls_downgrade_and_cleartext()
    scenario_04_protocol_anomalies_and_fuzzing()
    scenario_05_realworld_network_transports(ca_key, ca_cert)

    print("\n" + "=" * 60)
    print("PCAP generation complete. Consolidated 5 files generated:")
    print(f"Output: {DEMO_DIR}")
    pcaps = list(DEMO_DIR.glob("*.pcap"))
    for p in sorted(pcaps):
        print(f"  ✓ {p.name} ({p.stat().st_size:,} bytes)")
    print("=" * 60)


if __name__ == "__main__":
    main()
