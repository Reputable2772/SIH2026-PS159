#!/usr/bin/env python3
"""
SecureMailScope — Synthetic PCAP Generator
Generates reproducible test PCAPs using Scapy and cryptography.
Runs entirely in user space without requiring root or network interfaces.

Scenarios:
  01_secure_tls12.pcap       – SMTP with TLS 1.2 + ECDHE + valid cert
  02_legacy_tls10.pcap       – SMTP with TLS 1.0 (deprecated)
  03_weak_cipher.pcap        – SMTP TLS 1.2 with 3DES (weak cipher, no FS)
  04_expired_cert.pcap       – IMAP with an expired certificate
  05_starttls_fallback.pcap  – SMTP STARTTLS rejected + cleartext auth
  06_anomalous_handshake.pcap – Anomalous TLS configuration (weak 1024-bit RSA)
  07_plaintext_smtp.pcap     – SMTP with no TLS (plaintext)
"""

from __future__ import annotations

import datetime
from pathlib import Path

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
        .serial_number(100 + len(name))
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
        .serial_number(999 + len(name))
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
# Packet Crafting Helpers
# ---------------------------------------------------------------------------


def tcp_con(sport: int, dport: int, cli_ip: str = "192.168.1.100", srv_ip: str = "192.168.1.10"):
    eth_c2s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    eth_s2c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    ip_c2s = IP(src=cli_ip, dst=srv_ip)
    ip_s2c = IP(src=srv_ip, dst=cli_ip)
    pkts = [
        eth_c2s / ip_c2s / TCP(sport=sport, dport=dport, flags="S", seq=1000),
        eth_s2c / ip_s2c / TCP(sport=dport, dport=sport, flags="SA", seq=2000, ack=1001),
        eth_c2s / ip_c2s / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001),
    ]
    return pkts, eth_c2s / ip_c2s, eth_s2c / ip_s2c


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------


def scenario_01_secure_tls12(ca_key, ca_cert):
    """01: Secure SMTP session with TLS 1.2, ECDHE, valid certificate."""
    print("  [01] Generating 01_secure_tls12.pcap ...")
    cert = generate_cert("secure", "mail.secure.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51001, 587)
    p.append(
        s2c
        / TCP(sport=587, dport=51001, flags="PA", seq=2001, ack=1001)
        / b"220 mail.secure.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51001, dport=587, flags="PA", seq=1001, ack=2028) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51001, flags="PA", seq=2028, ack=1019)
        / b"250-mail.secure.local\r\n250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51001, dport=587, flags="PA", seq=1019, ack=2069) / b"STARTTLS\r\n")
    p.append(
        s2c
        / TCP(sport=587, dport=51001, flags="PA", seq=2069, ack=1029)
        / b"220 2.0.0 Ready to start TLS\r\n"
    )
    ch = TLS(
        msg=[
            TLSClientHello(
                version=0x0303,
                ciphers=[0xC02F, 0xC030, 0xCCA8, 0xCCA9, 0x009C, 0x009D],
                ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"mail.secure.local")])],
            )
        ]
    )
    p.append(c2s / TCP(sport=51001, dport=587, flags="PA", seq=1029, ack=2099) / ch)
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(
        s2c / TCP(sport=587, dport=51001, flags="PA", seq=2099, ack=1029 + len(bytes(ch))) / sh
    )
    wrpcap(str(DEMO_DIR / "01_secure_tls12.pcap"), p)


def scenario_02_legacy_tls10(ca_key, ca_cert):
    """02: Legacy TLS 1.0 session (deprecated)."""
    print("  [02] Generating 02_legacy_tls10.pcap ...")
    cert = generate_cert("legacy", "mail.legacy.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51002, 25)
    p.append(
        s2c
        / TCP(sport=25, dport=51002, flags="PA", seq=2001, ack=1001)
        / b"220 mail.legacy.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51002, dport=25, flags="PA", seq=1001, ack=2028) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51002, flags="PA", seq=2028, ack=1019)
        / b"250-mail.legacy.local\r\n250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51002, dport=25, flags="PA", seq=1019, ack=2069) / b"STARTTLS\r\n")
    p.append(
        s2c
        / TCP(sport=25, dport=51002, flags="PA", seq=2069, ack=1029)
        / b"220 2.0.0 Ready to start TLS\r\n"
    )
    ch = TLS(msg=[TLSClientHello(version=0x0301, ciphers=[0x002F, 0x0035])])
    p.append(c2s / TCP(sport=51002, dport=25, flags="PA", seq=1029, ack=2099) / ch)
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0301, cipher=0x002F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(s2c / TCP(sport=25, dport=51002, flags="PA", seq=2099, ack=1029 + len(bytes(ch))) / sh)
    wrpcap(str(DEMO_DIR / "02_legacy_tls10.pcap"), p)


def scenario_03_weak_cipher(ca_key, ca_cert):
    """03: Weak cipher (3DES / RSA key exchange, no forward secrecy)."""
    print("  [03] Generating 03_weak_cipher.pcap ...")
    cert = generate_cert("weak", "mail.weak.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51003, 25)
    p.append(
        s2c
        / TCP(sport=25, dport=51003, flags="PA", seq=2001, ack=1001)
        / b"220 mail.weak.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51003, dport=25, flags="PA", seq=1001, ack=2026) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51003, flags="PA", seq=2026, ack=1019)
        / b"250-mail.weak.local\r\n250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51003, dport=25, flags="PA", seq=1019, ack=2067) / b"STARTTLS\r\n")
    p.append(
        s2c
        / TCP(sport=25, dport=51003, flags="PA", seq=2067, ack=1029)
        / b"220 2.0.0 Ready to start TLS\r\n"
    )
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x000A, 0x002F])])
    p.append(c2s / TCP(sport=51003, dport=25, flags="PA", seq=1029, ack=2097) / ch)
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0x000A),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(s2c / TCP(sport=25, dport=51003, flags="PA", seq=2097, ack=1029 + len(bytes(ch))) / sh)
    wrpcap(str(DEMO_DIR / "03_weak_cipher.pcap"), p)


def scenario_04_expired_cert(ca_key, ca_cert):
    """04: IMAP session with expired certificate."""
    print("  [04] Generating 04_expired_cert.pcap ...")
    cert = generate_cert("expired", "mail.expired.local", ca_key, ca_cert, 2048, expired=True)
    p, c2s, s2c = tcp_con(51004, 993)
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    p.append(c2s / TCP(sport=51004, dport=993, flags="PA", seq=1001, ack=2001) / ch)
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(
        s2c / TCP(sport=993, dport=51004, flags="PA", seq=2001, ack=1001 + len(bytes(ch))) / sh
    )
    p.append(
        s2c
        / TCP(
            sport=993, dport=51004, flags="PA", seq=2001 + len(bytes(sh)), ack=1001 + len(bytes(ch))
        )
        / b"* OK IMAP4rev1 Server Ready\r\n"
    )
    wrpcap(str(DEMO_DIR / "04_expired_cert.pcap"), p)


def scenario_05_starttls_fallback():
    """05: STARTTLS rejected by server; client sends plaintext credentials."""
    print("  [05] Generating 05_starttls_fallback.pcap ...")
    p, c2s, s2c = tcp_con(51005, 25)
    p.append(
        s2c
        / TCP(sport=25, dport=51005, flags="PA", seq=2001, ack=1001)
        / b"220 fallback.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51005, dport=25, flags="PA", seq=1001, ack=2026) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51005, flags="PA", seq=2026, ack=1019)
        / b"250-fallback.local\r\n250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51005, dport=25, flags="PA", seq=1019, ack=2067) / b"STARTTLS\r\n")
    p.append(
        s2c
        / TCP(sport=25, dport=51005, flags="PA", seq=2067, ack=1029)
        / b"454 TLS not available\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51005, dport=25, flags="PA", seq=1029, ack=2091)
        / b"AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51005, flags="PA", seq=2091, ack=1063)
        / b"535 Authentication credentials invalid\r\n"
    )
    p.append(c2s / TCP(sport=51005, dport=25, flags="PA", seq=1063, ack=2131) / b"QUIT\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51005, flags="PA", seq=2131, ack=1069) / b"221 2.0.0 Bye\r\n"
    )
    wrpcap(str(DEMO_DIR / "05_starttls_fallback.pcap"), p)


def scenario_06_anomalous_handshake(ca_key, ca_cert):
    """06: Weak 1024-bit RSA key and no forward secrecy."""
    print("  [06] Generating 06_anomalous_handshake.pcap ...")
    cert = generate_cert("anomalous", "mail.anomalous.local", ca_key, ca_cert, 1024)
    p, c2s, s2c = tcp_con(51006, 587)
    p.append(
        s2c
        / TCP(sport=587, dport=51006, flags="PA", seq=2001, ack=1001)
        / b"220 mail.anomalous.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51006, dport=587, flags="PA", seq=1001, ack=2031) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51006, flags="PA", seq=2031, ack=1019)
        / b"250-mail.anomalous.local\r\n250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51006, dport=587, flags="PA", seq=1019, ack=2072) / b"STARTTLS\r\n")
    p.append(
        s2c
        / TCP(sport=587, dport=51006, flags="PA", seq=2072, ack=1029)
        / b"220 2.0.0 Ready to start TLS\r\n"
    )
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x002F, 0x0035])])
    p.append(c2s / TCP(sport=51006, dport=587, flags="PA", seq=1029, ack=2102) / ch)
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0x002F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(
        s2c / TCP(sport=587, dport=51006, flags="PA", seq=2102, ack=1029 + len(bytes(ch))) / sh
    )
    wrpcap(str(DEMO_DIR / "06_anomalous_handshake.pcap"), p)


def scenario_07_plaintext_smtp():
    """07: Pure plaintext SMTP without TLS."""
    print("  [07] Generating 07_plaintext_smtp.pcap ...")
    p, c2s, s2c = tcp_con(51007, 25)
    p.append(
        s2c
        / TCP(sport=25, dport=51007, flags="PA", seq=2001, ack=1001)
        / b"220 plain.local ESMTP Postfix\r\n"
    )
    p.append(
        c2s / TCP(sport=51007, dport=25, flags="PA", seq=1001, ack=2031) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51007, flags="PA", seq=2031, ack=1019)
        / b"250-plain.local\r\n250 8BITMIME\r\n250 OK\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51007, dport=25, flags="PA", seq=1019, ack=2062)
        / b"MAIL FROM:<user@plain.local>\r\n"
    )
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2062, ack=1049) / b"250 2.1.0 Ok\r\n")
    p.append(
        c2s
        / TCP(sport=51007, dport=25, flags="PA", seq=1049, ack=2076)
        / b"RCPT TO:<dest@plain.local>\r\n"
    )
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2076, ack=1076) / b"250 2.1.5 Ok\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1076, ack=2090) / b"DATA\r\n")
    p.append(
        s2c
        / TCP(sport=25, dport=51007, flags="PA", seq=2090, ack=1082)
        / b"354 End data with <CR><LF>.<CR><LF>\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51007, dport=25, flags="PA", seq=1082, ack=2127)
        / b"Subject: Unencrypted\r\n\r\nHello World\r\n.\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51007, flags="PA", seq=2127, ack=1122)
        / b"250 2.0.0 Ok: queued\r\n"
    )
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1122, ack=2141) / b"QUIT\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51007, flags="PA", seq=2141, ack=1128) / b"221 2.0.0 Bye\r\n"
    )
    wrpcap(str(DEMO_DIR / "07_plaintext_smtp.pcap"), p)


def scenario_08_midstream_truncated_tls(ca_key, ca_cert):
    """08: Truncated mid-stream capture starting after TCP 3-way handshake and ending abruptly."""
    print("  [08] Generating 08_midstream_truncated_tls.pcap ...")
    eth_c2s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    eth_s2c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    ip_c2s = IP(src="192.168.1.108", dst="192.168.1.10")
    ip_s2c = IP(src="192.168.1.10", dst="192.168.1.108")
    c2s = eth_c2s / ip_c2s
    s2c = eth_s2c / ip_s2c

    # Started mid-stream without SYN/ACK handshake
    p = []
    p.append(
        s2c
        / TCP(sport=587, dport=51008, flags="PA", seq=4001, ack=3001)
        / b"220 mail.truncated.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51008, dport=587, flags="PA", seq=3001, ack=4032) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51008, flags="PA", seq=4032, ack=3019)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51008, dport=587, flags="PA", seq=3019, ack=4055) / b"STARTTLS\r\n")
    p.append(
        s2c / TCP(sport=587, dport=51008, flags="PA", seq=4055, ack=3029) / b"220 Go ahead\r\n"
    )

    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    p.append(c2s / TCP(sport=51008, dport=587, flags="PA", seq=3029, ack=4069) / ch)
    # Server sends partial ServerHello, then connection is truncated by RST
    p.append(s2c / TCP(sport=587, dport=51008, flags="R", seq=4069, ack=3029 + len(bytes(ch))))
    wrpcap(str(DEMO_DIR / "08_midstream_truncated_tls.pcap"), p)


def scenario_09_starttls_stripping_mitm():
    """09: Active MitM STARTTLS stripping attack replacing STARTTLS with NOOP/PIPELINING."""
    print("  [09] Generating 09_starttls_stripping_mitm.pcap ...")
    p, c2s, s2c = tcp_con(51009, 25, cli_ip="10.10.1.55", srv_ip="10.10.1.1")
    p.append(
        s2c
        / TCP(sport=25, dport=51009, flags="PA", seq=2001, ack=1001)
        / b"220 mail.victim-corp.com ESMTP Postfix\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51009, dport=25, flags="PA", seq=1001, ack=2040)
        / b"EHLO victim-workstation.lan\r\n"
    )
    # MitM proxy strips '250-STARTTLS' and sends '250-PIPELINING'
    p.append(
        s2c
        / TCP(sport=25, dport=51009, flags="PA", seq=2040, ack=1030)
        / b"250-mail.victim-corp.com\r\n250-PIPELINING\r\n250-AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n"
    )
    # Client believing server does not support TLS sends plaintext authentication!
    p.append(c2s / TCP(sport=51009, dport=25, flags="PA", seq=1030, ack=2115) / b"AUTH LOGIN\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51009, flags="PA", seq=2115, ack=1042) / b"334 VXNlcm5hbWU6\r\n"
    )  # Username:
    p.append(
        c2s
        / TCP(sport=51009, dport=25, flags="PA", seq=1042, ack=2133)
        / b"ZXhlY3V0aXZlQHZpY3RpbS5jb20=\r\n"
    )  # executive@victim.com
    p.append(
        s2c / TCP(sport=25, dport=51009, flags="PA", seq=2133, ack=1072) / b"334 UGFzc3dvcmQ6\r\n"
    )  # Password:
    p.append(
        c2s
        / TCP(sport=51009, dport=25, flags="PA", seq=1072, ack=2151)
        / b"U2VjcmV0UGEkJHcwcmQyMDI2IQ==\r\n"
    )  # SecretPa$$w0rd2026!
    p.append(
        s2c
        / TCP(sport=25, dport=51009, flags="PA", seq=2151, ack=1102)
        / b"535 5.7.8 Authentication credentials invalid\r\n"
    )
    p.append(c2s / TCP(sport=51009, dport=25, flags="PA", seq=1102, ack=2197) / b"QUIT\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51009, flags="PA", seq=2197, ack=1108) / b"221 2.0.0 Bye\r\n"
    )
    wrpcap(str(DEMO_DIR / "09_starttls_stripping_mitm.pcap"), p)


def scenario_10_multi_stream_mixed_protocols(ca_key, ca_cert):
    """10: Multi-stream mixed capture with 4 concurrent email flows and network noise."""
    print("  [10] Generating 10_multi_stream_mixed_protocols.pcap ...")
    all_pkts = []

    # Stream 1: SMTP Port 25 with STARTTLS & TLS 1.2
    cert = generate_cert("multi_smtp", "mail.multi.local", ca_key, ca_cert, 2048)
    p1, c2s_1, s2c_1 = tcp_con(52001, 25, cli_ip="192.168.10.50", srv_ip="192.168.10.1")
    p1.append(
        s2c_1
        / TCP(sport=25, dport=52001, flags="PA", seq=2001, ack=1001)
        / b"220 mail.multi.local ESMTP\r\n"
    )
    p1.append(
        c2s_1
        / TCP(sport=52001, dport=25, flags="PA", seq=1001, ack=2028)
        / b"EHLO mta.relay.local\r\n"
    )
    p1.append(
        s2c_1
        / TCP(sport=25, dport=52001, flags="PA", seq=2028, ack=1023)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p1.append(c2s_1 / TCP(sport=52001, dport=25, flags="PA", seq=1023, ack=2051) / b"STARTTLS\r\n")
    p1.append(
        s2c_1 / TCP(sport=25, dport=52001, flags="PA", seq=2051, ack=1033) / b"220 2.0.0 Ready\r\n"
    )
    ch1 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    p1.append(c2s_1 / TCP(sport=52001, dport=25, flags="PA", seq=1033, ack=2068) / ch1)
    sh1 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p1.append(
        s2c_1 / TCP(sport=25, dport=52001, flags="PA", seq=2068, ack=1033 + len(bytes(ch1))) / sh1
    )
    all_pkts.extend(p1)

    # Stream 2: Submission Port 587 with Plaintext Auth Failure
    p2, c2s_2, s2c_2 = tcp_con(52002, 587, cli_ip="192.168.10.51", srv_ip="192.168.10.1")
    p2.append(
        s2c_2
        / TCP(sport=587, dport=52002, flags="PA", seq=2001, ack=1001)
        / b"220 mail.multi.local ESMTP Submission\r\n"
    )
    p2.append(
        c2s_2
        / TCP(sport=52002, dport=587, flags="PA", seq=1001, ack=2039)
        / b"EHLO dev-laptop.local\r\n"
    )
    p2.append(
        s2c_2
        / TCP(sport=587, dport=52002, flags="PA", seq=2039, ack=1024)
        / b"250-STARTTLS\r\n250 AUTH PLAIN\r\n250 OK\r\n"
    )
    p2.append(
        c2s_2
        / TCP(sport=52002, dport=587, flags="PA", seq=1024, ack=2079)
        / b"AUTH PLAIN dGVzdABkZXYAMTIzNA==\r\n"
    )
    p2.append(
        s2c_2
        / TCP(sport=587, dport=52002, flags="PA", seq=2079, ack=1057)
        / b"535 5.7.8 Authentication failed\r\n"
    )
    all_pkts.extend(p2)

    # Stream 3: IMAP Port 143 with Opportunistic STARTTLS
    p3, c2s_3, s2c_3 = tcp_con(52003, 143, cli_ip="192.168.10.52", srv_ip="192.168.10.1")
    p3.append(
        s2c_3
        / TCP(sport=143, dport=52003, flags="PA", seq=2001, ack=1001)
        / b"* OK [CAPABILITY IMAP4rev1 STARTTLS] IMAP4rev1 Ready\r\n"
    )
    p3.append(
        c2s_3 / TCP(sport=52003, dport=143, flags="PA", seq=1001, ack=2053) / b"a001 STARTTLS\r\n"
    )
    p3.append(
        s2c_3
        / TCP(sport=143, dport=52003, flags="PA", seq=2053, ack=1016)
        / b"a001 OK Begin TLS negotiation now\r\n"
    )
    all_pkts.extend(p3)

    # Stream 4: IMAPS Port 993 Direct TLS with Expired Certificate
    cert_exp = generate_cert("multi_exp", "imap.multi.local", ca_key, ca_cert, 2048, expired=True)
    p4, c2s_4, s2c_4 = tcp_con(52004, 993, cli_ip="192.168.10.53", srv_ip="192.168.10.1")
    ch4 = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    p4.append(c2s_4 / TCP(sport=52004, dport=993, flags="PA", seq=1001, ack=2001) / ch4)
    sh4 = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert_exp), cert_exp)]),
            TLSServerHelloDone(),
        ]
    )
    p4.append(
        s2c_4 / TCP(sport=993, dport=52004, flags="PA", seq=2001, ack=1001 + len(bytes(ch4))) / sh4
    )
    all_pkts.extend(p4)

    # Background non-email noise frames (DNS, HTTP)
    eth_noise = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ip_noise = IP(src="192.168.10.50", dst="8.8.8.8")
    all_pkts.append(
        eth_noise
        / ip_noise
        / TCP(sport=43210, dport=80, flags="PA", seq=500, ack=600)
        / b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
    )

    wrpcap(str(DEMO_DIR / "10_multi_stream_mixed_protocols.pcap"), all_pkts)


def scenario_11_retransmissions_loss_rst(ca_key, ca_cert):
    """11: Lossy network with duplicate TCP ACKs, retransmitted ClientHello, and TCP RST."""
    print("  [11] Generating 11_retransmissions_loss_rst.pcap ...")
    generate_cert("flaky", "mail.flaky.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51011, 25, cli_ip="172.16.5.20", srv_ip="172.16.5.1")
    p.append(
        s2c
        / TCP(sport=25, dport=51011, flags="PA", seq=2001, ack=1001)
        / b"220 mail.flaky.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51011, dport=25, flags="PA", seq=1001, ack=2027) / b"EHLO client.flaky\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51011, flags="PA", seq=2027, ack=1019)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51011, dport=25, flags="PA", seq=1019, ack=2050) / b"STARTTLS\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51011, flags="PA", seq=2050, ack=1029) / b"220 2.0.0 Ready\r\n"
    )

    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    # Client sends ClientHello
    p.append(c2s / TCP(sport=51011, dport=25, flags="PA", seq=1029, ack=2066) / ch)
    # Network drops ack, client retransmits duplicate ClientHello frame!
    p.append(c2s / TCP(sport=51011, dport=25, flags="PA", seq=1029, ack=2066) / ch)
    # Server sends duplicate ACK
    p.append(s2c / TCP(sport=25, dport=51011, flags="A", seq=2066, ack=1029 + len(bytes(ch))))
    # Middlebox issues abrupt TCP RST, ACK dropping connection
    p.append(s2c / TCP(sport=25, dport=51011, flags="RA", seq=2066, ack=1029 + len(bytes(ch))))
    wrpcap(str(DEMO_DIR / "11_retransmissions_loss_rst.pcap"), p)


def scenario_12_corrupt_tls_record():
    """12: Malformed/fuzzed TLS record with invalid content type and length mismatch."""
    print("  [12] Generating 12_corrupt_tls_record.pcap ...")
    p, c2s, s2c = tcp_con(51012, 587)
    p.append(
        s2c
        / TCP(sport=587, dport=51012, flags="PA", seq=2001, ack=1001)
        / b"220 mail.fuzzed.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51012, dport=587, flags="PA", seq=1001, ack=2028) / b"EHLO fuzzer.local\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51012, flags="PA", seq=2028, ack=1020)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51012, dport=587, flags="PA", seq=1020, ack=2051) / b"STARTTLS\r\n")
    p.append(
        s2c / TCP(sport=587, dport=51012, flags="PA", seq=2051, ack=1030) / b"220 2.0.0 Proceed\r\n"
    )

    # Corrupt TLS frame: Type 0x55 (invalid), version 0x0399 (bogus), length 0xFF00 but only 12 bytes follow
    corrupt_record = b"\x55\x03\x99\xff\x00\x01\x02\x03\x04\x05\x06\x07"
    p.append(c2s / TCP(sport=51012, dport=587, flags="PA", seq=1030, ack=2069) / corrupt_record)
    # Server terminates with TCP RST
    p.append(s2c / TCP(sport=587, dport=51012, flags="R", seq=2069, ack=1042))
    wrpcap(str(DEMO_DIR / "12_corrupt_tls_record.pcap"), p)


def scenario_13_bruteforce_credential_spray():
    """13: Repeated unencrypted cleartext AUTH LOGIN attempts followed by rate limit closing."""
    print("  [13] Generating 13_bruteforce_credential_spray.pcap ...")
    p, c2s, s2c = tcp_con(51013, 25, cli_ip="198.51.100.42", srv_ip="203.0.113.25")
    p.append(
        s2c
        / TCP(sport=25, dport=51013, flags="PA", seq=2001, ack=1001)
        / b"220 mail.corp-auth.com ESMTP\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51013, dport=25, flags="PA", seq=1001, ack=2030)
        / b"EHLO scanner.botnet\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51013, flags="PA", seq=2030, ack=1022)
        / b"250-mail.corp-auth.com\r\n250 AUTH LOGIN PLAIN\r\n250 8BITMIME\r\n"
    )

    # Attempt 1: admin / admin
    p.append(c2s / TCP(sport=51013, dport=25, flags="PA", seq=1022, ack=2089) / b"AUTH LOGIN\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51013, flags="PA", seq=2089, ack=1034) / b"334 VXNlcm5hbWU6\r\n"
    )
    p.append(
        c2s / TCP(sport=51013, dport=25, flags="PA", seq=1034, ack=2107) / b"YWRtaW4=\r\n"
    )  # admin
    p.append(
        s2c / TCP(sport=25, dport=51013, flags="PA", seq=2107, ack=1044) / b"334 UGFzc3dvcmQ6\r\n"
    )
    p.append(
        c2s / TCP(sport=51013, dport=25, flags="PA", seq=1044, ack=2125) / b"YWRtaW4=\r\n"
    )  # admin
    p.append(
        s2c
        / TCP(sport=25, dport=51013, flags="PA", seq=2125, ack=1054)
        / b"535 5.7.8 Authentication credentials invalid\r\n"
    )

    # Attempt 2: root / password123
    p.append(c2s / TCP(sport=51013, dport=25, flags="PA", seq=1054, ack=2171) / b"AUTH LOGIN\r\n")
    p.append(
        s2c / TCP(sport=25, dport=51013, flags="PA", seq=2171, ack=1066) / b"334 VXNlcm5hbWU6\r\n"
    )
    p.append(
        c2s / TCP(sport=51013, dport=25, flags="PA", seq=1066, ack=2189) / b"cm9vdA==\r\n"
    )  # root
    p.append(
        s2c / TCP(sport=25, dport=51013, flags="PA", seq=2189, ack=1076) / b"334 UGFzc3dvcmQ6\r\n"
    )
    p.append(
        c2s / TCP(sport=51013, dport=25, flags="PA", seq=1076, ack=2207) / b"cGFzc3dvcmQxMjM=\r\n"
    )  # password123
    p.append(
        s2c
        / TCP(sport=25, dport=51013, flags="PA", seq=2207, ack=1094)
        / b"421 4.7.0 Too many authentication failures, closing transmission channel\r\n"
    )
    p.append(s2c / TCP(sport=25, dport=51013, flags="FA", seq=2279, ack=1094))
    wrpcap(str(DEMO_DIR / "13_bruteforce_credential_spray.pcap"), p)


def scenario_14_tls13_encrypted_certs():
    """14: Modern TLS 1.3 handshake with encrypted certificate (RFC 8446 §4.4.2)."""
    print("  [14] Generating 14_tls13_encrypted_certs.pcap ...")
    p, c2s, s2c = tcp_con(51014, 587)
    p.append(
        s2c
        / TCP(sport=587, dport=51014, flags="PA", seq=2001, ack=1001)
        / b"220 mail.modern-tls13.net ESMTP\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51014, dport=587, flags="PA", seq=1001, ack=2033)
        / b"EHLO client.modern\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51014, flags="PA", seq=2033, ack=1021)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51014, dport=587, flags="PA", seq=1021, ack=2056) / b"STARTTLS\r\n")
    p.append(
        s2c
        / TCP(sport=587, dport=51014, flags="PA", seq=2056, ack=1031)
        / b"220 2.0.0 Ready to start TLS\r\n"
    )

    # TLS 1.3 ClientHello with supported_versions = 0x0304
    ch = TLS(
        msg=[
            TLSClientHello(
                version=0x0303,
                ciphers=[0x1301, 0x1302, 0xC02F, 0xC030],
                ext=[TLS_Ext_SupportedVersion_CH(versions=[0x0304, 0x0303])],
            )
        ]
    )
    p.append(c2s / TCP(sport=51014, dport=587, flags="PA", seq=1031, ack=2086) / ch)

    # TLS 1.3 ServerHello selecting 0x1301 (TLS_AES_128_GCM_SHA256)
    sh = TLS(
        msg=[
            TLSServerHello(
                version=0x0303, cipher=0x1301, ext=[TLS_Ext_SupportedVersion_SH(version=0x0304)]
            )
        ]
    )
    p.append(
        s2c / TCP(sport=587, dport=51014, flags="PA", seq=2086, ack=1031 + len(bytes(ch))) / sh
    )

    # Encrypted Handshake Records (RFC 8446 §4.4.2 Certificate is encrypted!)
    encrypted_handshake = b"\x17\x03\x03\x01\x20" + (
        b"\xaa" * 288
    )  # Application Data record type wrapping encrypted cert
    p.append(
        s2c
        / TCP(
            sport=587, dport=51014, flags="PA", seq=2086 + len(bytes(sh)), ack=1031 + len(bytes(ch))
        )
        / encrypted_handshake
    )
    wrpcap(str(DEMO_DIR / "14_tls13_encrypted_certs.pcap"), p)


def scenario_15_silent_server_timeout():
    """15: Client sends STARTTLS, but server drops connection into silent timeout."""
    print("  [15] Generating 15_silent_server_timeout.pcap ...")
    p, c2s, s2c = tcp_con(51015, 25, cli_ip="192.168.100.88", srv_ip="192.168.100.1")
    p.append(
        s2c
        / TCP(sport=25, dport=51015, flags="PA", seq=2001, ack=1001)
        / b"220 mail.blackhole.local ESMTP\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51015, dport=25, flags="PA", seq=1001, ack=2032)
        / b"EHLO test-agent.local\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51015, flags="PA", seq=2032, ack=1024)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51015, dport=25, flags="PA", seq=1024, ack=2055) / b"STARTTLS\r\n")
    # Server goes completely silent! No packets returned.
    # Client retransmits STARTTLS due to timeout
    p.append(c2s / TCP(sport=51015, dport=25, flags="PA", seq=1024, ack=2055) / b"STARTTLS\r\n")
    # Client retransmits again
    p.append(c2s / TCP(sport=51015, dport=25, flags="PA", seq=1024, ack=2055) / b"STARTTLS\r\n")
    # Client gives up and closes with FIN, ACK
    p.append(c2s / TCP(sport=51015, dport=25, flags="FA", seq=1034, ack=2055))
    wrpcap(str(DEMO_DIR / "15_silent_server_timeout.pcap"), p)


def scenario_16_unidirectional_tap_drop():
    """16: Asymmetric / Unidirectional TAP capture where server return packets are dropped."""
    print("  [16] Generating 16_unidirectional_tap_drop.pcap ...")
    eth_c2s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    ip_c2s = IP(src="10.10.1.50", dst="198.51.100.25")
    p = []
    # Client sends SYN
    p.append(eth_c2s / ip_c2s / TCP(sport=51016, dport=25, flags="S", seq=1000))
    # Client sends ACK (assuming 3-way completed, but server response missing from capture)
    p.append(eth_c2s / ip_c2s / TCP(sport=51016, dport=25, flags="A", seq=1001, ack=2001))
    # Client sends EHLO
    p.append(
        eth_c2s
        / ip_c2s
        / TCP(sport=51016, dport=25, flags="PA", seq=1001, ack=2001)
        / b"EHLO tap-test.internal\r\n"
    )
    # Client sends STARTTLS
    p.append(
        eth_c2s
        / ip_c2s
        / TCP(sport=51016, dport=25, flags="PA", seq=1025, ack=2040)
        / b"STARTTLS\r\n"
    )
    # Client sends TLS ClientHello
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    p.append(eth_c2s / ip_c2s / TCP(sport=51016, dport=25, flags="PA", seq=1035, ack=2060) / ch)
    # Retransmit ClientHello (timeout waiting for ServerHello)
    p.append(eth_c2s / ip_c2s / TCP(sport=51016, dport=25, flags="PA", seq=1035, ack=2060) / ch)
    # Client gives up and closes
    p.append(
        eth_c2s
        / ip_c2s
        / TCP(sport=51016, dport=25, flags="FA", seq=1035 + len(bytes(ch)), ack=2060)
    )
    wrpcap(str(DEMO_DIR / "16_unidirectional_tap_drop.pcap"), p)


def scenario_17_pop3_cleartext_auth():
    """17: Unencrypted POP3 session with cleartext credentials on port 110."""
    print("  [17] Generating 17_pop3_cleartext_auth.pcap ...")
    p, c2s, s2c = tcp_con(51017, 110, cli_ip="192.168.1.105", srv_ip="192.168.1.25")
    p.append(
        s2c
        / TCP(sport=110, dport=51017, flags="PA", seq=2001, ack=1001)
        / b"+OK POP3 server ready <1896.697@pop.corp.lan>\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51017, dport=110, flags="PA", seq=1001, ack=2048)
        / b"USER sarah.connor@cyberdyne.corp\r\n"
    )
    p.append(
        s2c
        / TCP(sport=110, dport=51017, flags="PA", seq=2048, ack=1034)
        / b"+OK Password required for sarah.connor\r\n"
    )
    p.append(
        c2s
        / TCP(sport=51017, dport=110, flags="PA", seq=1034, ack=2087)
        / b"PASS Skynet$2029!Immortal\r\n"
    )
    p.append(
        s2c
        / TCP(sport=110, dport=51017, flags="PA", seq=2087, ack=1060)
        / b"+OK Mailbox open, 3 messages (1420 octets)\r\n"
    )
    p.append(c2s / TCP(sport=51017, dport=110, flags="PA", seq=1060, ack=2130) / b"STAT\r\n")
    p.append(s2c / TCP(sport=110, dport=51017, flags="PA", seq=2130, ack=1066) / b"+OK 3 1420\r\n")
    p.append(c2s / TCP(sport=51017, dport=110, flags="PA", seq=1066, ack=2142) / b"QUIT\r\n")
    p.append(
        s2c
        / TCP(sport=110, dport=51017, flags="PA", seq=2142, ack=1072)
        / b"+OK POP3 server signing off\r\n"
    )
    p.append(c2s / TCP(sport=51017, dport=110, flags="FA", seq=1072, ack=2171))
    p.append(s2c / TCP(sport=110, dport=51017, flags="FA", seq=2171, ack=1073))
    wrpcap(str(DEMO_DIR / "17_pop3_cleartext_auth.pcap"), p)


def scenario_18_malformed_http_probe_on_smtp():
    """18: Web vulnerability scanner or misdirected HTTP probe hitting SMTP port 25."""
    print("  [18] Generating 18_malformed_http_probe_on_smtp.pcap ...")
    p, c2s, s2c = tcp_con(51018, 25, cli_ip="185.220.101.5", srv_ip="203.0.113.10")
    p.append(
        s2c
        / TCP(sport=25, dport=51018, flags="PA", seq=2001, ack=1001)
        / b"220 mail.securegate.net ESMTP Postfix\r\n"
    )
    # Attacker sends HTTP GET request to SMTP port
    p.append(
        c2s
        / TCP(sport=51018, dport=25, flags="PA", seq=1001, ack=2039)
        / b"GET /wp-admin/setup-config.php HTTP/1.1\r\nHost: mail.securegate.net\r\nUser-Agent: Nikto/2.1.6\r\n\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51018, flags="PA", seq=2039, ack=1092)
        / b'500 5.5.1 Error: command unrecognized: "GET /wp-admin/setup-config.php HTTP/1.1"\r\n'
    )
    # Follow-up HTTP POST probe
    p.append(
        c2s
        / TCP(sport=51018, dport=25, flags="PA", seq=1092, ack=2121)
        / b"POST /api/v1/auth HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51018, flags="PA", seq=2121, ack=1137)
        / b'500 5.5.1 Error: command unrecognized: "POST /api/v1/auth HTTP/1.1"\r\n'
    )
    p.append(
        s2c
        / TCP(sport=25, dport=51018, flags="PA", seq=2201, ack=1137)
        / b"421 4.7.0 Error: too many unrecognized commands, closing connection\r\n"
    )
    p.append(s2c / TCP(sport=25, dport=51018, flags="RA", seq=2271, ack=1137))
    wrpcap(str(DEMO_DIR / "18_malformed_http_probe_on_smtp.pcap"), p)


def scenario_19_oversized_buffer_fuzzing():
    """19: Oversized buffer overflow / fuzzing probe with 3.5KB command and smuggling."""
    print("  [19] Generating 19_oversized_buffer_fuzzing.pcap ...")
    p, c2s, s2c = tcp_con(51019, 25, cli_ip="198.51.100.99", srv_ip="203.0.113.10")
    p.append(
        s2c
        / TCP(sport=25, dport=51019, flags="PA", seq=2001, ack=1001)
        / b"220 mail.edge-mta.net ESMTP\r\n"
    )
    # Fuzzer sends oversized buffer
    fuzz_payload = b"EHLO " + (b"A" * 3200) + b"\r\n"
    p.append(c2s / TCP(sport=51019, dport=25, flags="PA", seq=1001, ack=2029) / fuzz_payload)
    p.append(
        s2c
        / TCP(sport=25, dport=51019, flags="PA", seq=2029, ack=1001 + len(fuzz_payload))
        / b"500 5.5.2 Error: command line too long\r\n"
    )
    # Smuggling attempt
    smuggle = b"MAIL FROM:<attacker@evil.com>\r\nRCPT TO:<victim@internal.net>\r\nDATA\r\n"
    p.append(
        c2s
        / TCP(sport=51019, dport=25, flags="PA", seq=1001 + len(fuzz_payload), ack=2069)
        / smuggle
    )
    p.append(
        s2c
        / TCP(
            sport=25, dport=51019, flags="PA", seq=2069, ack=1001 + len(fuzz_payload) + len(smuggle)
        )
        / b"503 5.5.1 Error: send HELO/EHLO first\r\n"
    )
    p.append(
        s2c
        / TCP(
            sport=25, dport=51019, flags="RA", seq=2109, ack=1001 + len(fuzz_payload) + len(smuggle)
        )
    )
    wrpcap(str(DEMO_DIR / "19_oversized_buffer_fuzzing.pcap"), p)


def scenario_20_self_signed_weak_rsa():
    """20: Untrusted self-signed certificate with weak 1024-bit RSA key."""
    print("  [20] Generating 20_self_signed_weak_rsa.pcap ...")
    cert = generate_self_signed_cert(
        "self_signed_weak_rsa", "*.corp-internal.local", key_size=1024, hash_algo=hashes.SHA256()
    )
    p, c2s, s2c = tcp_con(51020, 993)  # IMAPS
    ch = TLS(
        msg=[
            TLSClientHello(
                version=0x0303,
                ciphers=[0xC02F, 0xC030, 0x009C, 0x002F],
                ext=[
                    TLS_Ext_ServerName(
                        servernames=[ServerName(servername=b"mail.corp-internal.local")]
                    )
                ],
            )
        ]
    )
    p.append(c2s / TCP(sport=51020, dport=993, flags="PA", seq=1001, ack=2001) / ch)
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0x002F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(
        s2c / TCP(sport=993, dport=51020, flags="PA", seq=2001, ack=1001 + len(bytes(ch))) / sh
    )
    # Client rejects certificate with Fatal TLS Alert (Level 2: Fatal, 48: Unknown CA)
    tls_alert = b"\x15\x03\x03\x00\x02\x02\x30"
    p.append(
        c2s
        / TCP(
            sport=51020, dport=993, flags="PA", seq=1001 + len(bytes(ch)), ack=2001 + len(bytes(sh))
        )
        / tls_alert
    )
    p.append(
        c2s
        / TCP(
            sport=51020,
            dport=993,
            flags="RA",
            seq=1001 + len(bytes(ch)) + 7,
            ack=2001 + len(bytes(sh)),
        )
    )
    wrpcap(str(DEMO_DIR / "20_self_signed_weak_rsa.pcap"), p)


def scenario_21_syn_scan_half_open():
    """21: Multi-port TCP SYN stealth scan against all mail ports (no data)."""
    print("  [21] Generating 21_syn_scan_half_open.pcap ...")
    ports = [25, 110, 143, 465, 587, 993, 995]
    p = []
    eth_c2s = Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
    eth_s2c = Ether(src="02:00:00:00:00:02", dst="02:00:00:00:00:01")
    ip_c2s = IP(src="192.168.1.199", dst="192.168.1.10")
    ip_s2c = IP(src="192.168.1.10", dst="192.168.1.199")

    for port in ports:
        sp = 40000 + port
        # Scanner sends SYN
        p.append(eth_c2s / ip_c2s / TCP(sport=sp, dport=port, flags="S", seq=5000))
        # Server responds SYN-ACK
        p.append(eth_s2c / ip_s2c / TCP(sport=port, dport=sp, flags="SA", seq=8000, ack=5001))
        # Scanner immediately resets with RST (stealth scan complete, 0 bytes data)
        p.append(eth_c2s / ip_c2s / TCP(sport=sp, dport=port, flags="R", seq=5001, ack=0))

    wrpcap(str(DEMO_DIR / "21_syn_scan_half_open.pcap"), p)


def scenario_22_out_of_order_tcp_overlap(ca_key, ca_cert):
    """22: Fragmented TLS ClientHello with out-of-order segment arrival and overlapping bytes."""
    print("  [22] Generating 22_out_of_order_tcp_overlap.pcap ...")
    cert = generate_cert("overlap", "mail.overlap.test", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51022, 587)
    p.append(
        s2c
        / TCP(sport=587, dport=51022, flags="PA", seq=2001, ack=1001)
        / b"220 mail.overlap.test ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51022, dport=587, flags="PA", seq=1001, ack=2028) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51022, flags="PA", seq=2028, ack=1019)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51022, dport=587, flags="PA", seq=1019, ack=2051) / b"STARTTLS\r\n")
    p.append(
        s2c / TCP(sport=587, dport=51022, flags="PA", seq=2051, ack=1029) / b"220 2.0.0 Ready\r\n"
    )

    ch_bytes = bytes(TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030, 0xCCA8])]))
    seg1 = ch_bytes[:40]
    seg2 = ch_bytes[35:90]  # 5-byte overlap with seg1!
    seg3 = ch_bytes[90:]

    base_seq = 1029
    # Messy arrival order: Segment 3 arrives FIRST!
    p.append(c2s / TCP(sport=51022, dport=587, flags="PA", seq=base_seq + 90, ack=2067) / seg3)
    # Server sends DUP ACK for base_seq (requesting missing first fragment)
    p.append(s2c / TCP(sport=587, dport=51022, flags="A", seq=2067, ack=base_seq))
    # Segment 1 arrives
    p.append(c2s / TCP(sport=51022, dport=587, flags="PA", seq=base_seq, ack=2067) / seg1)
    # Segment 2 arrives with overlap
    p.append(c2s / TCP(sport=51022, dport=587, flags="PA", seq=base_seq + 35, ack=2067) / seg2)
    # Server acknowledges all reassembled data
    total_len = len(ch_bytes)
    p.append(s2c / TCP(sport=587, dport=51022, flags="A", seq=2067, ack=base_seq + total_len))

    # Server sends ServerHello
    sh = TLS(
        msg=[
            TLSServerHello(version=0x0303, cipher=0xC02F),
            TLSCertificate(certs=[(len(cert), cert)]),
            TLSServerHelloDone(),
        ]
    )
    p.append(s2c / TCP(sport=587, dport=51022, flags="PA", seq=2067, ack=base_seq + total_len) / sh)
    wrpcap(str(DEMO_DIR / "22_out_of_order_tcp_overlap.pcap"), p)


def scenario_23_imap_starttls_rejected_cleartext_login():
    """23: IMAP STARTTLS failure on port 143 followed by cleartext credentials login."""
    print("  [23] Generating 23_imap_starttls_rejected_cleartext_login.pcap ...")
    p, c2s, s2c = tcp_con(51023, 143, cli_ip="10.200.5.12", srv_ip="10.200.5.1")
    p.append(
        s2c
        / TCP(sport=143, dport=51023, flags="PA", seq=2001, ack=1001)
        / b"* OK [CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED] CoreMail IMAP4 ready\r\n"
    )
    p.append(
        c2s / TCP(sport=51023, dport=143, flags="PA", seq=1001, ack=2072) / b"a001 CAPABILITY\r\n"
    )
    p.append(
        s2c
        / TCP(sport=143, dport=51023, flags="PA", seq=2072, ack=1018)
        / b"* CAPABILITY IMAP4rev1 STARTTLS LOGINDISABLED\r\na001 OK CAPABILITY completed\r\n"
    )
    p.append(
        c2s / TCP(sport=51023, dport=143, flags="PA", seq=1018, ack=2147) / b"a002 STARTTLS\r\n"
    )
    # Server reports TLS subsystem error
    p.append(
        s2c
        / TCP(sport=143, dport=51023, flags="PA", seq=2147, ack=1033)
        / b"a002 NO [UNAVAILABLE] TLS handshake engine currently unavailable\r\n"
    )
    # Client recklessly attempts cleartext LOGIN despite LOGINDISABLED
    p.append(
        c2s
        / TCP(sport=51023, dport=143, flags="PA", seq=1033, ack=2213)
        / b"a003 LOGIN chief_officer SuperSecretBoardroomPassword2026\r\n"
    )
    p.append(
        s2c
        / TCP(sport=143, dport=51023, flags="PA", seq=2213, ack=1090)
        / b"a003 NO [PRIVACYREQUIRED] Plaintext authentication disallowed without TLS\r\n"
    )
    p.append(c2s / TCP(sport=51023, dport=143, flags="PA", seq=1090, ack=2287) / b"a004 LOGOUT\r\n")
    p.append(
        s2c
        / TCP(sport=143, dport=51023, flags="PA", seq=2287, ack=1103)
        / b"* BYE IMAP4rev1 Server logging out\r\na004 OK LOGOUT completed\r\n"
    )
    wrpcap(str(DEMO_DIR / "23_imap_starttls_rejected_cleartext_login.pcap"), p)


def scenario_24_smtp_pipelining_desync_rst():
    """24: Aggressive SMTP pipelining desync where client blasts commands before 220 banner."""
    print("  [24] Generating 24_smtp_pipelining_desync_rst.pcap ...")
    p, c2s, s2c = tcp_con(51024, 25, cli_ip="198.51.100.80", srv_ip="203.0.113.25")
    # Client sends pipelined spam payload BEFORE server 220 banner arrives!
    early_data = b"EHLO spam-pipe.bot\r\nMAIL FROM:<spammer@bot.org>\r\nRCPT TO:<victim@corp.com>\r\nDATA\r\n"
    p.append(c2s / TCP(sport=51024, dport=25, flags="PA", seq=1001, ack=2001) / early_data)
    # Server sends 220 greeting
    p.append(
        s2c
        / TCP(sport=25, dport=51024, flags="PA", seq=2001, ack=1001)
        / b"220 mail.strict-mta.com ESMTP\r\n"
    )
    # Server detects command pipelining violation
    p.append(
        s2c
        / TCP(sport=25, dport=51024, flags="PA", seq=2031, ack=1001 + len(early_data))
        / b"503 5.5.1 Error: command pipelining out of sequence\r\n"
    )
    # Server immediately terminates with RST
    p.append(s2c / TCP(sport=25, dport=51024, flags="R", seq=2083, ack=1001 + len(early_data)))
    wrpcap(str(DEMO_DIR / "24_smtp_pipelining_desync_rst.pcap"), p)


def scenario_25_truncated_handshake_cert_cutoff(ca_key, ca_cert):
    """25: TLS handshake packet sliced mid-certificate (MTU drop / capture truncation)."""
    print("  [25] Generating 25_truncated_handshake_cert_cutoff.pcap ...")
    cert = generate_cert("truncated_cert", "mail.truncated.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51025, 587)
    p.append(
        s2c
        / TCP(sport=587, dport=51025, flags="PA", seq=2001, ack=1001)
        / b"220 mail.truncated.local ESMTP\r\n"
    )
    p.append(
        c2s / TCP(sport=51025, dport=587, flags="PA", seq=1001, ack=2031) / b"EHLO client.test\r\n"
    )
    p.append(
        s2c
        / TCP(sport=587, dport=51025, flags="PA", seq=2031, ack=1019)
        / b"250-STARTTLS\r\n250 OK\r\n"
    )
    p.append(c2s / TCP(sport=51025, dport=587, flags="PA", seq=1019, ack=2054) / b"STARTTLS\r\n")
    p.append(
        s2c / TCP(sport=587, dport=51025, flags="PA", seq=2054, ack=1029) / b"220 2.0.0 Proceed\r\n"
    )

    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xC02F, 0xC030])])
    p.append(c2s / TCP(sport=51025, dport=587, flags="PA", seq=1029, ack=2072) / ch)

    sh = TLS(msg=[TLSServerHello(version=0x0303, cipher=0xC02F)])
    p.append(
        s2c / TCP(sport=587, dport=51025, flags="PA", seq=2072, ack=1029 + len(bytes(ch))) / sh
    )

    # Server sends Certificate record, but only first 48 bytes of DER are captured! (MTU drop / truncation)
    cert_raw = bytes(TLSCertificate(certs=[(len(cert), cert)]))
    truncated_cert_pkt = b"\x16\x03\x03" + len(cert_raw[:60]).to_bytes(2, "big") + cert_raw[:60]
    p.append(
        s2c
        / TCP(
            sport=587, dport=51025, flags="PA", seq=2072 + len(bytes(sh)), ack=1029 + len(bytes(ch))
        )
        / truncated_cert_pkt
    )
    # Client waits, times out and resets
    p.append(c2s / TCP(sport=51025, dport=587, flags="R", seq=1029 + len(bytes(ch)), ack=0))
    wrpcap(str(DEMO_DIR / "25_truncated_handshake_cert_cutoff.pcap"), p)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    DEMO_DIR.mkdir(parents=True, exist_ok=True)
    CERTS_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("SecureMailScope — Synthetic PCAP Generator (Scapy Engine)")
    print("=" * 60)

    ca_key, ca_cert = setup_ca()

    scenario_01_secure_tls12(ca_key, ca_cert)
    scenario_02_legacy_tls10(ca_key, ca_cert)
    scenario_03_weak_cipher(ca_key, ca_cert)
    scenario_04_expired_cert(ca_key, ca_cert)
    scenario_05_starttls_fallback()
    scenario_06_anomalous_handshake(ca_key, ca_cert)
    scenario_07_plaintext_smtp()
    scenario_08_midstream_truncated_tls(ca_key, ca_cert)
    scenario_09_starttls_stripping_mitm()
    scenario_10_multi_stream_mixed_protocols(ca_key, ca_cert)
    scenario_11_retransmissions_loss_rst(ca_key, ca_cert)
    scenario_12_corrupt_tls_record()
    scenario_13_bruteforce_credential_spray()
    scenario_14_tls13_encrypted_certs()
    scenario_15_silent_server_timeout()
    scenario_16_unidirectional_tap_drop()
    scenario_17_pop3_cleartext_auth()
    scenario_18_malformed_http_probe_on_smtp()
    scenario_19_oversized_buffer_fuzzing()
    scenario_20_self_signed_weak_rsa()
    scenario_21_syn_scan_half_open()
    scenario_22_out_of_order_tcp_overlap(ca_key, ca_cert)
    scenario_23_imap_starttls_rejected_cleartext_login()
    scenario_24_smtp_pipelining_desync_rst()
    scenario_25_truncated_handshake_cert_cutoff(ca_key, ca_cert)

    print("\n" + "=" * 60)
    print("PCAP generation complete.")
    print(f"Output: {DEMO_DIR}")
    pcaps = list(DEMO_DIR.glob("*.pcap"))
    for p in sorted(pcaps):
        print(f"  {p.name} ({p.stat().st_size:,} bytes)")
    print("=" * 60)
