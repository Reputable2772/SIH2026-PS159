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

from scapy.all import Ether, IP, TCP, wrpcap
from scapy.layers.tls.all import (
    TLS, TLSClientHello, TLSServerHello, TLSCertificate,
    TLSServerHelloDone, TLS_Ext_ServerName, ServerName
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
    ca_subject = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "SecureMailScope Root CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_subject)
        .issuer_name(ca_subject)
        .public_key(ca_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc))
        .not_valid_after(datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc))
        .sign(ca_key, hashes.SHA256())
    )

    ca_key_path.write_bytes(ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))
    ca_crt_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    return ca_key, ca_cert


def generate_cert(
    name: str,
    cn: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    key_size: int = 2048,
    expired: bool = False
) -> bytes:
    key_path = CERTS_DIR / f"{name}.key"
    crt_path = CERTS_DIR / f"{name}.crt"

    key = rsa.generate_private_key(65537, key_size)
    subj = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, cn)])

    if expired:
        nb = datetime.datetime(2019, 1, 1, tzinfo=datetime.timezone.utc)
        na = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    else:
        nb = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc)
        na = datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc)

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

    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption()
    ))
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
        eth_c2s / ip_c2s / TCP(sport=sport, dport=dport, flags="A", seq=1001, ack=2001)
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
    p.append(s2c / TCP(sport=587, dport=51001, flags="PA", seq=2001, ack=1001) / b"220 mail.secure.local ESMTP\r\n")
    p.append(c2s / TCP(sport=51001, dport=587, flags="PA", seq=1001, ack=2028) / b"EHLO client.test\r\n")
    p.append(s2c / TCP(sport=587, dport=51001, flags="PA", seq=2028, ack=1019) / b"250-mail.secure.local\r\n250-STARTTLS\r\n250 OK\r\n")
    p.append(c2s / TCP(sport=51001, dport=587, flags="PA", seq=1019, ack=2069) / b"STARTTLS\r\n")
    p.append(s2c / TCP(sport=587, dport=51001, flags="PA", seq=2069, ack=1029) / b"220 2.0.0 Ready to start TLS\r\n")
    ch = TLS(msg=[TLSClientHello(
        version=0x0303,
        ciphers=[0xc02f, 0xc030, 0xcca8, 0xcca9, 0x009c, 0x009d],
        ext=[TLS_Ext_ServerName(servernames=[ServerName(servername=b"mail.secure.local")])]
    )])
    p.append(c2s / TCP(sport=51001, dport=587, flags="PA", seq=1029, ack=2099) / ch)
    sh = TLS(msg=[
        TLSServerHello(version=0x0303, cipher=0xc02f),
        TLSCertificate(certs=[(len(cert), cert)]),
        TLSServerHelloDone()
    ])
    p.append(s2c / TCP(sport=587, dport=51001, flags="PA", seq=2099, ack=1029 + len(bytes(ch))) / sh)
    wrpcap(str(DEMO_DIR / "01_secure_tls12.pcap"), p)


def scenario_02_legacy_tls10(ca_key, ca_cert):
    """02: Legacy TLS 1.0 session (deprecated)."""
    print("  [02] Generating 02_legacy_tls10.pcap ...")
    cert = generate_cert("legacy", "mail.legacy.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51002, 25)
    p.append(s2c / TCP(sport=25, dport=51002, flags="PA", seq=2001, ack=1001) / b"220 mail.legacy.local ESMTP\r\n")
    p.append(c2s / TCP(sport=51002, dport=25, flags="PA", seq=1001, ack=2028) / b"EHLO client.test\r\n")
    p.append(s2c / TCP(sport=25, dport=51002, flags="PA", seq=2028, ack=1019) / b"250-mail.legacy.local\r\n250-STARTTLS\r\n250 OK\r\n")
    p.append(c2s / TCP(sport=51002, dport=25, flags="PA", seq=1019, ack=2069) / b"STARTTLS\r\n")
    p.append(s2c / TCP(sport=25, dport=51002, flags="PA", seq=2069, ack=1029) / b"220 2.0.0 Ready to start TLS\r\n")
    ch = TLS(msg=[TLSClientHello(version=0x0301, ciphers=[0x002f, 0x0035])])
    p.append(c2s / TCP(sport=51002, dport=25, flags="PA", seq=1029, ack=2099) / ch)
    sh = TLS(msg=[
        TLSServerHello(version=0x0301, cipher=0x002f),
        TLSCertificate(certs=[(len(cert), cert)]),
        TLSServerHelloDone()
    ])
    p.append(s2c / TCP(sport=25, dport=51002, flags="PA", seq=2099, ack=1029 + len(bytes(ch))) / sh)
    wrpcap(str(DEMO_DIR / "02_legacy_tls10.pcap"), p)


def scenario_03_weak_cipher(ca_key, ca_cert):
    """03: Weak cipher (3DES / RSA key exchange, no forward secrecy)."""
    print("  [03] Generating 03_weak_cipher.pcap ...")
    cert = generate_cert("weak", "mail.weak.local", ca_key, ca_cert, 2048)
    p, c2s, s2c = tcp_con(51003, 25)
    p.append(s2c / TCP(sport=25, dport=51003, flags="PA", seq=2001, ack=1001) / b"220 mail.weak.local ESMTP\r\n")
    p.append(c2s / TCP(sport=51003, dport=25, flags="PA", seq=1001, ack=2026) / b"EHLO client.test\r\n")
    p.append(s2c / TCP(sport=25, dport=51003, flags="PA", seq=2026, ack=1019) / b"250-mail.weak.local\r\n250-STARTTLS\r\n250 OK\r\n")
    p.append(c2s / TCP(sport=51003, dport=25, flags="PA", seq=1019, ack=2067) / b"STARTTLS\r\n")
    p.append(s2c / TCP(sport=25, dport=51003, flags="PA", seq=2067, ack=1029) / b"220 2.0.0 Ready to start TLS\r\n")
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x000a, 0x002f])])
    p.append(c2s / TCP(sport=51003, dport=25, flags="PA", seq=1029, ack=2097) / ch)
    sh = TLS(msg=[
        TLSServerHello(version=0x0303, cipher=0x000a),
        TLSCertificate(certs=[(len(cert), cert)]),
        TLSServerHelloDone()
    ])
    p.append(s2c / TCP(sport=25, dport=51003, flags="PA", seq=2097, ack=1029 + len(bytes(ch))) / sh)
    wrpcap(str(DEMO_DIR / "03_weak_cipher.pcap"), p)


def scenario_04_expired_cert(ca_key, ca_cert):
    """04: IMAP session with expired certificate."""
    print("  [04] Generating 04_expired_cert.pcap ...")
    cert = generate_cert("expired", "mail.expired.local", ca_key, ca_cert, 2048, expired=True)
    p, c2s, s2c = tcp_con(51004, 993)
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0xc02f, 0xc030])])
    p.append(c2s / TCP(sport=51004, dport=993, flags="PA", seq=1001, ack=2001) / ch)
    sh = TLS(msg=[
        TLSServerHello(version=0x0303, cipher=0xc02f),
        TLSCertificate(certs=[(len(cert), cert)]),
        TLSServerHelloDone()
    ])
    p.append(s2c / TCP(sport=993, dport=51004, flags="PA", seq=2001, ack=1001 + len(bytes(ch))) / sh)
    p.append(s2c / TCP(sport=993, dport=51004, flags="PA", seq=2001 + len(bytes(sh)), ack=1001 + len(bytes(ch))) / b"* OK IMAP4rev1 Server Ready\r\n")
    wrpcap(str(DEMO_DIR / "04_expired_cert.pcap"), p)


def scenario_05_starttls_fallback():
    """05: STARTTLS rejected by server; client sends plaintext credentials."""
    print("  [05] Generating 05_starttls_fallback.pcap ...")
    p, c2s, s2c = tcp_con(51005, 25)
    p.append(s2c / TCP(sport=25, dport=51005, flags="PA", seq=2001, ack=1001) / b"220 fallback.local ESMTP\r\n")
    p.append(c2s / TCP(sport=51005, dport=25, flags="PA", seq=1001, ack=2026) / b"EHLO client.test\r\n")
    p.append(s2c / TCP(sport=25, dport=51005, flags="PA", seq=2026, ack=1019) / b"250-fallback.local\r\n250-STARTTLS\r\n250 OK\r\n")
    p.append(c2s / TCP(sport=51005, dport=25, flags="PA", seq=1019, ack=2067) / b"STARTTLS\r\n")
    p.append(s2c / TCP(sport=25, dport=51005, flags="PA", seq=2067, ack=1029) / b"454 TLS not available\r\n")
    p.append(c2s / TCP(sport=51005, dport=25, flags="PA", seq=1029, ack=2091) / b"AUTH PLAIN dGVzdAB0ZXN0ADEyMzQ=\r\n")
    p.append(s2c / TCP(sport=25, dport=51005, flags="PA", seq=2091, ack=1063) / b"535 Authentication credentials invalid\r\n")
    p.append(c2s / TCP(sport=51005, dport=25, flags="PA", seq=1063, ack=2131) / b"QUIT\r\n")
    p.append(s2c / TCP(sport=25, dport=51005, flags="PA", seq=2131, ack=1069) / b"221 2.0.0 Bye\r\n")
    wrpcap(str(DEMO_DIR / "05_starttls_fallback.pcap"), p)


def scenario_06_anomalous_handshake(ca_key, ca_cert):
    """06: Weak 1024-bit RSA key and no forward secrecy."""
    print("  [06] Generating 06_anomalous_handshake.pcap ...")
    cert = generate_cert("anomalous", "mail.anomalous.local", ca_key, ca_cert, 1024)
    p, c2s, s2c = tcp_con(51006, 587)
    p.append(s2c / TCP(sport=587, dport=51006, flags="PA", seq=2001, ack=1001) / b"220 mail.anomalous.local ESMTP\r\n")
    p.append(c2s / TCP(sport=51006, dport=587, flags="PA", seq=1001, ack=2031) / b"EHLO client.test\r\n")
    p.append(s2c / TCP(sport=587, dport=51006, flags="PA", seq=2031, ack=1019) / b"250-mail.anomalous.local\r\n250-STARTTLS\r\n250 OK\r\n")
    p.append(c2s / TCP(sport=51006, dport=587, flags="PA", seq=1019, ack=2072) / b"STARTTLS\r\n")
    p.append(s2c / TCP(sport=587, dport=51006, flags="PA", seq=2072, ack=1029) / b"220 2.0.0 Ready to start TLS\r\n")
    ch = TLS(msg=[TLSClientHello(version=0x0303, ciphers=[0x002f, 0x0035])])
    p.append(c2s / TCP(sport=51006, dport=587, flags="PA", seq=1029, ack=2102) / ch)
    sh = TLS(msg=[
        TLSServerHello(version=0x0303, cipher=0x002f),
        TLSCertificate(certs=[(len(cert), cert)]),
        TLSServerHelloDone()
    ])
    p.append(s2c / TCP(sport=587, dport=51006, flags="PA", seq=2102, ack=1029 + len(bytes(ch))) / sh)
    wrpcap(str(DEMO_DIR / "06_anomalous_handshake.pcap"), p)


def scenario_07_plaintext_smtp():
    """07: Pure plaintext SMTP without TLS."""
    print("  [07] Generating 07_plaintext_smtp.pcap ...")
    p, c2s, s2c = tcp_con(51007, 25)
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2001, ack=1001) / b"220 plain.local ESMTP Postfix\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1001, ack=2031) / b"EHLO client.test\r\n")
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2031, ack=1019) / b"250-plain.local\r\n250 8BITMIME\r\n250 OK\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1019, ack=2062) / b"MAIL FROM:<user@plain.local>\r\n")
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2062, ack=1049) / b"250 2.1.0 Ok\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1049, ack=2076) / b"RCPT TO:<dest@plain.local>\r\n")
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2076, ack=1076) / b"250 2.1.5 Ok\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1076, ack=2090) / b"DATA\r\n")
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2090, ack=1082) / b"354 End data with <CR><LF>.<CR><LF>\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1082, ack=2127) / b"Subject: Unencrypted\r\n\r\nHello World\r\n.\r\n")
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2127, ack=1122) / b"250 2.0.0 Ok: queued\r\n")
    p.append(c2s / TCP(sport=51007, dport=25, flags="PA", seq=1122, ack=2141) / b"QUIT\r\n")
    p.append(s2c / TCP(sport=25, dport=51007, flags="PA", seq=2141, ack=1128) / b"221 2.0.0 Bye\r\n")
    wrpcap(str(DEMO_DIR / "07_plaintext_smtp.pcap"), p)


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

    print("\n" + "=" * 60)
    print("PCAP generation complete.")
    print(f"Output: {DEMO_DIR}")
    pcaps = list(DEMO_DIR.glob("*.pcap"))
    for p in sorted(pcaps):
        print(f"  {p.name} ({p.stat().st_size:,} bytes)")
    print("=" * 60)
