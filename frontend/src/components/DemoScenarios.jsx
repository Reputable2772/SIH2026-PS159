import React, { useState } from 'react'
import {
  ShieldCheck,
  ShieldAlert,
  AlertTriangle,
  Lock,
  Unlock,
  KeyRound,
  Sparkles,
  ArrowRight,
  Play,
  Layers,
  Flame,
  Radio,
  Scan,
  Scissors,
  Bug,
  Terminal,
  Globe,
  Server,
  Cloud,
  Download,
  FileCode
} from 'lucide-react'

export const CANONICAL_SCENARIOS = [
  // ── 1. Standard Protocols & Cryptographic Baselines ───────────────
  {
    id: '01_secure_tls12',
    filename: '01_secure_tls12.pcap',
    title: 'Secure TLS 1.2 (Clean Baseline)',
    category: 'standard',
    protocol: 'SMTP / STARTTLS',
    tag: 'Clean Baseline',
    tagColor: 'var(--info)',
    icon: ShieldCheck,
    description: 'Compliant opportunistic STARTTLS with ECDHE key exchange, AES-GCM cipher, and valid X.509 certificate.',
    expectedScore: '97 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '14_tls13_encrypted_certs',
    filename: '14_tls13_encrypted_certs.pcap',
    title: 'Modern TLS 1.3 (Encrypted Certs)',
    category: 'standard',
    protocol: 'SMTP / Submission (587)',
    tag: 'RFC 8446 Boundary',
    tagColor: 'var(--info)',
    icon: ShieldCheck,
    description: 'TLS 1.3 handshake where certificates are encrypted by protocol design (RFC 8446 §4.4.2).',
    expectedScore: '100 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '02_legacy_tls10',
    filename: '02_legacy_tls10.pcap',
    title: 'Legacy TLS 1.0 Negotiation',
    category: 'standard',
    protocol: 'SMTP / Submission',
    tag: 'Deprecated Protocol',
    tagColor: 'var(--high)',
    icon: AlertTriangle,
    description: 'Negotiation of deprecated TLS 1.0 (RFC 8996 violation) vulnerable to BEAST and known protocol flaws.',
    expectedScore: '50 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '04_expired_cert',
    filename: '04_expired_cert.pcap',
    title: 'Expired X.509 Certificate',
    category: 'standard',
    protocol: 'IMAPS (Port 993)',
    tag: 'Certificate Failure',
    tagColor: 'var(--critical)',
    icon: KeyRound,
    description: 'Direct TLS connection presenting an X.509 certificate whose validity period has lapsed.',
    expectedScore: '72 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '03_weak_cipher',
    filename: '03_weak_cipher.pcap',
    title: 'Weak Cipher & Static RSA (No FS)',
    category: 'standard',
    protocol: 'SMTP / SMTPS',
    tag: 'Weak Cryptography',
    tagColor: 'var(--high)',
    icon: Lock,
    description: 'Legacy 3DES cipher with static RSA key exchange lacking Forward Secrecy protection.',
    expectedScore: '65 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '07_plaintext_smtp',
    filename: '07_plaintext_smtp.pcap',
    title: 'Plaintext Unencrypted SMTP',
    category: 'standard',
    protocol: 'SMTP (Port 25)',
    tag: 'Cleartext',
    tagColor: 'var(--critical)',
    icon: Unlock,
    description: 'Completely unencrypted email session transmitting envelope headers and auth without TLS negotiation.',
    expectedScore: '55 / 100',
    expectedRisk: 'MEDIUM',
  },

  // ── 2. Active Attacks & Downgrades ─────────────────────────────────
  {
    id: '05_starttls_fallback',
    filename: '05_starttls_fallback.pcap',
    title: 'STARTTLS Downgrade / Fallback',
    category: 'attacks',
    protocol: 'SMTP (Port 25)',
    tag: 'Downgrade Attack',
    tagColor: 'var(--critical)',
    icon: Unlock,
    description: 'Server advertises STARTTLS, rejects request with 454, client falls back to transmitting credentials in cleartext.',
    expectedScore: '45 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '09_starttls_stripping_mitm',
    filename: '09_starttls_stripping_mitm.pcap',
    title: 'Active MitM STARTTLS Stripping',
    category: 'attacks',
    protocol: 'SMTP (Port 25)',
    tag: 'MitM Proxy Attack',
    tagColor: 'var(--critical)',
    icon: ShieldAlert,
    description: 'Attacker middlebox strips 250-STARTTLS into PIPELINING; victim client sends cleartext base64 credentials.',
    expectedScore: '55 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '13_bruteforce_credential_spray',
    filename: '13_bruteforce_credential_spray.pcap',
    title: 'Cleartext Auth Brute Force Spray',
    category: 'attacks',
    protocol: 'SMTP (Port 25)',
    tag: 'Credential Spray',
    tagColor: 'var(--critical)',
    icon: KeyRound,
    description: 'Repeated cleartext AUTH LOGIN attempts over unencrypted port 25, rejected with 535 and connection terminated.',
    expectedScore: '55 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '17_pop3_cleartext_auth',
    filename: '17_pop3_cleartext_auth.pcap',
    title: 'Unencrypted POP3 Cleartext Credentials',
    category: 'attacks',
    protocol: 'POP3 (Port 110)',
    tag: 'Harvested Credentials',
    tagColor: 'var(--critical)',
    icon: Unlock,
    description: 'Mail user logs in over legacy cleartext POP3; USER and PASS credentials harvested unencrypted.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '19_oversized_buffer_fuzzing',
    filename: '19_oversized_buffer_fuzzing.pcap',
    title: 'Oversized Buffer Overflow & Smuggling',
    category: 'attacks',
    protocol: 'SMTP (Port 25)',
    tag: 'Fuzzing & Smuggling',
    tagColor: 'var(--critical)',
    icon: Bug,
    description: 'Adversary floods SMTP with a 3.5KB EHLO buffer followed by command smuggling; terminated with 500 & RST.',
    expectedScore: '55 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '23_imap_starttls_rejected_cleartext_login',
    filename: '23_imap_starttls_rejected_cleartext_login.pcap',
    title: 'IMAP STARTTLS Failure & Insecure Login',
    category: 'attacks',
    protocol: 'IMAP (Port 143)',
    tag: 'IMAP Downgrade',
    tagColor: 'var(--critical)',
    icon: ShieldAlert,
    description: 'Server returns BAD on STARTTLS; client insecurely transmits plaintext LOGIN credentials across port 143.',
    expectedScore: '95 / 100',
    expectedRisk: 'MINIMAL',
  },

  // ── 3. Messy, Incomplete, Multi-Stream & Edge Cases ───────────────
  {
    id: '10_multi_stream_mixed_protocols',
    filename: '10_multi_stream_mixed_protocols.pcap',
    title: 'Multi-Stream Mixed Protocols & Noise',
    category: 'messy',
    protocol: 'Mixed (25, 587, 143, 993)',
    tag: 'Multi-Flow Chaos',
    tagColor: 'var(--critical)',
    icon: Layers,
    description: '4 concurrent email streams (SMTP 25, Submission 587, IMAP 143, IMAPS 993) plus HTTP & DNS noise frames.',
    expectedScore: '0 / 100',
    expectedRisk: 'CRITICAL',
  },
  {
    id: '21_syn_scan_half_open',
    filename: '21_syn_scan_half_open.pcap',
    title: 'Multi-Port TCP SYN Scan (7 Half-Open Probes)',
    category: 'messy',
    protocol: 'Scan (25, 110, 143, 465, 587, 993, 995)',
    tag: 'Stealth Scan',
    tagColor: 'var(--critical)',
    icon: Scan,
    description: 'Port scanner probes all mail ports with SYN/SYN-ACK/RST; zero application bytes exchanged across 7 streams.',
    expectedScore: '5 / 100',
    expectedRisk: 'CRITICAL',
  },
  {
    id: '16_unidirectional_tap_drop',
    filename: '16_unidirectional_tap_drop.pcap',
    title: 'Asymmetric TAP Drop (Client-Only Traffic)',
    category: 'messy',
    protocol: 'SMTP (Port 25)',
    tag: 'Asymmetric Capture',
    tagColor: 'var(--high)',
    icon: Scissors,
    description: 'SPAN mirror dropped all server packets; file contains only client SYN, EHLO, and unacknowledged ClientHello.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '20_self_signed_weak_rsa',
    filename: '20_self_signed_weak_rsa.pcap',
    title: 'Untrusted Self-Signed Cert & 1024-bit RSA',
    category: 'messy',
    protocol: 'IMAPS (Port 993)',
    tag: 'Untrusted Root',
    tagColor: 'var(--critical)',
    icon: KeyRound,
    description: 'Direct IMAPS session presenting a self-signed certificate with an insecure 1024-bit RSA key, rejected with Fatal Alert.',
    expectedScore: '43 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '08_midstream_truncated_tls',
    filename: '08_midstream_truncated_tls.pcap',
    title: 'Mid-Stream Truncated TLS Capture',
    category: 'messy',
    protocol: 'Submission (587)',
    tag: 'Half-Baked Flow',
    tagColor: 'var(--high)',
    icon: AlertTriangle,
    description: 'Capture started mid-stream without SYN/ACK handshake, and truncated mid-handshake by sudden TCP RST.',
    expectedScore: '95 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '11_retransmissions_loss_rst',
    filename: '11_retransmissions_loss_rst.pcap',
    title: 'Packet Loss, Duplicate ACKs & RST',
    category: 'messy',
    protocol: 'SMTP (Port 25)',
    tag: 'Lossy Network',
    tagColor: 'var(--high)',
    icon: AlertTriangle,
    description: 'Flaky network with duplicate ClientHello retransmissions, duplicate ACKs, and abrupt TCP RST termination.',
    expectedScore: '95 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '12_corrupt_tls_record',
    filename: '12_corrupt_tls_record.pcap',
    title: 'Corrupt / Malformed TLS Record',
    category: 'messy',
    protocol: 'Submission (587)',
    tag: 'Parser Stress',
    tagColor: 'var(--critical)',
    icon: Flame,
    description: 'STARTTLS negotiated, but client sends an invalid TLS record content-type (0x55) and bogus version byte (0x0399).',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '18_malformed_http_probe_on_smtp',
    filename: '18_malformed_http_probe_on_smtp.pcap',
    title: 'Non-Mail HTTP Probe on Port 25',
    category: 'messy',
    protocol: 'SMTP (Port 25)',
    tag: 'Protocol Mismatch',
    tagColor: 'var(--medium)',
    icon: Terminal,
    description: 'Nikto web scanner sends HTTP GET/POST requests to SMTP port 25; server returns 500 unrecognized command.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '22_out_of_order_tcp_overlap',
    filename: '22_out_of_order_tcp_overlap.pcap',
    title: 'Out-of-Order TCP Segments with Overlap',
    category: 'messy',
    protocol: 'Submission (587)',
    tag: 'Reassembly Stress',
    tagColor: 'var(--info)',
    icon: Layers,
    description: 'TLS ClientHello fragmented across 3 TCP packets arriving in reverse order with overlapping byte sequences.',
    expectedScore: '97 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '24_smtp_pipelining_desync_rst',
    filename: '24_smtp_pipelining_desync_rst.pcap',
    title: 'Broken SMTP Pipelining Desync & Early RST',
    category: 'messy',
    protocol: 'SMTP (Port 25)',
    tag: 'Pipelining Violation',
    tagColor: 'var(--medium)',
    icon: AlertTriangle,
    description: 'Spammer sends pipelined commands before server 220 banner arrives; triggers 503 Desync and immediate RST.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '25_truncated_handshake_cert_cutoff',
    filename: '25_truncated_handshake_cert_cutoff.pcap',
    title: 'Mid-Cert Truncated Handshake (MTU Drop)',
    category: 'messy',
    protocol: 'Submission (587)',
    tag: 'Cutoff Record',
    tagColor: 'var(--high)',
    icon: Scissors,
    description: 'Server Certificate packet sliced after 48 bytes due to path MTU black hole; client times out and resets.',
    expectedScore: '97 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '15_silent_server_timeout',
    filename: '15_silent_server_timeout.pcap',
    title: 'Silent Server Timeout (Zombie Flow)',
    category: 'messy',
    protocol: 'SMTP (Port 25)',
    tag: 'Asymmetric Blackhole',
    tagColor: 'var(--medium)',
    icon: Radio,
    description: 'Client connects and sends STARTTLS, but server drops packets into complete silence; client retransmits and times out.',
    expectedScore: '88 / 100',
    expectedRisk: 'MINIMAL',
  },
  {
    id: '06_anomalous_handshake',
    filename: '06_anomalous_handshake.pcap',
    title: 'ML Anomaly & Weak 1024-bit Key',
    category: 'messy',
    protocol: 'SMTP / Submission',
    tag: 'Statistical Anomaly',
    tagColor: 'var(--ml-color)',
    icon: Sparkles,
    description: 'Isolation Forest flags anomalous session metadata profile combined with 1024-bit weak RSA public key.',
    expectedScore: '50 / 100',
    expectedRisk: 'MEDIUM',
  },

  // ── 4. Real-World Online Captures (Wireshark & Arkime) ────────────
  {
    id: '26_online_wireshark_imap_mutt_msx',
    filename: '26_online_wireshark_imap_mutt_msx.cap',
    title: 'Wireshark: Mutt vs MS Exchange IMAP',
    category: 'online',
    protocol: 'IMAP (Port 143)',
    tag: 'Wireshark Sample',
    tagColor: 'var(--info)',
    icon: Globe,
    description: 'Authentic IMAP session captured using Mutt MUA against an MS Exchange server with cleartext commands.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '33_online_arkime_smtp_starttls',
    filename: '33_online_arkime_smtp_starttls.pcap',
    title: 'Arkime: Production SMTP STARTTLS',
    category: 'online',
    protocol: 'SMTP / STARTTLS',
    tag: 'Arkime Repo',
    tagColor: 'var(--critical)',
    icon: Server,
    description: 'Production STARTTLS negotiation from Arkime test corpus flagged with 10 cryptographic posture findings.',
    expectedScore: '0 / 100',
    expectedRisk: 'CRITICAL',
  },
  {
    id: '29_online_wireshark_smtp_ssl',
    filename: '29_online_wireshark_smtp_ssl.pcapng',
    title: 'Wireshark: Encrypted SMTP over TLS 1.2',
    category: 'online',
    protocol: 'SMTP / SMTPS',
    tag: 'Wireshark Sample',
    tagColor: 'var(--high)',
    icon: Globe,
    description: 'Real-world encrypted SMTP over TLS 1.2 capture contributed by Peter Wu with authentic certificates.',
    expectedScore: '48 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '30_online_wireshark_imap_ssl',
    filename: '30_online_wireshark_imap_ssl.pcapng',
    title: 'Wireshark: IMAP over TLS (IMAPS)',
    category: 'online',
    protocol: 'IMAP / IMAPS',
    tag: 'Wireshark Sample',
    tagColor: 'var(--info)',
    icon: Globe,
    description: 'Real IMAP over SSL/TLS session with authentic server certificate exchange and direct TLS connection.',
    expectedScore: '70 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '31_online_wireshark_pop_ssl',
    filename: '31_online_wireshark_pop_ssl.pcapng',
    title: 'Wireshark: POP3 over TLS (POP3S)',
    category: 'online',
    protocol: 'POP3 / POP3S',
    tag: 'Wireshark Sample',
    tagColor: 'var(--medium)',
    icon: Globe,
    description: 'Real POP3 over SSL/TLS session with authentic cryptographic negotiation from Wireshark test corpus.',
    expectedScore: '65 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '32_online_wireshark_smtp2525_ssl',
    filename: '32_online_wireshark_smtp2525_ssl.pcapng',
    title: 'Wireshark: SMTP TLS on Non-Standard Port 2525',
    category: 'online',
    protocol: 'SMTP (Port 2525)',
    tag: 'Wireshark Sample',
    tagColor: 'var(--high)',
    icon: Globe,
    description: 'Real SMTP over alternative port 2525 using SSL/TLS; tests non-standard port dissector classification.',
    expectedScore: '48 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '27_online_wireshark_smtp_cleartext',
    filename: '27_online_wireshark_smtp_cleartext.pcap',
    title: 'Wireshark: Plaintext SMTP Transaction',
    category: 'online',
    protocol: 'SMTP (Port 25)',
    tag: 'Wireshark Sample',
    tagColor: 'var(--critical)',
    icon: Globe,
    description: 'Real unencrypted SMTP mail exchange from Wireshark reference library; envelope and headers in cleartext.',
    expectedScore: '45 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '28_online_wireshark_sample_imf',
    filename: '28_online_wireshark_sample_imf.pcap',
    title: 'Wireshark: SMTP / IMF Multipart Email',
    category: 'online',
    protocol: 'SMTP (Port 25)',
    tag: 'Wireshark Sample',
    tagColor: 'var(--medium)',
    icon: Globe,
    description: 'Real Internet Message Format (IMF) multipart MIME transaction transmitted over unencrypted SMTP.',
    expectedScore: '55 / 100',
    expectedRisk: 'MEDIUM',
  },
  {
    id: '34_online_arkime_smtp_bof_attack',
    filename: '34_online_arkime_smtp_bof_attack.pcap',
    title: 'Arkime: SMTP Buffer Overflow Exploit',
    category: 'online',
    protocol: 'SMTP (Port 25)',
    tag: 'Arkime Exploit',
    tagColor: 'var(--critical)',
    icon: Bug,
    description: 'Real-world buffer overflow attack against an SMTP mail transfer agent captured in Arkime test suite.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '35_online_arkime_socks5_smtp_503',
    filename: '35_online_arkime_socks5_smtp_503.pcap',
    title: 'Arkime: SOCKS5 Proxied SMTP & 503 Desync',
    category: 'online',
    protocol: 'SMTP (Proxied)',
    tag: 'Arkime Repo',
    tagColor: 'var(--high)',
    icon: Server,
    description: 'SMTP traffic tunneled through SOCKS5 proxy encountering 503 Bad Sequence of Commands desynchronization.',
    expectedScore: '45 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '36_online_arkime_smtp_data_521',
    filename: '36_online_arkime_smtp_data_521.pcap',
    title: 'Arkime: SMTP Rejection (521 Error)',
    category: 'online',
    protocol: 'SMTP (Port 25)',
    tag: 'Arkime Repo',
    tagColor: 'var(--high)',
    icon: Server,
    description: 'Real mail transmission rejected by destination MTA with 521 channel closure error.',
    expectedScore: '45 / 100',
    expectedRisk: 'HIGH',
  },
  {
    id: '37_online_arkime_pop3_cleartext',
    filename: '37_online_arkime_pop3_cleartext.pcap',
    title: 'Arkime: Real POP3 Cleartext Session',
    category: 'online',
    protocol: 'POP3 (Port 110)',
    tag: 'Arkime Repo',
    tagColor: 'var(--medium)',
    icon: Server,
    description: 'Real unencrypted POP3 mail retrieval session from Arkime packet corpus.',
    expectedScore: '80 / 100',
    expectedRisk: 'LOW',
  },
  {
    id: '38_online_arkime_tls_split_clienthello',
    filename: '38_online_arkime_tls_split_clienthello.pcap',
    title: 'Arkime: Real TCP Split ClientHello',
    category: 'online',
    protocol: 'TLS Stream',
    tag: 'Arkime Repo',
    tagColor: 'var(--info)',
    icon: Server,
    description: 'Production capture where TLS ClientHello is fragmented across TCP frames; verified by reassembly engine.',
    expectedScore: '100 / 100',
    expectedRisk: 'MINIMAL',
  },
]

export default function DemoScenarios({ onSelectScenario, loading = false, activePcap = '' }) {
  const [activeCategory, setActiveCategory] = useState('all')
  const [showAll, setShowAll] = useState(false)

  const filteredScenarios = CANONICAL_SCENARIOS.filter(s => {
    if (activeCategory === 'all') return true
    return s.category === activeCategory
  })

  // When showing "all", limit to 6 by default to avoid overwhelming the page
  const INITIAL_LIMIT = 6
  const isLimited = activeCategory === 'all' && !showAll
  const visibleScenarios = isLimited ? filteredScenarios.slice(0, INITIAL_LIMIT) : filteredScenarios
  const hiddenCount = filteredScenarios.length - INITIAL_LIMIT

  return (
    <div className="card" style={{ marginBottom: '1.75rem' }}>
      <div className="card-header" style={{ alignItems: 'flex-start' }}>
        <div>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Play size={15} color="var(--accent)" />
            Evaluation PCAP Scenarios ({CANONICAL_SCENARIOS.length} Forensic Test Captures)
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            Extensive stress-test suite: baseline configurations, active MitM downgrades, credential harvesting, asymmetric drops, fuzzed payloads, and corrupted handshakes.
          </div>
        </div>

        {/* Category switcher */}
        <div className="filter-tabs">
          {[
            { id: 'all', label: `All (${CANONICAL_SCENARIOS.length})` },
            { id: 'online', label: `Real-World Online (${CANONICAL_SCENARIOS.filter(s => s.category === 'online').length})` },
            { id: 'messy', label: `Messy & Edge Cases (${CANONICAL_SCENARIOS.filter(s => s.category === 'messy').length})` },
            { id: 'attacks', label: `Attacks & Downgrades (${CANONICAL_SCENARIOS.filter(s => s.category === 'attacks').length})` },
            { id: 'standard', label: `Standard Protocols (${CANONICAL_SCENARIOS.filter(s => s.category === 'standard').length})` },
          ].map(cat => (
            <button
              key={cat.id}
              className={`filter-tab-btn ${activeCategory === cat.id ? 'active' : ''}`}
              onClick={() => { setActiveCategory(cat.id); setShowAll(false) }}
            >
              {cat.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(290px, 1fr))', gap: '0.85rem' }}>
        {visibleScenarios.map((sc) => {
          const Icon = sc.icon
          const isActive = activePcap && activePcap.includes(sc.filename)

          return (
            <div
              key={sc.id}
              onClick={() => !loading && onSelectScenario(sc)}
              style={{
                background: isActive ? 'var(--accent-dim)' : 'var(--bg-card-subtle)',
                border: `1px solid ${isActive ? 'var(--accent)' : 'var(--border)'}`,
                borderRadius: 'var(--radius-sm)',
                padding: '0.9rem 1rem',
                cursor: loading ? 'wait' : 'pointer',
                transition: 'all var(--trans)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
              className="scenario-card"
            >
              <div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.45rem' }}>
                  <span
                    style={{
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      textTransform: 'uppercase',
                      letterSpacing: '0.05em',
                      color: sc.tagColor,
                      background: 'var(--bg-card)',
                      padding: '0.15rem 0.45rem',
                      borderRadius: 4,
                      border: `1px solid var(--border)`,
                    }}
                  >
                    {sc.tag}
                  </span>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                    {sc.protocol}
                  </span>
                </div>

                <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <Icon size={15} color={sc.tagColor} style={{ flexShrink: 0 }} />
                  <span>{sc.title}</span>
                </div>

                <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.45, marginBottom: '0.75rem' }}>
                  {sc.description}
                </p>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '0.5rem', borderTop: '1px solid var(--border)', fontSize: '0.75rem' }}>
                <span style={{ color: 'var(--text-dim)' }}>
                  Expected: <strong style={{ color: 'var(--text)' }}>{sc.expectedScore}</strong>
                </span>
                <span style={{ color: 'var(--accent)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                  {isActive ? 'Current Analysis' : 'Run Scenario'} <ArrowRight size={12} />
                </span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Show all / Show less toggle */}
      {activeCategory === 'all' && hiddenCount > 0 && (
        <div style={{ textAlign: 'center', marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--border)' }}>
          <button
            className="btn btn-secondary"
            onClick={() => setShowAll(v => !v)}
            style={{ fontSize: '0.8rem', padding: '0.4rem 1rem', gap: '0.4rem' }}
          >
            {showAll ? (
              <>Show less</>
            ) : (
              <>Show all {filteredScenarios.length} scenarios ({hiddenCount} more) <ArrowRight size={13} /></>
            )}
          </button>
        </div>
      )}
    </div>
  )
}
