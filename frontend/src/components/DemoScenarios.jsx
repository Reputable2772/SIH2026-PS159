import React from 'react'
import {
  ShieldCheck,
  AlertTriangle,
  Unlock,
  Radio,
  Bug,
  ArrowRight,
  Play,
  Layers,
  CheckCircle2,
} from 'lucide-react'

export const CANONICAL_SCENARIOS = [
  {
    id: '01_enterprise_secure_baseline',
    filename: '01_enterprise_secure_baseline.pcap',
    title: 'Enterprise Secure Baseline',
    subtitle: 'Modern Multi-Protocol Encryption',
    streamCount: 3,
    streams: [
      'Stream 0: SMTP (Port 587) STARTTLS + TLS 1.3 & Encrypted Certs (RFC 8446 §4.4.2)',
      'Stream 1: IMAPS (Port 993) Direct TLS 1.2 with ECDHE-RSA-AES256-GCM & Valid CA Cert',
      'Stream 2: POP3S (Port 995) Direct TLS 1.2 with ECDHE-RSA-AES128-GCM Forward Secrecy'
    ],
    protocol: 'SMTP / IMAPS / POP3S',
    tag: 'Compliant Baseline',
    tagColor: 'var(--success)',
    icon: ShieldCheck,
    description: 'Fully compliant enterprise deployment demonstrating modern TLS 1.3 and TLS 1.2 configurations with perfect forward secrecy and proper certificate hygiene.',
    expectedScore: '99 / 100',
    expectedRisk: 'MINIMAL',
    riskLevel: 'minimal'
  },
  {
    id: '02_legacy_cryptography_and_certs',
    filename: '02_legacy_cryptography_and_certs.pcap',
    title: 'Cryptographic Obsolescence & Cert Failures',
    subtitle: 'Deprecated Protocols & Weak Hygiene',
    streamCount: 4,
    streams: [
      'Stream 0: SMTP (Port 25) Deprecated TLS 1.0 & CBC Mode (BEAST CVE-2011-3389)',
      'Stream 1: SMTPS (Port 465) 3DES-EDE & Static RSA lacking Forward Secrecy (Sweet32)',
      'Stream 2: IMAPS (Port 993) Expired X.509 Certificate presentation',
      'Stream 3: POP3S (Port 995) Self-Signed Certificate with Weak 1024-bit RSA Key'
    ],
    protocol: 'SMTP / SMTPS / IMAPS / POP3S',
    tag: 'Crypto Degradation',
    tagColor: 'var(--critical)',
    icon: AlertTriangle,
    description: 'Consolidated cryptographic violations: obsolete TLS 1.0 (RFC 8996), non-PFS key exchanges, Sweet32 64-bit block ciphers, expired certs, and 1024-bit keys.',
    expectedScore: '0 / 100',
    expectedRisk: 'CRITICAL',
    riskLevel: 'critical'
  },
  {
    id: '03_starttls_downgrade_and_cleartext',
    filename: '03_starttls_downgrade_and_cleartext.pcap',
    title: 'STARTTLS Downgrade & Cleartext Exfiltration',
    subtitle: 'Active MitM Tampering & Credential Spray',
    streamCount: 3,
    streams: [
      'Stream 0: SMTP (Port 25) Active MitM: Injects 454 TLS failure; client leaks AUTH LOGIN',
      'Stream 1: IMAP (Port 143) STARTTLS stripped from CAPABILITY; plaintext password leaked',
      'Stream 2: POP3 (Port 110) Pure unencrypted session with brute-force credential spray'
    ],
    protocol: 'SMTP / IMAP / POP3',
    tag: 'Active MitM Attack',
    tagColor: 'var(--critical)',
    icon: Unlock,
    description: 'Adversary-induced downgrade attacks forcing opportunistic STARTTLS to fail open into cleartext authentication and unencrypted mailbox credential exfiltration.',
    expectedScore: '5 / 100',
    expectedRisk: 'CRITICAL',
    riskLevel: 'critical'
  },
  {
    id: '04_protocol_anomalies_and_fuzzing',
    filename: '04_protocol_anomalies_and_fuzzing.pcap',
    title: 'Protocol Anomalies & Malformed Payloads',
    subtitle: 'Fuzzing, Web Probes & Record Corruptions',
    streamCount: 4,
    streams: [
      'Stream 0: Malformed HTTP GET probe sent to SMTP Port 25 triggering protocol desync',
      'Stream 1: Buffer fuzzing attempt with 2048-byte oversized EHLO command overflow',
      'Stream 2: Corrupted TLS record layer with illegal ContentType 0xFF and RST drop',
      'Stream 3: Split TLS ClientHello fragmented across TCP packets (fragmentation evasion)'
    ],
    protocol: 'SMTP / SMTPS / Submission',
    tag: 'Behavioral Anomaly',
    tagColor: 'var(--warning)',
    icon: Bug,
    description: 'Statistical deviations and protocol violations targeting mail servers: HTTP probes, buffer overflows, corrupted TLS records, and fragmented handshakes.',
    expectedScore: '54 / 100',
    expectedRisk: 'MEDIUM',
    riskLevel: 'medium'
  },
  {
    id: '05_realworld_network_transports',
    filename: '05_realworld_network_transports.pcap',
    title: 'Real-World Network Transport Chaos',
    subtitle: 'Loss, Retransmissions & Edge Cases',
    streamCount: 5,
    streams: [
      'Stream 0: Midstream truncated TLS with packet loss, duplicate ACKs, and unexpected RST',
      'Stream 1: Truncated Certificate handshake cut off mid-record due to MTU black hole',
      'Stream 2: Out-of-order TCP segment delivery with overlapping byte ranges in handshake',
      'Stream 3: Half-open TCP SYN port scan against mail ports without handshake completion',
      'Stream 4: SMTP pipelining desynchronization: commands sent prior to 220 banner'
    ],
    protocol: 'SMTP / IMAP / POP3',
    tag: 'Transport Edge Cases',
    tagColor: 'var(--high)',
    icon: Radio,
    description: 'Rigorous capture edge cases: asymmetric drops, packet fragmentation, out-of-order packet reassembly, silent resets, and pipelining desynchronization.',
    expectedScore: '49 / 100',
    expectedRisk: 'HIGH',
    riskLevel: 'high'
  },
]

export default function DemoScenarios({ onSelectScenario, loading = false, activePcap = '' }) {
  return (
    <div className="card" style={{ marginBottom: '1.75rem' }}>
      <div className="card-header" style={{ alignItems: 'flex-start' }}>
        <div>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Play size={15} color="var(--accent)" />
            Consolidated Forensic Scenarios (5 Multi-Stream PCAPs)
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Complete evaluation suite covering all email protocols (SMTP, IMAP, POP3), modern TLS 1.3 baselines, active MitM downgrades, credential harvesting, fuzzing, and transport-layer chaos.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', background: 'var(--bg-card-subtle)', padding: '0.35rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          <Layers size={14} color="var(--accent)" />
          <span><strong>19 Total Sessions</strong> across 5 PCAPs</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem' }}>
        {CANONICAL_SCENARIOS.map((sc) => {
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
                padding: '1.1rem 1.15rem',
                cursor: loading ? 'wait' : 'pointer',
                transition: 'all var(--trans)',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
              }}
              className="scenario-card"
            >
              <div>
                {/* Header tags */}
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <span
                      style={{
                        fontSize: '0.68rem',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        letterSpacing: '0.04em',
                        color: sc.tagColor,
                        background: 'var(--bg-card)',
                        padding: '0.18rem 0.45rem',
                        borderRadius: 4,
                        border: '1px solid var(--border)',
                      }}
                    >
                      {sc.tag}
                    </span>
                    <span
                      style={{
                        fontSize: '0.68rem',
                        fontWeight: 600,
                        color: 'var(--text-muted)',
                        background: 'var(--bg-card)',
                        padding: '0.18rem 0.45rem',
                        borderRadius: 4,
                        border: '1px solid var(--border)',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '0.25rem'
                      }}
                    >
                      <Layers size={10} />
                      {sc.streamCount} Streams
                    </span>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                    {sc.protocol}
                  </span>
                </div>

                {/* Title */}
                <div style={{ fontWeight: 600, fontSize: '0.96rem', color: 'var(--text)', marginBottom: '0.2rem', display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                  <Icon size={17} color={sc.tagColor} style={{ flexShrink: 0 }} />
                  <span>{sc.title}</span>
                </div>

                <div style={{ fontSize: '0.75rem', color: 'var(--accent)', fontWeight: 500, marginBottom: '0.55rem' }}>
                  {sc.subtitle}
                </div>

                <p style={{ fontSize: '0.79rem', color: 'var(--text-muted)', lineHeight: 1.45, marginBottom: '0.85rem' }}>
                  {sc.description}
                </p>

                {/* Multi-stream breakdown */}
                <div style={{ background: 'var(--bg-card)', borderRadius: 6, padding: '0.6rem 0.75rem', marginBottom: '0.85rem', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.7rem', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.04em', color: 'var(--text-dim)', marginBottom: '0.35rem' }}>
                    Streams Included:
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '0.28rem' }}>
                    {sc.streams.map((strText, idx) => (
                      <div key={idx} style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'flex-start', gap: '0.35rem', lineHeight: 1.35 }}>
                        <span style={{ color: sc.tagColor, marginTop: '0.15rem' }}>•</span>
                        <span>{strText}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Footer */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '0.65rem', borderTop: '1px solid var(--border)', fontSize: '0.78rem' }}>
                <span style={{ color: 'var(--text-dim)' }}>
                  Expected: <strong style={{ color: sc.expectedRisk === 'MINIMAL' ? 'var(--success)' : sc.expectedRisk === 'CRITICAL' ? 'var(--critical)' : 'var(--warning)' }}>{sc.expectedScore} ({sc.expectedRisk})</strong>
                </span>
                <span style={{ color: 'var(--accent)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                  {isActive ? (
                    <>
                      <CheckCircle2 size={13} color="var(--success)" /> Loaded
                    </>
                  ) : (
                    <>
                      Run Analysis <ArrowRight size={13} />
                    </>
                  )}
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
