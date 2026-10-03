import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Terminal,
  BookOpen,
  Copy,
  Check,
  ShieldCheck,
  Wifi,
  ArrowRight,
  Upload,
  AlertTriangle,
  FileText
} from 'lucide-react'

export default function Guide() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('tcpdump')
  const [copiedId, setCopiedId] = useState(null)

  const copyToClipboard = (text, id) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopiedId(id)
      setTimeout(() => setCopiedId(null), 2000)
    }).catch(() => {})
  }

  const captureCommands = {
    tcpdump: [
      {
        id: 'tcpdump-all',
        title: 'Capture All Email Protocols (SMTP, IMAP, POP3)',
        description: 'Recommended general capture command covering standard cleartext, submission, and direct TLS ports across all network interfaces.',
        cmd: 'sudo tcpdump -i any -s 0 -nn -w email_traffic.pcap "tcp port 25 or tcp port 587 or tcp port 465 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"',
        explanation: [
          '-i any : Sniff all network interfaces (eth0, wlan0, lo, docker0)',
          '-s 0 : Full snaplength — ensures complete TLS ClientHello, ServerHello, and certificate chains are not truncated',
          '-nn : Disable DNS and port name lookups to minimize capture latency',
          '-w file.pcap : Write raw packet frames to standard pcap file'
        ]
      },
      {
        id: 'tcpdump-smtp',
        title: 'SMTP Mail Transfer & Submission Only',
        description: 'Sniffs inbound mail relays (port 25), authenticated client submission (port 587), and legacy implicit SMTPS (port 465).',
        cmd: 'sudo tcpdump -i any -s 0 -nn -w smtp_capture.pcap "tcp port 25 or tcp port 587 or tcp port 465"',
        explanation: [
          'Port 25 : MTA-to-MTA mail routing with opportunistic STARTTLS',
          'Port 587 : MUA client mail submission with required STARTTLS',
          'Port 465 : Direct implicit TLS transport (SMTPS)'
        ]
      },
      {
        id: 'tcpdump-mailbox',
        title: 'IMAP & POP3 Mailbox Retrieval Only',
        description: 'Sniffs mailbox retrieval traffic including opportunistic STARTTLS/STLS and direct TLS ports.',
        cmd: 'sudo tcpdump -i any -s 0 -nn -w mailbox_capture.pcap "tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995"',
        explanation: [
          'Port 143 : IMAP4rev1 with opportunistic STARTTLS',
          'Port 993 : IMAPS direct implicit TLS',
          'Port 110 : POP3 with opportunistic STLS',
          'Port 995 : POP3S direct implicit TLS'
        ]
      }
    ],
    tshark: [
      {
        id: 'tshark-live',
        title: 'Headless TShark Packet Capture',
        description: 'Capture directly using Wireshark CLI engine with standard pcap output format.',
        cmd: 'tshark -i any -f "tcp port 25 or tcp port 587 or tcp port 465" -s 0 -w smtp_tshark.pcap',
        explanation: [
          '-f "..." : BPF (Berkeley Packet Filter) applied at capture socket level',
          '-s 0 : Capture full packet frames without slicing'
        ]
      },
      {
        id: 'tshark-inspect',
        title: 'Quick CLI Verification of Captured TLS Handshakes',
        description: 'Verify your capture contains valid email and TLS handshakes before uploading.',
        cmd: 'tshark -r email_traffic.pcap -Y "smtp || imap || pop || tls.handshake"',
        explanation: [
          '-r file : Read captured packets offline',
          '-Y "..." : Wireshark display filter to preview email protocol negotiation'
        ]
      }
    ],
    wireshark: [
      {
        id: 'wireshark-gui',
        title: 'Wireshark GUI Desktop Setup',
        description: 'Configure Wireshark desktop capture filters before starting packet sniffing.',
        cmd: 'tcp port 25 or tcp port 587 or tcp port 465 or tcp port 143 or tcp port 993 or tcp port 110 or tcp port 995',
        explanation: [
          '1. Open Wireshark and double-click your network interface (e.g. eth0, any).',
          '2. In the "Capture Filter" box (green toolbar), paste the filter above.',
          '3. Trigger email send/receive actions in your mail client.',
          '4. Stop capture: Capture → Stop (Ctrl+E).',
          '5. Save file: File → Save As → select "Wireshark/tcpdump/... - pcap" or "pcapng".'
        ]
      }
    ],
    containers: [
      {
        id: 'podman-sniff',
        title: 'Sniffing Containerized Mail Servers (Docker / Podman)',
        description: 'Capture traffic traversing container bridge networks without installing tools inside the container.',
        cmd: 'sudo tcpdump -i any -s 0 -nn -w container_mail.pcap "tcp port 25 or tcp port 587 or tcp port 8000"',
        explanation: [
          'Runs on host operating system',
          'Captures traffic between host, reverse proxy (Caddy), and mail services',
          'Works with rootless Podman and Docker Compose stacks'
        ]
      }
    ],
    synthetic: [
      {
        id: 'synth-gen',
        title: 'Synthetic Test PCAP Generation (Offline / Zero-Root)',
        description: 'Generate 5 comprehensive multi-session evaluation PCAPs with Scapy in user space covering all protocols, baselines, downgrades, and real-world edge cases.',
        cmd: 'just gen-pcaps',
        explanation: [
          '01_enterprise_secure_baseline.pcap : Clean multi-protocol baseline (TLS 1.3 encrypted certs, TLS 1.2 ECDHE, valid CA certs across SMTP/IMAP/POP3)',
          '02_legacy_cryptography_and_certs.pcap : Cryptographic degradation (TLS 1.0 BEAST, 3DES Sweet32, static RSA without PFS, expired certs, 1024-bit keys)',
          '03_starttls_downgrade_and_cleartext.pcap : Active MitM attacks (STARTTLS stripping, 454 downgrade fallback, plaintext credentials exfiltration)',
          '04_protocol_anomalies_and_fuzzing.pcap : Behavioral anomalies (HTTP probes on mail ports, 2048-byte buffer fuzzing, corrupt TLS records, split ClientHellos)',
          '05_realworld_network_transports.pcap : Real-world transport chaos (packet loss, retransmissions, midstream RSTs, truncated certs, out-of-order overlap, SYN scan)'
        ]
      }
    ]
  }

  return (
    <div style={{ maxWidth: 1100, margin: '0 auto' }}>
      {/* Header */}
      <div className="page-header">
        <h2 className="page-title">Packet Capture Guide & Documentation</h2>
        <p className="page-subtitle">
          Instructions for capturing email network traffic, understanding STARTTLS negotiation, and running forensic cryptographic audits.
        </p>
      </div>

      {/* Quick Action Hero Banner */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(88,166,255,0.12) 0%, rgba(167,139,250,0.08) 100%)',
        border: '1px solid rgba(88,166,255,0.25)',
        borderRadius: 12,
        padding: '1.25rem 1.5rem',
        marginBottom: '1.75rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div>
          <div style={{ fontWeight: 600, fontSize: '1rem', color: 'var(--text)', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <ShieldCheck size={18} color="var(--info)" />
            Zero-Payload Passive Forensic Auditing
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginTop: '0.35rem', maxWidth: 650 }}>
            SecureMailScope extracts network headers, protocol verbs (EHLO, STARTTLS), and TLS handshake records only.
            Email bodies, message contents, and attachments are strictly ignored and never stored.
          </div>
        </div>
        <div style={{ display: 'flex', gap: '0.75rem' }}>
          <button className="btn btn-secondary" onClick={() => navigate('/')} style={{ fontSize: '0.82rem' }}>
            <Upload size={14} /> Upload PCAP
          </button>
          <button className="btn btn-primary" onClick={() => navigate('/')} style={{ fontSize: '0.82rem' }}>
            View Dashboard <ArrowRight size={14} />
          </button>
        </div>
      </div>

      {/* 4-Step Interactive Workflow */}
      <div style={{ marginBottom: '2rem' }}>
        <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: 'var(--text)', marginBottom: '1rem' }}>
          End-to-End Operational Workflow
        </h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem' }}>
          <div className="card" style={{ position: 'relative' }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%', background: 'rgba(88,166,255,0.15)',
              color: 'var(--accent)', fontWeight: 700, display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: '0.85rem', marginBottom: '0.75rem'
            }}>1</div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.35rem' }}>Capture Network Packets</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Use <code>tcpdump</code>, <code>tshark</code>, or Wireshark on your network gateway or mail server to capture traffic into a <code>.pcap</code> or <code>.pcapng</code> file.
            </div>
          </div>

          <div className="card" style={{ position: 'relative' }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%', background: 'rgba(63,185,80,0.15)',
              color: 'var(--info)', fontWeight: 700, display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: '0.85rem', marginBottom: '0.75rem'
            }}>2</div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.35rem' }}>Upload or Select Scenario</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Drop your capture in the Upload tab or select one of the 7 bundled canonical evaluation scenarios to inspect baseline postures.
            </div>
          </div>

          <div className="card" style={{ position: 'relative' }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%', background: 'rgba(167,139,250,0.15)',
              color: 'var(--ml-color)', fontWeight: 700, display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: '0.85rem', marginBottom: '0.75rem'
            }}>3</div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.35rem' }}>Dual-Engine Forensic Analysis</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Deterministic rules flag RFC & CVE violations with 100% precision while the Isolation Forest models 16-D behavioral outliers.
            </div>
          </div>

          <div className="card" style={{ position: 'relative' }}>
            <div style={{
              width: 28, height: 28, borderRadius: '50%', background: 'rgba(245,166,35,0.15)',
              color: 'var(--high)', fontWeight: 700, display: 'flex', alignItems: 'center',
              justifyContent: 'center', fontSize: '0.85rem', marginBottom: '0.75rem'
            }}>4</div>
            <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.35rem' }}>Audit Reports & Provenance</div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Download publication-ready PDF audit reports with SHA-256 capture hashes, frame-level evidence, and JSON forensics.
            </div>
          </div>
        </div>
      </div>

      {/* Packet Capture Tool Command Generator */}
      <div className="card" style={{ marginBottom: '2rem' }}>
        <div className="card-header" style={{ alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Terminal size={17} color="var(--accent)" />
              Packet Capture Cheat Sheet & Commands
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
              Select your capture tool below, copy the command, and run it on your monitoring interface.
            </div>
          </div>

          {/* Tool Tab Switcher */}
          <div style={{ display: 'flex', background: 'var(--bg-surface)', padding: '0.2rem', borderRadius: 8, border: '1px solid var(--border)' }}>
            {[
              { id: 'tcpdump', label: 'tcpdump (CLI)' },
              { id: 'tshark', label: 'tshark (CLI)' },
              { id: 'wireshark', label: 'Wireshark GUI' },
              { id: 'containers', label: 'Containers' },
              { id: 'synthetic', label: 'Synthetic Generator' }
            ].map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`btn ${activeTab === tab.id ? 'btn-primary' : 'btn-secondary'}`}
                style={{
                  fontSize: '0.75rem',
                  padding: '0.3rem 0.7rem',
                  border: activeTab === tab.id ? undefined : 'none',
                  background: activeTab === tab.id ? undefined : 'transparent'
                }}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        {/* Capture Command List for Active Tab */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem', marginTop: '0.5rem' }}>
          {captureCommands[activeTab]?.map(item => (
            <div key={item.id} style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border)',
              borderRadius: 8,
              padding: '1rem'
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.4rem' }}>
                <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text)' }}>
                  {item.title}
                </div>
                <button
                  className="btn btn-secondary"
                  onClick={() => copyToClipboard(item.cmd, item.id)}
                  style={{
                    fontSize: '0.74rem',
                    padding: '0.25rem 0.6rem',
                    gap: '0.35rem',
                    color: copiedId === item.id ? 'var(--info)' : 'var(--text-muted)',
                    borderColor: copiedId === item.id ? 'var(--info)' : 'var(--border)'
                  }}
                >
                  {copiedId === item.id ? <Check size={13} /> : <Copy size={13} />}
                  {copiedId === item.id ? 'Copied!' : 'Copy Command'}
                </button>
              </div>

              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                {item.description}
              </div>

              {/* Code snippet block */}
              <div style={{
                background: '#0d1117',
                border: '1px solid var(--border-hi)',
                borderRadius: 6,
                padding: '0.75rem 1rem',
                fontFamily: 'monospace',
                fontSize: '0.82rem',
                color: '#79c0ff',
                overflowX: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                marginBottom: '0.75rem'
              }}>
                {item.cmd}
              </div>

              {/* Explanation bullet list */}
              {item.explanation && (
                <ul style={{
                  fontSize: '0.76rem',
                  color: 'var(--text-muted)',
                  paddingLeft: '1.2rem',
                  lineHeight: 1.6
                }}>
                  {item.explanation.map((exp, i) => (
                    <li key={i}>{exp}</li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Protocol & Port Matrix */}
      <div className="card" style={{ marginBottom: '2rem' }}>
        <div className="card-header">
          <div className="card-title">Email Protocol & Encryption Matrix</div>
          <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>RFC 5321 · RFC 3207 · RFC 3501 · RFC 8314</span>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Protocol</th>
                <th>Standard Port</th>
                <th>Transport Mode</th>
                <th>Encryption Mechanism</th>
                <th>Security Posture</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td><span className="proto-tag proto-SMTP">SMTP</span> Relay</td>
                <td><code>25</code></td>
                <td>Cleartext / Explicit Upgrade</td>
                <td>Opportunistic <code>STARTTLS</code> (RFC 3207)</td>
                <td><span style={{ color: 'var(--high)' }}>Vulnerable to downgrade if unauthenticated</span></td>
              </tr>
              <tr>
                <td><span className="proto-tag proto-SMTP">SMTP</span> Submission</td>
                <td><code>587</code></td>
                <td>Explicit Upgrade</td>
                <td>Required <code>STARTTLS</code></td>
                <td><span style={{ color: 'var(--info)' }}>Standard client submission channel</span></td>
              </tr>
              <tr>
                <td><span className="proto-tag proto-SMTP">SMTPS</span> Direct</td>
                <td><code>465</code></td>
                <td>Implicit TLS</td>
                <td>Direct TLS on connection (RFC 8314)</td>
                <td><span style={{ color: 'var(--info)' }}>Immune to STARTTLS stripping</span></td>
              </tr>
              <tr>
                <td><span className="proto-tag proto-IMAP">IMAP</span> Clear</td>
                <td><code>143</code></td>
                <td>Cleartext / Explicit Upgrade</td>
                <td>Opportunistic <code>STARTTLS</code> (RFC 2595)</td>
                <td><span style={{ color: 'var(--high)' }}>Cleartext credential risk if stripped</span></td>
              </tr>
              <tr>
                <td><span className="proto-tag proto-IMAP">IMAPS</span> Direct</td>
                <td><code>993</code></td>
                <td>Implicit TLS</td>
                <td>Direct TLS on connection (RFC 8314)</td>
                <td><span style={{ color: 'var(--info)' }}>Recommended modern mailbox retrieval</span></td>
              </tr>
              <tr>
                <td><span className="proto-tag proto-POP3">POP3</span> Clear</td>
                <td><code>110</code></td>
                <td>Cleartext / Explicit Upgrade</td>
                <td>Opportunistic <code>STLS</code> (RFC 2595)</td>
                <td><span style={{ color: 'var(--high)' }}>Cleartext credential risk if stripped</span></td>
              </tr>
              <tr>
                <td><span className="proto-tag proto-POP3">POP3S</span> Direct</td>
                <td><code>995</code></td>
                <td>Implicit TLS</td>
                <td>Direct TLS on connection (RFC 8314)</td>
                <td><span style={{ color: 'var(--info)' }}>Secure direct mailbox retrieval</span></td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* STARTTLS Downgrade Mechanics & RFC 8446 Note */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="card">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--critical)' }}>
            <AlertTriangle size={16} /> How STARTTLS Downgrades Occur
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, marginTop: '0.75rem' }}>
            <p style={{ marginBottom: '0.5rem' }}>
              Because STARTTLS begins in plaintext over cleartext TCP connections, an active network attacker can strip the <code>250-STARTTLS</code> capability advertisement from the server's greeting response.
            </p>
            <p style={{ marginBottom: '0.5rem' }}>
              SecureMailScope detects this via its <strong>Finite State Machine</strong>:
            </p>
            <ul style={{ paddingLeft: '1.2rem', lineHeight: 1.6 }}>
              <li><strong>SUSPICIOUS_FALLBACK:</strong> Server advertised STARTTLS capability, but the client subsequently transmitted email or authentication without completing a TLS handshake.</li>
              <li><strong>PLAINTEXT_AUTH:</strong> Client sent <code>AUTH</code>, <code>LOGIN</code>, <code>USER</code>, or <code>PASS</code> verbs before TLS encryption was established.</li>
            </ul>
          </div>
        </div>

        <div className="card">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--accent)' }}>
            <BookOpen size={16} /> TLS 1.3 Observability Boundaries (RFC 8446)
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6, marginTop: '0.75rem' }}>
            <p style={{ marginBottom: '0.5rem' }}>
              In TLS 1.3, the server's X.509 <code>Certificate</code> message is encrypted under ephemeral handshake traffic keys.
            </p>
            <p style={{ marginBottom: '0.5rem' }}>
              Passive network analyzers cannot decrypt the certificate without session keys (<code>SSLKEYLOGFILE</code>).
            </p>
            <p>
              SecureMailScope explicitly respects this cryptographic boundary. Rather than hallucinating or erroring, it reports:
            </p>
            <div style={{ background: 'rgba(88,166,255,0.08)', border: '1px solid rgba(88,166,255,0.25)', borderRadius: 6, padding: '0.6rem 0.8rem', marginTop: '0.5rem', fontSize: '0.78rem', color: 'var(--accent)' }}>
              ✓ TLS Version, Cipher Suite, and Forward Secrecy: <strong>Observable</strong><br />
              ✗ Server Certificate Subject & Expiry: <strong>Encrypted by Design (RFC 8446 §4.4.2)</strong>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
