import React, { useState } from 'react'
import {
  FileText,
  AlertTriangle,
  Lightbulb,
  ExternalLink,
  ShieldAlert,
  Sparkles,
  Search,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

export default function EvidenceInspector({ finding, onNavigateSession = null }) {
  const [expanded, setExpanded] = useState(true)

  if (!finding) return null

  const isMl = Boolean(finding.is_ml_finding)
  const evidence = finding.evidence || {}

  // Generate explanation based on category/title if not explicitly present
  const getExplanation = () => {
    if (isMl) {
      return (
        'The Isolation Forest unsupervised anomaly detector scored this session’s 16-dimensional metadata vector outside the baseline learned distribution. ' +
        'This represents a statistical outlier in parameter combinations (such as unusual cipher/extension ratios, key sizes, or timing) rather than a deterministic RFC breach.'
      )
    }

    const cat = (finding.category || '').toLowerCase()
    const title = (finding.title || '').toLowerCase()

    if (cat.includes('starttls') || title.includes('starttls') || title.includes('downgrade') || title.includes('fallback')) {
      return (
        'RFC 3207 and RFC 2595 specify that when STARTTLS is advertised and accepted, subsequent transport must be encrypted. ' +
        'In this capture, cleartext protocol verbs or authentication credentials were transmitted without completing a TLS handshake, matching the signature of a STARTTLS stripping attack or improper client fallback.'
      )
    }
    if (cat.includes('tls') || title.includes('tls 1.0') || title.includes('legacy')) {
      return (
        'RFC 8996 formally deprecated TLS 1.0 and TLS 1.1 due to structural vulnerabilities (e.g. lack of modern AEAD ciphers, CBC padding attacks like BEAST/Lucky13). ' +
        'Passive inspection of the TLS record header observed legacy protocol version negotiation.'
      )
    }
    if (cat.includes('expired') || title.includes('expired')) {
      return (
        'RFC 5280 Section 4.1.2.5 mandates that a certificate is only valid during the period delimited by notBefore and notAfter timestamps. ' +
        'The capture timestamp exceeded the certificate’s notAfter timestamp, rendering cryptographic trust unverified.'
      )
    }
    if (cat.includes('weak_key') || title.includes('key')) {
      return (
        'NIST SP 800-57 Part 1 requires a minimum RSA key size of 2048 bits for secure communications. ' +
        'The extracted SubjectPublicKeyInfo structure contained an insufficient key length that can be factored with modern computational resources.'
      )
    }
    if (cat.includes('weak_cipher') || title.includes('cipher') || title.includes('3des')) {
      return (
        'The negotiated cipher suite utilizes deprecated cryptographic primitives (such as 3DES or static RSA key exchange without Forward Secrecy). ' +
        'Static RSA key exchange allows retroactive decryption of all recorded sessions if the server private key is ever compromised.'
      )
    }
    return (
      'The observed protocol frame or handshake record violated standard security baselines for modern mail transfer and client retrieval.'
    )
  }

  return (
    <div
      className={`finding-card ${isMl ? 'finding-ml' : `finding-${(finding.severity || 'info').toLowerCase()}`}`}
      style={{ marginBottom: '1.25rem' }}
    >
      {/* 1. Finding Header & Classification */}
      <div className="card-header" style={{ marginBottom: '0.75rem' }}>
        <div className="finding-title-row">
          <SeverityBadge severity={finding.severity} isMl={isMl} />
          <span
            style={{
              fontSize: '0.72rem',
              color: isMl ? 'var(--ml-color)' : 'var(--text-dim)',
              border: `1px solid ${isMl ? 'var(--ml-border)' : 'var(--border)'}`,
              padding: '0.15rem 0.45rem',
              borderRadius: 4,
              textTransform: 'uppercase',
              fontWeight: 600,
              background: isMl ? 'var(--ml-bg)' : 'transparent',
            }}
          >
            {isMl ? '🤖 ML Behavioural Anomaly' : '🔍 Deterministic Rule'}
          </span>
          <span className="finding-title-text">{finding.title}</span>
        </div>

        <button
          className="btn btn-ghost"
          onClick={() => setExpanded(!expanded)}
          style={{ padding: '0.2rem 0.4rem', fontSize: '0.75rem' }}
          title={expanded ? 'Collapse finding' : 'Expand finding'}
        >
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>
      </div>

      {/* Description */}
      <div className="finding-description">{finding.description}</div>

      {expanded && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.85rem', marginTop: '0.75rem' }}>
          {/* 2. Observed Evidence (Forensic Provenance) */}
          <div className="evidence-box">
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
              <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                <Search size={13} color="var(--accent)" />
                Observed Traceable Evidence
              </div>
              {evidence.session_id && onNavigateSession && (
                <button
                  className="btn btn-ghost"
                  onClick={() => onNavigateSession(evidence.session_id)}
                  style={{ fontSize: '0.72rem', padding: '0.15rem 0.4rem', gap: '0.3rem', color: 'var(--accent)' }}
                >
                  Jump to Session <ExternalLink size={11} />
                </button>
              )}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.5rem', fontSize: '0.78rem' }}>
              <div>
                <span style={{ color: 'var(--text-dim)' }}>Source PCAP: </span>
                <code style={{ color: 'var(--text)' }}>
                  {evidence.pcap_file ? evidence.pcap_file.split('/').pop() : 'capture.pcap'}
                </code>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)' }}>Session ID: </span>
                <code style={{ color: 'var(--accent)' }}>
                  {evidence.session_id || 'Global'}
                </code>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)' }}>Packet Numbers: </span>
                <span style={{ color: 'var(--text)', fontWeight: 600 }}>
                  {evidence.packet_numbers && evidence.packet_numbers.length > 0
                    ? evidence.packet_numbers.map(n => `#${n}`).join(', ')
                    : 'Stream level / Handshake'}
                </span>
              </div>

              <div>
                <span style={{ color: 'var(--text-dim)' }}>Protocol Field: </span>
                <code style={{ color: 'var(--text)' }}>
                  {evidence.field || finding.category || 'protocol.field'}
                </code>
              </div>
            </div>

            {evidence.observed_value != null && (
              <div style={{ marginTop: '0.5rem', paddingTop: '0.4rem', borderTop: '1px solid var(--border)', fontSize: '0.78rem' }}>
                <span style={{ color: 'var(--text-dim)' }}>Observed Value: </span>
                <code style={{ color: 'var(--critical)', wordBreak: 'break-all' }}>
                  {typeof evidence.observed_value === 'object'
                    ? JSON.stringify(evidence.observed_value)
                    : String(evidence.observed_value)}
                </code>
              </div>
            )}
          </div>

          {/* 3. Why It Matters / Technical Explanation */}
          <div style={{ background: 'var(--bg-card-subtle)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '0.75rem 1rem', fontSize: '0.8rem' }}>
            <div style={{ fontWeight: 700, color: 'var(--text)', marginBottom: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <ShieldAlert size={14} color="var(--high)" />
              Why SecureMailScope Flagged This:
            </div>
            <div style={{ color: 'var(--text-muted)', lineHeight: 1.55 }}>
              {getExplanation()}
            </div>
          </div>

          {/* 4. Actionable Recommendation */}
          <div className="recommendation-box">
            <Lightbulb size={16} style={{ flexShrink: 0, marginTop: '0.1rem', color: 'var(--info)' }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.82rem', marginBottom: '0.15rem' }}>
                Remediation Recommendation
              </div>
              <div style={{ lineHeight: 1.5 }}>
                {finding.recommendation || 'Upgrade server configuration to modern TLS and enforce strict transport security.'}
              </div>
            </div>
          </div>

          {/* References & CVEs */}
          {finding.cve_references && finding.cve_references.length > 0 && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.74rem', color: 'var(--text-dim)' }}>
              <span>CVE / Security References:</span>
              {finding.cve_references.map((cve, i) => (
                <span key={i} style={{ background: 'var(--bg-surface)', padding: '0.1rem 0.4rem', borderRadius: 4, border: '1px solid var(--border)', fontFamily: 'monospace' }}>
                  {cve}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
