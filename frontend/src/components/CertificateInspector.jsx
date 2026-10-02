import React from 'react'
import { ShieldAlert, Key, Fingerprint, Lock, Copy, Check } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

export default function CertificateInspector({ certificates = [], certObservability = 'observed', certObservabilityNote = '', findings = [], isTls13 = false }) {
  const [copiedSha, setCopiedSha] = React.useState(null)

  const handleCopy = (text) => {
    navigator.clipboard?.writeText(text)
    setCopiedSha(text)
    setTimeout(() => setCopiedSha(null), 2000)
  }

  // Handle TLS 1.3 encrypted handshake note
  if (isTls13 || certObservability === 'not_observable') {
    return (
      <div className="card" style={{ borderLeft: '4px solid var(--accent)' }}>
        <div className="card-header">
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
            <Lock size={16} color="var(--accent)" />
            X.509 Certificate: Not Observable (TLS 1.3 Protocol Design)
          </div>
          <span className="sev-badge sev-low">Protocol Limitation</span>
        </div>

        <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
          <p style={{ marginBottom: '0.65rem' }}>
            <strong>TLS 1.3 encrypts the Certificate message during the handshake (RFC 8446 §4.4.2).</strong>
          </p>
          <p style={{ marginBottom: '0.65rem' }}>
            In TLS 1.3, after the initial ephemeral key exchange (ClientHello / ServerHello), all subsequent handshake messages — including the server's X.509 Certificate and CertificateVerify — are protected using handshake traffic encryption keys.
          </p>
          <div className="callout callout-info" style={{ marginTop: '0.75rem', marginBottom: '0.75rem' }}>
            <strong>Forensic Technical Distinction:</strong> This is a standard passive network observation limitation, <em>not a certificate failure or protocol error</em>. Unless session secrets (e.g. <code>SSLKEYLOGFILE</code>) are supplied to decrypt the capture, server certificate metadata cannot be inspected passively.
          </div>
          <p style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>
            {certObservabilityNote || 'Certificate payload was not extracted because handshake was encrypted.'}
          </p>
        </div>
      </div>
    )
  }

  if (!certificates || certificates.length === 0) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '2.5rem 1rem', color: 'var(--text-muted)' }}>
        <div style={{ fontSize: '2rem', marginBottom: '0.5rem', opacity: 0.5 }}>📜</div>
        <div style={{ fontWeight: 600, fontSize: '0.9rem', marginBottom: '0.25rem' }}>No Observable Certificates in Capture</div>
        <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
          No X.509 Certificate records were observed in this session's unencrypted handshake frames.
        </div>
      </div>
    )
  }

  // Filter certificate-related findings
  const certFindings = findings.filter(f =>
    f.category?.includes('cert') ||
    f.category?.includes('signature') ||
    f.category?.includes('weak_key') ||
    f.title?.toLowerCase().includes('cert') ||
    f.title?.toLowerCase().includes('key')
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
      {certificates.map((cert, idx) => {
        const isExpired = cert.is_expired
        const isWeakKey = cert.public_key?.key_size_bits && cert.public_key.key_size_bits < 2048
        const isWeakSig = cert.signature_algorithm && (cert.signature_algorithm.includes('sha1') || cert.signature_algorithm.includes('md5'))
        const isSelfSigned = cert.is_self_signed

        return (
          <div key={cert.fingerprint_sha256 || idx} className="card">
            {/* Header */}
            <div className="card-header" style={{ borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem' }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                  <span style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text)' }}>
                    {cert.subject_cn || 'X.509 Certificate'}
                  </span>
                  {isExpired && <SeverityBadge severity="CRITICAL" />}
                  {isWeakKey && <SeverityBadge severity="HIGH" />}
                  {isSelfSigned && <SeverityBadge severity="MEDIUM" />}
                  {!isExpired && !isWeakKey && !isWeakSig && <SeverityBadge severity="INFO" />}
                </div>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                  Issuer: <strong>{cert.issuer_cn || cert.issuer_dn || 'Self-Signed / Unknown'}</strong>
                </div>
              </div>

              <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textAlign: 'right' }}>
                Chain Index: #{idx + 1}
              </div>
            </div>

            {/* In-Line Findings Banner (Presented directly alongside relevant properties) */}
            {(isExpired || isWeakKey || isWeakSig || isSelfSigned) && (
              <div style={{
                background: 'var(--critical-bg)',
                border: '1px solid var(--critical-border)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.65rem 0.85rem',
                margin: '0.75rem 0',
                display: 'flex',
                flexDirection: 'column',
                gap: '0.35rem',
                fontSize: '0.8rem',
              }}>
                <div style={{ fontWeight: 700, color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <ShieldAlert size={14} /> Critical Certificate Posture Signals
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.65rem', marginTop: '0.2rem' }}>
                  {isExpired && (
                    <span style={{ color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      • <strong>Expired Status:</strong> Validity lapsed (Critical RFC 5280 violation)
                    </span>
                  )}
                  {isWeakKey && (
                    <span style={{ color: 'var(--high)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      • <strong>Weak Key Size:</strong> {cert.public_key.key_size_bits}-bit RSA &lt; 2048-bit minimum
                    </span>
                  )}
                  {isWeakSig && (
                    <span style={{ color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      • <strong>Weak Signature:</strong> {cert.signature_algorithm} vulnerable to collision attacks
                    </span>
                  )}
                  {isSelfSigned && (
                    <span style={{ color: 'var(--medium)', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                      • <strong>Self-Signed:</strong> Lacks verifiable trusted CA anchor
                    </span>
                  )}
                </div>
              </div>
            )}

            {/* Certificate Properties Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginTop: '0.85rem' }}>
              {/* Identity & Chain */}
              <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                  Subject & Issuer Identity
                </div>
                <PropRow label="Subject CN" value={cert.subject_cn || 'None'} />
                <PropRow label="Subject DN" value={cert.subject_dn || 'None'} mono />
                <PropRow label="Issuer CN" value={cert.issuer_cn || 'None'} />
                <PropRow label="Issuer DN" value={cert.issuer_dn || 'None'} mono />
                <PropRow label="Self-Signed" value={isSelfSigned ? 'Yes (Potential MitM)' : 'No (CA-signed)'} highlight={isSelfSigned ? 'warning' : 'ok'} />
              </div>

              {/* Cryptography & Keys */}
              <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                  Public Key & Cryptography
                </div>
                <PropRow
                  label="Algorithm"
                  value={cert.public_key?.algorithm || 'RSA'}
                />
                <PropRow
                  label="Key Size"
                  value={cert.public_key?.key_size_bits ? `${cert.public_key.key_size_bits} bits` : '—'}
                  highlight={isWeakKey ? 'danger' : 'ok'}
                  flag={isWeakKey ? 'Weak key (< 2048 bits)' : 'Standard'}
                />
                <PropRow
                  label="Public Exponent"
                  value={cert.public_key?.public_exponent ? `e = ${cert.public_key.public_exponent} (0x${cert.public_key.public_exponent.toString(16)})` : 'e = 65537'}
                  mono
                />
                <PropRow
                  label="Signature Algorithm"
                  value={cert.signature_algorithm || 'sha256WithRSAEncryption'}
                  highlight={isWeakSig ? 'danger' : 'ok'}
                />
                <PropRow
                  label="X.509 Version"
                  value={cert.version ? `v${cert.version}` : 'v3'}
                />
              </div>

              {/* Validity Window */}
              <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                  Validity Period
                </div>
                <PropRow
                  label="Not Before"
                  value={cert.not_before ? new Date(cert.not_before).toUTCString() : '—'}
                />
                <PropRow
                  label="Not After"
                  value={cert.not_after ? new Date(cert.not_after).toUTCString() : '—'}
                  highlight={isExpired ? 'danger' : 'ok'}
                />
                <PropRow
                  label="Expiration Status"
                  value={isExpired ? 'EXPIRED' : 'VALID'}
                  highlight={isExpired ? 'danger' : 'ok'}
                  flag={cert.days_until_expiry != null ? (cert.days_until_expiry < 0 ? `${Math.abs(cert.days_until_expiry)} days ago` : `${cert.days_until_expiry} days remaining`) : ''}
                />
              </div>

              {/* Fingerprint & SANs */}
              <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                  Fingerprint & Subject Alternative Names
                </div>
                <div style={{ marginBottom: '0.5rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>SHA-256 Fingerprint:</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.2rem' }}>
                    <code style={{ fontSize: '0.72rem', color: 'var(--accent)', wordBreak: 'break-all', flex: 1 }}>
                      {cert.fingerprint_sha256}
                    </code>
                    <button
                      className="btn btn-ghost"
                      style={{ padding: '0.2rem 0.4rem' }}
                      onClick={() => handleCopy(cert.fingerprint_sha256)}
                      title="Copy SHA-256 fingerprint"
                    >
                      {copiedSha === cert.fingerprint_sha256 ? <Check size={12} color="var(--info)" /> : <Copy size={12} />}
                    </button>
                  </div>
                </div>

                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>Subject Alternative Names (SANs):</div>
                  <div style={{ marginTop: '0.25rem', display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                    {cert.san && cert.san.length > 0 ? (
                      cert.san.map((name, sIdx) => (
                        <span key={sIdx} style={{
                          background: 'var(--bg-card)', border: '1px solid var(--border)',
                          padding: '0.15rem 0.45rem', borderRadius: 4, fontSize: '0.72rem', fontFamily: 'monospace'
                        }}>
                          {name}
                        </span>
                      ))
                    ) : (
                      <span style={{ fontSize: '0.75rem', color: 'var(--text-dim)' }}>No SAN extensions present</span>
                    )}
                  </div>
                </div>
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

function PropRow({ label, value, mono = false, highlight = 'none', flag = '' }) {
  let color = 'var(--text)'
  if (highlight === 'danger') color = 'var(--critical)'
  if (highlight === 'warning') color = 'var(--medium)'
  if (highlight === 'ok') color = 'var(--info)'

  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '0.25rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.78rem' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 100, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'monospace' : 'inherit', color, textAlign: 'right', wordBreak: 'break-all' }}>
        {value} {flag && <span style={{ fontSize: '0.72rem', opacity: 0.85 }}>({flag})</span>}
      </span>
    </div>
  )
}
