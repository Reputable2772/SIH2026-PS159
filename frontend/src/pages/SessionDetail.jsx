import React from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useAnalysis } from '../hooks/useApi.js'
import { ChevronLeft } from 'lucide-react'

export default function SessionDetail({ analysisId }) {
  const { sessionId } = useParams()
  const { data, loading } = useAnalysis(analysisId)
  const navigate = useNavigate()

  if (!analysisId || loading) return <div style={{ padding: '3rem', display: 'flex', gap: '1rem', alignItems: 'center' }}><div className="spinner" /> Loading...</div>
  if (!data) return null

  const session = data.sessions.find(s => s.session_id === decodeURIComponent(sessionId))
  if (!session) return <div style={{ padding: '2rem', color: 'var(--critical)' }}>Session not found</div>

  const tls = session.tls_handshake
  const findings = session.findings
  const ruleFindings = findings.filter(f => !f.is_ml_finding)
  const mlFindings = findings.filter(f => f.is_ml_finding)

  return (
    <div>
      <div style={{ marginBottom: '1.5rem' }}>
        <button className="btn btn-secondary" onClick={() => navigate('/sessions')}
          style={{ marginBottom: '1rem', fontSize: '0.8rem' }}>
          <ChevronLeft size={14} /> Back to Sessions
        </button>
        <div className="page-header" style={{ marginBottom: 0 }}>
          <h2 className="page-title">Session Detail</h2>
          <p className="page-subtitle">
            <code>{session.session_id}</code>
          </p>
        </div>
      </div>

      {/* Session info grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
        <div className="card">
          <div className="card-header"><div className="card-title">Connection</div></div>
          <InfoRow label="Protocol" value={<span className={`proto-tag proto-${session.protocol}`}>{session.protocol}</span>} />
          <InfoRow label="Source" value={`${session.src_ip}:${session.src_port}`} mono />
          <InfoRow label="Destination" value={`${session.dst_ip}:${session.dst_port}`} mono />
          <InfoRow label="Packets" value={session.packet_count} />
          <InfoRow label="Duration" value={session.duration_seconds != null ? `${session.duration_seconds.toFixed(3)}s` : '—'} />
          <InfoRow label="Bytes" value={session.bytes_transferred?.toLocaleString() || '—'} />
        </div>

        <div className="card">
          <div className="card-header"><div className="card-title">Risk</div></div>
          <InfoRow label="Session Score"
            value={<span style={{ fontWeight: 700, color: riskColor(session.session_risk_level) }}>{session.session_risk_score ?? '—'} / 100</span>} />
          <InfoRow label="Risk Level"
            value={<span className={`risk-badge risk-${session.session_risk_level || 'MINIMAL'}`}>{session.session_risk_level || '—'}</span>} />
          <InfoRow label="Findings" value={findings.length} />
          <InfoRow label="Critical/High" value={findings.filter(f => ['critical','high'].includes(f.severity)).length} />
          <InfoRow label="ML Anomaly"
            value={session.is_anomalous
              ? <span style={{ color: 'var(--ml-color)' }}>⚠ Yes (score: {session.anomaly_score?.toFixed(3)})</span>
              : <span style={{ color: 'var(--info)' }}>No</span>} />
        </div>
      </div>

      {/* STARTTLS timeline */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="card-header"><div className="card-title">STARTTLS State Machine</div></div>
        <STARTTLSTimeline session={session} />
      </div>

      {/* TLS Handshake */}
      {tls && (
        <div className="card" style={{ marginBottom: '1.25rem' }}>
          <div className="card-header"><div className="card-title">TLS Handshake</div></div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
            <div>
              <InfoRow label="TLS Version" value={
                <span style={{ color: tlsVersionColor(tls.tls_version) }}>{tls.tls_version}</span>
              } />
              <InfoRow label="Cipher Suite" value={tls.cipher_suite || '—'} mono />
              <InfoRow label="Key Exchange" value={tls.key_exchange || '—'} />
              <InfoRow label="Forward Secrecy" value={
                tls.forward_secrecy === 'yes' ? <span style={{ color: 'var(--info)' }}>✓ Yes</span> :
                tls.forward_secrecy === 'no' ? <span style={{ color: 'var(--critical)' }}>✗ No</span> :
                <span style={{ color: 'var(--text-muted)' }}>Unknown</span>
              } />
              <InfoRow label="JA3 Hash" value={tls.ja3_hash || '—'} mono />
              <InfoRow label="Handshake Complete" value={tls.handshake_complete ? '✓' : '—'} />
            </div>
            <div>
              <InfoRow label="Offered Ciphers" value={tls.client_offered_ciphers?.length || 0} />
              <InfoRow label="Client Extensions" value={tls.client_tls_extensions?.length || 0} />
              <InfoRow label="Server Extensions" value={tls.server_tls_extensions?.length || 0} />
            </div>
          </div>

          {/* TLS 1.3 cert note */}
          {tls.cert_observability === 'not_observable' && (
            <div className="tls13-note" style={{ marginTop: '1rem' }}>
              <strong>Certificate Not Observable (TLS 1.3):</strong><br />
              {tls.cert_observability_note}
            </div>
          )}

          {/* Certificates */}
          {tls.certificates?.length > 0 && (
            <div style={{ marginTop: '1rem' }}>
              <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '0.5rem' }}>
                Observed Certificates
              </div>
              {tls.certificates.map((cert, i) => (
                <CertCard key={i} cert={cert} />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Rule-based findings */}
      {ruleFindings.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text)', marginBottom: '0.75rem' }}>
            Deterministic Security Findings ({ruleFindings.length})
          </h3>
          {ruleFindings.map(f => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}

      {/* ML findings */}
      {mlFindings.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <h3 style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--ml-color)', marginBottom: '0.75rem' }}>
            🤖 ML Behavioural Anomalies ({mlFindings.length})
          </h3>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            These findings are <strong>probabilistic</strong>, not deterministic. They indicate statistically unusual TLS/protocol metadata.
          </p>
          {mlFindings.map(f => <FindingCard key={f.id} finding={f} />)}

          {/* Feature vector */}
          {session.anomaly_features && Object.keys(session.anomaly_features).length > 0 && (
            <div className="card" style={{ marginTop: '0.75rem' }}>
              <div className="card-title" style={{ marginBottom: '0.5rem' }}>ML Feature Vector</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
                {Object.entries(session.anomaly_features).map(([k, v]) => (
                  <div key={k} style={{
                    background: 'var(--bg-surface)', border: '1px solid var(--border)',
                    borderRadius: 4, padding: '0.25rem 0.5rem', fontSize: '0.72rem'
                  }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}:</span>{' '}
                    <span style={{ color: 'var(--accent)', fontFamily: 'monospace' }}>{v.toFixed(2)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Protocol banners */}
      {session.protocol_banners?.length > 0 && (
        <div className="card">
          <div className="card-header"><div className="card-title">Protocol Commands (Observed Cleartext)</div></div>
          <div style={{ fontFamily: 'monospace', fontSize: '0.78rem', color: 'var(--text-muted)', lineHeight: 1.8 }}>
            {session.protocol_banners.map((b, i) => (
              <div key={i}>{'> '}{b}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function STARTTLSTimeline({ session }) {
  const steps = []

  if (session.protocol !== 'UNKNOWN') {
    steps.push({ label: `TCP Connection`, detail: `${session.src_ip}:${session.src_port} → ${session.dst_ip}:${session.dst_port}`, ok: true })
  }

  const st = session.starttls_state
  if (st === 'direct_tls') {
    steps.push({ label: 'Direct TLS (Implicit)', detail: 'TLS negotiated immediately on connection', ok: true })
  } else if (st === 'no_tls') {
    steps.push({ label: 'No TLS', detail: 'Session conducted entirely in plaintext', ok: false })
  } else {
    if (session.starttls_advertised_pkt) {
      steps.push({ label: 'STARTTLS Advertised', detail: `Server offered STARTTLS (pkt #${session.starttls_advertised_pkt})`, ok: true })
    }
    if (session.starttls_requested_pkt) {
      steps.push({ label: 'STARTTLS Requested', detail: `Client sent STARTTLS command (pkt #${session.starttls_requested_pkt})`, ok: true })
    }
    if (st === 'negotiated') {
      steps.push({ label: 'TLS Handshake Complete', detail: `TLS ${session.tls_handshake?.tls_version || ''} negotiated`, ok: true })
    } else if (st === 'suspicious_fallback') {
      steps.push({ label: '⚠ Suspicious Fallback', detail: 'TLS handshake NOT observed — client continued in cleartext. Possible STARTTLS stripping.', ok: false })
    } else if (st === 'advertised') {
      steps.push({ label: 'STARTTLS Not Used', detail: 'Server offered STARTTLS but client did not initiate', ok: false })
    }
  }

  if (session.cleartext_auth_detected) {
    steps.push({ label: '⚠ Cleartext Auth', detail: 'Authentication commands observed before TLS', ok: false })
  }

  return (
    <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'stretch', flexWrap: 'wrap' }}>
      {steps.map((step, i) => (
        <React.Fragment key={i}>
          <div style={{
            background: step.ok ? 'rgba(63,185,80,0.08)' : 'rgba(255,107,107,0.08)',
            border: `1px solid ${step.ok ? 'rgba(63,185,80,0.3)' : 'rgba(255,107,107,0.3)'}`,
            borderRadius: 8, padding: '0.75rem', flex: 1, minWidth: 130
          }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: step.ok ? 'var(--info)' : 'var(--critical)', marginBottom: '0.25rem' }}>
              {step.label}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{step.detail}</div>
          </div>
          {i < steps.length - 1 && (
            <div style={{ display: 'flex', alignItems: 'center', color: 'var(--text-dim)', fontSize: '1.2rem', flexShrink: 0 }}>→</div>
          )}
        </React.Fragment>
      ))}
    </div>
  )
}

function CertCard({ cert }) {
  return (
    <div style={{
      background: 'var(--bg-surface)', border: '1px solid var(--border)',
      borderRadius: 8, padding: '0.75rem 1rem', marginBottom: '0.5rem'
    }}>
      <div style={{ fontWeight: 600, fontSize: '0.85rem', marginBottom: '0.5rem' }}>
        {cert.subject_cn || cert.subject_dn || 'Unknown Subject'}
        {cert.is_expired && <span className="sev-badge sev-critical" style={{ marginLeft: '0.5rem' }}>EXPIRED</span>}
        {cert.is_self_signed && <span className="sev-badge sev-medium" style={{ marginLeft: '0.5rem' }}>Self-Signed</span>}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.25rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
        <InfoRow label="Issuer" value={cert.issuer_cn || cert.issuer_dn} />
        <InfoRow label="Not Before" value={cert.not_before ? new Date(cert.not_before).toLocaleDateString() : '—'} />
        <InfoRow label="Not After" value={cert.not_after ? new Date(cert.not_after).toLocaleDateString() : '—'} />
        <InfoRow label="Days Until Expiry" value={cert.days_until_expiry != null ? cert.days_until_expiry : '—'} />
        <InfoRow label="Key Algorithm" value={cert.public_key?.algorithm || '—'} />
        <InfoRow label="Key Size" value={cert.public_key?.key_size_bits ? `${cert.public_key.key_size_bits} bits` : '—'} />
        <InfoRow label="Signature Algorithm" value={cert.signature_algorithm || '—'} />
        <InfoRow label="SHA-256 (cert)" value={cert.fingerprint_sha256?.slice(0, 20) + '...'} mono />
      </div>
      {cert.san?.length > 0 && (
        <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
          SAN: {cert.san.slice(0, 5).join(', ')}
        </div>
      )}
    </div>
  )
}

function FindingCard({ finding }) {
  return (
    <div className={`finding-card finding-${finding.severity}`}>
      <div className="finding-title">
        <span className={`sev-badge sev-${finding.severity}`}>{finding.severity}</span>
        {finding.is_ml_finding && <span className="sev-badge sev-ml">ML Anomaly</span>}
        {finding.title}
      </div>
      <div className="finding-desc">{finding.description}</div>
      <div className="finding-rec">💡 {finding.recommendation}</div>
      <div className="finding-evidence">
        Category: {finding.category} · Evidence field: {finding.evidence?.field || '—'}
        {finding.evidence?.observed_value != null && typeof finding.evidence.observed_value === 'string' &&
          ` · Value: ${finding.evidence.observed_value}`}
      </div>
    </div>
  )
}

function InfoRow({ label, value, mono }) {
  return (
    <div style={{ display: 'flex', gap: '0.5rem', padding: '0.2rem 0', borderBottom: '1px solid var(--border)', fontSize: '0.82rem' }}>
      <span style={{ color: 'var(--text-muted)', minWidth: 120, flexShrink: 0 }}>{label}</span>
      <span style={{ fontFamily: mono ? 'monospace' : 'inherit', wordBreak: 'break-all' }}>{value ?? '—'}</span>
    </div>
  )
}

function tlsVersionColor(v) {
  if (!v) return 'var(--text-muted)'
  if (v.includes('1.3')) return 'var(--info)'
  if (v.includes('1.2')) return 'var(--accent)'
  return 'var(--critical)'
}

function riskColor(level) {
  return { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)', MINIMAL: 'var(--info)' }[level] || 'var(--text-muted)'
}
