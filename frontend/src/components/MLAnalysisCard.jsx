import React from 'react'
import { Sparkles, AlertCircle, CheckCircle2 } from 'lucide-react'

// Feature friendly name map
const FEATURE_LABELS = {
  tls_version_num: 'Negotiated TLS Version',
  cipher_strength_cat: 'Cipher Strength Category',
  key_exchange_cat: 'Key Exchange Mechanism',
  forward_secrecy: 'Forward Secrecy Status',
  cert_observable: 'Certificate Observability',
  cert_expired: 'Certificate Expiry Status',
  cert_self_signed: 'Self-Signed Certificate Flag',
  cert_key_bits_norm: 'Public Key Bit Length',
  sig_alg_weak: 'Signature Algorithm Weakness',
  starttls_state_cat: 'STARTTLS Negotiation State',
  cleartext_auth: 'Cleartext Auth Transmission',
  protocol_cat: 'Application Protocol Type',
  offered_cipher_count: 'Client Offered Ciphers Count',
  extension_count: 'TLS Extension Count',
  session_duration_norm: 'Session Duration (seconds)',
  packet_count_norm: 'Total Packet Frame Count',
}

export default function MLAnalysisCard({ session }) {
  if (!session) return null

  const isAnomalous = Boolean(session.is_anomalous)
  const score = session.anomaly_score != null ? session.anomaly_score : 0
  const features = session.anomaly_features || {}
  const hasFeatures = Object.keys(features).length > 0

  return (
    <div className="card" style={{ borderLeft: `4px solid ${isAnomalous ? 'var(--ml-color)' : 'var(--info)'}` }}>
      <div className="card-header">
        <div>
          <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', color: isAnomalous ? 'var(--ml-color)' : 'var(--text-muted)' }}>
            <Sparkles size={16} color={isAnomalous ? 'var(--ml-color)' : 'var(--info)'} />
            ML Behavioural Anomaly Detection (Isolation Forest)
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Unsupervised statistical model trained on baseline email traffic metadata distributions.
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span
            style={{
              padding: '0.25rem 0.65rem',
              borderRadius: 'var(--radius-sm)',
              fontSize: '0.74rem',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '0.05em',
              background: isAnomalous ? 'var(--ml-bg)' : 'var(--info-bg)',
              color: isAnomalous ? 'var(--ml-color)' : 'var(--info)',
              border: `1px solid ${isAnomalous ? 'var(--ml-border)' : 'var(--info-border)'}`,
            }}
          >
            {isAnomalous ? 'ANOMALOUS SESSION' : 'WITHIN LEARNED BASELINE'}
          </span>
        </div>
      </div>

      {/* Main Score Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
        <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
            Model Anomaly Score
          </div>
          <div style={{ fontSize: '1.75rem', fontWeight: 800, color: isAnomalous ? 'var(--ml-color)' : 'var(--info)', fontFamily: 'monospace' }}>
            {score.toFixed(3)}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Decision threshold: &gt; 0.500
          </div>
        </div>

        <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
            Model Classification
          </div>
          <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text)', marginTop: '0.35rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            {isAnomalous ? <AlertCircle size={18} color="var(--ml-color)" /> : <CheckCircle2 size={18} color="var(--info)" />}
            {isAnomalous ? 'Statistical Outlier' : 'Conformant'}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Isolation Forest (100 estimators, 16 features)
          </div>
        </div>

        <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem 1rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>
            Forensic Meaning
          </div>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginTop: '0.35rem', lineHeight: 1.45 }}>
            {isAnomalous
              ? 'Unusual multi-dimensional parameter combination flagged for analyst review.'
              : 'Traffic characteristics align with typical expected mail server negotiations.'}
          </div>
        </div>
      </div>

      {/* Distinction Callout */}
      <div className="callout callout-info" style={{ marginBottom: '1.25rem', fontSize: '0.8rem' }}>
        <strong>Rules vs ML Distinction:</strong> Deterministic rules detect violations of explicit RFC standards (e.g. plaintext passwords or expired certificates). The Isolation Forest model detects multi-dimensional deviations from typical server traffic patterns. An ML anomaly is probabilistic and does not represent an RFC violation on its own.
      </div>

      {/* Notable Input Features Associated with this session */}
      {hasFeatures && (
        <div>
          <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)', marginBottom: '0.65rem' }}>
            Notable Input Features Associated with this Session
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: '0.65rem' }}>
            {Object.entries(features).map(([key, rawVal]) => {
              const label = FEATURE_LABELS[key] || key
              const val = typeof rawVal === 'number' ? rawVal.toFixed(3) : String(rawVal)
              const isNonZero = typeof rawVal === 'number' && Math.abs(rawVal) > 0.001

              return (
                <div
                  key={key}
                  style={{
                    background: isNonZero ? 'var(--bg-hover)' : 'var(--bg-card-subtle)',
                    border: `1px solid ${isNonZero ? 'var(--border-hi)' : 'var(--border)'}`,
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.55rem 0.75rem',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <span style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>{label}</span>
                  <span style={{ fontSize: '0.78rem', fontFamily: 'monospace', fontWeight: 600, color: isNonZero ? 'var(--accent)' : 'var(--text-dim)' }}>
                    {val}
                  </span>
                </div>
              )
            })}
          </div>

          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.65rem', fontStyle: 'italic' }}>
            Note: Features represent normalized 16-D vector inputs evaluated by the model. Values reflect feature encoding rather than mathematical attribution.
          </div>
        </div>
      )}
    </div>
  )
}
