import React, { useState } from 'react'
import { ChevronDown, ChevronUp } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

export default function RiskScoreCard({ riskScore, protocolSummary = null }) {
  const [expanded, setExpanded] = useState(false)
  if (!riskScore) return null

  const score = Math.round(riskScore.score ?? 0)
  const level = (riskScore.level || 'MINIMAL').toUpperCase()

  // Determine accent color
  const getScoreColor = (s) => {
    if (s >= 85) return 'var(--info)'
    if (s >= 70) return 'var(--low)'
    if (s >= 50) return 'var(--medium)'
    if (s >= 30) return 'var(--high)'
    return 'var(--critical)'
  }

  const scoreColor = getScoreColor(score)

  // Parse rationale items into deduction/bonus breakdown
  const rationaleList = riskScore.rationale || []

  // Check positive controls
  const hasFS = protocolSummary && protocolSummary.forward_secrecy_yes > 0
  const hasTLS13 = protocolSummary && Object.keys(protocolSummary.tls_versions || {}).some(v => v.includes('1.3'))

  return (
    <div className="posture-panel" style={{ marginBottom: '1.5rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1.5rem' }}>
        {/* Left: Score & Posture */}
        <div style={{ minWidth: 240 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
            <span style={{ fontSize: '0.72rem', fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: 'var(--text-muted)' }}>
              SecureMailScope Composite Risk Score
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.65rem' }}>
            <span className="score-display-number" style={{ color: scoreColor }}>
              {score}
            </span>
            <span style={{ fontSize: '1.15rem', color: 'var(--text-muted)', fontWeight: 600 }}>/ 100</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', marginTop: '0.45rem' }}>
            <SeverityBadge severity={level} />
            <span style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
              {score >= 85 ? 'Strong Cryptographic Posture' :
               score >= 70 ? 'Satisfactory with Minor Weaknesses' :
               score >= 50 ? 'Moderate Posture Deficiencies' :
               score >= 30 ? 'High Vulnerability Risk' : 'Critical Cryptographic Exposures'}
            </span>
          </div>

          {/* Linear bar meter */}
          <div className="score-meter-track" style={{ width: '100%', maxWidth: 280, marginTop: '0.85rem' }}>
            <div
              className="score-meter-fill"
              style={{ width: `${Math.max(5, Math.min(100, score))}%`, backgroundColor: scoreColor }}
            />
          </div>

          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.4rem' }}>
            Prototype assessment methodology · <em>Not an official NIST / BIS / NTRO rating</em>
          </div>
        </div>

        {/* Right: Key Impact Deductions Summary */}
        <div style={{ flex: 1, minWidth: 280 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.78rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-muted)' }}>
              Scoring Breakdown & Factors
            </div>
            <button
              className="btn btn-ghost"
              onClick={() => setExpanded(!expanded)}
              style={{ fontSize: '0.75rem', padding: '0.2rem 0.5rem', gap: '0.25rem' }}
            >
              {expanded ? 'Hide Trace' : 'View Full Trace'}
              {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
            </button>
          </div>

          {/* Quick factor pills */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.5rem', marginBottom: '0.75rem' }}>
            <div style={{ background: 'var(--bg-card-subtle)', padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Base Posture</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text)' }}>100.0 pts</div>
            </div>

            <div style={{
              background: riskScore.critical_count > 0 ? 'var(--critical-bg)' : 'var(--bg-card-subtle)',
              border: `1px solid ${riskScore.critical_count > 0 ? 'var(--critical-border)' : 'var(--border)'}`,
              padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)'
            }}>
              <div style={{ fontSize: '0.68rem', color: riskScore.critical_count > 0 ? 'var(--critical)' : 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Critical Deductions</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: riskScore.critical_count > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>
                {riskScore.critical_count > 0 ? `-${riskScore.critical_count * 25} pts` : '0 pts'}
              </div>
            </div>

            <div style={{
              background: riskScore.high_count > 0 ? 'var(--high-bg)' : 'var(--bg-card-subtle)',
              border: `1px solid ${riskScore.high_count > 0 ? 'var(--high-border)' : 'var(--border)'}`,
              padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)'
            }}>
              <div style={{ fontSize: '0.68rem', color: riskScore.high_count > 0 ? 'var(--high)' : 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>High Deductions</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: riskScore.high_count > 0 ? 'var(--high)' : 'var(--text-muted)' }}>
                {riskScore.high_count > 0 ? `-${riskScore.high_count * 15} pts` : '0 pts'}
              </div>
            </div>

            <div style={{
              background: riskScore.ml_anomaly_count > 0 ? 'var(--ml-bg)' : 'var(--bg-card-subtle)',
              border: `1px solid ${riskScore.ml_anomaly_count > 0 ? 'var(--ml-border)' : 'var(--border)'}`,
              padding: '0.5rem 0.75rem', borderRadius: 'var(--radius-sm)'
            }}>
              <div style={{ fontSize: '0.68rem', color: riskScore.ml_anomaly_count > 0 ? 'var(--ml-color)' : 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>ML Anomaly Impact</div>
              <div style={{ fontSize: '0.95rem', fontWeight: 700, color: riskScore.ml_anomaly_count > 0 ? 'var(--ml-color)' : 'var(--text-muted)' }}>
                {riskScore.ml_anomaly_count > 0 ? `-${riskScore.ml_anomaly_count * 5} pts` : '0 pts'}
              </div>
            </div>
          </div>

          {/* Rationale items */}
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
            {rationaleList.slice(0, expanded ? undefined : 2).map((item, idx) => (
              <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', padding: '0.15rem 0' }}>
                <span style={{ color: item.includes('critical') ? 'var(--critical)' : item.includes('ML') ? 'var(--ml-color)' : 'var(--high)' }}>•</span>
                <span>{item}</span>
              </div>
            ))}
            {!expanded && rationaleList.length > 2 && (
              <div style={{ fontSize: '0.72rem', color: 'var(--accent)', marginTop: '0.2rem', cursor: 'pointer' }} onClick={() => setExpanded(true)}>
                + {rationaleList.length - 2} more scoring factors...
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Expanded Step-by-Step Score Trace Panel */}
      {expanded && (
        <div style={{
          marginTop: '1.25rem',
          paddingTop: '1.25rem',
          borderTop: '1px solid var(--border)',
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
          gap: '1rem',
          fontSize: '0.82rem'
        }}>
          <div>
            <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: '0.5rem' }}>Deduction Pipeline</div>
            <ul style={{ listStyle: 'none', padding: 0, color: 'var(--text-muted)', lineHeight: 1.8 }}>
              <li>1. Baseline starting security posture: <strong style={{ color: 'var(--text)' }}>100.0</strong></li>
              <li>2. Critical deductions (RFC/plaintext violations): <strong style={{ color: 'var(--critical)' }}>-{riskScore.critical_count * 25.0}</strong></li>
              <li>3. High deductions (weak ciphers, deprecated TLS): <strong style={{ color: 'var(--high)' }}>-{riskScore.high_count * 15.0}</strong></li>
              <li>4. Medium deductions (weak keys, unrecommended params): <strong style={{ color: 'var(--medium)' }}>-{riskScore.medium_count * 8.0}</strong></li>
              <li>5. Isolation Forest ML behavioral anomaly contribution: <strong style={{ color: 'var(--ml-color)' }}>-{riskScore.ml_anomaly_count * 5.0}</strong></li>
            </ul>
          </div>

          <div>
            <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: '0.5rem' }}>Positive Security Controls & Posture</div>
            <ul style={{ listStyle: 'none', padding: 0, color: 'var(--text-muted)', lineHeight: 1.8 }}>
              <li>• Forward Secrecy confirmation: <strong style={{ color: hasFS ? 'var(--info)' : 'var(--text-dim)' }}>{hasFS ? 'Active (+bonus clamp)' : 'Not verified'}</strong></li>
              <li>• Modern TLS 1.3 protocol adoption: <strong style={{ color: hasTLS13 ? 'var(--info)' : 'var(--text-dim)' }}>{hasTLS13 ? 'Active (+bonus clamp)' : 'Not detected'}</strong></li>
              <li>• Floor/Ceiling clamping range: <strong style={{ color: 'var(--text)' }}>0.0 to 100.0</strong></li>
              <li>• Calculated Posture Score: <strong style={{ color: scoreColor }}>{score} / 100 ({level})</strong></li>
            </ul>
          </div>
        </div>
      )}
    </div>
  )
}
