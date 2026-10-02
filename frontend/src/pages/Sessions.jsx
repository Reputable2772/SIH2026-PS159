import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAnalysis } from '../hooks/useApi.js'
import { ChevronRight } from 'lucide-react'

const STARTTLS_LABELS = {
  no_tls: { label: 'No TLS', color: 'var(--critical)' },
  direct_tls: { label: 'Direct TLS', color: 'var(--info)' },
  negotiated: { label: 'STARTTLS ✓', color: 'var(--info)' },
  advertised: { label: 'Advertised', color: 'var(--medium)' },
  requested: { label: 'Requested', color: 'var(--medium)' },
  suspicious_fallback: { label: '⚠ Suspicious Fallback', color: 'var(--critical)' },
  failed: { label: 'Failed', color: 'var(--high)' },
}

function RiskCell({ score, level }) {
  const color = {
    CRITICAL: 'var(--critical)', HIGH: 'var(--high)',
    MEDIUM: 'var(--medium)', LOW: 'var(--low)', MINIMAL: 'var(--info)'
  }[level] || 'var(--text-muted)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
      <span style={{ color, fontWeight: 700 }}>{score ?? '—'}</span>
      {level && <span style={{ fontSize: '0.7rem', color }}>{level}</span>}
    </div>
  )
}

export default function Sessions({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)
  const navigate = useNavigate()
  const [filter, setFilter] = useState('all')

  if (!analysisId) return <EmptyState msg="Select or upload an analysis to view sessions." />
  if (loading) return <Loading />
  if (error || !data) return <Error msg={error} />

  let sessions = data.sessions
  if (filter !== 'all') {
    if (filter === 'tls') sessions = sessions.filter(s => s.tls_handshake)
    if (filter === 'plaintext') sessions = sessions.filter(s => !s.tls_handshake)
    if (filter === 'anomalous') sessions = sessions.filter(s => s.is_anomalous)
    if (filter === 'critical') sessions = sessions.filter(s => s.session_risk_level === 'CRITICAL')
    if (['SMTP','IMAP','POP3'].includes(filter)) sessions = sessions.filter(s => s.protocol === filter)
  }

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Sessions</h2>
        <p className="page-subtitle">{data.sessions.length} total sessions in {data.capture.pcap_filename}</p>
      </div>

      <div className="filter-bar">
        {['all', 'SMTP', 'IMAP', 'POP3', 'tls', 'plaintext', 'anomalous', 'critical'].map(f => (
          <button
            key={f}
            className={`btn ${filter === f ? 'btn-primary' : 'btn-secondary'}`}
            style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
            onClick={() => setFilter(f)}
          >
            {f === 'all' ? 'All' : f}
          </button>
        ))}
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
          {sessions.length} sessions shown
        </span>
      </div>

      <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Session</th>
              <th>Protocol</th>
              <th>Source</th>
              <th>Destination</th>
              <th>TLS Version</th>
              <th>Cipher</th>
              <th>STARTTLS</th>
              <th>FS</th>
              <th>Risk</th>
              <th>ML</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {sessions.map(s => {
              const starttls = STARTTLS_LABELS[s.starttls_state] || { label: s.starttls_state, color: 'var(--text-muted)' }
              const tls = s.tls_handshake
              return (
                <tr key={s.session_id} style={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/sessions/${encodeURIComponent(s.session_id)}`)}>
                  <td>
                    <code style={{ fontSize: '0.78rem', color: 'var(--accent)' }}>{s.session_id.slice(-8)}</code>
                  </td>
                  <td>
                    <span className={`proto-tag proto-${s.protocol}`}>{s.protocol}</span>
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {s.src_ip}:{s.src_port}
                  </td>
                  <td style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                    {s.dst_ip}:{s.dst_port}
                  </td>
                  <td>
                    {tls ? (
                      <span style={{
                        fontSize: '0.78rem',
                        color: tls.tls_version === 'TLS 1.3' ? 'var(--info)' :
                              tls.tls_version === 'TLS 1.2' ? 'var(--accent)' : 'var(--critical)'
                      }}>
                        {tls.tls_version}
                      </span>
                    ) : <span style={{ color: 'var(--text-dim)' }}>—</span>}
                  </td>
                  <td style={{ maxWidth: 180, fontSize: '0.75rem', color: 'var(--text-muted)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {tls?.cipher_suite || '—'}
                  </td>
                  <td>
                    <span style={{ fontSize: '0.78rem', color: starttls.color }}>{starttls.label}</span>
                  </td>
                  <td>
                    {tls ? (
                      tls.forward_secrecy === 'yes' ?
                        <span style={{ color: 'var(--info)' }}>✓</span> :
                        tls.forward_secrecy === 'no' ?
                          <span style={{ color: 'var(--critical)' }}>✗</span> :
                          <span style={{ color: 'var(--text-dim)' }}>?</span>
                    ) : <span style={{ color: 'var(--text-dim)' }}>—</span>}
                  </td>
                  <td><RiskCell score={s.session_risk_score} level={s.session_risk_level} /></td>
                  <td>
                    {s.is_anomalous && (
                      <span className="anomaly-indicator">⚠ {s.anomaly_score?.toFixed(2)}</span>
                    )}
                  </td>
                  <td>
                    <ChevronRight size={14} style={{ color: 'var(--text-dim)' }} />
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {sessions.length === 0 && (
          <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)' }}>
            No sessions match the current filter.
          </div>
        )}
      </div>
    </div>
  )
}

function EmptyState({ msg }) {
  return <div className="empty-state"><div className="empty-icon">📋</div><p>{msg}</p></div>
}
function Loading() {
  return <div style={{ display: 'flex', gap: '1rem', padding: '3rem', alignItems: 'center' }}><div className="spinner" />Loading...</div>
}
function Error({ msg }) {
  return <div style={{ color: 'var(--critical)', padding: '2rem' }}>Error: {msg}</div>
}
