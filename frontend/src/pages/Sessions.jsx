import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search, ChevronRight, Filter, Sparkles, Lock, Unlock, AlertTriangle, Layers } from 'lucide-react'
import { useAnalysis } from '../hooks/useApi.js'
import ProtocolTag from '../components/ProtocolTag.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'

export default function Sessions({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)
  const navigate = useNavigate()
  const [filter, setFilter] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')

  if (!analysisId) {
    return (
      <div className="empty-state-page">
        <div className="empty-state-icon">📋</div>
        <div className="empty-state-title">No Active Analysis Selected</div>
        <div className="empty-state-body">
          Upload a packet capture or select an existing analysis to explore individual email streams and forensic timelines.
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/')}>
          Select Capture in Overview
        </button>
      </div>
    )
  }

  if (loading) return <PageSkeleton label="Loading session streams..." />

  if (error || !data) {
    return <div className="callout callout-critical">Error: {error || 'Analysis not found'}</div>
  }

  let sessions = data.sessions || []

  // Apply quick filters
  if (filter === 'tls') sessions = sessions.filter(s => s.tls_handshake)
  else if (filter === 'plaintext') sessions = sessions.filter(s => !s.tls_handshake)
  else if (filter === 'anomalous') sessions = sessions.filter(s => s.is_anomalous)
  else if (filter === 'critical') sessions = sessions.filter(s => s.session_risk_level === 'CRITICAL' || s.session_risk_level === 'HIGH')
  else if (filter === 'fallback') sessions = sessions.filter(s => s.starttls_state === 'suspicious_fallback')
  else if (['SMTP', 'IMAP', 'POP3'].includes(filter)) sessions = sessions.filter(s => s.protocol === filter)

  if (searchTerm.trim()) {
    const q = searchTerm.toLowerCase().trim()
    sessions = sessions.filter(s =>
      s.session_id.toLowerCase().includes(q) ||
      s.src_ip.toLowerCase().includes(q) ||
      s.dst_ip.toLowerCase().includes(q) ||
      String(s.src_port).includes(q) ||
      String(s.dst_port).includes(q) ||
      (s.tls_handshake?.cipher_suite || '').toLowerCase().includes(q)
    )
  }

  const filterTabs = [
    { id: 'all', label: 'All', count: data.sessions?.length },
    { id: 'SMTP', label: 'SMTP' },
    { id: 'IMAP', label: 'IMAP' },
    { id: 'POP3', label: 'POP3' },
    { id: 'tls', label: 'Encrypted' },
    { id: 'plaintext', label: 'Plaintext' },
    { id: 'fallback', label: 'Downgrades' },
    { id: 'anomalous', label: 'ML Anomalies' },
  ]

  return (
    <div className="page-fade-in">
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <h1 className="page-title">Session Forensic Explorer</h1>
          <p className="page-subtitle">
            {data.sessions?.length || 0} reconstructed email flows in <code>{data.capture.pcap_filename}</code>.
            Click any session to drill into reconstructed protocol dialogue, STARTTLS transitions, and cryptographic evidence.
          </p>
        </div>
      </div>

      {/* Unified Filter Bar */}
      <div className="session-filter-bar">
        <div className="filter-tabs">
          {filterTabs.map(t => (
            <button
              key={t.id}
              className={`filter-tab-btn ${filter === t.id ? 'active' : ''}`}
              onClick={() => setFilter(t.id)}
            >
              {t.label}
              {t.count !== undefined && (
                <span className="filter-tab-count">{t.count}</span>
              )}
            </button>
          ))}
        </div>

        <div className="topbar-search-box" style={{ minWidth: 220 }}>
          <Search size={14} color="var(--text-dim)" />
          <input
            type="text"
            placeholder="Search IP, port, cipher..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="topbar-search-input"
          />
        </div>
      </div>

      {/* Session Cards */}
      <div className="session-card-list">
        {sessions.length === 0 ? (
          <div className="card" style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)' }}>
            No sessions match the current filter or search query.
          </div>
        ) : (
          sessions.map((s, idx) => {
            const tls = s.tls_handshake
            const isFallback = s.starttls_state === 'suspicious_fallback'
            const riskLevel = s.session_risk_level || 'MINIMAL'
            const riskColor = riskLevel === 'CRITICAL' ? 'var(--critical)' :
                              riskLevel === 'HIGH' ? 'var(--high)' :
                              riskLevel === 'MEDIUM' ? 'var(--medium)' :
                              riskLevel === 'LOW' ? 'var(--low)' : 'var(--info)'

            return (
              <div
                key={s.session_id}
                className="session-row-card"
                onClick={() => navigate(`/sessions/${encodeURIComponent(s.session_id)}`)}
                style={{ borderLeft: `3px solid ${riskColor}` }}
              >
                {/* Left: Stream identity */}
                <div className="session-row-identity">
                  <div className="session-row-num">#{idx + 1}</div>
                  <div>
                    <div className="session-row-endpoints">
                      <span className="mono-text">{s.src_ip}:{s.src_port}</span>
                      <span className="session-arrow">→</span>
                      <span className="mono-text">{s.dst_ip}:{s.dst_port}</span>
                    </div>
                    <div className="session-row-meta">
                      <ProtocolTag protocol={s.protocol} />
                      {isFallback && (
                        <span className="session-fallback-badge">
                          <AlertTriangle size={11} /> Downgrade
                        </span>
                      )}
                      {s.is_anomalous && (
                        <span className="session-ml-badge">
                          <Sparkles size={11} /> ML Anomaly
                        </span>
                      )}
                    </div>
                  </div>
                </div>

                {/* Center: TLS info */}
                <div className="session-row-tls">
                  {tls ? (
                    <>
                      <div className="session-tls-version" style={{
                        color: tls.tls_version === 'TLS 1.3' ? 'var(--info)' :
                               tls.tls_version === 'TLS 1.2' ? 'var(--low)' : 'var(--critical)'
                      }}>
                        <Lock size={13} /> {tls.tls_version}
                      </div>
                      <div className="session-cipher-text" title={tls.cipher_suite}>
                        {tls.cipher_suite || '—'}
                      </div>
                      <div className="session-fs-badge" style={{
                        color: tls.forward_secrecy === 'yes' ? 'var(--info)' : 'var(--critical)'
                      }}>
                        {tls.forward_secrecy === 'yes' ? '✓ Forward Secrecy' : '✗ No FS'}
                      </div>
                    </>
                  ) : (
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--critical)', fontWeight: 600, fontSize: '0.8rem' }}>
                      <Unlock size={13} /> Plaintext (No TLS)
                    </div>
                  )}
                </div>

                {/* Right: Risk */}
                <div className="session-row-risk">
                  <SeverityBadge severity={riskLevel} />
                  <div className="session-risk-score" style={{ color: riskColor }}>
                    {Math.round(s.session_risk_score ?? 0)}<span style={{ fontSize: '0.65rem', color: 'var(--text-dim)' }}>/100</span>
                  </div>
                </div>

                <ChevronRight size={15} color="var(--text-dim)" style={{ flexShrink: 0 }} />
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}

function PageSkeleton({ label }) {
  return (
    <div className="page-skeleton">
      <div className="skeleton-bar" style={{ width: '35%', height: 28, marginBottom: '0.5rem' }} />
      <div className="skeleton-bar" style={{ width: '65%', height: 16, marginBottom: '1.75rem' }} />
      <div className="skeleton-bar" style={{ width: '100%', height: 42, marginBottom: '1rem' }} />
      {[1,2,3,4].map(i => (
        <div key={i} className="skeleton-bar" style={{ width: '100%', height: 70, marginBottom: '0.6rem' }} />
      ))}
      <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.84rem', marginTop: '1.5rem' }}>{label}</div>
    </div>
  )
}
