import React, { useState } from 'react'
import { useAnalysis } from '../hooks/useApi.js'

export default function Findings({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)
  const [sevFilter, setSevFilter] = useState('all')
  const [catFilter, setCatFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all')

  if (!analysisId) return <EmptyState />
  if (loading) return <Loading />
  if (error || !data) return <ErrorState msg={error} />

  let findings = data.all_findings
  if (sevFilter !== 'all') findings = findings.filter(f => f.severity === sevFilter)
  if (catFilter !== 'all') findings = findings.filter(f => f.category === catFilter)
  if (typeFilter === 'rule') findings = findings.filter(f => !f.is_ml_finding)
  if (typeFilter === 'ml') findings = findings.filter(f => f.is_ml_finding)

  const categories = [...new Set(data.all_findings.map(f => f.category))].sort()

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Security Findings</h2>
        <p className="page-subtitle">
          {data.all_findings.length} total findings across {data.sessions.length} sessions
        </p>
      </div>

      {/* Summary badges */}
      <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        {[
          ['critical', 'Critical', data.risk_score.critical_count],
          ['high', 'High', data.risk_score.high_count],
          ['medium', 'Medium', data.risk_score.medium_count],
          ['low', 'Low', data.risk_score.low_count],
        ].map(([sev, label, count]) => count > 0 && (
          <span key={sev} className={`count-badge sev-${sev}`}
            style={{ display:'inline-block', padding:'0.4rem 0.8rem', borderRadius:6, fontSize:'0.82rem', fontWeight:600,
              cursor:'pointer', background: sevFilter === sev ? undefined : undefined }}
            onClick={() => setSevFilter(sevFilter === sev ? 'all' : sev)}>
            {count} {label}
          </span>
        ))}
        {data.risk_score.ml_anomaly_count > 0 && (
          <span className="sev-badge sev-ml" style={{ fontSize:'0.82rem', padding:'0.4rem 0.8rem', cursor:'pointer' }}
            onClick={() => setTypeFilter(typeFilter === 'ml' ? 'all' : 'ml')}>
            {data.risk_score.ml_anomaly_count} ML Anomalies
          </span>
        )}
      </div>

      {/* Filters */}
      <div className="filter-bar">
        <select className="filter-select" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select className="filter-select" value={catFilter} onChange={e => setCatFilter(e.target.value)}>
          <option value="all">All Categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="all">All Types</option>
          <option value="rule">Deterministic (Rule)</option>
          <option value="ml">ML Behavioural Anomaly</option>
        </select>
        <span style={{ marginLeft: 'auto', color: 'var(--text-muted)', fontSize: '0.82rem' }}>
          {findings.length} findings shown
        </span>
      </div>

      {/* Finding type legend */}
      <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
        <span>🔍 <strong>Deterministic Findings</strong> — from the rule engine, based on observed facts</span>
        <span>🤖 <strong>ML Anomalies</strong> — from Isolation Forest, probabilistic/statistical</span>
      </div>

      {findings.length === 0 && (
        <div className="empty-state">
          <div className="empty-icon">✅</div>
          <div>No findings match the current filter.</div>
        </div>
      )}

      {findings.map(f => (
        <div key={f.id} className={`finding-card finding-${f.severity}`}>
          <div className="finding-title">
            <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
            {f.is_ml_finding
              ? <span className="sev-badge sev-ml">🤖 ML Anomaly</span>
              : <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)' }}>🔍 Deterministic</span>
            }
            {f.title}
          </div>
          <div className="finding-desc">{f.description}</div>
          <div className="finding-rec">💡 {f.recommendation}</div>
          <div className="finding-evidence">
            Session: <code>{f.evidence?.session_id?.slice(-8)}</code> ·
            Category: {f.category} ·
            Field: {f.evidence?.field || '—'}
            {f.evidence?.observed_value != null && typeof f.evidence.observed_value === 'string'
              && ` · Observed: ${f.evidence.observed_value}`}
          </div>
        </div>
      ))}
    </div>
  )
}

function EmptyState() {
  return <div className="empty-state"><div className="empty-icon">🔎</div><p>Select or upload an analysis to view findings.</p></div>
}
function Loading() {
  return <div style={{ display: 'flex', gap: '1rem', padding: '3rem', alignItems: 'center' }}><div className="spinner" />Loading...</div>
}
function ErrorState({ msg }) {
  return <div style={{ color: 'var(--critical)', padding: '2rem' }}>Error: {msg}</div>
}
