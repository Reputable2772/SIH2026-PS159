import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Filter, Search, Sparkles, CheckCircle2, AlertTriangle, ShieldAlert } from 'lucide-react'
import { useAnalysis } from '../hooks/useApi.js'
import EvidenceInspector from '../components/EvidenceInspector.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'

export default function Findings({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)
  const navigate = useNavigate()

  const [sevFilter, setSevFilter] = useState('all')
  const [typeFilter, setTypeFilter] = useState('all') // all | rule | ml
  const [searchQuery, setSearchQuery] = useState('')

  if (!analysisId) {
    return (
      <div className="empty-state-page">
        <div className="empty-state-icon">🔎</div>
        <div className="empty-state-title">No Active Analysis Selected</div>
        <div className="empty-state-body">
          Upload a packet capture or select an analysis to inspect deterministic findings, evidence provenance, and ML anomalies.
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/')}>
          Go to Overview
        </button>
      </div>
    )
  }

  if (loading) return <PageSkeleton label="Retrieving security findings & evidence..." />

  if (error || !data) {
    return <div className="callout callout-critical">Error: {error || 'Analysis not found'}</div>
  }

  let findings = data.all_findings || []

  // Filtering
  if (sevFilter !== 'all') {
    findings = findings.filter(f => (f.severity || '').toLowerCase() === sevFilter.toLowerCase())
  }
  if (typeFilter === 'rule') {
    findings = findings.filter(f => !f.is_ml_finding)
  } else if (typeFilter === 'ml') {
    findings = findings.filter(f => f.is_ml_finding)
  }
  if (searchQuery.trim()) {
    const q = searchQuery.toLowerCase().trim()
    findings = findings.filter(f =>
      f.title?.toLowerCase().includes(q) ||
      f.description?.toLowerCase().includes(q) ||
      f.evidence?.session_id?.toLowerCase().includes(q) ||
      f.category?.toLowerCase().includes(q)
    )
  }

  const criticalCount = data.risk_score?.critical_count || 0
  const highCount = data.risk_score?.high_count || 0
  const medCount = data.risk_score?.medium_count || 0
  const lowCount = data.risk_score?.low_count || 0
  const mlCount = data.risk_score?.ml_anomaly_count || 0
  const totalCount = data.all_findings?.length || 0

  const sevTabs = [
    { id: 'all', label: 'All', count: totalCount },
    { id: 'critical', label: 'Critical', count: criticalCount, color: 'var(--critical)' },
    { id: 'high', label: 'High', count: highCount, color: 'var(--high)' },
    { id: 'medium', label: 'Medium', count: medCount, color: 'var(--medium)' },
    { id: 'low', label: 'Low', count: lowCount, color: 'var(--low)' },
  ]

  return (
    <div className="page-fade-in">
      {/* Page Header */}
      <div className="page-header">
        <h1 className="page-title">Cryptographic &amp; Protocol Findings</h1>
        <p className="page-subtitle">
          {totalCount} findings flagged across {data.sessions?.length || 0} sessions in <code>{data.capture?.pcap_filename}</code>.
          Every finding connects directly to observed packet frames.
        </p>
      </div>

      {/* Method Legend */}
      <div className="findings-legend">
        <span className="findings-legend-item">
          <span className="findings-legend-dot" style={{ background: 'var(--accent)' }} />
          <strong>Deterministic Rules</strong> — RFC violations &amp; CVE baselines
        </span>
        <span className="findings-legend-item">
          <Sparkles size={12} color="var(--ml-color)" />
          <strong>ML Anomalies</strong> — Isolation Forest behavioural deviations
        </span>
      </div>

      {/* Unified Filter Strip */}
      <div className="findings-filter-strip">
        {/* Severity pills */}
        <div className="filter-tabs">
          {sevTabs.map(t => (
            <button
              key={t.id}
              onClick={() => setSevFilter(t.id)}
              className={`filter-tab-btn ${sevFilter === t.id ? 'active' : ''}`}
              style={sevFilter === t.id && t.color ? { background: t.color, borderColor: t.color, color: '#fff' } : {}}
            >
              {t.label}
              <span className="filter-tab-count">{t.count}</span>
            </button>
          ))}
          {mlCount > 0 && (
            <button
              onClick={() => setTypeFilter(typeFilter === 'ml' ? 'all' : 'ml')}
              className={`filter-tab-btn ${typeFilter === 'ml' ? 'active' : ''}`}
              style={{ borderColor: 'var(--ml-border)', color: typeFilter === 'ml' ? '#fff' : 'var(--ml-color)', background: typeFilter === 'ml' ? 'var(--ml-color)' : undefined }}
            >
              <Sparkles size={12} /> ML Only
              <span className="filter-tab-count">{mlCount}</span>
            </button>
          )}
          <button
            onClick={() => setTypeFilter(typeFilter === 'rule' ? 'all' : 'rule')}
            className={`filter-tab-btn ${typeFilter === 'rule' ? 'active' : ''}`}
          >
            <Filter size={12} /> Rules Only
          </button>
        </div>

        {/* Search */}
        <div className="topbar-search-box" style={{ minWidth: 240, flexShrink: 0 }}>
          <Search size={14} color="var(--text-dim)" />
          <input
            type="text"
            placeholder="Search finding, title, session..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="topbar-search-input"
          />
        </div>
      </div>

      {/* Results summary */}
      {(sevFilter !== 'all' || typeFilter !== 'all' || searchQuery) && (
        <div className="findings-result-meta">
          Showing <strong>{findings.length}</strong> of <strong>{totalCount}</strong> findings
          {(sevFilter !== 'all' || typeFilter !== 'all' || searchQuery) && (
            <button
              className="findings-clear-btn"
              onClick={() => { setSevFilter('all'); setTypeFilter('all'); setSearchQuery('') }}
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {/* Findings List */}
      {findings.length === 0 ? (
        <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1.5rem', color: 'var(--info)' }}>
          <CheckCircle2 size={36} style={{ marginBottom: '0.75rem' }} />
          <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem' }}>
            No Findings Match the Selected Criteria
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            Try resetting filters or adjusting search keywords.
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {findings.map(f => (
            <EvidenceInspector
              key={f.id}
              finding={f}
              onNavigateSession={(sId) => navigate(`/sessions/${encodeURIComponent(sId)}?tab=conversation&finding=${encodeURIComponent(f.id)}`)}
            />
          ))}
        </div>
      )}
    </div>
  )
}

function PageSkeleton({ label }) {
  return (
    <div className="page-skeleton">
      <div className="skeleton-bar" style={{ width: '40%', height: 28, marginBottom: '0.5rem' }} />
      <div className="skeleton-bar" style={{ width: '70%', height: 16, marginBottom: '1.75rem' }} />
      <div className="skeleton-bar" style={{ width: '100%', height: 42, marginBottom: '1.25rem' }} />
      {[1, 2, 3].map(i => (
        <div key={i} className="skeleton-bar" style={{ width: '100%', height: 100, marginBottom: '0.75rem' }} />
      ))}
      <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.84rem', marginTop: '1.5rem' }}>{label}</div>
    </div>
  )
}
