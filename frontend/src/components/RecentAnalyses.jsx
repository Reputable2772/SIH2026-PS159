import React from 'react'
import { FileText, ChevronRight, Clock, Layers, AlertTriangle } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

export default function RecentAnalyses({ analyses = [], onSelectAnalysis, activeAnalysisId = null }) {
  const doneAnalyses = analyses.filter(a => a.status === 'done')

  if (doneAnalyses.length === 0) {
    return null
  }

  const formatDate = (isoString) => {
    if (!isoString) return 'Just now'
    try {
      const d = new Date(isoString)
      return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + ' · ' + d.toLocaleDateString([], { month: 'short', day: 'numeric' })
    } catch {
      return 'Recent'
    }
  }

  return (
    <div className="card" style={{ marginBottom: '1.75rem' }}>
      <div className="card-header">
        <div>
          <div className="card-title">Recent Captures & Analyses</div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            Previously audited PCAP captures ready for technical deep-dive investigation.
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
        {doneAnalyses.map((a) => {
          const isActive = a.analysis_id === activeAnalysisId
          const filename = a.pcap || `capture-${a.analysis_id.slice(0, 8)}.pcap`
          const score = Math.round(a.risk_score ?? 0)
          const level = a.risk_level || 'MINIMAL'

          return (
            <div
              key={a.analysis_id}
              onClick={() => onSelectAnalysis(a.analysis_id)}
              style={{
                background: isActive ? 'var(--accent-dim)' : 'var(--bg-card-subtle)',
                border: `1px solid ${isActive ? 'var(--accent)' : 'var(--border)'}`,
                borderRadius: 'var(--radius-sm)',
                padding: '0.75rem 1rem',
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: '1rem',
                transition: 'all var(--trans)',
              }}
              className="recent-analysis-row"
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', minWidth: 220 }}>
                <div style={{
                  width: 34, height: 34, borderRadius: 6,
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--accent)'
                }}>
                  <FileText size={17} />
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text)' }}>
                    {filename}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.15rem' }}>
                    <Clock size={11} /> {formatDate(a.analyzed_at)}
                  </div>
                </div>
              </div>

              {/* Metrics */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <Layers size={13} color="var(--text-dim)" />
                  <span><strong>{a.session_count || 1}</strong> session{(a.session_count || 1) > 1 ? 's' : ''}</span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  <AlertTriangle size={13} color={a.critical_count > 0 ? 'var(--critical)' : 'var(--text-dim)'} />
                  <span><strong>{a.finding_count || 0}</strong> finding{(a.finding_count || 0) !== 1 ? 's' : ''}</span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <SeverityBadge severity={level} />
                  <span style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--text)', fontFamily: 'monospace' }}>
                    {score}/100
                  </span>
                </div>

                <button
                  className="btn btn-secondary"
                  style={{
                    fontSize: '0.76rem',
                    padding: '0.3rem 0.65rem',
                    gap: '0.25rem',
                    borderColor: isActive ? 'var(--accent)' : undefined
                  }}
                  onClick={(e) => {
                    e.stopPropagation()
                    onSelectAnalysis(a.analysis_id)
                  }}
                >
                  {isActive ? 'Investigating' : 'Investigate'}
                  <ChevronRight size={13} />
                </button>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
