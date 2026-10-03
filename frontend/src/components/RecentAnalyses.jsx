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
    <div className="card" style={{ marginBottom: '2rem' }}>
      <div className="card-header" style={{ borderBottom: '1px solid var(--border)', paddingBottom: '0.75rem', marginBottom: '0.75rem' }}>
        <div>
          <div className="card-title" style={{ fontSize: '0.95rem', fontWeight: 700 }}>
            Recent Investigations
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            Previously audited network captures ready for deep-dive session investigation.
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', minWidth: 260 }}>
                <div style={{
                  width: 32, height: 32, borderRadius: 6,
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: 'var(--accent)',
                  flexShrink: 0
                }}>
                  <FileText size={16} />
                </div>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text)', fontFamily: 'monospace' }}>
                    {filename}
                  </div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '0.35rem', marginTop: '0.15rem' }}>
                    <Clock size={11} /> {formatDate(a.analyzed_at)}
                  </div>
                </div>
              </div>

              {/* Technical summary pills */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <Layers size={13} />
                  <span>{a.session_count || (a.sessions?.length ?? 1)} streams</span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <AlertTriangle size={13} color={a.finding_count > 0 ? 'var(--warning)' : 'var(--text-muted)'} />
                  <span>{a.finding_count ?? 0} findings</span>
                </div>

                <SeverityBadge severity={level} />

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.2rem', color: 'var(--accent)', fontWeight: 600, fontSize: '0.78rem' }}>
                  Open Case <ChevronRight size={14} />
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
