import React from 'react'
import { useAnalysis } from '../hooks/useApi.js'
import { FileJson, FileText, FileDown, ExternalLink } from 'lucide-react'

export default function Reports({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)

  if (!analysisId) return <EmptyState />
  if (loading) return <Loading />
  if (error || !data) return <ErrorState msg={error} />

  const id = data.analysis_id
  const baseUrl = `/api/analysis/${id}/report`

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Reports</h2>
        <p className="page-subtitle">{data.capture.pcap_filename} — Analysis {id.slice(0, 8)}</p>
      </div>

      {/* Report cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <ReportCard
          icon={<FileJson size={32} color="#3fb950" />}
          title="JSON Report"
          description="Machine-readable complete analysis. Contains all sessions, findings, certificates, risk scores, and metadata in structured JSON format."
          href={`${baseUrl}/json`}
          label="Download JSON"
          color="#3fb950"
        />
        <ReportCard
          icon={<FileText size={32} color="#58a6ff" />}
          title="HTML Report"
          description="Human-readable forensic report with dark-mode styling. Contains all findings, STARTTLS analysis, TLS summary, and recommendations."
          href={`${baseUrl}/html`}
          label="Open HTML Report"
          color="#58a6ff"
          newTab
        />
        <ReportCard
          icon={<FileDown size={32} color="#f5a623" />}
          title="PDF Report"
          description="Professional audit-ready PDF forensic report. Includes PCAP SHA-256 hash, all findings, TLS 1.3 limitation notes, and score rationale."
          href={`${baseUrl}/pdf`}
          label="Download PDF"
          color="#f5a623"
        />
      </div>

      {/* Report contents summary */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="card-header"><div className="card-title">Report Contents</div></div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.5rem', fontSize: '0.83rem' }}>
          {[
            ['Report Metadata', '✓'],
            ['Capture Metadata + SHA-256', '✓'],
            ['Protocol Summary', '✓'],
            ['Session Summary', `${data.sessions.length} sessions`],
            ['TLS Summary', `${data.protocol_summary.tls_sessions} TLS sessions`],
            ['Certificate Analysis', data.protocol_summary.tls_sessions > 0 ? '✓ (where observable)' : '—'],
            ['Security Findings', `${data.all_findings.length} total`],
            ['Risk Score', `${data.risk_score.score}/100 (${data.risk_score.level})`],
            ['Recommendations', `${data.recommendations?.length || 0} recommendations`],
            ['ML Anomaly Findings', `${data.risk_score.ml_anomaly_count} anomalies`],
            ['TLS 1.3 Limitations', '✓ documented'],
            ['Tool Version', 'SecureMailScope v0.1.0'],
          ].map(([label, value]) => (
            <div key={label} style={{ display: 'flex', gap: '0.5rem', padding: '0.3rem 0', borderBottom: '1px solid var(--border)' }}>
              <span style={{ color: 'var(--text-muted)', minWidth: 200 }}>{label}</span>
              <span style={{ color: 'var(--info)' }}>{value}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="limitation-box">
        <strong>Disclaimer:</strong> The SecureMailScope Composite Risk Score is a prototype scoring methodology
        developed for SIH 2026 PS 26159. It is <strong>NOT</strong> an official NIST, BIS, NTRO, or any other
        regulatory score. Do not use this score for compliance or regulatory purposes.
      </div>

      {/* TLS 1.3 note in reports context */}
      <div className="tls13-note" style={{ marginTop: '0.75rem' }}>
        <strong>TLS 1.3 in Reports:</strong> For TLS 1.3 sessions, the report correctly states that
        X.509 certificate contents are not observable from passive capture. This is documented as a
        technical limitation, not suppressed or falsified. Observable data (TLS version, cipher suite,
        key exchange type) is still reported.
      </div>
    </div>
  )
}

function ReportCard({ icon, title, description, href, label, color, newTab }) {
  return (
    <div className="card" style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
        {icon}
        <div style={{ fontWeight: 600, fontSize: '1rem' }}>{title}</div>
      </div>
      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', flex: 1, lineHeight: 1.6 }}>
        {description}
      </div>
      <a
        href={href}
        target={newTab ? '_blank' : '_self'}
        rel="noreferrer"
        className="btn btn-secondary"
        style={{ borderColor: color, color, justifyContent: 'center' }}
        download={!newTab}
      >
        {newTab ? <ExternalLink size={14} /> : <FileDown size={14} />}
        {label}
      </a>
    </div>
  )
}

function EmptyState() {
  return <div className="empty-state"><div className="empty-icon">📊</div><p>Select an analysis to generate reports.</p></div>
}
function Loading() {
  return <div style={{ display: 'flex', gap: '1rem', padding: '3rem', alignItems: 'center' }}><div className="spinner" />Loading...</div>
}
function ErrorState({ msg }) {
  return <div style={{ color: 'var(--critical)', padding: '2rem' }}>Error: {msg}</div>
}
