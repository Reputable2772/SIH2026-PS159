import React from 'react'
import { useNavigate } from 'react-router-dom'
import { FileJson, FileText, FileDown, ExternalLink, Hash, Shield, CheckCircle2, AlertTriangle, Calendar, HardDrive } from 'lucide-react'
import { useAnalysis } from '../hooks/useApi.js'
import SeverityBadge from '../components/SeverityBadge.jsx'

export default function Reports({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)
  const navigate = useNavigate()

  if (!analysisId) {
    return (
      <div className="empty-state-page">
        <div className="empty-state-icon">📄</div>
        <div className="empty-state-title">No Active Analysis Selected</div>
        <div className="empty-state-body">
          Upload or select an audited packet capture to generate publication-ready JSON, HTML, and PDF reports.
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/')}>
          Select Capture in Overview
        </button>
      </div>
    )
  }

  if (loading) return <PageSkeleton label="Preparing report artifacts..." />

  if (error || !data) {
    return <div className="callout callout-critical">Error: {error || 'Analysis not found'}</div>
  }

  const id = data.analysis_id
  const baseUrl = `/api/analysis/${id}/report`
  const capture = data.capture
  const risk = data.risk_score

  const exportFormats = [
    {
      icon: FileDown,
      label: 'PDF Executive Report',
      subtitle: 'Formal Forensic Summary',
      description: 'Publication-grade audit document including capture SHA-256 hash, score breakdown, findings with frame numbers, TLS 1.3 observability notes, and remediation guidance.',
      accent: 'var(--accent)',
      accentDim: 'var(--accent-dim)',
      href: `${baseUrl}/pdf`,
      download: `securemailscope_${id.slice(0, 8)}.pdf`,
      btnLabel: 'Download PDF Report',
      btnClass: 'btn btn-primary',
      target: undefined,
    },
    {
      icon: FileText,
      label: 'HTML Interactive Audit',
      subtitle: 'Self-Contained Dark-Mode Web Report',
      description: 'Standalone HTML document styled for presentations and audits. Features expandable findings, protocol summaries, and state machine diagrams.',
      accent: 'var(--low)',
      accentDim: 'var(--low-bg)',
      href: `${baseUrl}/html`,
      download: undefined,
      btnLabel: 'Open HTML Report',
      btnClass: 'btn btn-secondary',
      target: '_blank',
    },
    {
      icon: FileJson,
      label: 'Machine-Readable JSON',
      subtitle: 'Structured Automation Data',
      description: 'Complete JSON payload containing all session objects, certificate details, 16-D anomaly feature vectors, evidence records, and metadata for SIEM integration.',
      accent: 'var(--info)',
      accentDim: 'var(--info-bg)',
      href: `${baseUrl}/json`,
      download: `securemailscope_${id.slice(0, 8)}.json`,
      btnLabel: 'Download JSON Export',
      btnClass: 'btn btn-secondary',
      target: undefined,
    },
  ]

  const metaItems = [
    { icon: HardDrive, label: 'PCAP Filename', value: capture.pcap_filename, mono: false },
    { icon: Hash, label: 'File Size & Frames', value: `${((capture.file_size_bytes || 0) / 1024).toFixed(1)} KB · ${capture.packet_count} packets`, mono: false },
    { icon: Shield, label: 'SHA-256 Hash', value: `${capture.sha256_hash?.slice(0, 24)}...`, mono: true },
    { icon: Calendar, label: 'Analyzed At', value: new Date(capture.analyzed_at).toUTCString(), mono: false },
    { icon: Shield, label: 'Composite Score', value: `${Math.round(risk.score)} / 100`, mono: false, extra: <SeverityBadge severity={risk.level} /> },
    { icon: CheckCircle2, label: 'Total Sessions', value: `${data.sessions?.length || 0} TCP streams`, mono: false },
    { icon: Shield, label: 'Encrypted / Plaintext', value: `${data.protocol_summary?.tls_sessions} TLS · ${data.protocol_summary?.plaintext_sessions} Plaintext`, mono: false },
    { icon: CheckCircle2, label: 'Forward Secrecy', value: `${data.protocol_summary?.forward_secrecy_yes} sessions confirmed`, mono: false },
    { icon: AlertTriangle, label: 'Security Findings', value: `${data.all_findings?.length || 0} total · ${risk.critical_count} critical`, mono: false },
    { icon: Shield, label: 'ML Anomalies', value: `${risk.ml_anomaly_count} sessions flagged`, mono: false },
    { icon: Shield, label: 'TLS 1.3 Scope Note', value: 'RFC 8446 §4.4.2 — certs encrypted by protocol design', mono: false },
    { icon: Shield, label: 'Engine Version', value: `SecureMailScope v${capture.tool_version || '0.1.0'}`, mono: false },
  ]

  return (
    <div className="page-fade-in" style={{ maxWidth: 1050, margin: '0 auto' }}>
      <div className="page-header">
        <h1 className="page-title">Cryptographic Audit Reports</h1>
        <p className="page-subtitle">
          Export forensic findings, protocol state verification, and composite risk assessments in machine-readable JSON, interactive HTML, or publication-ready PDF formats.
        </p>
      </div>

      {/* Export Cards */}
      <div className="report-export-grid">
        {exportFormats.map(fmt => {
          const Icon = fmt.icon
          return (
            <div key={fmt.label} className="report-export-card" style={{ borderTop: `3px solid ${fmt.accent}` }}>
              <div className="report-export-card-top">
                <div className="report-export-icon" style={{ background: fmt.accentDim, color: fmt.accent }}>
                  <Icon size={24} />
                </div>
                <div>
                  <div className="report-export-label">{fmt.label}</div>
                  <div className="report-export-subtitle">{fmt.subtitle}</div>
                </div>
              </div>
              <p className="report-export-desc">{fmt.description}</p>
              <a
                href={fmt.href}
                download={fmt.download}
                target={fmt.target}
                rel={fmt.target ? 'noreferrer' : undefined}
                className={fmt.btnClass}
                style={{ width: '100%', gap: '0.4rem', ...(fmt.accent !== 'var(--accent)' ? { borderColor: fmt.accent, color: fmt.accent } : {}) }}
              >
                {fmt.target ? <ExternalLink size={15} /> : <FileDown size={15} />}
                {fmt.btnLabel}
              </a>
            </div>
          )
        })}
      </div>

      {/* Audit Provenance */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div className="card-header">
          <div className="card-title">Forensic Artifacts &amp; Audit Provenance</div>
          <span style={{ fontSize: '0.74rem', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
            ID: {id}
          </span>
        </div>

        <div className="report-meta-grid">
          {metaItems.map(({ icon: Icon, label, value, mono, extra }) => (
            <div key={label} className="report-meta-item">
              <div className="report-meta-label">
                <Icon size={13} color="var(--text-dim)" />
                {label}
              </div>
              <div className="report-meta-value" style={{ fontFamily: mono ? 'monospace' : 'inherit' }}>
                {value}
                {extra && <span style={{ marginLeft: '0.5rem' }}>{extra}</span>}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Disclaimer */}
      <div className="callout callout-info" style={{ fontSize: '0.8rem', lineHeight: 1.55 }}>
        <strong>Scoring Prototype Notice:</strong> The SecureMailScope Composite Risk Score is an experimental methodology developed for Smart India Hackathon 2026 (PS 26159). It is strictly a relative posture metric and is <strong>not</strong> an official NIST, BIS, NTRO, or regulatory compliance rating.
      </div>
    </div>
  )
}

function PageSkeleton({ label }) {
  return (
    <div className="page-skeleton">
      <div className="skeleton-bar" style={{ width: '40%', height: 28, marginBottom: '0.5rem' }} />
      <div className="skeleton-bar" style={{ width: '60%', height: 16, marginBottom: '2rem' }} />
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '1.25rem', marginBottom: '1.75rem' }}>
        {[1, 2, 3].map(i => <div key={i} className="skeleton-bar" style={{ height: 200 }} />)}
      </div>
      <div className="skeleton-bar" style={{ width: '100%', height: 300 }} />
      <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.84rem', marginTop: '1.5rem' }}>{label}</div>
    </div>
  )
}
