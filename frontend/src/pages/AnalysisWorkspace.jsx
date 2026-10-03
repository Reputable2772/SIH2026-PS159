import React, { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  Shield,
  Layers,
  AlertTriangle,
  FileText,
  Lock,
  Unlock,
  KeyRound,
  ExternalLink,
  ChevronRight,
  Sparkles,
  Download,
  Clock,
  HardDrive,
  Hash,
  ArrowLeft,
  RotateCw,
  CheckCircle2,
  FileDown,
  ShieldAlert,
  ChevronDown
} from 'lucide-react'
import { useAnalysis, useApi } from '../hooks/useApi.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ProtocolTag from '../components/ProtocolTag.jsx'

export default function AnalysisWorkspace({ analysisId }) {
  const { id } = useParams()
  const effectiveId = id || analysisId
  const navigate = useNavigate()
  const { post } = useApi()
  const { data, loading, error } = useAnalysis(effectiveId)
  const [downloadOpen, setDownloadOpen] = useState(false)
  const [reanalysing, setReanalysing] = useState(false)

  if (!effectiveId) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3.5rem 1.5rem', color: 'var(--text-muted)' }}>
        <div style={{ fontSize: '2.5rem', marginBottom: '0.75rem' }}>📁</div>
        <div style={{ fontWeight: 700, fontSize: '1.1rem', color: 'var(--text)', marginBottom: '0.35rem' }}>
          No Active Analysis Selected
        </div>
        <div style={{ fontSize: '0.84rem', maxWidth: 460, margin: '0 auto 1.5rem', lineHeight: 1.5 }}>
          Upload a packet capture or choose a canonical scenario from the Overview page to begin security posture analysis.
        </div>
        <button className="btn btn-primary" onClick={() => navigate('/')}>
          Go to Overview & Upload
        </button>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="page-skeleton">
        <div className="skeleton-bar" style={{ width: '40%', height: 28, marginBottom: '0.5rem' }} />
        <div className="skeleton-bar" style={{ width: '60%', height: 16, marginBottom: '1.75rem' }} />
        <div className="skeleton-bar" style={{ width: '100%', height: 110, marginBottom: '1.5rem' }} />
        <div style={{ display: 'grid', gridTemplateColumns: '60% 40%', gap: '1.25rem' }}>
          <div className="skeleton-bar" style={{ height: 320 }} />
          <div className="skeleton-bar" style={{ height: 320 }} />
        </div>
        <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.84rem', marginTop: '1.5rem' }}>
          Dissecting Capture Frames & Correlating Protocol States...
        </div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="callout callout-critical" style={{ padding: '1.5rem' }}>
        <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem' }}>Analysis Failed to Load</div>
        <div style={{ fontSize: '0.84rem' }}>{error || 'Unable to retrieve analysis data from backend.'}</div>
        <button className="btn btn-secondary" style={{ marginTop: '0.75rem' }} onClick={() => navigate('/')}>
          Return to Overview
        </button>
      </div>
    )
  }

  const { capture, risk_score, protocol_summary, sessions, all_findings } = data

  const handleReanalyse = async () => {
    if (!capture?.pcap_path) return
    setReanalysing(true)
    try {
      await post('/api/analysis/file', { pcap_path: capture.pcap_path })
      window.location.reload()
    } catch {
      setReanalysing(false)
    }
  }

  // Derive dynamic key observations from findings and states
  const observations = []
  const hasFallback = sessions.some(s => s.starttls_state === 'suspicious_fallback')
  const hasPlaintextAuth = sessions.some(s => s.cleartext_auth_detected)
  const hasTls13 = sessions.some(s => s.tls_handshake?.tls_version === 'TLS 1.3')
  const hasTls10 = sessions.some(s => s.tls_handshake?.tls_version === 'TLS 1.0')
  const hasWeakCipher = all_findings.some(f => f.category === 'weak_cipher')
  const hasExpiredCert = all_findings.some(f => f.category === 'expired_certificate')
  const hasMlAnomaly = all_findings.some(f => f.is_ml_finding)

  if (hasFallback) {
    observations.push({
      text: 'STARTTLS advertised by server but failed; client proceeded in cleartext',
      severity: 'critical'
    })
  }
  if (hasPlaintextAuth) {
    observations.push({
      text: 'Cleartext authentication observed without TLS encryption (credentials exposed)',
      severity: 'critical'
    })
  }
  if (hasTls10) {
    observations.push({
      text: 'Deprecated TLS 1.0 protocol detected (prohibited by RFC 8996)',
      severity: 'high'
    })
  }
  if (hasWeakCipher) {
    observations.push({
      text: 'Legacy cipher suite negotiated lacking Forward Secrecy',
      severity: 'high'
    })
  }
  if (hasExpiredCert) {
    observations.push({
      text: 'X.509 server certificate is expired or failed validation',
      severity: 'high'
    })
  }
  if (hasMlAnomaly) {
    observations.push({
      text: 'Machine learning model detected statistical behavioural deviation from baseline',
      severity: 'medium'
    })
  }
  if (observations.length === 0) {
    observations.push({
      text: 'All email protocol streams negotiated modern TLS with valid cryptography',
      severity: 'minimal'
    })
    if (hasTls13) {
      observations.push({
        text: 'TLS 1.3 encrypted handshake active (RFC 8446 §4.4.2 certificate privacy enforced)',
        severity: 'minimal'
      })
    }
  }

  const score = Math.round(risk_score?.score ?? 0)
  const level = (risk_score?.level || 'MINIMAL').toUpperCase()
  const levelClass = level.toLowerCase()

  const protoBreakdown = []
  if (protocol_summary?.smtp_sessions > 0) protoBreakdown.push(`SMTP ${protocol_summary.smtp_sessions}`)
  if (protocol_summary?.imap_sessions > 0) protoBreakdown.push(`IMAP ${protocol_summary.imap_sessions}`)
  if (protocol_summary?.pop3_sessions > 0) protoBreakdown.push(`POP3 ${protocol_summary.pop3_sessions}`)

  return (
    <div className="page-fade-in" style={{ maxWidth: 1200, margin: '0 auto' }}>
      {/* Context-First Header */}
      <div style={{ marginBottom: '1.25rem' }}>
        <button
          onClick={() => navigate('/')}
          className="btn-link"
          style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.35rem',
            fontSize: '0.8rem',
            color: 'var(--text-muted)',
            marginBottom: '0.5rem',
            padding: 0,
            background: 'none',
            border: 'none',
            cursor: 'pointer'
          }}
        >
          <ArrowLeft size={13} /> Back to Capture Library
        </button>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
              <h1 className="page-title" style={{ fontSize: '1.5rem', margin: 0, fontFamily: 'monospace' }}>
                {capture?.pcap_filename || 'capture.pcap'}
              </h1>
              <span className={`case-risk-pill ${levelClass}`} style={{ fontSize: '0.78rem', padding: '0.2rem 0.6rem' }}>
                {level} RISK
              </span>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.4rem', flexWrap: 'wrap' }}>
              <span>{((capture?.file_size_bytes || 0) / 1024).toFixed(1)} KB</span>
              <span>·</span>
              <span>{sessions.length} sessions</span>
              <span>·</span>
              <span>{all_findings.length} findings</span>
              <span>·</span>
              <span>{capture?.duration_seconds != null ? `${capture.duration_seconds.toFixed(2)}s capture` : '0.01s'}</span>
              <span>·</span>
              <span style={{ fontFamily: 'monospace' }}>SHA-256: {capture?.sha256_hash?.slice(0, 12)}...</span>
            </div>
          </div>

          {/* Quick Actions */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', position: 'relative' }}>
            <button
              className="btn btn-secondary"
              onClick={handleReanalyse}
              disabled={reanalysing}
              style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', gap: '0.4rem' }}
            >
              <RotateCw size={13} className={reanalysing ? 'spin' : ''} />
              Re-analyse
            </button>

            <div style={{ position: 'relative' }}>
              <button
                className="btn btn-primary"
                onClick={() => setDownloadOpen(!downloadOpen)}
                style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', gap: '0.4rem' }}
              >
                <Download size={13} />
                Download Report
                <ChevronDown size={13} />
              </button>

              {downloadOpen && (
                <div
                  className="report-dropdown-menu"
                  style={{
                    position: 'absolute',
                    top: '110%',
                    right: 0,
                    zIndex: 50,
                    minWidth: 180,
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    boxShadow: 'var(--shadow-md)',
                    padding: '0.35rem'
                  }}
                >
                  <a
                    href={`/api/analysis/${analysisId}/report/pdf`}
                    download={`securemailscope_${analysisId.slice(0, 8)}.pdf`}
                    className="report-dropdown-item"
                    onClick={() => setDownloadOpen(false)}
                  >
                    <FileDown size={14} color="var(--critical)" /> PDF Executive Audit
                  </a>
                  <a
                    href={`/api/analysis/${analysisId}/report/html`}
                    target="_blank"
                    rel="noreferrer"
                    className="report-dropdown-item"
                    onClick={() => setDownloadOpen(false)}
                  >
                    <FileText size={14} color="var(--info)" /> HTML Interactive Report
                  </a>
                  <a
                    href={`/api/analysis/${analysisId}/report/json`}
                    download={`securemailscope_${analysisId.slice(0, 8)}.json`}
                    className="report-dropdown-item"
                    onClick={() => setDownloadOpen(false)}
                  >
                    <Hash size={14} color="var(--accent)" /> JSON Raw Machine Data
                  </a>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Compact Case Summary */}
      <div className="card case-summary-card" style={{ marginBottom: '1.5rem', padding: '1rem 1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '1.75rem', alignItems: 'center' }}>
          {/* Posture Score Badge */}
          <div style={{ borderRight: '1px solid var(--border)', paddingRight: '1.75rem', minWidth: 150 }}>
            <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)', marginBottom: '0.2rem' }}>
              SECURITY POSTURE
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.35rem' }}>
              <span style={{ fontSize: '1.75rem', fontWeight: 800, color: level === 'MINIMAL' ? 'var(--success)' : level === 'CRITICAL' ? 'var(--critical)' : 'var(--warning)', fontFamily: 'monospace' }}>
                {score}
              </span>
              <span style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>/ 100</span>
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
              {all_findings.length} findings · {sessions.length} streams
            </div>
            {protoBreakdown.length > 0 && (
              <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', marginTop: '0.2rem', fontFamily: 'monospace' }}>
                {protoBreakdown.join(' · ')}
              </div>
            )}
          </div>

          {/* Key Observations */}
          <div>
            <div style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em', color: 'var(--text-dim)', marginBottom: '0.4rem' }}>
              Key Forensic Observations
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              {observations.map((obs, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '0.45rem', fontSize: '0.82rem', color: 'var(--text)' }}>
                  <span style={{
                    color: obs.severity === 'critical' ? 'var(--critical)' :
                           obs.severity === 'high' ? 'var(--high)' :
                           obs.severity === 'medium' ? 'var(--medium)' : 'var(--success)',
                    marginTop: '0.15rem'
                  }}>
                    ●
                  </span>
                  <span>{obs.text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Analysis Explorer: 2-Column Investigation View */}
      <div style={{ display: 'grid', gridTemplateColumns: '60% 40%', gap: '1.25rem', alignItems: 'start' }}>
        {/* Left Column: Sessions List */}
        <div className="card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Layers size={15} color="var(--accent)" />
              <span style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--text)' }}>
                Sessions ({sessions.length})
              </span>
            </div>
            <span style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>
              Click stream to investigate conversation
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {sessions.map((s, idx) => {
              const tls = s.tls_handshake
              const st = s.starttls_state
              const risk = (s.session_risk_level || 'MINIMAL').toLowerCase()
              const isFallback = st === 'suspicious_fallback'

              return (
                <div
                  key={s.session_id}
                  onClick={() => navigate(`/sessions/${encodeURIComponent(s.session_id)}`)}
                  className="analysis-session-row"
                  style={{
                    background: 'var(--bg-card-subtle)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '0.75rem 0.9rem',
                    cursor: 'pointer',
                    transition: 'all var(--trans)',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '0.35rem'
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span style={{ fontWeight: 700, fontSize: '0.85rem', color: 'var(--text)' }}>
                        Session {idx + 1}
                      </span>
                      <ProtocolTag protocol={s.protocol} />
                      {tls ? (
                        <span style={{ fontSize: '0.72rem', fontFamily: 'monospace', color: tls.tls_version === 'TLS 1.3' ? 'var(--info)' : 'var(--text-muted)' }}>
                          {tls.tls_version}
                        </span>
                      ) : (
                        <span style={{ fontSize: '0.72rem', color: isFallback ? 'var(--critical)' : 'var(--text-dim)', fontWeight: isFallback ? 700 : 400 }}>
                          {isFallback ? 'STARTTLS Failed (454)' : 'Plaintext'}
                        </span>
                      )}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <SeverityBadge severity={risk} />
                      <ChevronRight size={14} color="var(--text-dim)" />
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                    <span style={{ fontFamily: 'monospace' }}>
                      {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}
                    </span>
                    <span>
                      {s.packet_count} pkts · {s.duration_seconds != null ? `${s.duration_seconds.toFixed(2)}s` : '0.0s'}
                    </span>
                  </div>

                  {s.findings && s.findings.length > 0 && (
                    <div style={{ fontSize: '0.72rem', color: 'var(--critical)', display: 'flex', alignItems: 'center', gap: '0.3rem', marginTop: '0.1rem' }}>
                      <AlertTriangle size={11} />
                      <span>{s.findings.length} security finding{s.findings.length > 1 ? 's' : ''} detected</span>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Column: Findings Index */}
        <div className="card" style={{ padding: '1rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: '0.75rem', borderBottom: '1px solid var(--border)', marginBottom: '0.75rem' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <AlertTriangle size={15} color="var(--warning)" />
              <span style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--text)' }}>
                Findings ({all_findings.length})
              </span>
            </div>
            <button
              className="btn-link"
              onClick={() => navigate('/findings')}
              style={{ fontSize: '0.75rem', color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
            >
              All Findings →
            </button>
          </div>

          {all_findings.length === 0 ? (
            <div style={{ padding: '2rem 1rem', textAlign: 'center', color: 'var(--success)' }}>
              <CheckCircle2 size={24} style={{ marginBottom: '0.5rem' }} />
              <div style={{ fontWeight: 600, fontSize: '0.85rem' }}>Clean Security Posture</div>
              <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
                Zero cryptographic or protocol vulnerabilities detected.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {all_findings.map((f, idx) => {
                const targetSession = sessions.find(s => s.session_id === f.evidence?.session_id) || sessions[0]

                return (
                  <div
                    key={f.id || idx}
                    onClick={() => {
                      if (targetSession) {
                        navigate(`/sessions/${encodeURIComponent(targetSession.session_id)}?finding=${encodeURIComponent(f.id)}`)
                      }
                    }}
                    style={{
                      background: 'var(--bg-card-subtle)',
                      border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '0.65rem 0.8rem',
                      cursor: 'pointer',
                      transition: 'all var(--trans)'
                    }}
                    className="analysis-finding-row"
                  >
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.25rem' }}>
                      <SeverityBadge severity={f.severity} />
                      <span style={{ fontSize: '0.68rem', fontFamily: 'monospace', color: 'var(--text-dim)' }}>
                        {f.category}
                      </span>
                    </div>

                    <div style={{ fontWeight: 600, fontSize: '0.8rem', color: 'var(--text)', marginBottom: '0.2rem', lineHeight: 1.3 }}>
                      {f.title}
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                      <span>Stream {targetSession ? sessions.indexOf(targetSession) + 1 : 1}</span>
                      <span style={{ color: 'var(--accent)', display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                        Investigate <ChevronRight size={11} />
                      </span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
