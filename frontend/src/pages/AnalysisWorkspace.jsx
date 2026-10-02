import React from 'react'
import { useNavigate } from 'react-router-dom'
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
  Hash
} from 'lucide-react'
import { BarChart, Bar, Cell, ResponsiveContainer, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'
import { useAnalysis } from '../hooks/useApi.js'
import RiskScoreCard from '../components/RiskScoreCard.jsx'
import SeverityBadge from '../components/SeverityBadge.jsx'
import ProtocolTag from '../components/ProtocolTag.jsx'

export default function AnalysisWorkspace({ analysisId }) {
  const navigate = useNavigate()
  const { data, loading, error } = useAnalysis(analysisId)

  if (!analysisId) {
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
        <div className="skeleton-bar" style={{ width: '50%', height: 28, marginBottom: '0.5rem' }} />
        <div className="skeleton-bar" style={{ width: '75%', height: 16, marginBottom: '2rem' }} />
        <div className="skeleton-bar" style={{ width: '100%', height: 130, marginBottom: '1.25rem' }} />
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: '0.85rem', marginBottom: '1.5rem' }}>
          {[1,2,3,4,5].map(i => <div key={i} className="skeleton-bar" style={{ height: 80 }} />)}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.75rem' }}>
          {[1,2].map(i => <div key={i} className="skeleton-bar" style={{ height: 200 }} />)}
        </div>
        <div className="skeleton-bar" style={{ width: '100%', height: 250 }} />
        <div style={{ textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.84rem', marginTop: '1.5rem' }}>Dissecting Network Capture Frames...</div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="callout callout-critical" style={{ padding: '1.5rem' }}>
        <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem' }}>Analysis Failed to Load</div>
        <div style={{ fontSize: '0.84rem' }}>{error || 'Unable to retrieve analysis data from backend.'}</div>
      </div>
    )
  }

  const { capture, risk_score, protocol_summary, sessions, all_findings, limitations } = data

  // Top critical and high findings
  const criticalHighFindings = all_findings.filter(f => ['critical', 'high'].includes(f.severity)).slice(0, 4)
  const mlFindings = all_findings.filter(f => f.is_ml_finding)

  // Chart data
  const tlsVersionData = Object.entries(protocol_summary.tls_versions || {}).map(([ver, count]) => ({
    version: ver,
    count,
  })).sort((a, b) => a.version.localeCompare(b.version))

  const severityData = [
    { name: 'Critical', count: risk_score.critical_count, color: 'var(--critical)' },
    { name: 'High', count: risk_score.high_count, color: 'var(--high)' },
    { name: 'Medium', count: risk_score.medium_count, color: 'var(--medium)' },
    { name: 'Low', count: risk_score.low_count, color: 'var(--low)' },
    { name: 'ML Anomaly', count: risk_score.ml_anomaly_count, color: 'var(--ml-color)' },
  ].filter(d => d.count > 0)

  return (
    <div className="page-fade-in">
      {/* Level 2 Header: Capture Identification & File Metadata */}
      <div className="page-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <span style={{ fontSize: '0.72rem', color: 'var(--accent)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Level 2 · Security Posture Workspace
            </span>
          </div>
          <h1 className="page-title" style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <span>{capture.pcap_filename}</span>
          </h1>
          <div style={{ display: 'flex', alignItems: 'center', gap: '1.25rem', fontSize: '0.78rem', color: 'var(--text-muted)', flexWrap: 'wrap', marginTop: '0.35rem' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <HardDrive size={13} color="var(--text-dim)" />
              {((capture.file_size_bytes || 0) / 1024).toFixed(1)} KB
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Layers size={13} color="var(--text-dim)" />
              {capture.packet_count?.toLocaleString()} packets
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Clock size={13} color="var(--text-dim)" />
              {data.processing_time_seconds?.toFixed(3)}s processing
            </span>
            <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Hash size={13} color="var(--text-dim)" />
              SHA-256: <code style={{ fontSize: '0.74rem' }}>{capture.sha256_hash?.slice(0, 16)}...</code>
            </span>
          </div>
        </div>

        {/* Quick Report Actions */}
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <button
            className="btn btn-secondary"
            onClick={() => navigate('/reports')}
            style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', gap: '0.4rem' }}
          >
            <FileText size={14} /> View Audit Reports
          </button>
          <button
            className="btn btn-secondary"
            onClick={() => navigate('/compare')}
            style={{ fontSize: '0.8rem', padding: '0.45rem 0.85rem', gap: '0.4rem' }}
          >
            Compare Posture
          </button>
        </div>
      </div>

      {/* Composite Risk Score Breakdown Panel */}
      <RiskScoreCard riskScore={risk_score} protocolSummary={protocol_summary} />

      {/* Key Metric Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: '0.85rem', marginBottom: '1.5rem' }}>
        <div className="card" style={{ padding: '0.85rem 1rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Total Sessions</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: 'var(--text)', marginTop: '0.2rem' }}>
            {sessions.length}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>TCP application flows</div>
        </div>

        <div className="card" style={{ padding: '0.85rem 1rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Protocol Breakdown</div>
          <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text)', marginTop: '0.35rem', display: 'flex', gap: '0.4rem' }}>
            {protocol_summary.smtp_sessions > 0 && <span style={{ color: 'var(--low)' }}>{protocol_summary.smtp_sessions} SMTP</span>}
            {protocol_summary.imap_sessions > 0 && <span style={{ color: 'var(--info)' }}>{protocol_summary.imap_sessions} IMAP</span>}
            {protocol_summary.pop3_sessions > 0 && <span style={{ color: 'var(--high)' }}>{protocol_summary.pop3_sessions} POP3</span>}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>Email protocol services</div>
        </div>

        <div className="card" style={{ padding: '0.85rem 1rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>TLS Handshakes</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: protocol_summary.tls_sessions > 0 ? 'var(--info)' : 'var(--critical)', marginTop: '0.2rem' }}>
            {protocol_summary.tls_sessions} / {sessions.length}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            {protocol_summary.plaintext_sessions > 0 ? `${protocol_summary.plaintext_sessions} plaintext sessions` : 'All sessions encrypted'}
          </div>
        </div>

        <div className="card" style={{ padding: '0.85rem 1rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Forward Secrecy</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: protocol_summary.forward_secrecy_yes > 0 ? 'var(--info)' : 'var(--medium)', marginTop: '0.2rem' }}>
            {protocol_summary.forward_secrecy_yes} / {protocol_summary.tls_sessions || 1}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>ECDHE / DHE confirmed</div>
        </div>

        <div className="card" style={{ padding: '0.85rem 1rem' }}>
          <div style={{ fontSize: '0.7rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 600 }}>Security Findings</div>
          <div style={{ fontSize: '1.6rem', fontWeight: 700, color: all_findings.length > 0 ? 'var(--critical)' : 'var(--info)', marginTop: '0.2rem' }}>
            {all_findings.length}
          </div>
          <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
            {risk_score.critical_count} critical, {risk_score.high_count} high
          </div>
        </div>
      </div>

      {/* Charts Row: TLS Version Distribution & Findings by Severity */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1rem', marginBottom: '1.75rem' }}>
        {/* TLS Version Distribution Chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">TLS Protocol Version Distribution</div>
          </div>
          {tlsVersionData.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-dim)', fontSize: '0.85rem' }}>
              No TLS sessions detected in this capture.
            </div>
          ) : (
            <div style={{ height: 180, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={tlsVersionData} barSize={36}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
                  <XAxis dataKey="version" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
                  <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: '0.8rem' }}
                    labelStyle={{ color: 'var(--text)' }}
                  />
                  <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                    {tlsVersionData.map((d, i) => (
                      <Cell
                        key={i}
                        fill={d.version.includes('1.3') ? 'var(--info)' : d.version.includes('1.2') ? 'var(--low)' : 'var(--critical)'}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        {/* Findings by Severity Distribution Chart */}
        <div className="card">
          <div className="card-header">
            <div className="card-title">Findings by Severity & Classification</div>
          </div>
          {severityData.length === 0 ? (
            <div style={{ padding: '2rem', textAlign: 'center', color: 'var(--info)', fontSize: '0.85rem' }}>
              ✓ No cryptographic or protocol vulnerabilities detected.
            </div>
          ) : (
            <div style={{ height: 180, width: '100%' }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={severityData} barSize={32} layout="vertical">
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" horizontal={false} />
                  <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="name" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} width={85} />
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, fontSize: '0.8rem' }}
                    labelStyle={{ color: 'var(--text)' }}
                  />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {severityData.map((d, i) => (
                      <Cell key={i} fill={d.color} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>
      </div>

      {/* High-Level Sessions Explorer Summary */}
      <div className="card" style={{ marginBottom: '1.75rem' }}>
        <div className="card-header">
          <div>
            <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
              <Layers size={15} color="var(--accent)" />
              Session Forensic Explorer ({sessions.length} Flows)
            </div>
            <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
              Select any session to investigate the reconstructed SMTP conversation, STARTTLS state machine, and certificate chain.
            </div>
          </div>
          <button
            className="btn btn-secondary"
            onClick={() => navigate('/sessions')}
            style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem', gap: '0.3rem' }}
          >
            All Sessions <ChevronRight size={13} />
          </button>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Protocol</th>
                <th>Endpoints</th>
                <th>TLS Version</th>
                <th>Selected Cipher</th>
                <th>STARTTLS State</th>
                <th>Forward Secrecy</th>
                <th>Posture Risk</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {sessions.slice(0, 5).map((s) => {
                const tls = s.tls_handshake
                const st = s.starttls_state

                return (
                  <tr
                    key={s.session_id}
                    onClick={() => navigate(`/sessions/${encodeURIComponent(s.session_id)}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td>
                      <code style={{ color: 'var(--accent)', fontWeight: 600 }}>
                        {s.session_id.split(':').pop() || s.session_id}
                      </code>
                    </td>
                    <td>
                      <ProtocolTag protocol={s.protocol} />
                    </td>
                    <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      {s.src_ip}:{s.src_port} → {s.dst_ip}:{s.dst_port}
                    </td>
                    <td>
                      {tls ? (
                        <span style={{
                          fontWeight: 600,
                          fontSize: '0.78rem',
                          color: tls.tls_version === 'TLS 1.3' ? 'var(--info)' : tls.tls_version === 'TLS 1.2' ? 'var(--low)' : 'var(--critical)'
                        }}>
                          {tls.tls_version}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--text-dim)' }}>— (Plaintext)</span>
                      )}
                    </td>
                    <td style={{ maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: '0.76rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      {tls?.cipher_suite || '—'}
                    </td>
                    <td>
                      <span style={{
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        color: st === 'negotiated' || st === 'direct_tls' ? 'var(--info)' :
                               st === 'suspicious_fallback' ? 'var(--critical)' : 'var(--medium)'
                      }}>
                        {st === 'suspicious_fallback' ? '⚠ Suspicious Fallback' : st === 'negotiated' ? 'Negotiated ✓' : st}
                      </span>
                    </td>
                    <td>
                      {tls ? (
                        tls.forward_secrecy === 'yes' ? (
                          <span style={{ color: 'var(--info)', fontWeight: 700 }}>✓ Yes</span>
                        ) : (
                          <span style={{ color: 'var(--critical)', fontWeight: 700 }}>✗ No</span>
                        )
                      ) : (
                        <span style={{ color: 'var(--text-dim)' }}>—</span>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <span style={{ fontWeight: 700, fontFamily: 'monospace', fontSize: '0.82rem' }}>
                          {Math.round(s.session_risk_score ?? 0)}
                        </span>
                        <SeverityBadge severity={s.session_risk_level || 'MINIMAL'} />
                      </div>
                    </td>
                    <td>
                      <span style={{ color: 'var(--accent)', fontSize: '0.78rem', fontWeight: 600, display: 'flex', alignItems: 'center', gap: '0.2rem' }}>
                        Investigate <ChevronRight size={13} />
                      </span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Critical & High Findings Preview */}
      {criticalHighFindings.length > 0 && (
        <div className="card" style={{ marginBottom: '1.75rem' }}>
          <div className="card-header">
            <div>
              <div className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
                <AlertTriangle size={15} color="var(--critical)" />
                Important Security Findings Requiring Remediation
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                Deterministic cryptographic flaws and protocol anomalies flagged across observed sessions.
              </div>
            </div>
            <button
              className="btn btn-secondary"
              onClick={() => navigate('/findings')}
              style={{ fontSize: '0.76rem', padding: '0.35rem 0.75rem', gap: '0.3rem' }}
            >
              All {all_findings.length} Findings <ChevronRight size={13} />
            </button>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            {criticalHighFindings.map((f) => (
              <div
                key={f.id}
                onClick={() => navigate('/findings')}
                style={{
                  background: 'var(--bg-card-subtle)',
                  border: '1px solid var(--border)',
                  borderLeft: `4px solid ${f.severity === 'critical' ? 'var(--critical)' : 'var(--high)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '0.85rem 1rem',
                  cursor: 'pointer',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem', flexWrap: 'wrap', gap: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <SeverityBadge severity={f.severity} isMl={f.is_ml_finding} />
                    <span style={{ fontWeight: 600, fontSize: '0.88rem', color: 'var(--text)' }}>
                      {f.title}
                    </span>
                  </div>
                  <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'monospace' }}>
                    Session: {f.evidence?.session_id}
                  </span>
                </div>
                <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '0.45rem', lineHeight: 1.5 }}>
                  {f.description}
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--info-text)', background: 'var(--info-bg)', padding: '0.35rem 0.65rem', borderRadius: 4, display: 'inline-block' }}>
                  💡 {f.recommendation}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Limitations Documentation (e.g. TLS 1.3 encrypted handshake note) */}
      {limitations && limitations.length > 0 && (
        <div className="card" style={{ borderLeft: '4px solid var(--accent)' }}>
          <div className="card-header">
            <div className="card-title">Technical Capability & Observability Bounds</div>
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', lineHeight: 1.6 }}>
            {limitations.map((lim, i) => (
              <div key={i} style={{ marginBottom: i < limitations.length - 1 ? '0.5rem' : 0 }}>
                • {lim}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
