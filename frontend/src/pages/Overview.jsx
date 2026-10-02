import React from 'react'
import { useAnalysis } from '../hooks/useApi.js'
import { RadialBarChart, RadialBar, PieChart, Pie, Cell, Tooltip, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts'
import { Shield, ChevronRight, BookOpen } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

function ScoreGauge({ score, level }) {
  const color = score >= 85 ? '#3fb950' : score >= 70 ? '#56d364' : score >= 50 ? '#f5a623' : score >= 30 ? '#e3b341' : '#ff6b6b'
  return (
    <div className="score-widget">
      <div style={{ display: 'flex', gap: '2rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div>
          <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginBottom: '0.25rem', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
            SecureMailScope Composite Risk Score
          </div>
          <div className="score-number" style={{ color }}>{score}</div>
          <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginTop: '0.2rem' }}>
            / 100 — prototype methodology
          </div>
        </div>
        <div>
          <div className={`risk-badge risk-${level}`}>
            <Shield size={14} />
            {level} Risk
          </div>
          <div style={{ marginTop: '0.5rem', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
            NOT an official NIST/BIS/NTRO score
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 200, height: 120 }}>
          <ResponsiveContainer width="100%" height="100%">
            <RadialBarChart innerRadius={30} outerRadius={55} data={[{ value: score, fill: color }]} startAngle={180} endAngle={0}>
              <RadialBar dataKey="value" cornerRadius={4} />
            </RadialBarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}

function FindingsPieChart({ risk_score }) {
  const data = [
    { name: 'Critical', value: risk_score.critical_count, color: '#ff6b6b' },
    { name: 'High', value: risk_score.high_count, color: '#f5a623' },
    { name: 'Medium', value: risk_score.medium_count, color: '#ffd700' },
    { name: 'Low', value: risk_score.low_count, color: '#58a6ff' },
  ].filter(d => d.value > 0)

  if (!data.length) return (
    <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--info)' }}>
      ✓ No security issues found
    </div>
  )

  return (
    <ResponsiveContainer width="100%" height={200}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="name" cx="50%" cy="50%"
          outerRadius={80} label={({ name, value }) => `${name}: ${value}`}
          labelLine={{ stroke: 'var(--text-muted)' }}>
          {data.map((d, i) => <Cell key={i} fill={d.color} />)}
        </Pie>
        <Tooltip
          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}
          labelStyle={{ color: 'var(--text)' }}
        />
      </PieChart>
    </ResponsiveContainer>
  )
}

function TLSVersionChart({ tls_versions }) {
  const data = Object.entries(tls_versions || {}).map(([ver, count]) => ({ version: ver, count }))
    .sort((a, b) => a.version.localeCompare(b.version))

  if (!data.length) return <div style={{ color: 'var(--text-muted)', padding: '1rem' }}>No TLS sessions</div>

  const versionColor = (ver) => {
    if (ver.includes('1.3')) return '#3fb950'
    if (ver.includes('1.2')) return '#58a6ff'
    if (ver.includes('1.1') || ver.includes('1.0')) return '#f5a623'
    return '#ff6b6b'
  }

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data} barSize={32}>
        <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" vertical={false} />
        <XAxis dataKey="version" tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 11 }} axisLine={false} tickLine={false} />
        <Tooltip
          contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8 }}
          labelStyle={{ color: 'var(--text)' }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((d, i) => <Cell key={i} fill={versionColor(d.version)} />)}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  )
}

export default function Overview({ analysisId }) {
  const { data, loading, error } = useAnalysis(analysisId)
  const navigate = useNavigate()

  if (!analysisId) {
    return (
      <div>
        <div className="page-header">
          <h2 className="page-title">Dashboard Overview</h2>
          <p className="page-subtitle">Upload a PCAP file to begin cryptographic security posture analysis</p>
        </div>
        <div className="empty-state">
          <div className="empty-icon">🔒</div>
          <div style={{ fontSize: '1.1rem', fontWeight: 600, marginBottom: '0.5rem' }}>No Analysis Active</div>
          <div style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
            Upload a PCAP containing SMTP, IMAP, or POP3 traffic to analyse cryptographic security posture.
          </div>
          <div style={{ display: 'flex', gap: '0.75rem', justifyContent: 'center', flexWrap: 'wrap' }}>
            <button className="btn btn-primary" onClick={() => navigate('/upload')}>
              Upload PCAP
            </button>
            <button className="btn btn-secondary" onClick={() => navigate('/guide')} style={{ gap: '0.4rem' }}>
              <BookOpen size={14} /> Capture Guide & Instructions
            </button>
          </div>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', padding: '3rem' }}>
        <div className="spinner" />
        <span>Analysing PCAP traffic...</span>
      </div>
    )
  }

  if (error || !data) {
    return <div style={{ color: 'var(--critical)', padding: '2rem' }}>Error: {error || 'Analysis not found'}</div>
  }

  const { risk_score, capture, protocol_summary, sessions, all_findings, limitations } = data

  // Top findings (critical/high)
  const topFindings = all_findings.filter(f => ['critical', 'high'].includes(f.severity)).slice(0, 5)
  const mlFindings = all_findings.filter(f => f.is_ml_finding)

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Security Posture Overview</h2>
        <p className="page-subtitle">
          {capture.pcap_filename} · {capture.packet_count.toLocaleString()} packets · {sessions.length} sessions · {data.processing_time_seconds.toFixed(2)}s
        </p>
      </div>

      {/* Score */}
      <ScoreGauge score={risk_score.score} level={risk_score.level} />

      {/* Key stats */}
      <div className="stat-grid" style={{ margin: '1.25rem 0' }}>
        <StatCard icon="🔍" label="Sessions" value={sessions.length} color="var(--accent)" />
        <StatCard icon="📧" label="SMTP" value={protocol_summary.smtp_sessions} color="#79b8ff" />
        <StatCard icon="📬" label="IMAP" value={protocol_summary.imap_sessions} color="#56d364" />
        <StatCard icon="📮" label="POP3" value={protocol_summary.pop3_sessions} color="#f0c674" />
        <StatCard icon="🔐" label="TLS Sessions" value={protocol_summary.tls_sessions} color="var(--info)" />
        <StatCard icon="🔓" label="Plaintext" value={protocol_summary.plaintext_sessions} color={protocol_summary.plaintext_sessions > 0 ? 'var(--critical)' : 'var(--text-muted)'} />
        <StatCard icon="⚡" label="Forward Secrecy" value={`${protocol_summary.forward_secrecy_yes}/${protocol_summary.tls_sessions}`} color="var(--info)" />
        <StatCard icon="🤖" label="ML Anomalies" value={risk_score.ml_anomaly_count} color="var(--ml-color)" />
      </div>

      {/* Charts row */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
        <div className="card">
          <div className="card-header">
            <div className="card-title">Findings by Severity</div>
          </div>
          <FindingsPieChart risk_score={risk_score} />
        </div>
        <div className="card">
          <div className="card-header">
            <div className="card-title">TLS Version Distribution</div>
          </div>
          <TLSVersionChart tls_versions={protocol_summary.tls_versions} />
        </div>
      </div>

      {/* Top findings */}
      {topFindings.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <h3 style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text)' }}>
              Top Critical / High Findings
            </h3>
            <button className="btn btn-secondary" style={{ fontSize: '0.78rem', padding: '0.35rem 0.75rem' }}
              onClick={() => navigate('/findings')}>
              View all <ChevronRight size={13} />
            </button>
          </div>
          {topFindings.map(f => (
            <div key={f.id} className={`finding-card finding-${f.severity}`}>
              <div className="finding-title">
                <span className={`sev-badge sev-${f.severity}`}>{f.severity}</span>
                {f.is_ml_finding && <span className="sev-badge sev-ml">ML</span>}
                {f.title}
              </div>
              <div className="finding-desc">{f.description.slice(0, 200)}...</div>
              <div className="finding-rec">💡 {f.recommendation}</div>
            </div>
          ))}
        </div>
      )}

      {/* ML anomaly note */}
      {mlFindings.length > 0 && (
        <div style={{ marginBottom: '1.25rem' }}>
          <div className="card">
            <div className="card-header">
              <div className="card-title">🤖 ML Behavioural Anomalies ({mlFindings.length})</div>
            </div>
            <p style={{ fontSize: '0.83rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
              The following sessions were flagged by the Isolation Forest anomaly detector as statistically
              unusual. These are <strong style={{ color: 'var(--ml-color)' }}>probabilistic findings</strong> distinct
              from deterministic rule-based findings — they indicate unusual TLS/protocol metadata patterns.
            </p>
            {mlFindings.slice(0, 3).map(f => (
              <div key={f.id} style={{ padding: '0.6rem', background: 'rgba(167,139,250,0.06)', border: '1px solid rgba(167,139,250,0.2)', borderRadius: 6, marginBottom: '0.5rem', fontSize: '0.82rem' }}>
                <span className="sev-badge sev-ml" style={{ marginRight: '0.5rem' }}>ML Anomaly</span>
                {f.title}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TLS 1.3 note */}
      {limitations && limitations.some(l => l.includes('TLS 1.3')) && (
        <div className="tls13-note" style={{ marginBottom: '1.25rem' }}>
          <strong>TLS 1.3 Certificate Observability:</strong> {' '}
          TLS 1.3 encrypts Certificate messages by default (RFC 8446 §4.4.2). This tool correctly reports
          the limitation rather than fabricating certificate data — observable fields (TLS version, cipher suite)
          are still reported for TLS 1.3 sessions.
        </div>
      )}

      {/* Score rationale */}
      {risk_score.rationale.length > 0 && (
        <div className="card">
          <div className="card-header">
            <div className="card-title">Score Rationale</div>
          </div>
          <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)' }}>
            <div style={{ marginBottom: '0.5rem' }}>Base score: 100</div>
            {risk_score.rationale.map((r, i) => (
              <div key={i} style={{ padding: '0.2rem 0' }}>― {r}</div>
            ))}
            <div style={{ marginTop: '0.5rem', fontWeight: 600, color: 'var(--text)' }}>
              Final score: {risk_score.score} / 100
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

function StatCard({ icon, label, value, color }) {
  return (
    <div className="stat-card">
      <div style={{ fontSize: '1.4rem', marginBottom: '0.3rem' }}>{icon}</div>
      <div className="stat-value" style={{ color }}>{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  )
}
