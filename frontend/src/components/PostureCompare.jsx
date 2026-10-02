import React, { useState, useEffect } from 'react'
import { GitCompare, ArrowRight } from 'lucide-react'
import SeverityBadge from './SeverityBadge.jsx'

export default function PostureCompare({ analyses = [], defaultBeforeId = null, defaultAfterId = null }) {
  const [beforeId, setBeforeId] = useState(defaultBeforeId || '')
  const [afterId, setAfterId] = useState(defaultAfterId || '')
  const [beforeData, setBeforeData] = useState(null)
  const [afterData, setAfterData] = useState(null)
  const [loading, setLoading] = useState(false)

  const doneAnalyses = analyses.filter(a => a.status === 'done')

  // Set default selection if none provided
  useEffect(() => {
    if (!beforeId && doneAnalyses.length > 0) {
      // Pick first critical/high analysis as before if available, or first item
      const degraded = doneAnalyses.find(a => ['CRITICAL', 'HIGH'].includes(a.risk_level))
      setBeforeId(degraded ? degraded.analysis_id : doneAnalyses[0].analysis_id)
    }
    if (!afterId && doneAnalyses.length > 1) {
      // Pick minimal/low analysis as after if available
      const clean = doneAnalyses.find(a => ['MINIMAL', 'LOW'].includes(a.risk_level))
      setAfterId(clean ? clean.analysis_id : doneAnalyses[1].analysis_id)
    }
  }, [analyses])

  // Fetch full analysis results for both sides
  useEffect(() => {
    let cancelled = false
    const fetchBoth = async () => {
      if (!beforeId || !afterId) return
      setLoading(true)
      try {
        const [resBefore, resAfter] = await Promise.all([
          fetch(`/api/analysis/${beforeId}`).then(r => r.json()),
          fetch(`/api/analysis/${afterId}`).then(r => r.json()),
        ])
        if (!cancelled) {
          setBeforeData(resBefore)
          setAfterData(resAfter)
          setLoading(false)
        }
      } catch (err) {
        if (!cancelled) setLoading(false)
      }
    }
    fetchBoth()
    return () => { cancelled = true }
  }, [beforeId, afterId])

  if (doneAnalyses.length < 2) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem', color: 'var(--text-muted)' }}>
        <GitCompare size={36} color="var(--accent)" style={{ marginBottom: '0.75rem', opacity: 0.7 }} />
        <div style={{ fontWeight: 600, fontSize: '1rem', color: 'var(--text)', marginBottom: '0.35rem' }}>
          At Least Two Analyses Required for Comparison
        </div>
        <div style={{ fontSize: '0.84rem', maxWidth: 500, margin: '0 auto', lineHeight: 1.5 }}>
          Run or upload at least two PCAP captures (such as a degraded capture and its remediated counterpart) to perform side-by-side evidence-based posture comparison.
        </div>
      </div>
    )
  }

  // Derive feature states from sessions
  const getFeatureStates = (analysis) => {
    if (!analysis) return {}
    const s0 = analysis.sessions?.[0]
    const tls = s0?.tls_handshake
    const cert = tls?.certificates?.[0]
    const st = s0?.starttls_state

    return {
      filename: analysis.capture?.pcap_filename || 'capture.pcap',
      score: Math.round(analysis.risk_score?.score ?? 0),
      level: analysis.risk_score?.level || 'MINIMAL',
      tlsVersion: tls?.tls_version || (st === 'no_tls' ? 'Plaintext (None)' : 'Unobserved'),
      tlsOk: tls?.tls_version === 'TLS 1.3' || tls?.tls_version === 'TLS 1.2',
      cipher: tls?.cipher_suite || (st === 'no_tls' ? 'No Cipher' : 'Unknown'),
      cipherOk: tls?.cipher_suite && !tls.cipher_suite.includes('3DES') && !tls.cipher_suite.includes('RC4') && !tls.cipher_suite.includes('NULL'),
      kex: tls?.key_exchange || (tls?.tls_version === 'TLS 1.3' ? 'ECDHE' : 'None'),
      kexOk: tls?.key_exchange?.includes('ECDHE') || tls?.key_exchange?.includes('DHE') || tls?.tls_version === 'TLS 1.3',
      fs: tls?.forward_secrecy || 'unknown',
      fsOk: tls?.forward_secrecy === 'yes',
      certStatus: cert ? (cert.is_expired ? 'Expired' : cert.public_key?.key_size_bits < 2048 ? 'Weak Key' : 'Valid') : (tls?.tls_version === 'TLS 1.3' ? 'Encrypted (TLS 1.3)' : 'No Cert'),
      certOk: cert ? (!cert.is_expired && (cert.public_key?.key_size_bits >= 2048 || !cert.public_key?.key_size_bits)) : true,
      starttlsState: st || 'no_tls',
      starttlsOk: st === 'negotiated' || st === 'direct_tls',
      criticalCount: analysis.risk_score?.critical_count || 0,
      highCount: analysis.risk_score?.high_count || 0,
      findingCount: analysis.all_findings?.length || 0,
    }
  }

  const bFeat = getFeatureStates(beforeData)
  const aFeat = getFeatureStates(afterData)
  const scoreDelta = (aFeat.score || 0) - (bFeat.score || 0)

  return (
    <div>
      <div className="page-header">
        <h2 className="page-title">Before / After Security Posture Comparison</h2>
        <p className="page-subtitle">
          Evidence-based comparative assessment demonstrating remediation verification and cryptographic hardening across captures.
        </p>
      </div>

      {/* Selectors Bar */}
      <div className="card" style={{ marginBottom: '1.5rem', padding: '1rem 1.25rem' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: '1rem', alignItems: 'center' }}>
          <div>
            <label style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
              Baseline / Pre-Remediation (Before)
            </label>
            <select
              className="filter-select"
              style={{ width: '100%' }}
              value={beforeId}
              onChange={e => setBeforeId(e.target.value)}
            >
              {doneAnalyses.map(a => (
                <option key={a.analysis_id} value={a.analysis_id}>
                  {a.pcap || a.analysis_id.slice(0, 8)} ({a.risk_level} · {Math.round(a.risk_score || 0)} pts)
                </option>
              ))}
            </select>
          </div>

          <div style={{ color: 'var(--text-dim)', textAlign: 'center', paddingTop: '1.25rem' }}>
            <ArrowRight size={20} />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', display: 'block', marginBottom: '0.35rem' }}>
              Hardened / Post-Remediation (After)
            </label>
            <select
              className="filter-select"
              style={{ width: '100%' }}
              value={afterId}
              onChange={e => setAfterId(e.target.value)}
            >
              {doneAnalyses.map(a => (
                <option key={a.analysis_id} value={a.analysis_id}>
                  {a.pcap || a.analysis_id.slice(0, 8)} ({a.risk_level} · {Math.round(a.risk_score || 0)} pts)
                </option>
              ))}
            </select>
          </div>
        </div>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: '3rem' }}>
          <div className="spinner" style={{ marginBottom: '0.75rem' }} />
          <div style={{ color: 'var(--text-muted)' }}>Calculating comparative cryptographic deltas...</div>
        </div>
      ) : beforeData && afterData ? (
        <div>
          {/* Top Posture Delta Summary */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '1rem',
            marginBottom: '1.5rem',
          }}>
            {/* Before Card */}
            <div className="card" style={{ borderLeft: '4px solid var(--critical)' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                Baseline Posture
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.25rem' }}>
                <span style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--critical)', fontFamily: 'monospace' }}>
                  {bFeat.score}
                </span>
                <span style={{ color: 'var(--text-muted)' }}>/ 100</span>
                <SeverityBadge severity={bFeat.level} style={{ marginLeft: 'auto' }} />
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                {bFeat.filename} · {bFeat.criticalCount} critical, {bFeat.findingCount} total findings
              </div>
            </div>

            {/* Delta Card */}
            <div className="card" style={{
              background: 'linear-gradient(135deg, var(--bg-card) 0%, var(--bg-surface) 100%)',
              textAlign: 'center',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'center',
              alignItems: 'center',
            }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                Remediation Delta
              </div>
              <div style={{ fontSize: '2.2rem', fontWeight: 800, color: scoreDelta >= 0 ? 'var(--info)' : 'var(--critical)', fontFamily: 'monospace', marginTop: '0.2rem' }}>
                {scoreDelta >= 0 ? `+${scoreDelta}` : scoreDelta} pts
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                {scoreDelta > 0 ? 'Cryptographic posture hardened' : 'No net improvement observed'}
              </div>
            </div>

            {/* After Card */}
            <div className="card" style={{ borderLeft: '4px solid var(--info)' }}>
              <div style={{ fontSize: '0.7rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)' }}>
                Hardened Posture
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.5rem', marginTop: '0.25rem' }}>
                <span style={{ fontSize: '2.5rem', fontWeight: 800, color: 'var(--info)', fontFamily: 'monospace' }}>
                  {aFeat.score}
                </span>
                <span style={{ color: 'var(--text-muted)' }}>/ 100</span>
                <SeverityBadge severity={aFeat.level} style={{ marginLeft: 'auto' }} />
              </div>
              <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.4rem' }}>
                {aFeat.filename} · {aFeat.criticalCount} critical, {aFeat.findingCount} total findings
              </div>
            </div>
          </div>

          {/* Comparative Matrix Table */}
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: '25%' }}>Security Control</th>
                  <th style={{ width: '35%' }}>Baseline Capture (Before)</th>
                  <th style={{ width: '35%' }}>Hardened Capture (After)</th>
                  <th style={{ width: '5%', textAlign: 'center' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                <CompareRow
                  label="Protocol & TLS Version"
                  beforeVal={bFeat.tlsVersion}
                  beforeOk={bFeat.tlsOk}
                  afterVal={aFeat.tlsVersion}
                  afterOk={aFeat.tlsOk}
                />
                <CompareRow
                  label="Negotiated Cipher Suite"
                  beforeVal={bFeat.cipher}
                  beforeOk={bFeat.cipherOk}
                  afterVal={aFeat.cipher}
                  afterOk={aFeat.cipherOk}
                />
                <CompareRow
                  label="Key Exchange Mechanism"
                  beforeVal={bFeat.kex}
                  beforeOk={bFeat.kexOk}
                  afterVal={aFeat.kex}
                  afterOk={aFeat.kexOk}
                />
                <CompareRow
                  label="Forward Secrecy (FS)"
                  beforeVal={bFeat.fs === 'yes' ? 'Confirmed (ECDHE/DHE)' : 'Absent / Static RSA'}
                  beforeOk={bFeat.fsOk}
                  afterVal={aFeat.fs === 'yes' ? 'Confirmed (ECDHE/DHE)' : 'Absent / Static RSA'}
                  afterOk={aFeat.fsOk}
                />
                <CompareRow
                  label="X.509 Certificate Validity"
                  beforeVal={bFeat.certStatus}
                  beforeOk={bFeat.certOk}
                  afterVal={aFeat.certStatus}
                  afterOk={aFeat.certOk}
                />
                <CompareRow
                  label="STARTTLS Negotiation State"
                  beforeVal={bFeat.starttlsState === 'suspicious_fallback' ? 'Suspicious Fallback / Stripped' : bFeat.starttlsState}
                  beforeOk={bFeat.starttlsOk}
                  afterVal={aFeat.starttlsState === 'negotiated' ? 'Clean Negotiated ✓' : aFeat.starttlsState}
                  afterOk={aFeat.starttlsOk}
                />
                <CompareRow
                  label="Critical Security Findings"
                  beforeVal={`${bFeat.criticalCount} Critical Violations`}
                  beforeOk={bFeat.criticalCount === 0}
                  afterVal={`${aFeat.criticalCount} Critical Violations`}
                  afterOk={aFeat.criticalCount === 0}
                />
              </tbody>
            </table>
          </div>
        </div>
      ) : null}
    </div>
  )
}

function CompareRow({ label, beforeVal, beforeOk, afterVal, afterOk }) {
  const isImproved = !beforeOk && afterOk
  const isWorse = beforeOk && !afterOk

  return (
    <tr>
      <td style={{ fontWeight: 600, color: 'var(--text)' }}>{label}</td>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
          <span style={{ color: beforeOk ? 'var(--info)' : 'var(--critical)', fontWeight: 700 }}>
            {beforeOk ? '✓' : '✗'}
          </span>
          <span style={{ color: beforeOk ? 'var(--text)' : 'var(--critical-text)', fontFamily: 'monospace', fontSize: '0.8rem' }}>
            {beforeVal}
          </span>
        </div>
      </td>
      <td>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.45rem' }}>
          <span style={{ color: afterOk ? 'var(--info)' : 'var(--critical)', fontWeight: 700 }}>
            {afterOk ? '✓' : '✗'}
          </span>
          <span style={{ color: afterOk ? 'var(--text)' : 'var(--critical-text)', fontFamily: 'monospace', fontSize: '0.8rem' }}>
            {afterVal}
          </span>
        </div>
      </td>
      <td style={{ textAlign: 'center' }}>
        {isImproved ? (
          <span style={{ color: 'var(--info)', fontSize: '0.75rem', fontWeight: 700, background: 'var(--info-bg)', padding: '0.15rem 0.45rem', borderRadius: 4 }}>
            FIXED
          </span>
        ) : isWorse ? (
          <span style={{ color: 'var(--critical)', fontSize: '0.75rem', fontWeight: 700, background: 'var(--critical-bg)', padding: '0.15rem 0.45rem', borderRadius: 4 }}>
            DEGRADED
          </span>
        ) : (
          <span style={{ color: 'var(--text-dim)', fontSize: '0.75rem' }}>—</span>
        )}
      </td>
    </tr>
  )
}
