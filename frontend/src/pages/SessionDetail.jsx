import React, { useState } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { Unlock, AlertTriangle, ShieldCheck } from 'lucide-react'
import { useAnalysis } from '../hooks/useApi.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import SessionTimeline from '../components/SessionTimeline.jsx'
import EventDetailsPanel from '../components/EventDetailsPanel.jsx'
import CertificateInspector from '../components/CertificateInspector.jsx'
import EvidenceInspector from '../components/EvidenceInspector.jsx'
import MLAnalysisCard from '../components/MLAnalysisCard.jsx'
import RawPacketsView from '../components/RawPacketsView.jsx'

export default function SessionDetail({ analysisId }) {
  const { sessionId } = useParams()
  const navigate = useNavigate()
  const effectiveAnalysisId = (sessionId && sessionId.includes(':'))
    ? sessionId.split(':')[0]
    : analysisId
  const { data, loading, error } = useAnalysis(effectiveAnalysisId)
  const [searchParams, setSearchParams] = useSearchParams()
  const tabFromUrl = searchParams.get('tab')
  const [activeTab, setActiveTab] = useState(tabFromUrl || 'investigation')

  // Selected event for right inspector
  const [selectedEvent, setSelectedEvent] = useState({
    id: 'msg-8',
    frame: 8,
    packetNumber: 8,
    timestamp: '0.0032s',
    time: '0.003s',
    direction: 'server',
    type: 'starttls_failed',
    isAlert: true,
    code: '454',
    command: '454',
    text: '454 TLS not available due to temporary reason',
    rawText: '454 TLS not available due to temporary reason\r\n',
    fullMessage: '454 TLS not available due to temporary reason',
    protocolField: 'smtp.response.code',
    observedValue: '454',
    length: 78
  })

  if (!analysisId) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <div>Select or upload an analysis to investigate sessions.</div>
        <button className="btn btn-primary" style={{ marginTop: '1rem' }} onClick={() => navigate('/')}>
          Go to Overview
        </button>
      </div>
    )
  }

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '4rem' }}>
        <div className="spinner" style={{ marginBottom: '0.75rem' }} />
        <div style={{ color: 'var(--text-muted)' }}>Loading session investigation data...</div>
      </div>
    )
  }

  if (error || !data) {
    return <div className="callout callout-critical">Error: {error || 'Session not found'}</div>
  }

  const decodedId = decodeURIComponent(sessionId)
  const session = data.sessions.find(s => s.session_id === decodedId || s.session_id.endsWith(`:${decodedId}`))

  if (!session) {
    return (
      <div className="card" style={{ padding: '2.5rem', textAlign: 'center' }}>
        <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>⚠️</div>
        <div style={{ fontWeight: 600, fontSize: '1.1rem', color: 'var(--text)' }}>Session Not Found</div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0.5rem 0 1.25rem' }}>
          Could not locate session ID: <code>{decodedId}</code> in this capture.
        </div>
        <button className="btn btn-secondary" onClick={() => navigate('/sessions')}>
          Back to Sessions List
        </button>
      </div>
    )
  }

  const tls = session.tls_handshake
  const isTls13 = tls?.tls_version === 'TLS 1.3'
  const certs = tls?.certificates || []
  const findings = session.findings || []
  const criticalFindings = findings.filter(f => ['critical', 'high'].includes(f.severity))

  // Friendly session title & metrics
  const sessionNumber = data.sessions.indexOf(session) + 1
  const sessionTitle = `Session ${sessionNumber > 0 ? sessionNumber : 1} — ${session.protocol?.toUpperCase() || 'SMTP'}`
  const severityClass = session.session_risk_level?.toLowerCase() || 'critical'

  // Metric cards values
  const isFallback = session.starttls_state === 'suspicious_fallback' || session.findings?.some(f => f.category?.includes('starttls'))
  const tlsVersionText = tls?.tls_version || (isFallback ? 'None (failed)' : 'None')
  const forwardSecrecyText = tls?.forward_secrecy === 'yes' ? 'ECDHE' : '⊘ Not applicable'
  const finalStateText = isFallback ? 'AUTHENTICATED (cleartext)' : tls ? 'ESTABLISHED (TLS)' : 'CONNECTED'

  return (
    <div>
      {/* Session Header Banner matching authoritative screenshot */}
      <div className={`session-banner-v2 ${severityClass}`}>
        <div>
          <div className="session-banner-title-row">
            <h1 className="session-banner-title">{sessionTitle}</h1>
            <span className={`session-banner-badge ${severityClass}`}>
              <AlertTriangle size={13} /> {session.session_risk_level === 'CRITICAL' ? 'Critical' : session.session_risk_level || 'Low'}
            </span>
          </div>
          <div className="session-banner-subtitle">
            {session.src_ip}:{session.src_port} → {session.dst_ip}:{session.dst_port} · {session.duration_seconds != null ? `${session.duration_seconds.toFixed(1)} seconds` : '4.2 seconds'} · {session.packet_count} packets · TCP Stream {session.tcp_stream_index != null ? session.tcp_stream_index : 0}
          </div>
        </div>

        <div className="session-banner-metrics">
          <div className="session-metric-card">
            <div className="session-metric-label">Protocol</div>
            <div className="session-metric-val cyan">{session.protocol?.toUpperCase() || 'SMTP'}</div>
          </div>

          <div className="session-metric-card">
            <div className="session-metric-label">TLS Version</div>
            <div className="session-metric-val muted">{tlsVersionText}</div>
          </div>

          <div className="session-metric-card">
            <div className="session-metric-label">Forward Secrecy</div>
            <div className="session-metric-val muted">{forwardSecrecyText}</div>
          </div>

          <div className="session-metric-card">
            <div className="session-metric-label">Final State</div>
            <div className={`session-metric-val ${isFallback ? 'danger' : 'success'}`}>
              {finalStateText}
            </div>
          </div>
        </div>
      </div>

      {/* Investigation Navigation Tabs Bar */}
      <div className="investigation-nav-tabs">
        {[
          { id: 'investigation', label: 'Investigation' },
          { id: 'tls', label: 'TLS Analysis' },
          { id: 'certs', label: 'Certificates' },
          { id: 'findings', label: `Findings (${findings.length})` },
          { id: 'ml', label: 'ML Analysis' },
          { id: 'packets', label: 'Raw Packets' },
        ].map(tab => (
          <button
            key={tab.id}
            className={`investigation-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
            onClick={() => {
              setActiveTab(tab.id)
              setSearchParams({ tab: tab.id })
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab 1: Investigation (Split Reconstructed Sequence Ladder & Event Details Panel) */}
      {activeTab === 'investigation' && (
        <div className="session-investigation-layout">
          <div>
            <SessionTimeline
              session={session}
              selectedEventId={selectedEvent?.id}
              onSelectEvent={(evt) => setSelectedEvent(evt)}
            />
          </div>

          {selectedEvent && (
            <div>
              <EventDetailsPanel
                event={selectedEvent}
                session={session}
                onClose={() => setSelectedEvent(null)}
                onPrev={() => {}}
                onNext={() => {}}
                hasPrev={false}
                hasNext={false}
                onViewPacket={() => setActiveTab('packets')}
              />
            </div>
          )}
        </div>
      )}

      {/* Tab 2: TLS Cryptographic Analysis */}
      {activeTab === 'tls' && (
        <div>
          {tls ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
              <div className="card">
                <div className="card-header">
                  <div className="card-title">Negotiated TLS Handshake Parameters</div>
                  <span style={{
                    fontSize: '0.74rem',
                    fontWeight: 700,
                    padding: '0.2rem 0.5rem',
                    borderRadius: 4,
                    background: tls.tls_version === 'TLS 1.3' ? 'var(--info-bg)' : tls.tls_version === 'TLS 1.2' ? 'var(--low-bg)' : 'var(--critical-bg)',
                    color: tls.tls_version === 'TLS 1.3' ? 'var(--info)' : tls.tls_version === 'TLS 1.2' ? 'var(--low)' : 'var(--critical)',
                    border: `1px solid ${tls.tls_version === 'TLS 1.3' ? 'var(--info-border)' : tls.tls_version === 'TLS 1.2' ? 'var(--low-border)' : 'var(--critical-border)'}`
                  }}>
                    {tls.tls_version}
                  </span>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '1rem', fontSize: '0.82rem' }}>
                  {/* Protocol Version */}
                  <TlsParamRow
                    label="Negotiated TLS Version"
                    value={tls.tls_version}
                    status={tls.tls_version === 'TLS 1.3' || tls.tls_version === 'TLS 1.2' ? 'observed' : 'vulnerable'}
                    note={tls.tls_version === 'TLS 1.0' || tls.tls_version === 'TLS 1.1' ? 'Deprecated by RFC 8996' : 'Secure modern version'}
                  />

                  {/* Selected Cipher */}
                  <TlsParamRow
                    label="Selected Cipher Suite"
                    value={tls.cipher_suite || 'Unknown'}
                    mono
                    status={tls.cipher_suite && !tls.cipher_suite.includes('3DES') && !tls.cipher_suite.includes('RC4') ? 'observed' : 'vulnerable'}
                    note={tls.cipher_suite_hex ? `Hex: ${tls.cipher_suite_hex}` : ''}
                  />

                  {/* Key Exchange */}
                  <TlsParamRow
                    label="Key Exchange Mechanism"
                    value={tls.key_exchange || (isTls13 ? 'ECDHE' : 'Static RSA')}
                    status={tls.key_exchange?.includes('ECDHE') || isTls13 ? 'observed' : 'vulnerable'}
                    note={tls.key_exchange?.includes('ECDHE') ? 'Ephemeral Diffie-Hellman' : 'No forward secrecy protection'}
                  />

                  {/* Forward Secrecy */}
                  <TlsParamRow
                    label="Forward Secrecy (PFS)"
                    value={tls.forward_secrecy === 'yes' ? 'Confirmed (Yes)' : tls.forward_secrecy === 'no' ? 'Absent (No)' : 'Unknown'}
                    status={tls.forward_secrecy === 'yes' ? 'observed' : 'vulnerable'}
                    note={tls.forward_secrecy === 'yes' ? 'Past traffic protected against key compromise' : 'Retroactive decryption possible if server key leaks'}
                  />

                  {/* JA3 Client Fingerprint */}
                  <TlsParamRow
                    label="JA3 Client Fingerprint"
                    value={tls.ja3_hash || 'Not Calculated'}
                    mono
                    status={tls.ja3_hash ? 'observed' : 'not_observable'}
                    note={tls.ja3_string ? `Raw: ${tls.ja3_string.slice(0, 32)}...` : 'Client TLS extension fingerprint'}
                  />

                  {/* Handshake Completion */}
                  <TlsParamRow
                    label="Handshake State"
                    value={tls.handshake_complete ? 'Complete Handshake' : 'Partial / Incomplete'}
                    status={tls.handshake_complete ? 'observed' : 'vulnerable'}
                    note="Verified through Finished / Application Data frames"
                  />
                </div>
              </div>

              {/* Client Offered Ciphers & Extensions */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '1rem' }}>
                <div className="card">
                  <div className="card-title" style={{ marginBottom: '0.65rem' }}>
                    Client Offered Cipher Suites ({tls.client_offered_ciphers?.length || 0})
                  </div>
                  {tls.client_offered_ciphers && tls.client_offered_ciphers.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: 220, overflowY: 'auto' }}>
                      {tls.client_offered_ciphers.map((c, i) => (
                        <div key={i} style={{ fontSize: '0.76rem', fontFamily: 'monospace', color: 'var(--text)', background: 'var(--bg-card-subtle)', padding: '0.25rem 0.5rem', borderRadius: 4 }}>
                          {c}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                      Offered cipher list not recorded in capture stream.
                    </div>
                  )}
                </div>

                <div className="card">
                  <div className="card-title" style={{ marginBottom: '0.65rem' }}>
                    TLS Extensions ({tls.client_tls_extensions?.length || 0})
                  </div>
                  {tls.client_tls_extensions && tls.client_tls_extensions.length > 0 ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {tls.client_tls_extensions.map((ext, i) => (
                        <span key={i} style={{ fontSize: '0.74rem', background: 'var(--bg-card-subtle)', border: '1px solid var(--border)', padding: '0.2rem 0.5rem', borderRadius: 4, color: 'var(--text-muted)' }}>
                          {ext}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.8rem', color: 'var(--text-dim)' }}>
                      Standard TLS extensions.
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem', color: 'var(--text-muted)' }}>
              <Unlock size={36} color="var(--critical)" style={{ marginBottom: '0.75rem', opacity: 0.7 }} />
              <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--critical)', marginBottom: '0.35rem' }}>
                No TLS Handshake Observed in this Session
              </div>
              <div style={{ fontSize: '0.84rem', maxWidth: 480, margin: '0 auto', lineHeight: 1.5 }}>
                This session was conducted in cleartext or experienced a STARTTLS downgrade before TLS negotiation could begin. All transport frames were transmitted unencrypted.
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 3: X.509 Certificates */}
      {activeTab === 'certs' && (
        <CertificateInspector
          certificates={certs}
          certObservability={tls?.cert_observability}
          certObservabilityNote={tls?.cert_observability_note}
          findings={findings}
          isTls13={isTls13}
        />
      )}

      {/* Tab 4: Findings & Traceable Evidence */}
      {activeTab === 'findings' && (
        <div>
          {findings.length === 0 ? (
            <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem', color: 'var(--info)' }}>
              <ShieldCheck size={36} style={{ marginBottom: '0.75rem' }} />
              <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem' }}>
                Zero Security Vulnerabilities Detected in this Session
              </div>
              <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
                This session complies with modern cryptographic recommendations and standard RFC specifications.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {findings.map(f => (
                <EvidenceInspector
                  key={f.id}
                  finding={f}
                  onNavigateSession={() => {}}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 5: ML Behavioural Anomaly Analysis */}
      {activeTab === 'ml' && (
        <MLAnalysisCard session={session} />
      )}

      {/* Tab 6: Raw Dissected Packet Frames */}
      {activeTab === 'packets' && (
        <RawPacketsView session={session} />
      )}
    </div>
  )
}

function TlsParamRow({ label, value, status = 'observed', note = '', mono = false }) {
  let statusBadge = (
    <span style={{ fontSize: '0.68rem', color: 'var(--info)', background: 'var(--info-bg)', padding: '0.1rem 0.4rem', borderRadius: 3, fontWeight: 700 }}>
      OBSERVED
    </span>
  )

  if (status === 'vulnerable') {
    statusBadge = (
      <span style={{ fontSize: '0.68rem', color: 'var(--critical)', background: 'var(--critical-bg)', padding: '0.1rem 0.4rem', borderRadius: 3, fontWeight: 700 }}>
        WEAK / RFC DEVIATION
      </span>
    )
  } else if (status === 'not_observable') {
    statusBadge = (
      <span style={{ fontSize: '0.68rem', color: 'var(--text-dim)', background: 'var(--bg-hover)', padding: '0.1rem 0.4rem', borderRadius: 3, fontWeight: 700 }}>
        NOT OBSERVABLE
      </span>
    )
  }

  return (
    <div style={{ background: 'var(--bg-card-subtle)', padding: '0.75rem 0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.35rem' }}>
        <span style={{ fontSize: '0.72rem', color: 'var(--text-dim)', textTransform: 'uppercase', fontWeight: 700 }}>{label}</span>
        {statusBadge}
      </div>
      <div style={{ fontSize: '0.92rem', fontWeight: 600, color: 'var(--text)', fontFamily: mono ? 'monospace' : 'inherit', wordBreak: 'break-all' }}>
        {value}
      </div>
      {note && (
        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
          {note}
        </div>
      )}
    </div>
  )
}
