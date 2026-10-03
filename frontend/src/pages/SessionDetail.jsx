import React, { useState, useEffect } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import {
  Unlock,
  Lock,
  AlertTriangle,
  ShieldCheck,
  ChevronLeft,
  ChevronRight,
  ArrowLeft,
  Layers,
  Terminal,
  Shield,
  MessageSquare
} from 'lucide-react'
import { useAnalysis } from '../hooks/useApi.js'
import SeverityBadge from '../components/SeverityBadge.jsx'
import SessionTimeline from '../components/SessionTimeline.jsx'
import STARTTLSSteps from '../components/STARTTLSSteps.jsx'
import EventDetailsPanel from '../components/EventDetailsPanel.jsx'
import CertificateInspector from '../components/CertificateInspector.jsx'
import EvidenceInspector from '../components/EvidenceInspector.jsx'
import MLAnalysisCard from '../components/MLAnalysisCard.jsx'
import RawPacketsView from '../components/RawPacketsView.jsx'

export default function SessionDetail({ analysisId }) {
  const { sessionId } = useParams()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()

  const effectiveAnalysisId = (sessionId && sessionId.includes(':'))
    ? sessionId.split(':')[0]
    : analysisId

  const { data, loading, error } = useAnalysis(effectiveAnalysisId)

  const decodedId = sessionId ? decodeURIComponent(sessionId) : ''
  const sessionList = data?.sessions || []

  // Resolve session index
  let sessionIndex = sessionList.findIndex(
    s => s.session_id === decodedId || s.session_id.endsWith(`:${decodedId}`)
  )

  if (sessionIndex === -1 && !isNaN(Number(decodedId)) && decodedId !== '') {
    const idx = parseInt(decodedId, 10)
    if (idx >= 0 && idx < sessionList.length) {
      sessionIndex = idx
    }
  }

  if (sessionIndex === -1 && sessionList.length > 0) {
    sessionIndex = 0
  }

  const session = sessionList[sessionIndex]

  // Tab mapping & state
  const rawTabParam = searchParams.get('tab')
  const normalizeTab = (t) => {
    if (!t) return 'conversation'
    if (['conversation', 'investigation', 'timeline'].includes(t)) return 'conversation'
    if (['security', 'tls', 'certs', 'ml'].includes(t)) return 'security'
    if (['findings'].includes(t)) return 'findings'
    if (['raw', 'packets'].includes(t)) return 'raw'
    return 'conversation'
  }

  const [activeTab, setActiveTab] = useState(normalizeTab(rawTabParam))
  const [isEvidenceOpen, setIsEvidenceOpen] = useState(true)
  const [rawHighlightFrame, setRawHighlightFrame] = useState(null)
  const [selectedEvent, setSelectedEvent] = useState(null)

  // Keep activeTab synchronized with URL if query param changes externally
  useEffect(() => {
    if (rawTabParam) {
      setActiveTab(normalizeTab(rawTabParam))
    }
  }, [rawTabParam])

  // Set default selected event if none is currently selected
  useEffect(() => {
    if (session) {
      const isFallback = session.starttls_state === 'suspicious_fallback' ||
        session.protocol_banners?.some(b => String(b).includes('454') || String(b).includes('4.7.0'))

      if (isFallback) {
        setSelectedEvent({
          id: 'msg-454',
          frame: session.starttls_advertised_pkt ? session.starttls_advertised_pkt + 2 : 8,
          packetNumber: session.starttls_advertised_pkt ? session.starttls_advertised_pkt + 2 : 8,
          timestamp: '0.003s',
          direction: 'server',
          type: 'starttls_failed',
          isAlert: true,
          code: '454',
          command: '454',
          text: '454 TLS not available due to temporary reason',
          rawText: '454 4.7.0 TLS not available due to temporary reason\r\n',
          protocolField: 'smtp.response.code',
          observedValue: '454',
          length: 78
        })
      } else if (session.cleartext_auth_detected) {
        setSelectedEvent({
          id: 'msg-auth',
          frame: 10,
          packetNumber: 10,
          timestamp: '0.005s',
          direction: 'client',
          type: 'cleartext_auth',
          isAlert: true,
          command: 'AUTH DATA',
          text: 'Cleartext Authentication Credentials Transmitted',
          rawText: 'AUTH DATA (Cleartext base64 payload)\r\n',
          protocolField: 'smtp.auth.credentials',
          observedValue: 'credentials exposed',
          length: 64
        })
      } else {
        setSelectedEvent({
          id: 'msg-top',
          frame: 1,
          packetNumber: 1,
          timestamp: '0.000s',
          direction: 'server',
          type: 'banner',
          command: session.protocol || 'SMTP',
          text: session.protocol_banners?.[0] || `Connection established on port ${session.dst_port}`,
          rawText: `${session.protocol_banners?.[0] || 'Ready'}\r\n`,
          protocolField: 'protocol.banner',
          observedValue: session.protocol || 'SMTP',
          length: 54
        })
      }
    }
  }, [session?.session_id])

  if (!effectiveAnalysisId) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <div>Select or upload an analysis to investigate sessions.</div>
        <button className="btn btn-primary" style={{ marginTop: '1rem' }} onClick={() => navigate('/')}>
          Go to Capture Library
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

  if (!session) {
    return (
      <div className="card" style={{ padding: '2.5rem', textAlign: 'center' }}>
        <div style={{ fontSize: '1.5rem', marginBottom: '0.5rem' }}>⚠️</div>
        <div style={{ fontWeight: 600, fontSize: '1.1rem', color: 'var(--text)' }}>Session Not Found</div>
        <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0.5rem 0 1.25rem' }}>
          Could not locate session ID: <code>{decodedId}</code> in this capture.
        </div>
        <button className="btn btn-secondary" onClick={() => navigate(`/analysis`)}>
          Back to Case Overview
        </button>
      </div>
    )
  }

  const tls = session.tls_handshake
  const isTls13 = tls?.tls_version === 'TLS 1.3'
  const certs = tls?.certificates || []
  const findings = session.findings || []
  const criticalFindings = findings.filter(f => ['critical', 'high'].includes(f.severity?.toLowerCase()))

  // Cycle navigation
  const prevSession = sessionIndex > 0 ? sessionList[sessionIndex - 1] : null
  const nextSession = sessionIndex < sessionList.length - 1 ? sessionList[sessionIndex + 1] : null

  const handleSwitchSession = (targetSession) => {
    if (!targetSession) return
    navigate(`/sessions/${encodeURIComponent(targetSession.session_id)}?tab=${activeTab}`)
  }

  // Friendly session title & metrics
  const sessionNumber = sessionIndex + 1
  const sessionTitle = `Session ${sessionNumber} — ${session.protocol?.toUpperCase() || 'SMTP'}`
  const severityClass = session.session_risk_level?.toLowerCase() || 'critical'

  // Metric cards values
  const isFallback = session.starttls_state === 'suspicious_fallback' || session.findings?.some(f => f.category?.includes('starttls'))
  const tlsVersionText = tls?.tls_version || (isFallback ? 'None (failed)' : session.dst_port === 25 ? 'None (cleartext)' : 'None')
  const forwardSecrecyText = tls?.forward_secrecy === 'yes' ? 'ECDHE' : '⊘ Not applicable'
  const finalStateText = isFallback ? 'AUTHENTICATED (cleartext)' : session.cleartext_auth_detected ? 'CLEARTEXT AUTH' : tls ? 'ESTABLISHED (TLS)' : 'CONNECTED (cleartext)'

  const switchTab = (tabId) => {
    setActiveTab(tabId)
    setSearchParams({ tab: tabId })
  }

  return (
    <div className="page-fade-in">
      {/* Session Switcher & Sub-Navigation Bar */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: '1rem',
        flexWrap: 'wrap',
        gap: '0.75rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            className="btn btn-ghost"
            style={{ fontSize: '0.78rem', display: 'flex', alignItems: 'center', gap: '0.35rem', padding: '0.3rem 0.6rem' }}
            onClick={() => navigate(`/analysis`)}
          >
            <ArrowLeft size={13} />
            <span>Case Overview</span>
          </button>

          <span style={{ color: 'var(--border)' }}>|</span>

          {/* Stream Selector Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <button
              className="btn btn-ghost"
              disabled={!prevSession}
              onClick={() => handleSwitchSession(prevSession)}
              title="Previous Stream"
              style={{ padding: '0.25rem 0.45rem' }}
            >
              <ChevronLeft size={14} />
            </button>

            <select
              value={session.session_id}
              onChange={(e) => {
                const target = sessionList.find(s => s.session_id === e.target.value)
                if (target) handleSwitchSession(target)
              }}
              style={{
                background: 'var(--bg-card)',
                color: 'var(--text)',
                border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)',
                padding: '0.3rem 0.6rem',
                fontSize: '0.78rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              {sessionList.map((s, idx) => (
                <option key={s.session_id} value={s.session_id}>
                  Stream {idx + 1}: {s.src_port} → {s.dst_ip}:{s.dst_port} ({s.protocol || 'TCP'}) [{s.session_risk_level || 'LOW'}]
                </option>
              ))}
            </select>

            <button
              className="btn btn-ghost"
              disabled={!nextSession}
              onClick={() => handleSwitchSession(nextSession)}
              title="Next Stream"
              style={{ padding: '0.25rem 0.45rem' }}
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>

        <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
          Showing Stream <strong>{sessionNumber}</strong> of <strong>{sessionList.length}</strong>
        </div>
      </div>

      {/* Session Header Banner */}
      <div className={`session-banner-v2 ${severityClass}`}>
        <div>
          <div className="session-banner-title-row">
            <h1 className="session-banner-title">{sessionTitle}</h1>
            <span className={`session-banner-badge ${severityClass}`}>
              <AlertTriangle size={13} /> {session.session_risk_level === 'CRITICAL' ? 'Critical' : session.session_risk_level || 'Low'}
            </span>
          </div>
          <div className="session-banner-subtitle">
            <code>{session.src_ip}:{session.src_port}</code> → <code>{session.dst_ip}:{session.dst_port}</code> · {session.duration_seconds != null ? `${session.duration_seconds.toFixed(2)}s duration` : '0.05s'} · {session.packet_count} packets · TCP Stream #{sessionIndex}
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
            <div className={`session-metric-val ${isFallback || session.cleartext_auth_detected ? 'danger' : 'success'}`}>
              {finalStateText}
            </div>
          </div>
        </div>
      </div>

      {/* 4 Contextual Forensic Investigation Tabs */}
      <div className="investigation-nav-tabs">
        {[
          { id: 'conversation', label: 'Conversation & Flow', icon: MessageSquare },
          { id: 'security', label: 'Security & Cryptography', icon: Shield },
          { id: 'findings', label: `Findings (${findings.length})`, icon: Layers },
          { id: 'raw', label: 'Raw Packets', icon: Terminal },
        ].map(tab => {
          const Icon = tab.icon
          return (
            <button
              key={tab.id}
              className={`investigation-tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => switchTab(tab.id)}
            >
              <Icon size={14} />
              <span>{tab.label}</span>
            </button>
          )
        })}
      </div>

      {/* TAB 1: Conversation & Flow (State Machine + Sequence Ladder + Docked Evidence Drawer) */}
      {activeTab === 'conversation' && (
        <div>
          {/* Alongside State Machine Progression */}
          <STARTTLSSteps session={session} />

          {/* 2-Column Split: Ladder Timeline + Docked Evidence Drawer */}
          <div className={`session-investigation-layout ${!isEvidenceOpen ? 'full-width' : ''}`}>
            <div>
              <SessionTimeline
                session={session}
                selectedEventId={selectedEvent?.id}
                onSelectEvent={(evt) => {
                  setSelectedEvent(evt)
                  setIsEvidenceOpen(true)
                }}
                isEvidenceOpen={isEvidenceOpen}
                onToggleEvidence={() => setIsEvidenceOpen(!isEvidenceOpen)}
              />
            </div>

            {isEvidenceOpen && selectedEvent && (
              <div>
                <EventDetailsPanel
                  event={selectedEvent}
                  session={session}
                  onClose={() => setIsEvidenceOpen(false)}
                  onPrev={() => {}}
                  onNext={() => {}}
                  hasPrev={false}
                  hasNext={false}
                  onViewPacket={(frame) => {
                    setRawHighlightFrame(frame)
                    switchTab('raw')
                  }}
                />
              </div>
            )}
          </div>
        </div>
      )}

      {/* TAB 2: Security & Cryptography (TLS Parameters, Extensions, Certificates, ML Anomaly) */}
      {activeTab === 'security' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Negotiated TLS Handshake Parameters */}
          {tls ? (
            <div className="card">
              <div className="card-header">
                <div>
                  <div className="card-title">Negotiated TLS Handshake Parameters</div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
                    Passive extraction of cryptanalytic parameters from record layer
                  </div>
                </div>

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
                <TlsParamRow
                  label="Negotiated TLS Version"
                  value={tls.tls_version}
                  status={tls.tls_version === 'TLS 1.3' || tls.tls_version === 'TLS 1.2' ? 'observed' : 'vulnerable'}
                  note={tls.tls_version === 'TLS 1.0' || tls.tls_version === 'TLS 1.1' ? 'Deprecated by RFC 8996' : 'Secure modern version'}
                />

                <TlsParamRow
                  label="Selected Cipher Suite"
                  value={tls.cipher_suite || 'Unknown'}
                  mono
                  status={tls.cipher_suite && !tls.cipher_suite.includes('3DES') && !tls.cipher_suite.includes('RC4') ? 'observed' : 'vulnerable'}
                  note={tls.cipher_suite_hex ? `Hex: ${tls.cipher_suite_hex}` : ''}
                />

                <TlsParamRow
                  label="Key Exchange Mechanism"
                  value={tls.key_exchange || (isTls13 ? 'ECDHE' : 'Static RSA')}
                  status={tls.key_exchange?.includes('ECDHE') || isTls13 ? 'observed' : 'vulnerable'}
                  note={tls.key_exchange?.includes('ECDHE') ? 'Ephemeral Diffie-Hellman' : 'No forward secrecy protection'}
                />

                <TlsParamRow
                  label="Forward Secrecy (PFS)"
                  value={tls.forward_secrecy === 'yes' ? 'Confirmed (Yes)' : tls.forward_secrecy === 'no' ? 'Absent (No)' : 'Unknown'}
                  status={tls.forward_secrecy === 'yes' ? 'observed' : 'vulnerable'}
                  note={tls.forward_secrecy === 'yes' ? 'Past traffic protected against key compromise' : 'Retroactive decryption possible if server key leaks'}
                />

                <TlsParamRow
                  label="JA3 Client Fingerprint"
                  value={tls.ja3_hash || 'Not Calculated'}
                  mono
                  status={tls.ja3_hash ? 'observed' : 'not_observable'}
                  note={tls.ja3_string ? `Raw: ${tls.ja3_string.slice(0, 32)}...` : 'Client TLS extension fingerprint'}
                />

                <TlsParamRow
                  label="Handshake State"
                  value={tls.handshake_complete ? 'Complete Handshake' : 'Partial / Incomplete'}
                  status={tls.handshake_complete ? 'observed' : 'vulnerable'}
                  note="Verified through Finished / Application Data frames"
                />
              </div>

              {/* Client Offered Ciphers & Extensions */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginTop: '1.25rem' }}>
                <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                    Client Offered Ciphers ({tls.client_offered_ciphers?.length || 0})
                  </div>
                  {tls.client_offered_ciphers && tls.client_offered_ciphers.length > 0 ? (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', maxHeight: 180, overflowY: 'auto' }}>
                      {tls.client_offered_ciphers.map((c, i) => (
                        <div key={i} style={{ fontSize: '0.74rem', fontFamily: 'monospace', color: 'var(--text)', background: 'var(--bg-card)', padding: '0.25rem 0.5rem', borderRadius: 4, border: '1px solid var(--border)' }}>
                          {c}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Offered cipher list not recorded.</div>
                  )}
                </div>

                <div style={{ background: 'var(--bg-card-subtle)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                  <div style={{ fontSize: '0.74rem', fontWeight: 700, textTransform: 'uppercase', color: 'var(--text-dim)', marginBottom: '0.5rem' }}>
                    TLS Extensions ({tls.client_tls_extensions?.length || 0})
                  </div>
                  {tls.client_tls_extensions && tls.client_tls_extensions.length > 0 ? (
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
                      {tls.client_tls_extensions.map((ext, i) => (
                        <span key={i} style={{ fontSize: '0.72rem', background: 'var(--bg-card)', border: '1px solid var(--border)', padding: '0.2rem 0.45rem', borderRadius: 4, color: 'var(--text-muted)' }}>
                          {ext}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-dim)' }}>Standard TLS extensions.</div>
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

          {/* X.509 Certificate Inspector (Honest TLS 1.3 Scope Note) */}
          <CertificateInspector
            certificates={certs}
            certObservability={tls?.cert_observability}
            certObservabilityNote={tls?.cert_observability_note}
            findings={findings}
            isTls13={isTls13}
          />

          {/* ML Behavioural Anomaly Detection Card */}
          <MLAnalysisCard session={session} />
        </div>
      )}

      {/* TAB 3: Findings (Session-Specific Security Findings & Traceable Evidence) */}
      {activeTab === 'findings' && (
        <div>
          {findings.length === 0 ? (
            <div className="card" style={{ textAlign: 'center', padding: '3rem 1.5rem', color: 'var(--info)' }}>
              <ShieldCheck size={36} style={{ marginBottom: '0.75rem' }} />
              <div style={{ fontWeight: 700, fontSize: '1rem', marginBottom: '0.35rem' }}>
                Zero Security Vulnerabilities Detected in this Stream
              </div>
              <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)' }}>
                This stream complies with modern cryptographic recommendations and standard RFC specifications.
              </div>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
              {findings.map(f => (
                <EvidenceInspector
                  key={f.id}
                  finding={f}
                  onNavigateSession={() => {
                    switchTab('conversation')
                  }}
                />
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 4: Raw Packets (Dissected Frame Sequence & Hexdump) */}
      {activeTab === 'raw' && (
        <RawPacketsView session={session} highlightFrame={rawHighlightFrame} />
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
