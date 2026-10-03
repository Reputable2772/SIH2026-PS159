import React, { useState, useMemo } from 'react'
import {
  KeyRound,
  AlertTriangle,
  Lightbulb,
  ShieldCheck,
  ShieldAlert,
  ChevronDown,
  Filter,
  CheckCircle2,
  Lock,
  Unlock,
  Layers,
  Sidebar
} from 'lucide-react'

export default function SessionTimeline({
  session,
  selectedEventId,
  onSelectEvent = () => {},
  isEvidenceOpen = true,
  onToggleEvidence = () => {}
}) {
  const [showPacketNumbers, setShowPacketNumbers] = useState(true)
  const [alertsOnly, setAlertsOnly] = useState(false)

  if (!session) return null

  const banners = session.protocol_banners || []
  const tls = session.tls_handshake
  const isStarttlsFallback = session.starttls_state === 'suspicious_fallback' ||
    banners.some(b => String(b).includes('454') || String(b).includes('4.7.0'))
  const proto = (session.protocol || 'SMTP').toUpperCase()

  const clientHost = `${session.src_ip || '10.0.0.1'}:${session.src_port || '54321'}`
  const serverHost = `${session.dst_ip || '10.0.0.2'}:${session.dst_port || '25'}`

  // Dynamically reconstruct messages from actual session data
  const messages = useMemo(() => {
    const list = []
    let frameCounter = 1
    const totalDuration = session.duration_seconds || 0.05
    let timeStep = 0.000

    // Helper to calculate realistic frame time
    const getTimeStr = (idx, total) => {
      const t = total > 0 ? (idx / Math.max(total, 1)) * totalDuration : idx * 0.001
      return `${t.toFixed(3)}s`
    }

    if (banners.length > 0) {
      banners.forEach((b, idx) => {
        const text = String(b).trim()
        if (!text) return

        let direction = 'client'
        let type = 'cmd'
        let isAlert = false
        let callout = null
        let command = text.split(' ')[0]
        let protocolField = 'protocol.command'
        let observedValue = command

        // Check if server response based on protocol
        const isServerResponse =
          /^(220|250|334|354|454|4\.7\.0|500|502|535|235)/i.test(text) ||
          text.startsWith('250-') ||
          text.startsWith('* OK') ||
          text.startsWith('+OK') ||
          text.startsWith('-ERR') ||
          /^[a-zA-Z0-9]+\s+(OK|NO|BAD)/i.test(text) ||
          text.includes('ESMTP') ||
          text.includes('Ready to start TLS')

        if (isServerResponse) {
          direction = 'server'
          type = 'response'
          protocolField = 'protocol.response'
        }

        // STARTTLS Advertised
        if (text.includes('STARTTLS') && isServerResponse) {
          type = 'capabilities'
          protocolField = 'smtp.rsp.parameter'
          observedValue = 'STARTTLS'
          callout = {
            type: 'success',
            icon: KeyRound,
            title: 'STARTTLS Advertised',
            subtitle: 'Server announced opportunistic TLS capability'
          }
        }
        // STARTTLS Requested
        else if (/^STARTTLS/i.test(text) || /^STAR$/i.test(text) || /^STLS$/i.test(text)) {
          type = 'cmd'
          protocolField = 'smtp.req.command'
          observedValue = text
          callout = {
            type: 'info',
            icon: Lock,
            title: 'STARTTLS Requested',
            subtitle: 'Client initiated upgrade to TLS encryption'
          }
        }
        // 454 / Temporary failure / STARTTLS Rejected
        else if (text.includes('454') || text.includes('4.7.0') || /tls not available/i.test(text)) {
          type = 'starttls_failed'
          isAlert = true
          protocolField = 'smtp.response.code'
          observedValue = '454'
          callout = {
            type: 'danger',
            icon: AlertTriangle,
            title: 'STARTTLS Rejected (454 / 4.7.0)',
            subtitle: 'Server refused TLS; client continued unencrypted (downgrade)'
          }
        }
        // Cleartext Authentication
        else if (
          text.startsWith('AUTH') ||
          /^[a-zA-Z0-9+/=]{8,}$/.test(text) ||
          text.includes('LOGIN ') ||
          (session.cleartext_auth_detected && (text.includes('VXNlcm5hbWU') || text.includes('cGFzc3dvcmQ') || text.includes('UltraSecret')))
        ) {
          type = 'cleartext_auth'
          isAlert = true
          protocolField = 'smtp.auth.credentials'
          observedValue = text.length > 24 ? `${text.slice(0, 20)}...` : text
          callout = {
            type: 'danger',
            icon: Lightbulb,
            title: 'Cleartext Authentication Exposed',
            subtitle: 'Credentials transmitted across unencrypted transport'
          }
        }
        // Authentication Accepted
        else if (text.startsWith('235') || text.includes('Logged in') || text.includes('Authentication successful')) {
          type = 'ok'
          protocolField = 'smtp.response.code'
          observedValue = '235'
          callout = {
            type: 'success',
            icon: CheckCircle2,
            title: 'Authentication Succeeded',
            subtitle: 'Server authenticated the client session'
          }
        }
        // Protocol Syntax Error / Anomaly
        else if (/^(500|501|502|503|504|535|-ERR)/i.test(text)) {
          type = 'error'
          isAlert = true
          protocolField = 'protocol.error'
          observedValue = text.split(' ')[0]
          callout = {
            type: 'danger',
            icon: AlertTriangle,
            title: `Protocol Error (${observedValue})`,
            subtitle: text
          }
        }

        // Frame number correlation
        let frameNum = frameCounter++
        if (text.includes('STARTTLS') && isServerResponse && session.starttls_advertised_pkt) {
          frameNum = session.starttls_advertised_pkt
        } else if ((text.startsWith('STARTTLS') || text === 'STAR') && session.starttls_requested_pkt) {
          frameNum = session.starttls_requested_pkt
        }

        list.push({
          id: `msg-${idx + 1}`,
          frame: frameNum,
          packetNumber: frameNum,
          time: getTimeStr(idx, banners.length),
          direction,
          type,
          isAlert,
          text,
          rawText: `${text}\r\n`,
          command,
          protocolField,
          observedValue,
          callout
        })
      })

      // Insert TLS records if TLS was established
      if (tls) {
        const chFrame = tls.client_hello_pkt || frameCounter++
        list.push({
          id: 'tls-client-hello',
          frame: chFrame,
          packetNumber: chFrame,
          time: getTimeStr(banners.length + 1, banners.length + 3),
          direction: 'client',
          type: 'tls',
          command: 'ClientHello',
          text: `TLS ClientHello (${tls.tls_version || 'TLS 1.2'}, ciphers: ${tls.client_offered_ciphers?.length || 'standard'})`,
          rawText: `TLSv1.2 Record Layer: Handshake Protocol: Client Hello\r\n`,
          protocolField: 'tls.handshake.type',
          observedValue: '1 (ClientHello)',
          callout: {
            type: 'info',
            icon: Lock,
            title: 'TLS ClientHello',
            subtitle: `Negotiating ${tls.tls_version || 'TLS'} parameters`
          }
        })

        const shFrame = tls.server_hello_pkt || frameCounter++
        list.push({
          id: 'tls-server-hello',
          frame: shFrame,
          packetNumber: shFrame,
          time: getTimeStr(banners.length + 2, banners.length + 3),
          direction: 'server',
          type: 'tls',
          command: 'ServerHello',
          text: `TLS ServerHello (${tls.cipher_suite || 'Selected Cipher'})`,
          rawText: `TLSv1.2 Record Layer: Handshake Protocol: Server Hello\r\n`,
          protocolField: 'tls.handshake.ciphersuite',
          observedValue: tls.cipher_suite || 'Standard',
          callout: {
            type: 'success',
            icon: ShieldCheck,
            title: 'TLS Established',
            subtitle: `${tls.cipher_suite || 'AES-GCM'} · ${tls.forward_secrecy === 'yes' ? 'PFS Active' : 'No PFS'}`
          }
        })
      }
    } else {
      // Fallback minimal sequence if no banners recorded
      list.push({
        id: 'msg-1',
        frame: 1,
        packetNumber: 1,
        time: '0.000s',
        direction: 'server',
        type: 'banner',
        text: `TCP Connection Established (${proto})`,
        rawText: `TCP Handshake Complete\r\n`,
        command: 'CONNECT',
        protocolField: 'tcp.flags',
        observedValue: 'SYN-ACK'
      })

      if (tls) {
        list.push({
          id: 'msg-tls',
          frame: 4,
          packetNumber: 4,
          time: '0.002s',
          direction: 'client',
          type: 'tls',
          text: `Direct TLS Handshake (${tls.tls_version})`,
          command: 'TLS',
          protocolField: 'tls.handshake.version',
          observedValue: tls.tls_version,
          callout: {
            type: 'success',
            icon: ShieldCheck,
            title: 'Encrypted Channel',
            subtitle: `${tls.cipher_suite || 'TLS'} negotiated on port ${session.dst_port}`
          }
        })
      }
    }

    return list
  }, [session, banners, tls])

  // Filter if alerts only
  const displayMessages = alertsOnly ? messages.filter(m => m.isAlert) : messages

  return (
    <div className="card ladder-timeline-card">
      {/* Top Timeline Bar */}
      <div className="ladder-header">
        <div>
          <div className="card-title" style={{ fontSize: '0.96rem', fontWeight: 700, color: 'var(--text)' }}>
            Reconstructed Protocol Conversation
          </div>
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            Bidirectional message ladder · Click any event to inspect forensic evidence
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem', flexWrap: 'wrap' }}>
          {/* Packet numbers toggle */}
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.76rem', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <input
              type="checkbox"
              checked={showPacketNumbers}
              onChange={(e) => setShowPacketNumbers(e.target.checked)}
              style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
            />
            Frame numbers
          </label>

          {/* Filter alerts button */}
          <button
            className={`timeline-filter-btn ${alertsOnly ? 'active' : ''}`}
            onClick={() => setAlertsOnly(!alertsOnly)}
            style={alertsOnly ? { background: 'var(--critical-bg)', color: 'var(--critical)', borderColor: 'var(--critical-border)' } : {}}
          >
            <Filter size={12} />
            <span>{alertsOnly ? 'Showing Alerts Only' : 'All Events'}</span>
          </button>

          {/* Toggle Right Inspector */}
          <button
            className="timeline-filter-btn"
            onClick={onToggleEvidence}
            title={isEvidenceOpen ? 'Hide Evidence Drawer' : 'Open Evidence Drawer'}
          >
            <Sidebar size={12} />
            <span>{isEvidenceOpen ? 'Hide Inspector' : 'Show Inspector'}</span>
          </button>
        </div>
      </div>

      {/* Sequence Lifelines Headers */}
      <div className="ladder-lifelines-header">
        <div className="lifeline-node-col client-col">
          <div className="lifeline-node-dot" />
          <div className="lifeline-title">
            Client <span className="lifeline-ip">({clientHost})</span>
          </div>
        </div>
        <div className="lifeline-node-col server-col">
          <div className="lifeline-node-dot" />
          <div className="lifeline-title">
            Server <span className="lifeline-ip">({serverHost})</span>
          </div>
        </div>
      </div>

      {/* The Diagram Body with Lifeline vertical rails */}
      <div className="ladder-diagram-canvas">
        {/* Continuous Lifeline Rails */}
        <div className="lifeline-rail client-rail" />
        <div className="lifeline-rail server-rail" />

        {/* Message Rows */}
        <div className="ladder-rows-container">
          {displayMessages.length === 0 ? (
            <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)', fontSize: '0.8rem' }}>
              No alert events found in this session.
            </div>
          ) : (
            displayMessages.map((m) => {
              const isSelected = selectedEventId === m.id
              const isClient = m.direction === 'client'
              const CalloutIcon = m.callout?.icon

              return (
                <div
                  key={m.id}
                  className={`ladder-row ${isSelected ? 'row-selected' : ''}`}
                  onClick={() => onSelectEvent(m)}
                >
                  {/* Timestamp */}
                  <div className="ladder-timestamp">
                    {m.time}
                  </div>

                  {/* Arrow & Message Zone */}
                  <div className="ladder-arrow-zone">
                    {/* Lifeline intersection dot */}
                    <div className={`rail-dot ${isClient ? 'left-dot' : 'right-dot'} ${m.isAlert ? 'dot-alert' : ''}`} />

                    {/* Horizontal Arrow Line */}
                    <div className={`arrow-line ${isClient ? 'dir-c2s' : 'dir-s2c'} ${m.isAlert ? 'arrow-alert' : ''}`}>
                      {/* Arrowhead */}
                      <div className={`arrow-head ${isClient ? 'head-right' : 'head-left'} ${m.isAlert ? 'head-alert' : ''}`} />

                      {/* Message Bubble */}
                      <div className={`ladder-bubble ${m.type} ${m.isAlert ? 'bubble-alert' : ''} ${isSelected ? 'bubble-selected' : ''}`}>
                        <span className="bubble-text" style={{ wordBreak: 'break-word' }}>{m.text}</span>

                        {showPacketNumbers && (
                          <span className={`packet-badge ${m.isAlert ? 'badge-alert' : ''}`}>
                            #{m.frame}
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Other side intersection dot */}
                    <div className={`rail-dot ${isClient ? 'right-dot' : 'left-dot'} ${m.isAlert ? 'dot-alert' : ''}`} />
                  </div>

                  {/* Side Callout Annotation Zone */}
                  <div className="ladder-callout-zone">
                    {m.callout && (
                      <div className={`ladder-callout-card callout-${m.callout.type}`}>
                        <div className="callout-icon-box" style={{ flexShrink: 0, marginTop: 1 }}>
                          <CalloutIcon size={14} />
                        </div>
                        <div className="callout-text-box">
                          <div className="callout-title">{m.callout.title}</div>
                          <div className="callout-desc">{m.callout.subtitle}</div>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )
            })
          )}
        </div>
      </div>
    </div>
  )
}
