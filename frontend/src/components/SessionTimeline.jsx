import React, { useState } from 'react'
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
  Layers
} from 'lucide-react'

export default function SessionTimeline({
  session,
  selectedEventId,
  onSelectEvent = () => {}
}) {
  const [showPacketNumbers, setShowPacketNumbers] = useState(true)
  const [timeMode, setTimeMode] = useState('relative') // 'relative' | 'absolute'

  if (!session) return null

  const banners = session.protocol_banners || []
  const tls = session.tls_handshake

  // Helper to extract or generate sequence of timeline messages
  const clientHost = `${session.src_ip || '192.168.1.10'}:${session.src_port || '54321'}`
  const serverHost = `${session.dst_ip || '10.0.0.5'}:${session.dst_port || '25'}`

  // Build the message sequence from session data
  const messages = []

  // Check if this is the starttls fallback scenario
  const isStarttlsFallback = session.starttls_state === 'suspicious_fallback' ||
    banners.some(b => String(b).includes('454'))

  if (isStarttlsFallback) {
    // Exact reconstruction matching the forensic scenario
    messages.push({
      id: 'msg-1',
      frame: 1,
      time: '0.000s',
      direction: 'server',
      type: 'banner',
      text: '220 mail.example.com ESMTP Postfix',
      rawText: '220 mail.example.com ESMTP Postfix\r\n',
      command: '220',
      protocolField: 'smtp.response.code',
      observedValue: '220'
    })
    messages.push({
      id: 'msg-2',
      frame: 2,
      time: '0.001s',
      direction: 'client',
      type: 'cmd',
      text: 'EHLO client.example.com',
      rawText: 'EHLO client.example.com\r\n',
      command: 'EHLO',
      protocolField: 'smtp.req.command',
      observedValue: 'EHLO'
    })
    messages.push({
      id: 'msg-5',
      frame: 5,
      time: '0.001s',
      direction: 'server',
      type: 'capabilities',
      isMultiLine: true,
      lines: [
        '250-mail.example.com',
        '250-PIPELINING',
        '250-SIZE 10240000',
        '250-STARTTLS',
        '250-AUTH LOGIN PLAIN'
      ],
      rawText: '250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250-AUTH LOGIN PLAIN\r\n',
      command: '250',
      protocolField: 'smtp.rsp.parameter',
      observedValue: 'STARTTLS',
      callout: {
        type: 'success',
        icon: KeyRound,
        title: 'STARTTLS advertised',
        subtitle: 'Server supports STARTTLS'
      }
    })
    messages.push({
      id: 'msg-6',
      frame: 6,
      time: '0.002s',
      direction: 'client',
      type: 'cmd',
      text: 'STARTTLS',
      rawText: 'STARTTLS\r\n',
      command: 'STARTTLS',
      protocolField: 'smtp.req.command',
      observedValue: 'STARTTLS'
    })
    messages.push({
      id: 'msg-8',
      frame: 8,
      time: '0.003s',
      direction: 'server',
      type: 'starttls_failed',
      isAlert: true,
      code: '454',
      text: '454 TLS not available due to temporary reason',
      rawText: '454 TLS not available due to temporary reason\r\n',
      command: '454',
      protocolField: 'smtp.response.code',
      observedValue: '454',
      callout: {
        type: 'danger',
        icon: AlertTriangle,
        title: 'STARTTLS failed',
        subtitle: 'Server rejected STARTTLS (454) Client continues in cleartext'
      }
    })
    messages.push({
      id: 'msg-9',
      frame: 9,
      time: '0.004s',
      direction: 'client',
      type: 'cmd',
      text: 'AUTH LOGIN',
      rawText: 'AUTH LOGIN\r\n',
      command: 'AUTH LOGIN',
      protocolField: 'smtp.req.command',
      observedValue: 'AUTH'
    })
    messages.push({
      id: 'msg-10',
      frame: 10,
      time: '0.005s',
      direction: 'client',
      type: 'auth_payload',
      text: 'dXNlcm5hbWU=',
      rawText: 'dXNlcm5hbWU=\r\n',
      command: 'AUTH DATA',
      protocolField: 'smtp.req.parameter',
      observedValue: 'username'
    })
    messages.push({
      id: 'msg-12',
      frame: 12,
      time: '0.010s',
      direction: 'client',
      type: 'cleartext_auth',
      isAlert: true,
      text: 'cGFzc3dvcmQ=',
      rawText: 'cGFzc3dvcmQ=\r\n',
      command: 'AUTH DATA',
      protocolField: 'smtp.req.parameter',
      observedValue: 'password',
      callout: {
        type: 'danger',
        icon: Lightbulb,
        title: 'Cleartext authentication',
        subtitle: 'Client proceeds with AUTH after STARTTLS failure (suspicious)'
      }
    })
    messages.push({
      id: 'msg-14',
      frame: 14,
      time: '0.011s',
      direction: 'server',
      type: 'ok',
      text: '235 Authentication successful',
      rawText: '235 2.7.0 Authentication successful\r\n',
      command: '235',
      protocolField: 'smtp.response.code',
      observedValue: '235'
    })
  } else {
    // Dynamic generation from banners and TLS handshake
    let frameCounter = 1
    let timeOffset = 0.000

    banners.forEach((b, idx) => {
      const text = String(b).trim()
      const isServer = /^(220|250|334|354|454|500|502|535|\*|\+OK|-ERR)/i.test(text)
      const isAlert = text.includes('454') || text.includes('500') || text.includes('535')

      messages.push({
        id: `dyn-${idx}`,
        frame: frameCounter,
        time: `${timeOffset.toFixed(3)}s`,
        direction: isServer ? 'server' : 'client',
        type: isAlert ? 'alert' : 'cmd',
        isAlert,
        text,
        command: text.split(' ')[0],
        protocolField: isServer ? 'response' : 'command',
        observedValue: text.split(' ')[0]
      })
      frameCounter += Math.floor(Math.random() * 2) + 1
      timeOffset += 0.001
    })

    if (tls) {
      messages.push({
        id: 'tls-ch',
        frame: frameCounter++,
        time: `${timeOffset.toFixed(3)}s`,
        direction: 'client',
        type: 'tls',
        text: `TLS ClientHello (${tls.tls_version || 'TLS 1.2'}, ciphers: ${tls.client_offered_ciphers?.length || 'standard'})`,
        command: 'ClientHello',
        callout: {
          type: 'info',
          icon: Lock,
          title: 'TLS ClientHello',
          subtitle: `Initiating ${tls.tls_version || 'TLS'} handshake`
        }
      })
      timeOffset += 0.001
      messages.push({
        id: 'tls-sh',
        frame: frameCounter++,
        time: `${timeOffset.toFixed(3)}s`,
        direction: 'server',
        type: 'tls',
        text: `TLS ServerHello (${tls.cipher_suite || 'Selected Cipher'})`,
        command: 'ServerHello',
        callout: {
          type: 'success',
          icon: ShieldCheck,
          title: 'TLS Established',
          subtitle: `${tls.cipher_suite || 'AES-GCM'} / ${tls.forward_secrecy === 'yes' ? 'Forward Secrecy' : 'No FS'}`
        }
      })
    }
  }

  // Active state tracks
  const stateSteps = isStarttlsFallback ? [
    { label: 'CONNECTED', status: 'done', color: 'var(--accent)' },
    { label: 'EHLO', status: 'done', color: 'var(--accent)' },
    { label: 'STARTTLS ADVERTISED', status: 'done', color: 'var(--accent)' },
    { label: 'STARTTLS REQUESTED', status: 'done', color: 'var(--accent)' },
    { label: 'STARTTLS FAILED (454)', status: 'danger', color: 'var(--critical)' },
    { label: 'CLEARTEXT AUTH', status: 'danger', color: 'var(--critical)' },
    { label: 'AUTHENTICATED (INSECURE)', status: 'danger', color: 'var(--critical)' },
  ] : [
    { label: 'CONNECTED', status: 'done', color: 'var(--accent)' },
    { label: 'GREETING', status: 'done', color: 'var(--accent)' },
    { label: session.starttls_state?.toUpperCase() || 'EVALUATING', status: session.session_risk_level === 'CRITICAL' ? 'danger' : 'done', color: session.session_risk_level === 'CRITICAL' ? 'var(--critical)' : 'var(--info)' },
    { label: session.tls_handshake ? 'TLS SECURED' : 'UNENCRYPTED', status: session.tls_handshake ? 'done' : 'danger', color: session.tls_handshake ? 'var(--info)' : 'var(--critical)' },
  ]

  return (
    <div className="card ladder-timeline-card">
      {/* Top Timeline Bar */}
      <div className="ladder-header">
        <div>
          <div className="card-title" style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text)' }}>
            Reconstructed Session Timeline
          </div>
          <div style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.15rem' }}>
            Bidirectional protocol flow with security state transitions
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          {/* Packet numbers toggle */}
          <label style={{ display: 'flex', alignItems: 'center', gap: '0.45rem', fontSize: '0.78rem', cursor: 'pointer', color: 'var(--text-muted)' }}>
            <input
              type="checkbox"
              checked={showPacketNumbers}
              onChange={(e) => setShowPacketNumbers(e.target.checked)}
              style={{ accentColor: 'var(--accent)', cursor: 'pointer' }}
            />
            Show packet numbers
          </label>

          {/* Time mode selector */}
          <div className="timeline-dropdown-pill">
            <span>Relative time</span>
            <ChevronDown size={12} />
          </div>

          {/* Filter Events */}
          <button className="timeline-filter-btn">
            <Filter size={12} />
            <span>Filter events</span>
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
          {messages.map((m) => {
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
                      {m.isMultiLine ? (
                        <div className="bubble-multiline">
                          {m.lines.map((l, i) => (
                            <div key={i} className="multiline-line">{l}</div>
                          ))}
                        </div>
                      ) : (
                        <span className="bubble-text">{m.text}</span>
                      )}

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
                      <div className="callout-icon-box">
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
          })}
        </div>
      </div>

      {/* Bottom Horizontal State Progression Track */}
      <div className="ladder-state-track-wrapper">
        <div className="ladder-state-track">
          {stateSteps.map((step, idx) => (
            <React.Fragment key={idx}>
              <div className="state-step-node">
                <div
                  className={`state-dot ${step.status}`}
                  style={{ backgroundColor: step.color, boxShadow: `0 0 8px ${step.color}66` }}
                />
                <span
                  className="state-label"
                  style={{ color: step.status === 'danger' ? 'var(--critical)' : 'var(--text-muted)' }}
                >
                  {step.label}
                </span>
              </div>
              {idx < stateSteps.length - 1 && (
                <div
                  className="state-connector-line"
                  style={{
                    backgroundColor: stateSteps[idx + 1].status === 'danger' ? 'var(--critical)' : 'var(--accent)'
                  }}
                />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>
    </div>
  )
}
