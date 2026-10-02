import React, { useState } from 'react'
import {
  X,
  ChevronLeft,
  ChevronRight,
  AlertTriangle,
  ShieldAlert,
  Lightbulb,
  ExternalLink,
  FileCode,
  Layers,
  Clock,
  ArrowRight
} from 'lucide-react'

export default function EventDetailsPanel({
  event,
  session,
  onClose = () => {},
  onPrev = () => {},
  onNext = () => {},
  hasPrev = false,
  hasNext = false,
  onViewPacket = () => {}
}) {
  const [activeTab, setActiveTab] = useState('details') // 'details' | 'packet' | 'raw'

  if (!event) return null

  // Correlate finding if this event is linked to a security issue
  const finding = session?.findings?.find(f => {
    if (event.findingId && f.id === event.findingId) return true
    if (event.isAlert) {
      if (event.type === 'starttls_failed' || event.code === '454') {
        return f.category?.toLowerCase().includes('starttls') || f.title?.toLowerCase().includes('starttls')
      }
      if (event.type === 'cleartext_auth') {
        return f.title?.toLowerCase().includes('cleartext') || f.category?.toLowerCase().includes('auth')
      }
    }
    return false
  }) || (event.isAlert ? {
    title: event.type === 'starttls_failed' ? 'STARTTLS Downgrade / Fallback' :
           event.type === 'cleartext_auth' ? 'Unencrypted Cleartext Authentication' : 'Protocol Exposure Warning',
    severity: 'critical',
    description: event.type === 'starttls_failed'
      ? 'STARTTLS was advertised by the server but the TLS handshake failed (454), followed by cleartext authentication. This may indicate an active downgrade attack or a misconfigured server.'
      : 'Authentication credentials were transmitted across the channel in cleartext without established TLS encryption.',
    recommendation: 'Ensure STARTTLS is properly configured and enforced. Clients should not proceed with authentication after STARTTLS failure.'
  } : null)

  const directionText = event.direction === 'client' ? 'Client → Server' : 'Server → Client'
  const sourceIp = event.direction === 'client' ? `${session?.src_ip || '192.168.1.10'}:${session?.src_port || '54321'}` : `${session?.dst_ip || '10.0.0.5'}:${session?.dst_port || '25'}`
  const destIp = event.direction === 'client' ? `${session?.dst_ip || '10.0.0.5'}:${session?.dst_port || '25'}` : `${session?.src_ip || '192.168.1.10'}:${session?.src_port || '54321'}`

  return (
    <div className="event-details-card">
      {/* Header */}
      <div className="event-details-header">
        <div style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text)' }}>
          Event Details
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
          <button
            className="panel-ctrl-btn"
            disabled={!hasPrev}
            onClick={onPrev}
            title="Previous Event"
          >
            <ChevronLeft size={14} />
          </button>
          <button
            className="panel-ctrl-btn"
            disabled={!hasNext}
            onClick={onNext}
            title="Next Event"
          >
            <ChevronRight size={14} />
          </button>
          <button
            className="panel-ctrl-btn"
            onClick={onClose}
            title="Close Panel"
          >
            <X size={14} />
          </button>
        </div>
      </div>

      {/* Subheader Title */}
      <div className="event-details-subhead">
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <div className={`event-subhead-icon ${event.isAlert ? 'critical' : 'info'}`}>
            {event.isAlert ? <AlertTriangle size={15} /> : <FileCode size={15} />}
          </div>
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.88rem', color: 'var(--text)' }}>
              {event.title || event.command || (event.code ? `STARTTLS Failure (${event.code})` : 'Protocol Transmission')}
            </div>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-dim)', fontFamily: 'monospace', marginTop: '0.1rem' }}>
              Packet #{event.packetNumber || event.frame || '8'} · {event.timestamp || '0.0032s'}
            </div>
          </div>
        </div>
      </div>

      {/* Tab Switcher */}
      <div className="event-details-tabs">
        <button
          className={`event-tab-btn ${activeTab === 'details' ? 'active' : ''}`}
          onClick={() => setActiveTab('details')}
        >
          Details
        </button>
        <button
          className={`event-tab-btn ${activeTab === 'packet' ? 'active' : ''}`}
          onClick={() => setActiveTab('packet')}
        >
          Packet
        </button>
        <button
          className={`event-tab-btn ${activeTab === 'raw' ? 'active' : ''}`}
          onClick={() => setActiveTab('raw')}
        >
          Raw Data
        </button>
      </div>

      {/* Tab Content */}
      <div className="event-details-body">
        {activeTab === 'details' && (
          <>
            {/* Key-Value Metadata Table */}
            <div className="event-meta-table">
              <div className="event-meta-row">
                <span className="event-meta-key">Protocol</span>
                <span className="event-meta-val" style={{ color: 'var(--accent)', fontWeight: 600 }}>
                  {session?.protocol?.toUpperCase() || 'SMTP'}
                </span>
              </div>
              <div className="event-meta-row">
                <span className="event-meta-key">Direction</span>
                <span className="event-meta-val">{directionText}</span>
              </div>
              <div className="event-meta-row">
                <span className="event-meta-key">Command / Response</span>
                <span className="event-meta-val" style={{ fontFamily: 'monospace' }}>
                  {event.command || event.code || 'DATA'}
                </span>
              </div>
              <div className="event-meta-row">
                <span className="event-meta-key">Full Message</span>
                <span className="event-meta-val message-block">
                  {event.rawText || event.fullMessage || event.text || '220 Ready'}
                </span>
              </div>
            </div>

            {/* Security Finding Card */}
            {finding && (
              <div className="event-finding-card">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.4rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--critical)', fontWeight: 700, fontSize: '0.78rem' }}>
                    <ShieldAlert size={14} />
                    Security Finding
                  </div>
                  <span className="event-badge-critical">Critical</span>
                </div>
                <div style={{ fontWeight: 600, fontSize: '0.82rem', color: 'var(--text)', marginBottom: '0.25rem' }}>
                  {finding.title}
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                  {finding.description}
                </div>
              </div>
            )}

            {/* Evidence Block */}
            <div className="event-evidence-block">
              <div className="evidence-title">
                <Layers size={13} color="var(--accent)" />
                Evidence
              </div>
              <div className="evidence-grid">
                <div className="evidence-row">
                  <span className="evidence-label">Packet Number</span>
                  <span className="evidence-data">{event.packetNumber || event.frame || '8'}</span>
                </div>
                <div className="evidence-row">
                  <span className="evidence-label">Timestamp</span>
                  <span className="evidence-data">{event.timestamp || '0.0032s'}</span>
                </div>
                <div className="evidence-row">
                  <span className="evidence-label">Source</span>
                  <span className="evidence-data">{sourceIp}</span>
                </div>
                <div className="evidence-row">
                  <span className="evidence-label">Destination</span>
                  <span className="evidence-data">{destIp}</span>
                </div>
                <div className="evidence-row">
                  <span className="evidence-label">Protocol Field</span>
                  <span className="evidence-data code-font">{event.protocolField || 'smtp.response.code'}</span>
                </div>
                <div className="evidence-row">
                  <span className="evidence-label">Observed Value</span>
                  <span className="evidence-data code-font highlight-val">{event.observedValue || event.code || '454'}</span>
                </div>
              </div>

              <button
                className="btn-link"
                style={{ marginTop: '0.65rem', fontSize: '0.75rem', display: 'flex', alignItems: 'center', gap: '0.25rem', color: 'var(--accent)', background: 'transparent', border: 'none', cursor: 'pointer', padding: 0 }}
                onClick={() => onViewPacket(event.packetNumber || event.frame || 1)}
              >
                View in Packet Details →
              </button>
            </div>

            {/* Recommendation Callout */}
            {finding?.recommendation && (
              <div className="event-recommendation-card">
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--medium)', fontWeight: 700, fontSize: '0.78rem', marginBottom: '0.25rem' }}>
                  <Lightbulb size={14} />
                  Recommendation
                </div>
                <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', lineHeight: 1.45 }}>
                  {finding.recommendation}
                </div>
              </div>
            )}
          </>
        )}

        {activeTab === 'packet' && (
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
            <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: '0.5rem' }}>
              Frame {event.packetNumber || 8}: Layer Dissection
            </div>
            <pre className="code-block" style={{ padding: '0.75rem', fontSize: '0.72rem', background: 'var(--bg-base)' }}>
{`Frame ${event.packetNumber || 8}: ${event.length || 78} bytes on wire
Ethernet II, Src: 02:00:00:00:00:02, Dst: 02:00:00:00:00:01
Internet Protocol Version 4, Src: ${sourceIp.split(':')[0]}, Dst: ${destIp.split(':')[0]}
Transmission Control Protocol, Src Port: ${sourceIp.split(':')[1]}, Dst Port: ${destIp.split(':')[1]}
Simple Mail Transfer Protocol
    Response: ${event.rawText || event.fullMessage || '454 TLS not available'}`}
            </pre>
          </div>
        )}

        {activeTab === 'raw' && (
          <div style={{ fontSize: '0.76rem', color: 'var(--text-muted)' }}>
            <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: '0.5rem' }}>
              Hexdump & ASCII Payload
            </div>
            <pre className="code-block" style={{ padding: '0.75rem', fontSize: '0.7rem', background: 'var(--bg-base)', fontFamily: 'monospace' }}>
{`0000   02 00 00 00 00 01 02 00 00 00 00 02 08 00 45 00  ..............E.
0010   00 50 1a 2b 40 00 40 06 a1 2c c0 a8 01 0a 0a 00  .P.+@.@..,......
0020   00 05 d4 31 00 19 00 00 03 e9 00 00 07 d1 80 18  ...1............
0030   01 f5 b4 1e 00 00 01 01 08 0a 00 00 00 03 00 00  ................
0040   34 35 34 20 54 4c 53 20 6e 6f 74 20 61 76 61 69  454 TLS not avai
0050   6c 61 62 6c 65 0d 0a                              lable..`}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}
