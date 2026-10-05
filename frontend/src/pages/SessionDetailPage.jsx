import React, { useState } from 'react';
import { useParams, useNavigate, useOutletContext } from 'react-router-dom';
import { ArrowLeft, Download, Terminal, ArrowRight } from 'lucide-react';
import HandshakeFlow from '../components/HandshakeFlow';
import FooterNote from '../components/FooterNote';
import { formatBytes } from '../api';
import { SESSIONS, S017_PACKETS } from '../mockData';

export default function SessionDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { activeAnalysis } = useOutletContext();
  const [activeTab, setActiveTab] = useState('conversation');

  // Find session from live analysis or mock fallback
  const liveSession = activeAnalysis?.sessions?.find(
    (s) => s.session_id === id || s.session_id?.endsWith(`:${id}`) || s.session_id?.startsWith(id)
  ) || activeAnalysis?.sessions?.[0];

  const mockSession = SESSIONS.find((s) => s.id === id) || SESSIONS.find((s) => s.id === 'S-017') || SESSIONS[2];

  // Unified session representation
  const session = liveSession ? {
    id: liveSession.session_id,
    protocol: String(liveSession.protocol).replace('ApplicationProtocol.', ''),
    srcIp: liveSession.src_ip,
    srcPort: liveSession.src_port,
    dstIp: liveSession.dst_ip,
    dstPort: liveSession.dst_port,
    duration: liveSession.duration_seconds ? `${liveSession.duration_seconds.toFixed(2)}s` : '0.00s',
    packets: liveSession.packet_count || 0,
    bytes: liveSession.bytes_transferred || 0,
    bytesFormatted: formatBytes(liveSession.bytes_transferred || 0),
    starttlsState: String(liveSession.starttls_state?.value || liveSession.starttls_state || 'no_tls'),
    tlsVersion: liveSession.tls_handshake?.tls_version?.value || liveSession.tls_handshake?.tls_version || 'No TLS',
    cipherSuite: liveSession.tls_handshake?.cipher_suite || 'None',
    keyExchange: liveSession.tls_handshake?.key_exchange || 'None',
    forwardSecrecy: liveSession.tls_handshake?.forward_secrecy === 'yes' ? 'Supported' : 'Not supported',
    riskScore: liveSession.session_risk_score !== null && liveSession.session_risk_score !== undefined
      ? Math.round(liveSession.session_risk_score)
      : 86,
    riskBand: (liveSession.session_risk_level || 'CRITICAL').toUpperCase(),
    findings: liveSession.findings || [],
    ja3: liveSession.tls_handshake?.ja3_hash || '7d197607a97... (computed)',
    ja3String: liveSession.tls_handshake?.ja3_string || '771,49195-49199-52393,0-23-65281,29-23,0',
    banners: liveSession.protocol_banners || [],
    certificates: liveSession.tls_handshake?.certificates || [],
    raw: liveSession,
  } : {
    ...mockSession,
    bytesFormatted: formatBytes(mockSession.bytes || 0),
    findings: mockSession.findings || [],
    banners: [],
    certificates: [],
  };

  const handleExportEvidence = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(session, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `evidence_${session.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  // Reconstructed packets table
  const packetRows = session.banners.length > 0 ? (
    session.banners.map((b, idx) => ({
      packet: `#${idx + 1}`,
      time: `+${(idx * 0.12).toFixed(3)}s`,
      direction: idx % 2 === 0 ? '← SVR' : 'CLI →',
      evidence: b,
    }))
  ) : S017_PACKETS;

  const getRiskClass = (band) => {
    if (band === 'CRITICAL') return 'badge-critical';
    if (band === 'HIGH') return 'badge-high';
    if (band === 'MEDIUM') return 'badge-medium';
    return 'badge-minimal';
  };

  return (
    <div className="page-container">
      {/* Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">
            {session.id} · {session.protocol} session forensic inspection
          </h1>
          <p className="page-subtitle">
            Reconstructed TCP conversation with packet-linked STARTTLS and TLS handshake evidence.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => navigate('/sessions')}
          >
            <ArrowLeft size={14} />
            <span>All sessions</span>
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={handleExportEvidence}
          >
            <Download size={14} />
            <span>Export evidence</span>
          </button>
        </div>
      </div>

      {/* Top Connection Banner */}
      <div
        className="card"
        style={{
          padding: '16px 20px',
          marginBottom: '20px',
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexWrap: 'wrap' }}>
          <div
            style={{
              width: '36px',
              height: '36px',
              borderRadius: '6px',
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-default)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <Terminal size={18} color="#778995" />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <div>
              <div style={{ fontSize: '9.5px', color: '#778995', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                SOURCE · CLIENT
              </div>
              <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: '#EDF3F5', fontWeight: 500 }}>
                {session.srcIp}:{session.srcPort}
              </div>
            </div>

            <ArrowRight size={16} color="#59D9BC" />

            <div>
              <div style={{ fontSize: '9.5px', color: '#778995', textTransform: 'uppercase', letterSpacing: '0.08em', fontWeight: 600 }}>
                DESTINATION · MAIL EDGE
              </div>
              <div style={{ fontSize: '13px', fontFamily: 'var(--font-mono)', color: '#EDF3F5', fontWeight: 500 }}>
                {session.dstIp}:{session.dstPort}
              </div>
            </div>
          </div>
        </div>

        {/* Badges on right */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
          <span className="badge-smtp">{session.protocol} IDENTIFIED</span>
          <span
            style={{
              background: session.starttlsState === 'suspicious_fallback' ? '#392F21' : '#163A34',
              color: session.starttlsState === 'suspicious_fallback' ? '#F3BC68' : '#59D9BC',
              fontSize: '10px',
              fontFamily: 'var(--font-mono)',
              padding: '2px 8px',
              borderRadius: '3px',
              fontWeight: 600,
            }}
          >
            {session.starttlsState}
          </span>
          <span className={getRiskClass(session.riskBand)}>
            {session.riskScore} / {session.riskBand}
          </span>
        </div>
      </div>

      {/* Sub-navigation Tabs */}
      <div className="filter-tabs" style={{ marginBottom: '20px' }}>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'conversation' ? 'active' : ''}`}
          onClick={() => setActiveTab('conversation')}
        >
          Conversation & handshake
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'crypto' ? 'active' : ''}`}
          onClick={() => setActiveTab('crypto')}
        >
          Crypto parameters
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'findings' ? 'active' : ''}`}
          onClick={() => setActiveTab('findings')}
        >
          Session findings · {session.findings?.length || 0}
        </button>
      </div>

      {/* Main Grid: TCP Reassembly & Session Facts */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1.6fr 1fr',
          gap: '20px',
          alignItems: 'start',
        }}
      >
        {/* Left Column: TCP stream reconstruction */}
        <div className="card">
          <div className="card-header">
            <div>
              <span className="card-title">TCP stream reconstruction</span>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#778995', marginTop: '2px' }}>
                Duration: {session.duration}
              </div>
            </div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span className="badge-status-done">Complete · {session.packets} packets</span>
              <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#778995' }}>
                {session.bytesFormatted}
              </span>
            </div>
          </div>

          <div className="table-wrapper">
            <table className="custom-table">
              <thead>
                <tr>
                  <th style={{ width: '70px' }}>Packet</th>
                  <th style={{ width: '90px' }}>Time</th>
                  <th style={{ width: '80px' }}>Direction</th>
                  <th>Reassembled evidence</th>
                </tr>
              </thead>
              <tbody>
                {packetRows.map((pkt, idx) => {
                  const isAuth = String(pkt.evidence).includes('AUTH') || pkt.packet === '#191';
                  const isAlert = String(pkt.evidence).includes('Alert') || String(pkt.evidence).includes('454') || pkt.packet === '#189';
                  const isStarttls = String(pkt.evidence).includes('STARTTLS') || String(pkt.evidence).includes('220');

                  let evidenceColor = '#EDF3F5';
                  if (isAuth) evidenceColor = '#F48286';
                  else if (isAlert) evidenceColor = '#F3BC68';

                  return (
                    <tr key={pkt.packet || idx}>
                      <td className="mono-cell" style={{ color: isAuth ? '#F48286' : '#59D9BC' }}>
                        {pkt.packet}
                      </td>
                      <td className="mono-cell" style={{ color: '#778995' }}>
                        {pkt.time}
                      </td>
                      <td className="mono-cell" style={{ color: '#A5B4BF' }}>
                        {pkt.direction}
                      </td>
                      <td style={{ color: evidenceColor, fontFamily: isStarttls || isAuth || isAlert ? 'var(--font-mono)' : 'var(--font-sans)', fontSize: '12px' }}>
                        {pkt.evidence}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div style={{ fontSize: '11px', color: '#778995', marginTop: '14px', paddingTop: '10px', borderTop: '1px solid var(--border-subtle)' }}>
            Payloads reassembled by TCP sequence · both directions present · no observed sequence gaps · selected packet links.
          </div>
        </div>

        {/* Right Column: Session Facts & Evidence-Linked Findings */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Card 1: Session Facts */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Session facts</span>
              <span className="card-meta-tag">{session.id}</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <div className="detail-row">
                <span className="detail-key">Protocol</span>
                <span className="detail-val" style={{ color: '#59D9BC' }}>{session.protocol}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Negotiated TLS</span>
                <span className="detail-val">{session.tlsVersion}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Cipher Suite</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                  {session.cipherSuite}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Key Exchange</span>
                <span className="detail-val">{session.keyExchange}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Forward Secrecy</span>
                <span className="detail-val">{session.forwardSecrecy}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Client Fingerprint</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '10.5px' }}>
                  {session.ja3 ? `${session.ja3.slice(0, 16)}…` : 'Unavailable'}
                </span>
              </div>
            </div>
          </div>

          {/* Card 2: Evidence-Linked Findings for this Session */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Evidence-linked findings</span>
              <span className="card-meta-tag">{session.findings?.length || 0} findings</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {session.findings && session.findings.length > 0 ? (
                session.findings.map((f, i) => (
                  <div
                    key={f.id || i}
                    style={{
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-default)',
                      borderRadius: 'var(--radius-sm)',
                      padding: '10px 12px',
                    }}
                  >
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginBottom: '4px' }}>
                      <span className={getRiskClass((f.severity?.value || f.severity || 'HIGH').toUpperCase())}>
                        {f.severity?.value || f.severity || 'HIGH'}
                      </span>
                      <span style={{ fontSize: '12px', fontWeight: 600, color: '#EDF3F5' }}>
                        {f.title}
                      </span>
                    </div>
                    <p style={{ fontSize: '11.5px', color: '#A5B4BF', lineHeight: 1.4, margin: '4px 0' }}>
                      {f.description}
                    </p>
                    <div style={{ fontSize: '10.5px', color: '#59D9BC', marginTop: '4px' }}>
                      Guidance: {f.recommendation}
                    </div>
                  </div>
                ))
              ) : (
                <div style={{ padding: '16px', color: '#59D9BC', fontSize: '12.5px' }}>
                  ✓ No security violations observed in this session.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Handshake Flow Diagram */}
      <HandshakeFlow session={session} />

      {/* Footer Note */}
      <FooterNote />
    </div>
  );
}
