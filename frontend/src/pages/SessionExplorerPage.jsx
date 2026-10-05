import React, { useState, useMemo } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { Download, Search, ArrowRight } from 'lucide-react';
import FooterNote from '../components/FooterNote';
import { formatBytes } from '../api';
import { SESSIONS } from '../mockData';

export default function SessionExplorerPage() {
  const navigate = useNavigate();
  const { activeAnalysis } = useOutletContext();
  const [activeTab, setActiveTab] = useState('all'); // 'all' | 'SMTP' | 'IMAP' | 'POP3' | 'Unknown'
  const [searchQuery, setSearchQuery] = useState('');
  const [starttlsFilter, setStarttlsFilter] = useState('all');
  const [tlsFilter] = useState('all');
  const [riskFilter, setRiskFilter] = useState('all');
  const [selectedSessionId, setSelectedSessionId] = useState(null);

  // Normalize sessions from live backend or mock fallback
  const rawSessions = useMemo(() => {
    if (activeAnalysis?.sessions && activeAnalysis.sessions.length > 0) {
      return activeAnalysis.sessions.map((s, idx) => {
        const id = s.session_id || `S-${String(idx + 1).padStart(3, '0')}`;
        const protoRaw = String(s.protocol || 'UNKNOWN').replace('ApplicationProtocol.', '');
        const proto = ['SMTP', 'IMAP', 'POP3'].includes(protoRaw.toUpperCase())
          ? protoRaw.toUpperCase()
          : 'Unknown';
        const starttls = String(s.starttls_state?.value || s.starttls_state || 'no_tls');
        const tlsVer = s.tls_handshake?.tls_version?.value || s.tls_handshake?.tls_version || 'No TLS';
        const risk = (s.session_risk_level || (s.findings?.length > 0 ? 'HIGH' : 'MINIMAL')).toUpperCase();
        const score = s.session_risk_score !== null && s.session_risk_score !== undefined
          ? Math.round(s.session_risk_score)
          : risk === 'CRITICAL' ? 12 : risk === 'HIGH' ? 34 : 95;

        return {
          id,
          rawId: s.session_id,
          protocol: proto,
          srcIp: s.src_ip,
          srcPort: s.src_port,
          dstIp: s.dst_ip,
          dstPort: s.dst_port,
          duration: `${s.duration_seconds ? s.duration_seconds.toFixed(2) : '0.00'}s`,
          packets: s.packet_count || 0,
          bytes: s.bytes_transferred || 0,
          bytesFormatted: formatBytes(s.bytes_transferred || 0),
          starttlsState: starttls,
          tlsVersion: tlsVer,
          cipherSuite: s.tls_handshake?.cipher_suite || 'None',
          forwardSecrecy: s.tls_handshake?.forward_secrecy === 'yes' ? 'Supported' : 'Not supported',
          riskScore: score,
          riskBand: risk,
          findings: s.findings || [],
          raw: s,
        };
      });
    }
    return SESSIONS.map((s) => ({
      ...s,
      bytesFormatted: s.bytes ? formatBytes(s.bytes) : '—',
    }));
  }, [activeAnalysis]);

  const activeId = selectedSessionId || rawSessions[0]?.id;

  const filteredSessions = useMemo(() => {
    return rawSessions.filter((s) => {
      // Tab filter
      if (activeTab !== 'all' && s.protocol !== activeTab) return false;

      // STARTTLS filter
      if (starttlsFilter !== 'all' && !s.starttlsState.includes(starttlsFilter)) return false;

      // TLS filter
      if (tlsFilter !== 'all' && s.tlsVersion !== tlsFilter) return false;

      // Risk filter
      if (riskFilter !== 'all' && s.riskBand !== riskFilter) return false;

      // Search
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = String(s.id).toLowerCase().includes(q);
        const matchSrc = `${s.srcIp}:${s.srcPort}`.toLowerCase().includes(q);
        const matchDst = `${s.dstIp}:${s.dstPort}`.toLowerCase().includes(q);
        if (!matchId && !matchSrc && !matchDst) return false;
      }

      return true;
    });
  }, [rawSessions, activeTab, starttlsFilter, tlsFilter, riskFilter, searchQuery]);

  const selectedSession = rawSessions.find((s) => s.id === activeId) || rawSessions[0];
  const controlSession = rawSessions.find((s) => s.id !== activeId && s.riskBand === 'MINIMAL') || rawSessions[1] || rawSessions[0];

  const handleExportSessions = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rawSessions, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `sessions_export_${activeAnalysis?.analysis_id || 'all'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getStarttlsBadge = (state) => {
    if (state.includes('suspicious_fallback')) {
      return <span style={{ color: '#F3BC68', fontFamily: 'var(--font-mono)' }}>suspicious_fallback</span>;
    }
    if (state.includes('direct_tls')) {
      return <span style={{ color: '#59D9BC', fontFamily: 'var(--font-mono)' }}>direct_tls</span>;
    }
    if (state.includes('negotiated')) {
      return <span style={{ color: '#59D9BC', fontFamily: 'var(--font-mono)' }}>{state}</span>;
    }
    if (state === 'failed') {
      return <span style={{ color: '#F48286', fontFamily: 'var(--font-mono)' }}>failed</span>;
    }
    return <span style={{ color: '#778995', fontFamily: 'var(--font-mono)' }}>{state}</span>;
  };

  const getRiskScorePill = (score, band) => {
    if (score === null || band === 'unavailable') {
      return <span style={{ color: '#778995', fontFamily: 'var(--font-mono)' }}>— / unavailable</span>;
    }
    let color = '#59D9BC';
    if (band === 'CRITICAL') color = '#F48286';
    else if (band === 'HIGH' || band === 'MEDIUM') color = '#F3BC68';

    return (
      <span style={{ color, fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
        {score} / {band}
      </span>
    );
  };

  // KPI counts
  const totalCount = rawSessions.length;
  const negotiatedCount = rawSessions.filter((s) => ['negotiated', 'direct_tls'].includes(s.starttlsState)).length;
  const fallbackCount = rawSessions.filter((s) => s.starttlsState === 'suspicious_fallback').length;
  const plainCount = rawSessions.filter((s) => s.starttlsState === 'no_tls' || s.starttlsState === 'failed').length;

  const smtpCount = rawSessions.filter((s) => s.protocol === 'SMTP').length;
  const imapCount = rawSessions.filter((s) => s.protocol === 'IMAP').length;
  const pop3Count = rawSessions.filter((s) => s.protocol === 'POP3').length;
  const unknownCount = rawSessions.filter((s) => s.protocol === 'Unknown').length;

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Session explorer</h1>
          <p className="page-subtitle">
            {totalCount} reconstructed conversations · automatic SMTP, IMAP and POP3 identification · capture-scoped evidence.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={handleExportSessions}
          id="btn-export-sessions"
        >
          <Download size={14} />
          <span>Export sessions JSON</span>
        </button>
      </div>

      {/* 4 Top Metric Cards */}
      <div className="kpi-row" style={{ gridTemplateColumns: 'repeat(4, 1fr)' }}>
        <div className="kpi-card">
          <span className="kpi-label">Reconstructed TCP streams</span>
          <span className="kpi-value" style={{ color: '#59D9BC' }}>{totalCount}</span>
          <span className="kpi-subtext">
            {totalCount - unknownCount} identified · {unknownCount} unclassified
          </span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">STARTTLS / TLS streams</span>
          <span className="kpi-value" style={{ color: '#59D9BC' }}>{negotiatedCount}</span>
          <span className="kpi-subtext">
            {smtpCount} SMTP · {imapCount} IMAP · {pop3Count} POP3
          </span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Suspicious fallback</span>
          <span className="kpi-value" style={{ color: fallbackCount > 0 ? '#F3BC68' : '#59D9BC' }}>
            {fallbackCount}
          </span>
          <span className="kpi-subtext">
            {fallbackCount > 0 ? 'Review plaintext continuation' : 'No fallback detected'}
          </span>
        </div>
        <div className="kpi-card">
          <span className="kpi-label">Plaintext sessions</span>
          <span className="kpi-value" style={{ color: plainCount > 0 ? '#F3BC68' : '#59D9BC' }}>
            {plainCount}
          </span>
          <span className="kpi-subtext">
            {plainCount > 0 ? 'Cleartext credentials / commands' : 'All sessions encrypted'}
          </span>
        </div>
      </div>

      {/* Reconstructed Sessions Table Card */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <span className="card-title">Reconstructed sessions</span>
          <span className="card-meta-tag">
            {filteredSessions.length} OF {totalCount} SESSIONS
          </span>
        </div>

        {/* Filter Tabs */}
        <div className="filter-tabs">
          <button
            type="button"
            className={`tab-btn ${activeTab === 'all' ? 'active' : ''}`}
            onClick={() => setActiveTab('all')}
          >
            All sessions · {totalCount}
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'SMTP' ? 'active' : ''}`}
            onClick={() => setActiveTab('SMTP')}
          >
            SMTP · {smtpCount}
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'IMAP' ? 'active' : ''}`}
            onClick={() => setActiveTab('IMAP')}
          >
            IMAP · {imapCount}
          </button>
          <button
            type="button"
            className={`tab-btn ${activeTab === 'POP3' ? 'active' : ''}`}
            onClick={() => setActiveTab('POP3')}
          >
            POP3 · {pop3Count}
          </button>
          {unknownCount > 0 && (
            <button
              type="button"
              className={`tab-btn ${activeTab === 'Unknown' ? 'active' : ''}`}
              onClick={() => setActiveTab('Unknown')}
            >
              Unknown · {unknownCount}
            </button>
          )}
        </div>

        {/* Controls Bar */}
        <div className="filter-bar">
          <div className="search-input-wrapper">
            <Search size={14} color="#778995" />
            <input
              type="text"
              placeholder="Search stream ID, IP:port..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
            <select
              className="select-custom"
              value={starttlsFilter}
              onChange={(e) => setStarttlsFilter(e.target.value)}
            >
              <option value="all">STARTTLS: all</option>
              <option value="negotiated">negotiated</option>
              <option value="suspicious_fallback">suspicious_fallback</option>
              <option value="direct_tls">direct_tls</option>
              <option value="no_tls">no_tls</option>
              <option value="failed">failed</option>
            </select>

            <select
              className="select-custom"
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
            >
              <option value="all">Risk: all</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="MINIMAL">Minimal</option>
            </select>
          </div>
        </div>

        {/* Sessions Table */}
        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr>
                <th style={{ width: '90px' }}>Stream ID</th>
                <th style={{ width: '70px' }}>Proto</th>
                <th>Source IP:Port → Destination IP:Port</th>
                <th style={{ width: '75px' }}>Duration</th>
                <th style={{ width: '100px' }}>Packets / Bytes</th>
                <th style={{ width: '140px' }}>STARTTLS state</th>
                <th style={{ width: '90px' }}>TLS Version</th>
                <th style={{ width: '120px' }}>Risk score / Band</th>
                <th style={{ width: '80px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredSessions.length > 0 ? (
                filteredSessions.map((s) => {
                  const isSelected = s.id === selectedSession?.id;
                  const protoClass =
                    s.protocol === 'SMTP'
                      ? 'badge-smtp'
                      : s.protocol === 'IMAP'
                      ? 'badge-imap'
                      : s.protocol === 'POP3'
                      ? 'badge-pop3'
                      : 'badge-unknown';

                  return (
                    <tr
                      key={s.id}
                      className={isSelected ? 'row-selected' : ''}
                      onClick={() => setSelectedSessionId(s.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td className="mono-cell" style={{ color: '#59D9BC', fontWeight: 600 }}>
                        {s.id}
                      </td>
                      <td>
                        <span className={protoClass}>{s.protocol}</span>
                      </td>
                      <td className="mono-cell" style={{ fontSize: '11.5px', color: '#EDF3F5' }}>
                        {s.srcIp}:{s.srcPort} → {s.dstIp}:{s.dstPort}
                      </td>
                      <td className="mono-cell" style={{ color: '#A5B4BF' }}>
                        {s.duration}
                      </td>
                      <td className="mono-cell" style={{ fontSize: '11px', color: '#A5B4BF' }}>
                        {s.packets} pkts · {s.bytesFormatted}
                      </td>
                      <td>{getStarttlsBadge(s.starttlsState)}</td>
                      <td>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '11px', color: '#A5B4BF' }}>
                          {s.tlsVersion}
                        </span>
                      </td>
                      <td>{getRiskScorePill(s.riskScore, s.riskBand)}</td>
                      <td style={{ textAlign: 'right' }}>
                        <button
                          type="button"
                          className="btn-secondary"
                          style={{ padding: '3px 8px', fontSize: '11px' }}
                          onClick={(e) => {
                            e.stopPropagation();
                            navigate(`/sessions/${s.rawId || s.id}`);
                          }}
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={9} style={{ textAlign: 'center', padding: '30px', color: '#778995' }}>
                    No sessions match the selected filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Dual Comparison Cards */}
      {selectedSession && (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '20px',
            marginBottom: '20px',
          }}
        >
          {/* Left: Selected Session Preview */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Selected conversation ({selectedSession.id})</span>
              <button
                type="button"
                className="btn-secondary"
                style={{ padding: '3px 8px', fontSize: '11px' }}
                onClick={() => navigate(`/sessions/${selectedSession.rawId || selectedSession.id}`)}
              >
                <span>Full inspection</span>
                <ArrowRight size={12} />
              </button>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div className="detail-row">
                <span className="detail-key">Coordinates</span>
                <span className="detail-val">
                  {selectedSession.srcIp}:{selectedSession.srcPort} → {selectedSession.dstIp}:{selectedSession.dstPort}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">STARTTLS State</span>
                <span className="detail-val">{selectedSession.starttlsState}</span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Negotiated TLS / Cipher</span>
                <span className="detail-val" style={{ color: '#59D9BC' }}>
                  {selectedSession.tlsVersion} · {selectedSession.cipherSuite}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Risk Evaluation</span>
                <span className="detail-val">
                  {selectedSession.riskScore} / {selectedSession.riskBand} ({selectedSession.findings?.length || 0} findings)
                </span>
              </div>
            </div>
          </div>

          {/* Right: Control or Comparison Session */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Comparative baseline ({controlSession.id})</span>
              <span className="badge-status-done">{controlSession.riskBand}</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
              <div className="detail-row">
                <span className="detail-key">Coordinates</span>
                <span className="detail-val">
                  {controlSession.srcIp}:{controlSession.srcPort} → {controlSession.dstIp}:{controlSession.dstPort}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">STARTTLS State</span>
                <span className="detail-val" style={{ color: '#59D9BC' }}>
                  {controlSession.starttlsState}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Negotiated TLS / Cipher</span>
                <span className="detail-val" style={{ color: '#59D9BC' }}>
                  {controlSession.tlsVersion} · {controlSession.cipherSuite}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Risk Evaluation</span>
                <span className="detail-val" style={{ color: '#59D9BC' }}>
                  {controlSession.riskScore} / {controlSession.riskBand}
                </span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Footer Note */}
      <FooterNote />
    </div>
  );
}
