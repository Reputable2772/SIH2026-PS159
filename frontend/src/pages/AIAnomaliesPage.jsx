import React, { useState, useMemo } from 'react';
import { useOutletContext, useNavigate } from 'react-router-dom';
import { Download, ArrowUpRight } from 'lucide-react';
import AnomalyScatterPlot from '../components/AnomalyScatterPlot';
import FooterNote from '../components/FooterNote';
import { AI_ANOMALY_SESSIONS, S017_FEATURE_BREAKDOWN } from '../mockData';

export default function AIAnomaliesPage() {
  const navigate = useNavigate();
  const { activeAnalysis } = useOutletContext();
  const [selectedSessionId, setSelectedSessionId] = useState(null);
  const [filterMode, setFilterMode] = useState('all'); // 'all' | 'anomalous'

  // Extract anomaly sessions from live activeAnalysis or mockData
  const anomalySessions = useMemo(() => {
    if (activeAnalysis?.sessions && activeAnalysis.sessions.length > 0) {
      return activeAnalysis.sessions.map((s, idx) => {
        const id = s.session_id || `S-${String(idx + 1).padStart(3, '0')}`;
        const isAnom = Boolean(s.is_anomalous || (s.anomaly_score !== null && s.anomaly_score > 0.5) || s.findings?.some((f) => f.is_ml_finding || f.category === 'ml_anomaly'));
        const rawScore = s.anomaly_score !== null && s.anomaly_score !== undefined ? s.anomaly_score : (isAnom ? 0.65 : 0.22);
        // Map 0..1 score to -0.30..+0.30 range for the scatter plot
        const plotY = (rawScore - 0.5) * 0.6;
        const plotX = Math.min(16, Math.max(1, Math.round((s.packet_count || 10) / 4)));

        // Extract dimension descriptions
        const dims = [];
        if (s.cleartext_auth_detected) dims.push('cleartext_auth');
        if (s.starttls_state === 'suspicious_fallback') dims.push('suspicious_fallback');
        if (s.tls_handshake?.tls_version?.includes('1.0') || s.tls_handshake?.tls_version?.includes('SSL')) dims.push('deprecated_tls');
        if (s.tls_handshake?.forward_secrecy === 'no') dims.push('no_forward_secrecy');
        if (dims.length === 0) dims.push(isAnom ? 'outlier_feature_vector' : 'baseline_traffic');

        return {
          id,
          rawId: s.session_id,
          protocol: String(s.protocol).replace('ApplicationProtocol.', ''),
          anomalyScore: rawScore.toFixed(4),
          plotY,
          plotX,
          isAnomalous: isAnom,
          dimensions: dims.join(', '),
          packets: s.packet_count || 0,
          features: s.anomaly_features || {},
          raw: s,
        };
      });
    }
    return AI_ANOMALY_SESSIONS.map((s) => ({
      ...s,
      plotY: parseFloat(s.anomalyScore) || 0,
      plotX: 4,
      features: {},
    }));
  }, [activeAnalysis]);

  const activeId = selectedSessionId || anomalySessions.find((s) => s.isAnomalous)?.id || anomalySessions[0]?.id;

  const filteredSessions = filterMode === 'anomalous'
    ? anomalySessions.filter((s) => s.isAnomalous)
    : anomalySessions;

  const selectedSession = anomalySessions.find((s) => s.id === activeId) || anomalySessions[0];

  // Scatter plot points
  const scatterPoints = useMemo(() => {
    return anomalySessions.map((s) => ({
      id: s.id,
      x: s.plotX,
      y: s.plotY,
      isAnomalous: s.isAnomalous,
    }));
  }, [anomalySessions]);

  // Dynamic 16-D feature breakdown for selected session
  const featureBreakdown = useMemo(() => {
    if (selectedSession?.features && Object.keys(selectedSession.features).length > 0) {
      return Object.entries(selectedSession.features).map(([name, val]) => ({
        dimension: name,
        value: typeof val === 'number' ? val.toFixed(3) : String(val),
        flagged: typeof val === 'number' && (val > 0.8 || val === 1.0),
        desc: `Normalized dimension: ${name}`,
      }));
    }
    return S017_FEATURE_BREAKDOWN;
  }, [selectedSession]);

  const handleExportEvidence = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(anomalySessions, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `anomaly_evidence_${activeAnalysis?.analysis_id || 'all'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const anomalousCount = anomalySessions.filter((s) => s.isAnomalous).length;
  const normalCount = anomalySessions.length - anomalousCount;

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">AI anomalies</h1>
          <p className="page-subtitle">
            Session-level outliers from a 16-dimensional Isolation Forest. Investigate unusual behavior, not assumed maliciousness.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={handleExportEvidence}
          id="btn-export-anomalies"
        >
          <Download size={14} />
          <span>Export anomaly evidence</span>
        </button>
      </div>

      {/* Top Row: Scatter Plot & Model Interpretation */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '20px',
          marginBottom: '20px',
          alignItems: 'start',
        }}
      >
        {/* Scatter Plot Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Suspicious TLS session landscape</span>
            <span className="card-meta-tag">
              {anomalySessions.length} SESSIONS · {activeAnalysis?.analysis_id ? 'LIVE MODEL' : 'DEMO DATA'}
            </span>
          </div>

          <AnomalyScatterPlot
            selectedId={activeId}
            onSelectSession={setSelectedSessionId}
            points={scatterPoints}
          />
        </div>

        {/* Model Interpretation Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Model & interpretation</span>
            <span className="card-meta-tag">16-D ISOLATION FOREST</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1 }}>
            <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#EDF3F5', letterSpacing: '-0.01em' }}>
              16-D Isolation Forest
            </h2>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <div className="detail-row">
                <span className="detail-key">Scope</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-sans)', color: '#EDF3F5' }}>
                  {activeAnalysis?.capture?.pcap_filename || 'Selected capture'} / {anomalySessions.length} sessions
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">is_anomalous = true</span>
                <span className="detail-val" style={{ color: '#F3BC68', fontWeight: 600 }}>
                  {anomalousCount} sessions
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">is_anomalous = false</span>
                <span className="detail-val" style={{ color: '#59D9BC', fontWeight: 600 }}>
                  {normalCount} sessions
                </span>
              </div>
            </div>

            <p style={{ fontSize: '12px', color: '#A5B4BF', lineHeight: 1.45 }}>
              Trained on canonical baseline distributions across SMTP, IMAP and POP3. The model isolates sparse feature coordinate subspaces without requiring labeled attack data.
            </p>

            <div
              style={{
                fontSize: '11px',
                color: '#778995',
                marginTop: 'auto',
                paddingTop: '8px',
                borderTop: '1px solid var(--border-subtle)',
              }}
            >
              Evaluates 16 dimensions: cipher suite entropy, key length, TLS extensions, STARTTLS state, timing & cert validity.
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: Scored Sessions Table */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <span className="card-title">Scored sessions</span>
          <span className="card-meta-tag">
            {filteredSessions.length} SESSIONS
          </span>
        </div>

        {/* Filter buttons */}
        <div className="filter-tabs">
          <button
            type="button"
            className={`tab-btn ${filterMode === 'all' ? 'active' : ''}`}
            onClick={() => setFilterMode('all')}
          >
            All sessions · {anomalySessions.length}
          </button>
          <button
            type="button"
            className={`tab-btn ${filterMode === 'anomalous' ? 'active' : ''}`}
            onClick={() => setFilterMode('anomalous')}
          >
            Anomalous only · {anomalousCount}
          </button>
        </div>

        {/* Table */}
        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr>
                <th style={{ width: '90px' }}>Stream ID</th>
                <th style={{ width: '70px' }}>Protocol</th>
                <th style={{ width: '130px' }}>Anomaly score</th>
                <th style={{ width: '120px' }}>Classification</th>
                <th>Key anomalous dimensions</th>
                <th style={{ width: '90px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredSessions.map((s) => {
                const isSelected = s.id === selectedSession?.id;
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
                      <span className={s.protocol === 'SMTP' ? 'badge-smtp' : s.protocol === 'IMAP' ? 'badge-imap' : 'badge-pop3'}>
                        {s.protocol}
                      </span>
                    </td>
                    <td className="mono-cell" style={{ color: s.isAnomalous ? '#F3BC68' : '#A5B4BF', fontWeight: 600 }}>
                      {s.anomalyScore}
                    </td>
                    <td>
                      {s.isAnomalous ? (
                        <span className="badge-high">Anomalous</span>
                      ) : (
                        <span className="badge-minimal">Normal</span>
                      )}
                    </td>
                    <td style={{ color: s.isAnomalous ? '#EDF3F5' : '#778995', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                      {s.dimensions}
                    </td>
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
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Card: Feature Breakdown for Selected Session */}
      {selectedSession && (
        <div className="card" style={{ marginBottom: '20px' }}>
          <div className="card-header">
            <div>
              <span className="card-title">
                Feature breakdown · {selectedSession.id} ({selectedSession.protocol})
              </span>
              <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
                Normalized feature vector evaluated by 16-D Isolation Forest
              </div>
            </div>
            <button
              type="button"
              className="btn-secondary"
              onClick={() => navigate(`/sessions/${selectedSession.rawId || selectedSession.id}`)}
              style={{ fontSize: '11.5px', padding: '4px 10px' }}
            >
              <span>Inspect full conversation</span>
              <ArrowUpRight size={13} />
            </button>
          </div>

          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: '12px',
            }}
          >
            {featureBreakdown.map((item) => (
              <div
                key={item.dimension}
                style={{
                  background: item.flagged ? '#2A2016' : 'var(--bg-surface)',
                  border: `1px solid ${item.flagged ? '#F3BC68' : 'var(--border-default)'}`,
                  borderRadius: 'var(--radius-sm)',
                  padding: '10px 12px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: '10.5px', fontFamily: 'var(--font-mono)', color: '#778995', textTransform: 'uppercase' }}>
                    {item.dimension}
                  </span>
                  {item.flagged && (
                    <span style={{ fontSize: '9px', color: '#F3BC68', fontWeight: 700 }}>OUTLIER</span>
                  )}
                </div>
                <div style={{ fontSize: '14px', fontFamily: 'var(--font-mono)', fontWeight: 600, color: item.flagged ? '#F3BC68' : '#EDF3F5' }}>
                  {item.value}
                </div>
                <div style={{ fontSize: '10.5px', color: '#778995', lineHeight: 1.3 }}>
                  {item.desc}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Footer Note */}
      <FooterNote />
    </div>
  );
}
