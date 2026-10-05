import React from 'react';
import { Link, useOutletContext } from 'react-router-dom';
import { Download, ArrowRight, Info } from 'lucide-react';
import DonutGauge from '../components/DonutGauge';
import ActivityChart from '../components/ActivityChart';
import FooterNote from '../components/FooterNote';
import { formatBytes } from '../api';
import {
  TLS_DISTRIBUTION,
  CIPHER_SUITES,
  FORWARD_SECRECY_STATS,
  PROTOCOL_STATS,
} from '../mockData';

export default function OverviewPage() {
  const { activeAnalysis, selectedCapture } = useOutletContext();
  const analysis = activeAnalysis;
  const cap = selectedCapture;

  const score = Math.round(analysis?.risk_score?.score ?? 72);
  const level = (analysis?.risk_score?.level || 'HIGH').toUpperCase();
  const sessionsCount = analysis?.sessions?.length || 48;
  const tlsCount = analysis?.protocol_summary?.tls_sessions ?? 40;
  const plainCount = analysis?.protocol_summary?.plaintext_sessions ?? 8;
  const totalSessionCount = tlsCount + plainCount > 0 ? (tlsCount + plainCount) : sessionsCount;
  const encryptedPct = totalSessionCount > 0 ? `${((tlsCount / totalSessionCount) * 100).toFixed(1)}%` : '83.3%';

  // Top findings for "Investigate first" card
  const topFindings = analysis?.all_findings?.slice(0, 3) || [];

  // Negotiated TLS distribution
  const tlsVersionsData = React.useMemo(() => {
    if (analysis?.protocol_summary?.tls_versions && Object.keys(analysis.protocol_summary.tls_versions).length > 0) {
      const versions = analysis.protocol_summary.tls_versions;
      const total = Object.values(versions).reduce((a, b) => a + b, 0) || 1;
      const colors = {
        'TLS 1.3': '#59D9BC',
        'TLS 1.2': '#4BA3E3',
        'TLS 1.1': '#F3BC68',
        'TLS 1.0': '#F3BC68',
        'SSL 3.0': '#F48286',
        'SSL 2.0': '#F48286',
        'Unknown': '#778995',
      };
      return Object.entries(versions).map(([ver, count]) => ({
        version: ver,
        count,
        pct: (count / total) * 100,
        color: colors[ver] || '#778995',
      }));
    }
    return TLS_DISTRIBUTION;
  }, [analysis]);

  // Cipher suites distribution
  const cipherSuitesData = React.useMemo(() => {
    if (analysis?.protocol_summary?.cipher_suites && Object.keys(analysis.protocol_summary.cipher_suites).length > 0) {
      const ciphers = analysis.protocol_summary.cipher_suites;
      const maxCount = Math.max(...Object.values(ciphers), 1);
      const palette = ['#59D9BC', '#4BA3E3', '#F3BC68', '#F48286', '#8892a4'];
      return Object.entries(ciphers).map(([name, count], i) => ({
        name,
        count,
        max: maxCount,
        color: palette[i % palette.length],
      }));
    }
    return CIPHER_SUITES;
  }, [analysis]);

  // Forward Secrecy stats
  const fsData = React.useMemo(() => {
    if (analysis?.protocol_summary) {
      const ps = analysis.protocol_summary;
      const total = totalSessionCount || 1;
      return [
        {
          label: 'Forward Secrecy confirmed',
          count: ps.forward_secrecy_yes ?? 37,
          pct: ((ps.forward_secrecy_yes ?? 37) / total) * 100,
          color: '#59D9BC',
        },
        {
          label: 'Forward Secrecy absent',
          count: ps.forward_secrecy_no ?? 3,
          pct: ((ps.forward_secrecy_no ?? 3) / total) * 100,
          color: '#F3BC68',
        },
        {
          label: 'Unknown / Not negotiated',
          count: ps.forward_secrecy_unknown ?? 8,
          pct: ((ps.forward_secrecy_unknown ?? 8) / total) * 100,
          color: '#778995',
        },
      ];
    }
    return FORWARD_SECRECY_STATS;
  }, [analysis, totalSessionCount]);

  // Protocol identification table
  const protocolData = React.useMemo(() => {
    if (analysis?.protocol_summary) {
      const ps = analysis.protocol_summary;
      return [
        {
          protocol: 'SMTP',
          badgeClass: 'badge-smtp',
          sessions: ps.smtp_sessions,
          evidence: ps.smtp_sessions > 0 ? 'STARTTLS command / 220 banner / EHLO handshake' : 'No SMTP observed',
        },
        {
          protocol: 'IMAP',
          badgeClass: 'badge-imap',
          sessions: ps.imap_sessions,
          evidence: ps.imap_sessions > 0 ? 'CAPABILITY / STARTTLS / Port 143/993' : 'No IMAP observed',
        },
        {
          protocol: 'POP3',
          badgeClass: 'badge-pop3',
          sessions: ps.pop3_sessions,
          evidence: ps.pop3_sessions > 0 ? '+OK banner / STLS command / Port 110/995' : 'No POP3 observed',
        },
        {
          protocol: 'Unknown',
          badgeClass: 'badge-unknown',
          sessions: ps.unknown_sessions,
          evidence: ps.unknown_sessions > 0 ? 'Non-standard port / unclassified payloads' : 'Zero unclassified streams',
        },
      ];
    }
    return PROTOCOL_STATS;
  }, [analysis]);

  const handleExportAssessment = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(analysis, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `assessment_${analysis?.analysis_id || 'export'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getRiskBadgeClass = (l) => {
    switch (l) {
      case 'CRITICAL':
        return 'badge-critical';
      case 'HIGH':
        return 'badge-high';
      case 'MEDIUM':
        return 'badge-medium';
      case 'LOW':
        return 'badge-low';
      case 'MINIMAL':
        return 'badge-minimal';
      default:
        return 'badge-neutral';
    }
  };

  const getSeverityBadgeClass = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return 'badge-critical';
      case 'high':
        return 'badge-high';
      case 'medium':
        return 'badge-medium';
      case 'low':
        return 'badge-low';
      default:
        return 'badge-info';
    }
  };

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Cryptographic posture</h1>
          <p className="page-subtitle">
            A capture-scoped assessment of email transport security, reconstructed from packet evidence.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={handleExportAssessment}
          id="btn-export-assessment"
        >
          <Download size={14} />
          <span>Export assessment</span>
        </button>
      </div>

      {/* Top Section: Posture Banner & Investigate First */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '2fr 1fr',
          gap: '20px',
          marginBottom: '20px',
        }}
      >
        {/* Left Posture Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">
              {level === 'MINIMAL'
                ? 'Email transport · robust posture'
                : level === 'CRITICAL'
                ? 'Email transport · critical security degradation'
                : 'Email transport · mixed posture'}
            </span>
            <span className="badge-status-done">Analysis done</span>
          </div>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '28px',
              padding: '8px 0 16px',
            }}
          >
            {/* Donut Gauge */}
            <DonutGauge
              encryptedCount={tlsCount}
              totalCount={totalSessionCount}
              percentage={encryptedPct}
              size={170}
            />

            {/* Description & Score */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', flex: 1 }}>
              <h2 style={{ fontSize: '20px', fontWeight: 700, color: '#EDF3F5', lineHeight: 1.25 }}>
                {score >= 80 ? (
                  <>
                    Strong encryption across streams.<br />
                    Modern ciphers and forward secrecy verified.
                  </>
                ) : score >= 50 ? (
                  <>
                    Encryption is prevalent.<br />
                    The fallback path is not safe.
                  </>
                ) : (
                  <>
                    Critical exposure detected.<br />
                    Insecure ciphers or cleartext credential transmission.
                  </>
                )}
              </h2>
              <p style={{ fontSize: '12.5px', color: '#A5B4BF', lineHeight: 1.45 }}>
                {analysis?.risk_score?.rationale?.length > 0
                  ? analysis.risk_score.rationale.slice(0, 2).join(' ')
                  : `${topFindings.length} findings identified across ${sessionsCount} sessions.`}
              </p>

              {/* Legend dots */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '18px', fontSize: '11.5px', marginTop: '2px' }}>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#EDF3F5' }}>
                  <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#59D9BC' }}></span>
                  {tlsCount} encrypted
                </span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', color: '#EDF3F5' }}>
                  <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: '#F3BC68' }}></span>
                  {plainCount} plaintext
                </span>
              </div>

              {/* Composite Score Row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginTop: '6px' }}>
                <span style={{ fontSize: '11px', color: '#778995', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600 }}>
                  AI-assisted composite score
                </span>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: '4px' }}>
                  <span style={{ fontSize: '24px', fontWeight: 700, color: '#EDF3F5' }}>
                    {score}
                  </span>
                  <span style={{ fontSize: '13px', color: '#778995' }}>/ 100</span>
                </div>
                <span className={getRiskBadgeClass(level)}>
                  {level.charAt(0) + level.slice(1).toLowerCase()}
                </span>
              </div>
            </div>
          </div>

          {/* Bottom disclaimer in card */}
          <div className="disclaimer-box" style={{ marginTop: 'auto' }}>
            <Info size={14} />
            <span>
              Prototype composite methodology. Score and {level} band are backend-computed via rule deduction and ML Isolation Forest.
            </span>
          </div>
        </div>

        {/* Right Investigate First Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Investigate first</span>
            <span className="card-meta-tag">
              {analysis?.all_findings?.length ?? 18} findings
            </span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', flex: 1 }}>
            {topFindings.length > 0 ? (
              topFindings.map((f, idx) => (
                <div
                  key={f.id || idx}
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                    paddingTop: idx > 0 ? '10px' : 0,
                    borderTop: idx > 0 ? '1px solid var(--border-subtle)' : 'none',
                  }}
                >
                  <div>
                    <span className={getSeverityBadgeClass(f.severity)}>
                      {f.severity ? f.severity.charAt(0).toUpperCase() + f.severity.slice(1) : 'Finding'}
                    </span>
                  </div>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: '#EDF3F5' }}>
                    {f.title}
                  </span>
                  <span style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: '#778995' }}>
                    {f.evidence?.session_id || 'Global'} · {f.evidence?.packet_numbers?.length ? `pkt #${f.evidence.packet_numbers.join(', #')}` : (f.evidence?.field || 'evidence')} · {f.is_ml_finding ? 'ML anomaly' : 'deterministic'}
                  </span>
                </div>
              ))
            ) : (
              <div style={{ padding: '20px 0', color: '#59D9BC', fontSize: '13px', display: 'flex', alignItems: 'center', gap: '8px' }}>
                ✓ No critical findings detected. All sessions adhere to secure baseline.
              </div>
            )}

            {/* Link to findings */}
            <div style={{ marginTop: 'auto', paddingTop: '10px' }}>
              <Link
                to="/findings"
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: '6px',
                  color: '#59D9BC',
                  textDecoration: 'none',
                  fontSize: '12px',
                  fontWeight: 600,
                }}
              >
                <span>Open prioritized findings</span>
                <ArrowRight size={13} />
              </Link>
            </div>
          </div>
        </div>
      </div>

      {/* Middle Row: 3 Detail Metric Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '20px',
          marginBottom: '20px',
        }}
      >
        {/* Negotiated TLS */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Negotiated TLS</span>
            <span className="card-meta-tag">{tlsCount} TLS sessions</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
            {tlsVersionsData.map((item) => (
              <div key={item.version} className="progress-item">
                <div className="progress-header">
                  <span className="progress-label">{item.version}</span>
                  <span className="progress-count">
                    {item.count} · {item.pct.toFixed(1)}%
                  </span>
                </div>
                <div className="progress-track">
                  <div
                    className="progress-fill"
                    style={{ width: `${Math.min(item.pct, 100)}%`, background: item.color }}
                  ></div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ fontSize: '11px', color: '#778995', marginTop: 'auto', paddingTop: '8px' }}>
            {plainCount} sessions have no negotiated TLS version.
          </div>
        </div>

        {/* Cipher Suites */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Cipher suites</span>
            <span className="card-meta-tag">Negotiated</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
            {cipherSuitesData.map((item) => (
              <div key={item.name} className="progress-item">
                <div className="progress-header">
                  <span className="progress-label" style={{ fontFamily: 'var(--font-mono)', fontSize: '11.5px' }}>
                    {item.name}
                  </span>
                  <span className="progress-count">{item.count}</span>
                </div>
                <div className="progress-track">
                  <div
                    className="progress-fill"
                    style={{ width: `${(item.count / (item.max || 1)) * 100}%`, background: item.color }}
                  ></div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ fontSize: '11px', color: '#778995', marginTop: 'auto', paddingTop: '8px' }}>
            Full suite identifiers and hex values in Cryptography.
          </div>
        </div>

        {/* Forward Secrecy */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Forward Secrecy</span>
            <span className="card-meta-tag">{totalSessionCount} sessions</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', flex: 1 }}>
            {fsData.map((item) => (
              <div key={item.label} className="progress-item">
                <div className="progress-header">
                  <span className="progress-label">{item.label}</span>
                  <span className="progress-count">{item.count}</span>
                </div>
                <div className="progress-track">
                  <div
                    className="progress-fill"
                    style={{ width: `${Math.min(item.pct, 100)}%`, background: item.color }}
                  ></div>
                </div>
              </div>
            ))}
          </div>

          <div style={{ fontSize: '11px', color: '#778995', marginTop: 'auto', paddingTop: '8px' }}>
            Derived from observed key exchange, not TLS version alone.
          </div>
        </div>
      </div>

      {/* Bottom Row: Protocol Table & Activity Chart */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '20px',
        }}
      >
        {/* Automatic Protocol Identification */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Automatic protocol identification</span>
            <span className="card-meta-tag">{totalSessionCount} sessions</span>
          </div>

          <div className="table-wrapper">
            <table className="custom-table">
              <thead>
                <tr>
                  <th style={{ width: '90px' }}>Protocol</th>
                  <th style={{ width: '80px' }}>Sessions</th>
                  <th>Identification evidence</th>
                </tr>
              </thead>
              <tbody>
                {protocolData.map((proto) => (
                  <tr key={proto.protocol}>
                    <td>
                      <span className={proto.badgeClass}>{proto.protocol}</span>
                    </td>
                    <td className="mono-cell">{proto.sessions}</td>
                    <td style={{ color: '#A5B4BF', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                      {proto.evidence}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Packet Activity Within Capture */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Packet activity within this capture</span>
            <span className="card-meta-tag">
              {analysis?.capture?.pcap_filename || cap?.filename || 'capture.pcap'}
            </span>
          </div>

          <ActivityChart
            packets={`${analysis?.capture?.packet_count?.toLocaleString() || cap?.packetsCount || '0'} packets`}
            duration={
              analysis?.capture?.capture_duration_seconds
                ? `${analysis.capture.capture_duration_seconds.toFixed(1)}s duration`
                : cap?.duration || '14m 32s duration'
            }
            analyzedAt={`Analyzed ${
              analysis?.capture?.analyzed_at
                ? new Date(analysis.capture.analyzed_at).toUTCString().slice(17, 25) + ' UTC'
                : cap?.analyzedAt || 'recent'
            }`}
            size={analysis?.capture?.file_size_bytes ? formatBytes(analysis.capture.file_size_bytes) : cap?.size || '—'}
            starttls={`${analysis?.protocol_summary?.starttls_sessions ?? 26} STARTTLS negotiated`}
            toolInfo={`v${analysis?.capture?.tool_version || '0.1.0'} · processed in ${analysis?.processing_time_seconds || 8.2}s`}
          />
        </div>
      </div>

      {/* Footer Disclaimer */}
      <FooterNote />
    </div>
  );
}
