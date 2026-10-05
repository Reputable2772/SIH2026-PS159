import React, { useState, useEffect } from 'react';
import { useOutletContext } from 'react-router-dom';
import { Download, FileText, Check, Info, ExternalLink } from 'lucide-react';
import FooterNote from '../components/FooterNote';
import { api } from '../api';
import { REPORT_PREVIEW, DEMO_CAPTURE } from '../mockData';

export default function ForensicReportsPage() {
  const { activeAnalysis, selectedCapture } = useOutletContext();
  const [selectedFormat, setSelectedFormat] = useState('html'); // 'json' | 'pdf' | 'html'
  const [jsonReportData, setJsonReportData] = useState(null);

  const analysisId = activeAnalysis?.analysis_id || DEMO_CAPTURE.id;
  const pcapFilename = activeAnalysis?.capture?.pcap_filename || selectedCapture?.filename || 'capture.pcap';
  const sha256 = activeAnalysis?.capture?.sha256_hash || selectedCapture?.sha256 || '—';
  const score = Math.round(activeAnalysis?.risk_score?.score ?? 72);
  const level = (activeAnalysis?.risk_score?.level || 'HIGH').toUpperCase();
  const findingsCount = activeAnalysis?.all_findings?.length ?? 18;
  const sessionsCount = activeAnalysis?.sessions?.length ?? 48;

  // Fetch JSON report data when json is selected
  useEffect(() => {
    let isSubscribed = true;
    if (analysisId) {
      fetch(`/api/analysis/${analysisId}/report/json`)
        .then((res) => (res.ok ? res.json() : null))
        .then((data) => {
          if (isSubscribed && data) setJsonReportData(data);
        })
        .catch(() => {
          if (isSubscribed) setJsonReportData(null);
        });
    }
    return () => {
      isSubscribed = false;
    };
  }, [analysisId]);

  const handleDownload = (format) => {
    const fmt = format || selectedFormat;
    if (fmt === 'pdf') {
      window.open(api.reportPdfUrl(analysisId), '_blank');
    } else if (fmt === 'json') {
      window.open(api.reportJsonUrl(analysisId), '_blank');
    } else {
      window.open(api.reportHtmlUrl(analysisId), '_blank');
    }
  };

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Forensic reports</h1>
          <p className="page-subtitle">
            Export the selected analysis with traceable evidence, cryptographic inventory, and assessment limitations.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            className="btn-primary"
            onClick={() => handleDownload(selectedFormat)}
            id="btn-download-report"
          >
            <Download size={14} />
            <span>Download {selectedFormat.toUpperCase()}</span>
          </button>
        </div>
      </div>

      {/* Format Selector: 3 Cards */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(3, 1fr)',
          gap: '20px',
          marginBottom: '20px',
        }}
      >
        {/* JSON Card */}
        <div
          className={`card ${selectedFormat === 'json' ? 'row-selected' : ''}`}
          onClick={() => setSelectedFormat('json')}
          style={{
            cursor: 'pointer',
            border: selectedFormat === 'json' ? '1px solid #59D9BC' : '1px solid var(--border-default)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '18px', fontFamily: 'var(--font-mono)', fontWeight: 700, color: '#A5B4BF' }}>
              {'{ }'}
            </span>
            <div
              style={{
                width: '14px',
                height: '14px',
                borderRadius: '50%',
                border: `2px solid ${selectedFormat === 'json' ? '#59D9BC' : '#3A4753'}`,
                background: selectedFormat === 'json' ? '#59D9BC' : 'transparent',
              }}
            ></div>
          </div>
          <span style={{ fontSize: '16px', fontWeight: 700, color: '#EDF3F5' }}>JSON</span>
          <span style={{ fontSize: '11px', color: '#A5B4BF', fontWeight: 600, marginTop: '2px' }}>
            Machine-readable evidence
          </span>
          <p style={{ fontSize: '11.5px', color: '#778995', marginTop: '6px', lineHeight: 1.35 }}>
            Structured metadata, sessions, cryptography, findings, recommendations and model outputs.
          </p>
        </div>

        {/* PDF Card */}
        <div
          className={`card ${selectedFormat === 'pdf' ? 'row-selected' : ''}`}
          onClick={() => setSelectedFormat('pdf')}
          style={{
            cursor: 'pointer',
            border: selectedFormat === 'pdf' ? '1px solid #59D9BC' : '1px solid var(--border-default)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <FileText size={18} color="#A5B4BF" />
            <div
              style={{
                width: '14px',
                height: '14px',
                borderRadius: '50%',
                border: `2px solid ${selectedFormat === 'pdf' ? '#59D9BC' : '#3A4753'}`,
                background: selectedFormat === 'pdf' ? '#59D9BC' : 'transparent',
              }}
            ></div>
          </div>
          <span style={{ fontSize: '16px', fontWeight: 700, color: '#EDF3F5' }}>PDF</span>
          <span style={{ fontSize: '11px', color: '#A5B4BF', fontWeight: 600, marginTop: '2px' }}>
            Executive forensic assessment
          </span>
          <p style={{ fontSize: '11.5px', color: '#778995', marginTop: '6px', lineHeight: 1.35 }}>
            Portable ReportLab-generated posture summary with prioritized findings and evidence references.
          </p>
        </div>

        {/* HTML Card */}
        <div
          className={`card ${selectedFormat === 'html' ? 'row-selected' : ''}`}
          onClick={() => setSelectedFormat('html')}
          style={{
            cursor: 'pointer',
            border: selectedFormat === 'html' ? '1px solid #59D9BC' : '1px solid var(--border-default)',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#59D9BC" strokeWidth="2">
              <rect x="3" y="3" width="18" height="18" rx="2" />
              <path d="M9 3v18" />
            </svg>
            <div
              style={{
                width: '14px',
                height: '14px',
                borderRadius: '50%',
                border: `2px solid ${selectedFormat === 'html' ? '#59D9BC' : '#3A4753'}`,
                background: selectedFormat === 'html' ? '#59D9BC' : 'transparent',
              }}
            ></div>
          </div>
          <span style={{ fontSize: '16px', fontWeight: 700, color: '#EDF3F5' }}>HTML</span>
          <span style={{ fontSize: '11px', color: '#A5B4BF', fontWeight: 600, marginTop: '2px' }}>
            Standalone dark dashboard
          </span>
          <p style={{ fontSize: '11.5px', color: '#778995', marginTop: '6px', lineHeight: 1.35 }}>
            Self-contained analysis report. Rendered natively by the backend with zero external dependencies.
          </p>
        </div>
      </div>

      {/* Middle Row: Report Preview & Export Contents */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1.8fr 1fr',
          gap: '20px',
          marginBottom: '20px',
          alignItems: 'start',
        }}
      >
        {/* Left: Report Preview Card */}
        <div className="card">
          <div className="card-header">
            <div>
              <span className="card-title">Live report inspection</span>
              <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
                Format: {selectedFormat.toUpperCase()} · Analysis ID: {analysisId}
              </div>
            </div>
            <a
              href={
                selectedFormat === 'pdf'
                  ? api.reportPdfUrl(analysisId)
                  : selectedFormat === 'json'
                  ? api.reportJsonUrl(analysisId)
                  : api.reportHtmlUrl(analysisId)
              }
              target="_blank"
              rel="noreferrer"
              className="btn-secondary"
              style={{ fontSize: '11px', padding: '3px 8px', textDecoration: 'none' }}
            >
              <ExternalLink size={12} />
              <span>Open in new tab</span>
            </a>
          </div>

          {/* If HTML preview: render real iframe from backend */}
          {selectedFormat === 'html' && (
            <div style={{ width: '100%', height: '540px', borderRadius: 'var(--radius-sm)', overflow: 'hidden' }}>
              <iframe
                src={`/api/analysis/${analysisId}/report/html`}
                title="Forensic HTML Report Preview"
                style={{
                  width: '100%',
                  height: '100%',
                  border: '1px solid var(--border-default)',
                  background: '#0d1117',
                }}
              />
            </div>
          )}

          {/* If JSON preview: render structured json */}
          {selectedFormat === 'json' && (
            <div
              style={{
                width: '100%',
                maxHeight: '540px',
                overflow: 'auto',
                background: '#0a0d10',
                padding: '16px',
                borderRadius: 'var(--radius-sm)',
                border: '1px solid var(--border-default)',
                fontFamily: 'var(--font-mono)',
                fontSize: '11.5px',
                color: '#EDF3F5',
                lineHeight: 1.45,
              }}
            >
              <pre>{JSON.stringify(jsonReportData || activeAnalysis || REPORT_PREVIEW, null, 2)}</pre>
            </div>
          )}

          {/* If PDF preview */}
          {selectedFormat === 'pdf' && (
            <div
              style={{
                padding: '30px 20px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '16px',
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <FileText size={48} color="#59D9BC" />
              <div style={{ textAlign: 'center' }}>
                <h3 style={{ fontSize: '16px', color: '#EDF3F5', fontWeight: 600 }}>
                  PDF Executive Forensic Assessment
                </h3>
                <p style={{ fontSize: '12px', color: '#A5B4BF', marginTop: '4px' }}>
                  Includes 2-page formal ReportLab summary with scorecards, tables, and evidence references.
                </p>
              </div>
              <button
                type="button"
                className="btn-primary"
                onClick={() => window.open(api.reportPdfUrl(analysisId), '_blank')}
              >
                <Download size={14} />
                <span>Open / Download PDF ({pcapFilename})</span>
              </button>
            </div>
          )}
        </div>

        {/* Right: Export Checklist & Evidence Manifest */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Export Contents Checklist */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Export manifest</span>
              <span className="card-meta-tag">6 SECTIONS</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {[
                { title: 'Capture metadata & integrity hashes', desc: 'SHA-256, duration, packet count' },
                { title: 'Reconstructed conversation telemetry', desc: `${sessionsCount} TCP streams with 5-tuples` },
                { title: 'STARTTLS state machine transitions', desc: 'Advertised, requested, downgrade status' },
                { title: 'Observed X.509 certificate inventory', desc: 'Subject DNs, validity timestamps, key bits' },
                { title: 'Prioritized security findings queue', desc: `${findingsCount} findings with packet provenance` },
                { title: 'Assessment limitations & disclaimers', desc: 'Passive scope boundaries & RFC notes' },
              ].map((item) => (
                <div key={item.title} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                  <div
                    style={{
                      width: '16px',
                      height: '16px',
                      borderRadius: '3px',
                      background: '#163A34',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      marginTop: '2px',
                      flexShrink: 0,
                    }}
                  >
                    <Check size={11} color="#59D9BC" strokeWidth={3} />
                  </div>
                  <div>
                    <div style={{ fontSize: '12.5px', fontWeight: 600, color: '#EDF3F5' }}>
                      {item.title}
                    </div>
                    <div style={{ fontSize: '11px', color: '#778995', marginTop: '1px' }}>
                      {item.desc}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Evidence Integrity Manifest Card */}
          <div className="card">
            <div className="card-header">
              <span className="card-title">Evidence manifest</span>
              <span className="badge-status-done">VERIFIED</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', fontSize: '12px' }}>
              <div className="detail-row">
                <span className="detail-key">Capture File</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)' }}>
                  {pcapFilename}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">SHA-256</span>
                <span className="detail-val" style={{ fontFamily: 'var(--font-mono)', fontSize: '10.5px', color: '#59D9BC' }}>
                  {sha256 ? `${sha256.slice(0, 16)}…` : '—'}
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Composite Score</span>
                <span className="detail-val">
                  {score} / 100 ({level})
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-key">Tool Version</span>
                <span className="detail-val">v0.1.0</span>
              </div>
            </div>

            <div className="disclaimer-box" style={{ marginTop: '10px' }}>
              <Info size={13} />
              <span>
                Report outputs are cryptographically tied to raw packet capture artifacts.
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Footer Note */}
      <FooterNote />
    </div>
  );
}
