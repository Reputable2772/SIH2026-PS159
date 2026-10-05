import React, { useState, useMemo } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { Play, UploadCloud, Search, Download, RefreshCw, CheckCircle2, ArrowRight, Loader2 } from 'lucide-react';
import FooterNote from '../components/FooterNote';
import { api, formatBytes } from '../api';
import { AVAILABLE_CAPTURES, PROCESSING_JOBS } from '../mockData';

export default function CaptureLibraryPage() {
  const navigate = useNavigate();
  const {
    pcaps = AVAILABLE_CAPTURES,
    analyses = [],
    selectedCapture,
    selectCapture,
    loadAnalysisById,
    runAllScenarios,
    onOpenNewAnalysis,
    refreshAnalyses,
  } = useOutletContext();

  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [serverPath, setServerPath] = useState('01_enterprise_secure_baseline.pcap');
  const [isAsync, setIsAsync] = useState(true);
  const [actionMessage, setActionMessage] = useState('');
  const [isBatchRunning, setIsBatchRunning] = useState(false);

  const captureList = Array.isArray(pcaps) && pcaps.length > 0 ? pcaps : AVAILABLE_CAPTURES;

  const filteredCaptures = useMemo(() => {
    return captureList.filter((cap) => {
      if (categoryFilter !== 'all' && cap.category !== categoryFilter) return false;
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        if (!cap.filename.toLowerCase().includes(q) && !(cap.title || '').toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [captureList, categoryFilter, searchQuery]);

  const handleRunAll = async () => {
    setIsBatchRunning(true);
    setActionMessage('Dispatching batch analysis across demo PCAPs...');
    try {
      await runAllScenarios();
      setActionMessage('Batch demo scenarios triggered successfully!');
      setTimeout(() => setActionMessage(''), 4000);
    } catch (err) {
      setActionMessage(`Batch demo error: ${err.message}`);
    } finally {
      setIsBatchRunning(false);
    }
  };

  const handleAnalyzeServerPath = async () => {
    const filename = serverPath.split('/').pop() || serverPath;
    setActionMessage(`Analyzing ${filename}...`);
    try {
      if (isAsync) {
        await api.analyseByName(filename);
        setActionMessage(`Background job queued for ${filename}.`);
        setTimeout(() => refreshAnalyses?.(), 1500);
      } else {
        await selectCapture(filename);
        setActionMessage(`Analysis complete for ${filename}!`);
        navigate('/overview');
      }
    } catch (err) {
      setActionMessage(`Analysis failed: ${err.message}`);
    }
  };

  const getStatusBadge = (status) => {
    if (status === 'done') return <span className="badge-status-done">done</span>;
    if (status === 'running') return <span className="badge-status-running">running</span>;
    if (status === 'pending') return <span className="badge-status-pending">pending</span>;
    return <span className="badge-status-pending">{status || 'available'}</span>;
  };

  // Cached analyses or processing jobs
  const displayJobs = useMemo(() => {
    if (Array.isArray(analyses) && analyses.length > 0) {
      return analyses.map((a) => ({
        id: a.analysis_id ? a.analysis_id.slice(0, 8) : 'job',
        fullId: a.analysis_id,
        filename: a.pcap || 'capture.pcap',
        score: a.risk_score !== null ? `${Math.round(a.risk_score)} / ${a.risk_level || 'MINIMAL'}` : '—',
        sessions: `${a.session_count || 0} sessions`,
        findings: `${a.finding_count || 0} findings`,
        status: a.status || 'done',
        started: a.analyzed_at ? new Date(a.analyzed_at).toLocaleTimeString() : 'recently',
      }));
    }
    return PROCESSING_JOBS;
  }, [analyses]);

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Capture library & ingestion</h1>
          <p className="page-subtitle">
            Upload packet captures, analyze stored benchmark files, and inspect cached analysis history. Passive network inspection only.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '10px' }}>
          <button
            type="button"
            className="btn-secondary"
            onClick={() => refreshAnalyses?.()}
            title="Refresh capture list and jobs"
          >
            <RefreshCw size={13} />
            <span>Refresh</span>
          </button>
          <button
            type="button"
            className="btn-secondary"
            onClick={handleRunAll}
            id="btn-run-all-demos"
            disabled={isBatchRunning}
          >
            {isBatchRunning ? <Loader2 size={13} className="spin" /> : <Play size={13} fill="#59D9BC" color="#59D9BC" />}
            <span>Run all demo scenarios</span>
          </button>
        </div>
      </div>

      {actionMessage && (
        <div
          style={{
            background: '#163A34',
            border: '1px solid #1E463E',
            color: '#59D9BC',
            padding: '10px 16px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '12.5px',
            marginBottom: '16px',
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <CheckCircle2 size={16} />
          <span>{actionMessage}</span>
        </div>
      )}

      {/* Top Row: Upload & Server Ingestion */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          gap: '20px',
          marginBottom: '20px',
        }}
      >
        {/* Upload Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Upload a capture</span>
            <span className="card-meta-tag">MULTIPART INGESTION</span>
          </div>

          <div
            className="upload-dropzone"
            onClick={onOpenNewAnalysis}
            style={{ flex: 1, minHeight: '130px' }}
          >
            <UploadCloud size={30} color="#59D9BC" />
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#EDF3F5' }}>
              Drop a PCAP here, or browse files
            </div>
            <div style={{ fontSize: '11px', color: '#778995' }}>
              .pcap · .pcapng · .cap
            </div>
            <button
              type="button"
              className="btn-primary"
              style={{ marginTop: '4px' }}
              onClick={(e) => {
                e.stopPropagation();
                onOpenNewAnalysis();
              }}
            >
              + Choose file
            </button>
          </div>

          <div style={{ fontSize: '11px', color: '#778995', marginTop: '12px' }}>
            Stored with SHA-256 integrity metadata before asynchronous analysis.
          </div>
        </div>

        {/* Server File Ingestion Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Analyze a server file</span>
            <span className="card-meta-tag">FILESYSTEM PATH</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', flex: 1 }}>
            <p style={{ fontSize: '12px', color: '#A5B4BF', lineHeight: 1.4 }}>
              Select a benchmark capture or provide a server-side PCAP path to trigger analysis pipeline.
            </p>

            <select
              value={serverPath}
              onChange={(e) => setServerPath(e.target.value)}
              className="select-custom"
              style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', padding: '9px 12px' }}
            >
              {captureList.map((c) => (
                <option key={c.filename} value={c.filename}>
                  {c.filename} ({c.title || c.category})
                </option>
              ))}
            </select>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '4px', flexWrap: 'wrap', gap: '8px' }}>
              <div style={{ display: 'flex', gap: '14px', fontSize: '12px', color: '#A5B4BF' }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="ingest-mode"
                    checked={isAsync}
                    onChange={() => setIsAsync(true)}
                  />
                  <span>Async job</span>
                </label>
                <label style={{ display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                  <input
                    type="radio"
                    name="ingest-mode"
                    checked={!isAsync}
                    onChange={() => setIsAsync(false)}
                  />
                  <span>Synchronous</span>
                </label>
              </div>

              <button
                type="button"
                className="btn-primary"
                onClick={handleAnalyzeServerPath}
              >
                <Play size={13} fill="#0D1115" />
                <span>Analyze file</span>
              </button>
            </div>
          </div>

          <div style={{ fontSize: '11px', color: '#778995', marginTop: '12px' }}>
            The API server verifies file presence and executes TShark dissection.
          </div>
        </div>
      </div>

      {/* Available Captures Table */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <div>
            <span className="card-title">Available captures</span>
            <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
              Stored PCAPs available on the backend server for forensic evaluation
            </div>
          </div>
          <span className="card-meta-tag">{filteredCaptures.length} CAPTURES</span>
        </div>

        {/* Filter bar */}
        <div className="filter-bar">
          <div className="search-input-wrapper">
            <Search size={14} color="#778995" />
            <input
              type="text"
              placeholder="Search filename or scenario title..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <select
            className="select-custom"
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
          >
            <option value="all">Category: all</option>
            <option value="secure_baseline">secure_baseline</option>
            <option value="legacy_crypto">legacy_crypto</option>
            <option value="downgrade_attack">downgrade_attack</option>
            <option value="anomalies">anomalies</option>
          </select>
        </div>

        {/* Table */}
        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr>
                <th>Capture filename</th>
                <th style={{ width: '130px' }}>Category</th>
                <th style={{ width: '90px' }}>File size</th>
                <th style={{ width: '220px' }}>SHA-256 checksum</th>
                <th style={{ width: '180px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {filteredCaptures.map((cap) => {
                const isCurrent = selectedCapture?.filename === cap.filename;
                return (
                  <tr
                    key={cap.filename}
                    className={isCurrent ? 'row-selected' : ''}
                    style={{ cursor: 'pointer' }}
                    onClick={() => selectCapture(cap.filename)}
                  >
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                        <span style={{ fontWeight: 600, color: '#EDF3F5', fontFamily: 'var(--font-mono)' }}>
                          {cap.filename}
                        </span>
                        {isCurrent && (
                          <span className="badge-status-done" style={{ fontSize: '9.5px', padding: '1px 6px' }}>
                            ACTIVE
                          </span>
                        )}
                      </div>
                      <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
                        {cap.title || cap.description}
                      </div>
                    </td>
                    <td>
                      <span className="badge-neutral">{cap.category || 'general'}</span>
                    </td>
                    <td className="mono-cell" style={{ color: '#A5B4BF' }}>
                      {cap.size || (cap.size_bytes ? formatBytes(cap.size_bytes) : '—')}
                    </td>
                    <td className="mono-cell" style={{ fontSize: '11px', color: '#778995' }}>
                      {cap.sha256 ? `${cap.sha256.slice(0, 16)}…` : '—'}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'inline-flex', gap: '6px' }}>
                        <a
                          href={api.downloadPcap(cap.filename)}
                          download={cap.filename}
                          className="btn-secondary"
                          style={{ padding: '3px 8px', fontSize: '11px', textDecoration: 'none' }}
                          onClick={(e) => e.stopPropagation()}
                          title="Download raw PCAP file"
                        >
                          <Download size={12} />
                          <span>PCAP</span>
                        </a>
                        <button
                          type="button"
                          className="btn-primary"
                          style={{ padding: '3px 10px', fontSize: '11px' }}
                          onClick={(e) => {
                            e.stopPropagation();
                            selectCapture(cap.filename).then(() => navigate('/overview'));
                          }}
                        >
                          <span>Analyze</span>
                          <ArrowRight size={12} />
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Processing Lifecycle Jobs Table */}
      <div className="card" style={{ marginBottom: '20px' }}>
        <div className="card-header">
          <div>
            <span className="card-title">Processing jobs & analysis history</span>
            <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
              Cached forensic analysis outputs stored in the backend runtime memory
            </div>
          </div>
          <span className="card-meta-tag">{displayJobs.length} RUNS</span>
        </div>

        <div className="table-wrapper">
          <table className="custom-table">
            <thead>
              <tr>
                <th style={{ width: '90px' }}>Job ID</th>
                <th>Capture filename</th>
                <th style={{ width: '130px' }}>Risk Score</th>
                <th style={{ width: '110px' }}>Sessions</th>
                <th style={{ width: '110px' }}>Findings</th>
                <th style={{ width: '90px' }}>Status</th>
                <th style={{ width: '100px', textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {displayJobs.map((job) => (
                <tr key={job.fullId || job.id}>
                  <td className="mono-cell" style={{ color: '#59D9BC' }}>
                    {job.id}
                  </td>
                  <td className="mono-cell" style={{ color: '#EDF3F5' }}>
                    {job.filename}
                  </td>
                  <td className="mono-cell" style={{ color: '#F3BC68', fontWeight: 600 }}>
                    {job.score}
                  </td>
                  <td className="mono-cell" style={{ color: '#A5B4BF' }}>
                    {job.sessions}
                  </td>
                  <td className="mono-cell" style={{ color: '#A5B4BF' }}>
                    {job.findings}
                  </td>
                  <td>{getStatusBadge(job.status)}</td>
                  <td style={{ textAlign: 'right' }}>
                    {job.fullId && (
                      <button
                        type="button"
                        className="btn-secondary"
                        style={{ padding: '3px 8px', fontSize: '11px' }}
                        onClick={() => {
                          loadAnalysisById(job.fullId).then(() => navigate('/overview'));
                        }}
                      >
                        Inspect
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Footer Note */}
      <FooterNote />
    </div>
  );
}
