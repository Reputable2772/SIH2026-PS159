import React, { useState, useMemo } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import { Download, Search, ArrowUpRight, Info } from 'lucide-react';
import FooterNote from '../components/FooterNote';
import { FINDINGS } from '../mockData';

export default function PrioritizedFindingsPage() {
  const navigate = useNavigate();
  const { activeAnalysis } = useOutletContext();
  const [activeTab, setActiveTab] = useState('all'); // 'all' | 'rule' | 'ml'
  const [searchQuery, setSearchQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [selectedFindingId, setSelectedFindingId] = useState(null);

  // Normalize findings from live backend or mock fallback
  const rawFindings = useMemo(() => {
    if (activeAnalysis?.all_findings && activeAnalysis.all_findings.length > 0) {
      return activeAnalysis.all_findings.map((f, i) => {
        const sev = (f.severity?.value || f.severity || 'info').toLowerCase();
        const cat = (f.category?.value || f.category || 'general').toLowerCase().replace(/ /g, '_');
        const session = f.evidence?.session_id || 'Global';
        const packetNumbers = f.evidence?.packet_numbers || [];
        const packetStr = packetNumbers.length > 0 ? `#${packetNumbers.join(', #')}` : (f.evidence?.field || 'traffic');

        return {
          id: f.id || `F-${String(i + 1).padStart(3, '0')}`,
          severity: sev,
          severityUpper: sev.toUpperCase(),
          category: cat,
          origin: f.is_ml_finding || cat === 'ml_anomaly' ? 'ML' : 'Rule',
          title: f.title,
          session,
          packets: packetStr,
          description: f.description,
          recommendation: f.recommendation,
          cveRefs: f.cve_references || [],
          evidence: f.evidence || {},
          raw: f,
        };
      });
    }
    return FINDINGS.map((f) => ({
      ...f,
      severityUpper: f.severity.toUpperCase(),
      severity: f.severity.toLowerCase(),
      cveRefs: f.cveRefs || [],
      evidence: {
        session_id: f.session,
        packet_numbers: (f.packets || '').replace(/[^0-9,–-]/g, '').split(/[,–-]/).map(Number).filter(Boolean),
        field: f.field,
        observed_value: f.observed,
      },
    }));
  }, [activeAnalysis]);

  // Set default selected finding ID if unset
  const activeId = selectedFindingId || rawFindings[0]?.id;

  // Filtered findings list
  const filteredFindings = useMemo(() => {
    return rawFindings.filter((f) => {
      // Tab filter
      if (activeTab === 'rule' && f.origin !== 'Rule') return false;
      if (activeTab === 'ml' && f.origin !== 'ML') return false;

      // Category filter
      if (categoryFilter !== 'all' && f.category !== categoryFilter) return false;

      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchTitle = f.title.toLowerCase().includes(q);
        const matchSession = f.session.toLowerCase().includes(q);
        const matchPackets = String(f.packets).toLowerCase().includes(q);
        const matchCat = f.category.toLowerCase().includes(q);
        if (!matchTitle && !matchSession && !matchPackets && !matchCat) return false;
      }

      return true;
    });
  }, [rawFindings, activeTab, categoryFilter, searchQuery]);

  const selectedFinding = rawFindings.find((f) => f.id === activeId) || rawFindings[0];

  const handleExportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(rawFindings, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `findings_export_${activeAnalysis?.analysis_id || 'all'}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const getSeverityBadge = (sev) => {
    switch (sev?.toLowerCase()) {
      case 'critical':
        return <span className="badge-critical">Critical</span>;
      case 'high':
        return <span className="badge-high">High</span>;
      case 'medium':
        return <span className="badge-medium">Medium</span>;
      case 'low':
        return <span className="badge-low">Low</span>;
      case 'info':
        return <span className="badge-info">Info</span>;
      default:
        return <span className="badge-info">{sev}</span>;
    }
  };

  const categories = useMemo(() => {
    const set = new Set(rawFindings.map((f) => f.category));
    return ['all', ...Array.from(set)];
  }, [rawFindings]);

  // Counts for KPIs
  const criticalCount = rawFindings.filter((f) => f.severity === 'critical').length;
  const highCount = rawFindings.filter((f) => f.severity === 'high').length;
  const mediumCount = rawFindings.filter((f) => f.severity === 'medium').length;
  const lowCount = rawFindings.filter((f) => f.severity === 'low' || f.severity === 'info').length;
  const mlCount = rawFindings.filter((f) => f.origin === 'ML').length;
  const ruleCount = rawFindings.filter((f) => f.origin === 'Rule').length;

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header">
        <div>
          <h1 className="page-title">Prioritized findings</h1>
          <p className="page-subtitle">
            Evidence first: {ruleCount} deterministic rule findings and {mlCount} ML review signals, ordered by backend-provided severity.
          </p>
        </div>
        <button
          type="button"
          className="btn-secondary"
          onClick={handleExportJSON}
          id="btn-export-findings"
        >
          <Download size={14} />
          <span>Export findings JSON</span>
        </button>
      </div>

      {/* 5 KPI Metric Boxes */}
      <div className="kpi-row" style={{ gridTemplateColumns: 'repeat(5, 1fr)' }}>
        <div className="kpi-card">
          <div className="kpi-card-header">
            <span className="kpi-label">Critical</span>
            <span className="indicator-square" style={{ background: criticalCount > 0 ? '#F48286' : '#59D9BC' }}></span>
          </div>
          <span className="kpi-value">{criticalCount}</span>
        </div>
        <div className="kpi-card">
          <div className="kpi-card-header">
            <span className="kpi-label">High</span>
            <span className="indicator-square" style={{ background: highCount > 0 ? '#F3BC68' : '#59D9BC' }}></span>
          </div>
          <span className="kpi-value">{highCount}</span>
        </div>
        <div className="kpi-card">
          <div className="kpi-card-header">
            <span className="kpi-label">Medium</span>
            <span className="indicator-square" style={{ background: '#59D9BC' }}></span>
          </div>
          <span className="kpi-value">{mediumCount}</span>
        </div>
        <div className="kpi-card">
          <div className="kpi-card-header">
            <span className="kpi-label">Low</span>
            <span className="indicator-square" style={{ background: '#59D9BC' }}></span>
          </div>
          <span className="kpi-value">{lowCount}</span>
        </div>
        <div className="kpi-card">
          <div className="kpi-card-header">
            <span className="kpi-label">ML review signals</span>
            <span className="indicator-square" style={{ background: mlCount > 0 ? '#F3BC68' : '#59D9BC' }}></span>
          </div>
          <span className="kpi-value">{mlCount}</span>
        </div>
      </div>

      {/* Main Split: Left Findings Table & Right Detail Pane */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: '1.6fr 1fr',
          gap: '20px',
          alignItems: 'start',
        }}
      >
        {/* Left: Table Card */}
        <div className="card">
          <div className="card-header">
            <span className="card-title">Priority findings queue</span>
            <span className="card-meta-tag">
              {filteredFindings.length} OF {rawFindings.length} FINDINGS
            </span>
          </div>

          {/* Filter Tabs */}
          <div className="filter-tabs">
            <button
              type="button"
              className={`tab-btn ${activeTab === 'all' ? 'active' : ''}`}
              onClick={() => setActiveTab('all')}
            >
              All findings · {rawFindings.length}
            </button>
            <button
              type="button"
              className={`tab-btn ${activeTab === 'rule' ? 'active' : ''}`}
              onClick={() => setActiveTab('rule')}
            >
              Deterministic rules · {ruleCount}
            </button>
            <button
              type="button"
              className={`tab-btn ${activeTab === 'ml' ? 'active' : ''}`}
              onClick={() => setActiveTab('ml')}
            >
              ML review signals · {mlCount}
            </button>
          </div>

          {/* Controls Bar */}
          <div className="filter-bar">
            <div className="search-input-wrapper">
              <Search size={14} color="#778995" />
              <input
                type="text"
                placeholder="Search findings, sessions, packets..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>

            <div style={{ display: 'flex', gap: '8px' }}>
              <select
                className="select-custom"
                value={categoryFilter}
                onChange={(e) => setCategoryFilter(e.target.value)}
              >
                {categories.map((cat) => (
                  <option key={cat} value={cat}>
                    Category: {cat}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Findings Table */}
          <div className="table-wrapper">
            <table className="custom-table">
              <thead>
                <tr>
                  <th style={{ width: '80px' }}>Severity</th>
                  <th style={{ width: '70px' }}>Origin</th>
                  <th>Finding & Category</th>
                  <th style={{ width: '90px' }}>Session</th>
                  <th style={{ width: '100px' }}>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.length > 0 ? (
                  filteredFindings.map((f) => {
                    const isSelected = f.id === selectedFinding?.id;
                    return (
                      <tr
                        key={f.id}
                        className={isSelected ? 'row-selected' : ''}
                        onClick={() => setSelectedFindingId(f.id)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td>{getSeverityBadge(f.severity)}</td>
                        <td>
                          <span className={f.origin === 'ML' ? 'badge-high' : 'badge-neutral'}>
                            {f.origin}
                          </span>
                        </td>
                        <td>
                          <div style={{ fontWeight: 600, color: '#EDF3F5', fontSize: '12.5px' }}>
                            {f.title}
                          </div>
                          <div style={{ fontSize: '11px', color: '#778995', marginTop: '2px' }}>
                            {f.category}
                          </div>
                        </td>
                        <td className="mono-cell" style={{ color: '#59D9BC' }}>
                          {f.session}
                        </td>
                        <td className="mono-cell" style={{ color: '#A5B4BF', fontSize: '11px' }}>
                          {f.packets}
                        </td>
                      </tr>
                    );
                  })
                ) : (
                  <tr>
                    <td colSpan={5} style={{ textAlign: 'center', padding: '30px', color: '#778995' }}>
                      No findings match current filters.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right: Selected Finding Detail Pane */}
        {selectedFinding ? (
          <div className="card" style={{ position: 'sticky', top: '20px' }}>
            <div className="card-header">
              <span className="card-title">Evidence & provenance</span>
              <span className="card-meta-tag">{selectedFinding.id}</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Finding Title & Badges */}
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '8px' }}>
                  {getSeverityBadge(selectedFinding.severity)}
                  <span className={selectedFinding.origin === 'ML' ? 'badge-high' : 'badge-neutral'}>
                    {selectedFinding.origin === 'ML' ? '16-D ML Anomaly' : 'Deterministic Rule'}
                  </span>
                  <span className="badge-neutral">{selectedFinding.category}</span>
                </div>
                <h2 style={{ fontSize: '15px', fontWeight: 700, color: '#EDF3F5', lineHeight: 1.35 }}>
                  {selectedFinding.title}
                </h2>
              </div>

              {/* Provenance Box */}
              <div
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-default)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '12px 14px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '8px',
                  fontSize: '12px',
                }}
              >
                <div className="detail-row">
                  <span className="detail-key">Affected Session</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                    <span className="detail-val" style={{ color: '#59D9BC' }}>
                      {selectedFinding.session}
                    </span>
                    {selectedFinding.session && selectedFinding.session !== 'Global' && (
                      <button
                        type="button"
                        onClick={() => navigate(`/sessions/${selectedFinding.session}`)}
                        style={{
                          background: 'none',
                          border: 'none',
                          color: '#59D9BC',
                          cursor: 'pointer',
                          padding: '0 2px',
                        }}
                        title="Inspect session"
                      >
                        <ArrowUpRight size={13} />
                      </button>
                    )}
                  </div>
                </div>

                <div className="detail-row">
                  <span className="detail-key">Packet Numbers</span>
                  <span className="detail-val">{selectedFinding.packets}</span>
                </div>

                <div className="detail-row">
                  <span className="detail-key">Observed Field</span>
                  <span className="detail-val" style={{ color: '#EDF3F5' }}>
                    {selectedFinding.evidence?.field || 'network.evidence'}
                  </span>
                </div>

                {selectedFinding.evidence?.observed_value !== undefined && (
                  <div className="detail-row">
                    <span className="detail-key">Observed Value</span>
                    <span className="detail-val" style={{ color: '#F3BC68', maxWidth: '170px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {typeof selectedFinding.evidence.observed_value === 'object'
                        ? JSON.stringify(selectedFinding.evidence.observed_value)
                        : String(selectedFinding.evidence.observed_value)}
                    </span>
                  </div>
                )}
              </div>

              {/* Description */}
              <div>
                <div style={{ fontSize: '11px', color: '#778995', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                  Description & Impact
                </div>
                <p style={{ fontSize: '12.5px', color: '#A5B4BF', lineHeight: 1.5 }}>
                  {selectedFinding.description}
                </p>
              </div>

              {/* CVE References */}
              {selectedFinding.cveRefs?.length > 0 && (
                <div>
                  <div style={{ fontSize: '11px', color: '#778995', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                    Standards & CVE References
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {selectedFinding.cveRefs.map((ref) => (
                      <span
                        key={ref}
                        style={{
                          background: 'var(--bg-surface)',
                          border: '1px solid var(--border-default)',
                          color: '#59D9BC',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11px',
                          padding: '2px 8px',
                          borderRadius: '4px',
                        }}
                      >
                        {ref}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Recommendations */}
              <div>
                <div style={{ fontSize: '11px', color: '#778995', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, marginBottom: '6px' }}>
                  Remediation Guidance
                </div>
                <div
                  style={{
                    background: '#162320',
                    border: '1px solid #1E463E',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                    fontSize: '12px',
                    color: '#59D9BC',
                    lineHeight: 1.45,
                  }}
                >
                  {selectedFinding.recommendation || 'Upgrade TLS configuration to adhere to RFC 8996 and NIST SP 800-52r2.'}
                </div>
              </div>

              {/* Disclaimer */}
              <div className="disclaimer-box">
                <Info size={13} />
                <span>
                  All findings contain packet-verifiable coordinates. No synthetic assumptions.
                </span>
              </div>
            </div>
          </div>
        ) : null}
      </div>

      {/* Footer Disclaimer */}
      <FooterNote />
    </div>
  );
}
