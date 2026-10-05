import React, { useState, useRef, useEffect } from 'react';
import { FileText, ChevronDown, Plus, Radio, Loader2 } from 'lucide-react';
import { AVAILABLE_CAPTURES } from '../mockData';

export default function Topbar({
  selectedCapture,
  pcaps = AVAILABLE_CAPTURES,
  onSelectCapture,
  onOpenNewAnalysis,
  isBackendLive = false,
  isLoading = false,
}) {
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef(null);

  useEffect(() => {
    function handleClickOutside(event) {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const captureList = Array.isArray(pcaps) && pcaps.length > 0 ? pcaps : AVAILABLE_CAPTURES;

  return (
    <header className="topbar">
      {/* Left Breadcrumb */}
      <div className="topbar-left">
        <span className="topbar-ws-label">Workspace</span>
        <span className="topbar-ws-sep">/</span>
        <span className="topbar-ws-target">
          {selectedCapture?.shortId || 'a8c42e16'} · {(selectedCapture?.title || 'mixed mail edge').toLowerCase()}
        </span>
      </div>

      {/* Right Controls */}
      <div className="topbar-right">
        {isBackendLive ? (
          <span
            className="badge-status-done"
            style={{
              background: '#163A34',
              color: '#59D9BC',
              display: 'inline-flex',
              alignItems: 'center',
              gap: '5px',
              padding: '2px 8px',
              borderRadius: '4px',
              fontSize: '11px',
              fontWeight: 600,
            }}
          >
            <Radio size={12} color="#59D9BC" />
            <span>Backend live</span>
          </span>
        ) : (
          <span className="badge-demo">Demo data</span>
        )}

        <div className="dropdown-wrapper" ref={dropdownRef}>
          <button
            type="button"
            className="btn-pcap-dropdown"
            onClick={() => setDropdownOpen(!dropdownOpen)}
            id="pcap-dropdown-btn"
          >
            {isLoading ? (
              <Loader2 size={14} className="spin" color="#59D9BC" />
            ) : (
              <FileText size={14} color="#778995" />
            )}
            <span>{selectedCapture?.filename || '01_enterprise_secure_baseline.pcap'}</span>
            <ChevronDown size={14} color="#778995" />
          </button>

          {dropdownOpen && (
            <div className="dropdown-menu">
              <div
                style={{
                  padding: '8px 12px 6px',
                  fontSize: '10px',
                  color: '#778995',
                  textTransform: 'uppercase',
                  letterSpacing: '0.08em',
                  fontWeight: 600,
                }}
              >
                Select capture analysis
              </div>
              {captureList.map((cap) => (
                <div
                  key={cap.id || cap.filename}
                  className={`dropdown-item ${selectedCapture?.filename === cap.filename ? 'active' : ''}`}
                  onClick={() => {
                    onSelectCapture?.(cap);
                    setDropdownOpen(false);
                  }}
                >
                  <div className="dropdown-item-title">{cap.filename}</div>
                  <div className="dropdown-item-sub">
                    {cap.title} · {cap.size} {cap.category ? `· ${cap.category}` : ''}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        <button
          type="button"
          className="btn-primary"
          onClick={onOpenNewAnalysis}
          id="btn-new-analysis"
        >
          <Plus size={14} strokeWidth={2.5} />
          <span>New analysis</span>
        </button>
      </div>
    </header>
  );
}
