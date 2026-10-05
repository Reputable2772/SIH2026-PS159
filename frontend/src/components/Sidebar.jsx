import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  LayoutGrid,
  FolderArchive,
  AlignLeft,
  GitCommit,
  KeyRound,
  Scan,
  AlertTriangle,
  FileText,
} from 'lucide-react';

export default function Sidebar({ selectedCapture, isBackendLive, activeAnalysis }) {
  const location = useLocation();

  const firstSessionId = activeAnalysis?.sessions?.[0]?.session_id || 'S-017';

  const navItems = [
    { label: 'Overview', path: '/overview', altPath: '/', icon: LayoutGrid },
    { label: 'Capture library', path: '/captures', icon: FolderArchive },
    { label: 'Session explorer', path: '/sessions', icon: AlignLeft, exact: true },
    { label: 'Session detail', path: `/sessions/${firstSessionId}`, icon: GitCommit, matchPrefix: '/sessions/' },
    { label: 'Cryptography', path: '/crypto', icon: KeyRound },
    { label: 'AI anomalies', path: '/anomalies', icon: Scan },
    { label: 'Findings', path: '/findings', icon: AlertTriangle },
    { label: 'Forensic reports', path: '/reports', icon: FileText },
  ];

  return (
    <aside className="sidebar">
      {/* Brand Header */}
      <div className="sidebar-header">
        <div className="sidebar-brand-icon">
          <svg width="18" height="20" viewBox="0 0 18 20" fill="none" xmlns="http://www.w3.org/2000/svg">
            <path
              d="M9 1L1 4.5V9.5C1 14.5 4.4 17.8 9 19C13.6 17.8 17 14.5 17 9.5V4.5L9 1Z"
              stroke="#59D9BC"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
            <path
              d="M6 10L8 12L12 8"
              stroke="#59D9BC"
              strokeWidth="1.6"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </div>
        <div className="sidebar-brand-text">
          <span className="sidebar-brand-name">SecureMailScope</span>
          <span className="sidebar-brand-sub">FORENSIC WORKBENCH</span>
        </div>
      </div>

      {/* Nav Section */}
      <div className="sidebar-section-title">Analyze & Investigate</div>
      <nav className="sidebar-nav">
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = item.matchPrefix
            ? location.pathname.startsWith(item.matchPrefix) && location.pathname !== '/sessions'
            : item.exact
            ? location.pathname === item.path
            : location.pathname === item.path || (item.altPath && location.pathname === item.altPath);

          return (
            <Link
              key={item.label}
              to={item.path}
              className={`sidebar-nav-item ${isActive ? 'active' : ''}`}
            >
              <Icon />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      {/* Selected Analysis Card */}
      <div className="sidebar-selected-card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span className="sidebar-selected-label">Selected Analysis</span>
          {isBackendLive ? (
            <span
              style={{
                fontSize: '9.5px',
                fontWeight: 700,
                color: '#59D9BC',
                background: '#163A34',
                padding: '1px 6px',
                borderRadius: '3px',
                letterSpacing: '0.06em',
                textTransform: 'uppercase',
              }}
            >
              Live API
            </span>
          ) : (
            <span className="badge-demo">Demo data</span>
          )}
        </div>
        <div className="sidebar-selected-file">
          {selectedCapture?.filename || '01_enterprise_secure_baseline.pcap'}
        </div>
        <p className="sidebar-selected-desc">
          Passive PCAP analysis only. No live capture or endpoint scanning.
        </p>
      </div>

      {/* Engine Status Footer */}
      <div className="sidebar-footer">
        <div className="sidebar-footer-title">
          Engine status · {isBackendLive ? 'Live pipeline' : 'Demo fallback'}
        </div>
        <div className="sidebar-status-row">
          <span className={`status-dot ${isBackendLive ? 'active' : ''}`}></span>
          <span>{isBackendLive ? 'FastAPI & TShark active' : 'Offline simulation'}</span>
        </div>
        <div style={{ fontSize: '10px', color: '#778995', marginTop: '6px' }}>
          SIH 2026 · PS 26159 Prototype
        </div>
      </div>
    </aside>
  );
}
