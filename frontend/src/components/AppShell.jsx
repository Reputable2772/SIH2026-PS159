import React, { useState } from 'react'
import { NavLink, useNavigate, useLocation } from 'react-router-dom'
import {
  Shield,
  AlertTriangle,
  FileText,
  BookOpen,
  LayoutDashboard,
  Search,
  Settings,
  Plus,
  Home,
  ChevronRight,
  Terminal,
  Activity,
  Layers,
  ChevronDown
} from 'lucide-react'
import ThemeToggle from './ThemeToggle.jsx'

export default function AppShell({
  children,
  analyses = [],
  activeAnalysisId = null,
  onSelectAnalysis = () => {},
}) {
  const navigate = useNavigate()
  const location = useLocation()
  const [searchQuery, setSearchQuery] = useState('')
  const [showSettingsModal, setShowSettingsModal] = useState(false)

  const doneAnalyses = analyses.filter(a => a.status === 'done')
  const currentAnalysis = doneAnalyses.find(a => a.analysis_id === activeAnalysisId) || doneAnalyses[0]
  const criticalCount = doneAnalyses.reduce(
    (sum, a) => sum + (a.critical_count || (a.risk_level === 'CRITICAL' ? 1 : 0)),
    0
  )

  const activeSessions = currentAnalysis?.sessions || []

  // Derive breadcrumbs from path
  let breadcrumbPcap = currentAnalysis?.pcap || '01_enterprise_secure_baseline.pcap'
  let breadcrumbSession = null

  if (location.pathname.startsWith('/sessions/')) {
    const rawSessionId = decodeURIComponent(location.pathname.replace('/sessions/', ''))
    const sessIndex = activeSessions.findIndex(
      s => s.session_id === rawSessionId || s.session_id.endsWith(`:${rawSessionId}`)
    )
    breadcrumbSession = sessIndex >= 0 ? `Session ${sessIndex + 1}` : (rawSessionId ? `Session ${rawSessionId}` : null)
  }

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Overview', exact: true },
    { to: '/analysis', icon: Shield, label: 'Analyses' },
    {
      to: '/findings',
      icon: AlertTriangle,
      label: 'Findings',
      badge: criticalCount > 0 ? criticalCount : null
    },
    { to: '/reports', icon: FileText, label: 'Reports' },
  ]

  const riskClass = (currentAnalysis?.risk_level || 'minimal').toLowerCase()

  return (
    <div className="app-shell">
      {/* Investigation-First Sidebar */}
      <nav className="sidebar-v2">
        {/* Brand Header */}
        <div className="sidebar-v2-header">
          <div className="brand-icon-shield">
            <Shield size={18} />
          </div>
          <div>
            <div className="brand-v2-title">SecureMailScope</div>
            <div className="brand-v2-subtitle">Forensic Email Security</div>
          </div>
        </div>

        {/* Sidebar Body */}
        <div className="sidebar-v2-body">
          {/* Quick Active Case Indicator */}
          {currentAnalysis && (
            <div className="sidebar-active-case-box">
              <div className="sidebar-active-case-head">
                <span className="sidebar-active-case-tag">ACTIVE CASE</span>
                <span className={`case-risk-pill ${riskClass}`}>
                  {currentAnalysis.risk_level || 'MINIMAL'}
                </span>
              </div>
              <div className="sidebar-active-case-title" title={currentAnalysis.pcap}>
                {currentAnalysis.pcap || 'capture.pcap'}
              </div>
              <div className="sidebar-active-case-meta">
                <span>{activeSessions.length} streams</span>
                <span>·</span>
                <span>{currentAnalysis.finding_count ?? 0} findings</span>
              </div>
            </div>
          )}

          {/* Core Persistent Navigation Links */}
          <div className="sidebar-v2-nav-list" style={{ marginTop: '0.75rem' }}>
            <div className="sidebar-nav-section-label">WORKSPACE</div>
            {navItems.map(({ to, icon: Icon, label, badge, exact }) => (
              <NavLink
                key={to}
                to={to}
                end={exact}
                className={({ isActive }) => `sidebar-v2-nav-link${isActive ? ' active' : ''}`}
              >
                <Icon size={16} />
                <span>{label}</span>
                {badge && (
                  <span className="sidebar-nav-badge-pill">
                    {badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        </div>

        {/* Sidebar Footer */}
        <div className="sidebar-v2-footer">
          <button onClick={() => navigate('/guide')} title="Investigation Guide & Reference">
            <BookOpen size={14} /> Documentation
          </button>
          <button onClick={() => setShowSettingsModal(true)} title="System Engine & Configuration">
            <Settings size={14} /> Settings
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <div className="main-wrapper">
        {/* Top Bar with Contextual Breadcrumbs */}
        <header className="top-bar-v2">
          {/* Breadcrumbs */}
          <div className="breadcrumb-trail">
            <NavLink to="/" title="Capture Library (Home)">
              <Home size={14} />
            </NavLink>
            <ChevronRight size={13} className="breadcrumb-separator" />
            <NavLink to="/analysis" className={location.pathname === '/analysis' ? 'breadcrumb-active' : ''}>
              Analyses
            </NavLink>
            <ChevronRight size={13} className="breadcrumb-separator" />
            <span className="breadcrumb-current" title={breadcrumbPcap}>
              {breadcrumbPcap}
            </span>
            {breadcrumbSession && (
              <>
                <ChevronRight size={13} className="breadcrumb-separator" />
                <span className="breadcrumb-current" style={{ color: 'var(--accent)', fontWeight: 600 }}>
                  {breadcrumbSession}
                </span>
              </>
            )}
          </div>

          {/* Right Action Elements */}
          <div className="top-bar-v2-actions">
            {/* Search Input */}
            <div className="topbar-search-box">
              <Search size={14} color="var(--text-dim)" />
              <input
                type="text"
                placeholder="Search sessions, findings, packets..."
                className="topbar-search-input"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && searchQuery.trim()) {
                    navigate(`/findings?q=${encodeURIComponent(searchQuery.trim())}`)
                  }
                }}
              />
              <span className="kbd-shortcut">↵ Enter</span>
            </div>

            {/* Quick Upload Button */}
            <button
              className="btn btn-secondary topbar-btn-compact"
              onClick={() => navigate('/')}
              title="Open PCAP Capture Library & Upload"
            >
              <Plus size={13} /> Drop PCAP
            </button>

            {/* Generate Report Button */}
            <button
              className="topbar-report-btn"
              onClick={() => navigate('/reports')}
              title="Generate Executive Audit Report"
            >
              <FileText size={14} />
              <span>Report</span>
            </button>

            {/* Dark Mode Theme Toggle */}
            <ThemeToggle />
          </div>
        </header>

        {/* Page Content */}
        <main className="main-content">
          {children}
        </main>
      </div>

      {/* Settings Modal */}
      {showSettingsModal && (
        <div className="modal-backdrop" onClick={() => setShowSettingsModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 480 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontWeight: 700, fontSize: '1rem', color: 'var(--text)' }}>
                <Settings size={18} color="var(--accent)" />
                Engine & Configuration
              </div>
              <button
                className="panel-ctrl-btn"
                onClick={() => setShowSettingsModal(false)}
              >
                ✕
              </button>
            </div>

            <div style={{ fontSize: '0.84rem', color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: '1.25rem' }}>
              <div style={{ marginBottom: '0.5rem' }}>
                <strong style={{ color: 'var(--text)' }}>SecureMailScope Forensic Engine</strong> · v0.1.0
              </div>
              <div>Smart India Hackathon 2026 · Problem Statement 26159</div>
              <div>Architecture: Passive TShark / Scapy Dissector + Isolation Forest Anomaly Classifier</div>
            </div>

            <div className="card" style={{ padding: '0.85rem 1rem', background: 'var(--bg-card-subtle)', marginBottom: '1.25rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.4rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Capture Storage Mode</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text)' }}>Zero-Payload (In-Memory / Temp)</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem', marginBottom: '0.4rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Deterministic Rule Count</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text)' }}>14 Security Rules Active</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.78rem' }}>
                <span style={{ color: 'var(--text-muted)' }}>Backend Pipeline Status</span>
                <span style={{ color: 'var(--success)', fontWeight: 600 }}>ONLINE</span>
              </div>
            </div>

            <button
              className="btn btn-primary"
              style={{ width: '100%' }}
              onClick={() => setShowSettingsModal(false)}
            >
              Done
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
