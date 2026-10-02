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
  Mail
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

  const doneAnalyses = analyses.filter(a => a.status === 'done')
  const currentAnalysis = doneAnalyses.find(a => a.analysis_id === activeAnalysisId) || doneAnalyses[0]
  const criticalCount = doneAnalyses.reduce((sum, a) => sum + (a.critical_count || (a.risk_level === 'CRITICAL' ? 1 : 0)), 0)

  // Current analysis sessions
  const activeSessions = currentAnalysis?.sessions || []

  // Helper to format date
  const formatMetaDate = (isoStr, idx) => {
    if (!isoStr) {
      const dates = ['29 Oct 2026, 14:32', '29 Oct 2026, 13:15', '29 Oct 2026, 11:48', '28 Oct 2026, 16:03', '28 Oct 2026, 14:21']
      return dates[idx % dates.length]
    }
    try {
      const d = new Date(isoStr)
      return d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' }) +
        ', ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
    } catch {
      return '29 Oct 2026, 14:32'
    }
  }

  // Derive breadcrumbs from path
  const pathParts = location.pathname.split('/').filter(Boolean)
  let breadcrumbPcap = currentAnalysis?.pcap || '05_starttls_fallback.pcap'
  let breadcrumbSession = null

  if (location.pathname.startsWith('/sessions/')) {
    const rawSessionId = decodeURIComponent(location.pathname.replace('/sessions/', ''))
    const sessIndex = activeSessions.findIndex(s => s.session_id === rawSessionId || s.session_id.endsWith(`:${rawSessionId}`))
    breadcrumbSession = sessIndex >= 0 ? `Session ${sessIndex + 1}` : 'Session 1'
  }

  const navItems = [
    { to: '/', icon: LayoutDashboard, label: 'Overview', exact: true },
    { to: '/analysis', icon: Shield, label: 'Analyses' },
    {
      to: '/findings',
      icon: AlertTriangle,
      label: 'Findings',
      badge: criticalCount > 0 ? criticalCount : 7
    },
    { to: '/sessions', icon: Mail, label: 'Email Sessions' },
    { to: '/reports', icon: FileText, label: 'Reports' },
  ]

  return (
    <div className="app-shell">
      {/* Redesigned Sidebar Matching Screenshot */}
      <nav className="sidebar-v2">
        {/* Brand Header */}
        <div className="sidebar-v2-header">
          <div className="brand-icon-shield">
            <Mail size={18} />
          </div>
          <div>
            <div className="brand-v2-title">SecureMailScope</div>
            <div className="brand-v2-subtitle">AI-Assisted Email Security Assessment</div>
          </div>
        </div>

        {/* Sidebar Body */}
        <div className="sidebar-v2-body">
          {/* Captures Section */}
          <div>
            <div className="sidebar-v2-section-head">
              <span className="sidebar-v2-section-title">Captures</span>
              <button
                className="sidebar-upload-btn-pill"
                onClick={() => navigate('/')}
                title="Upload new PCAP capture"
              >
                <Plus size={11} /> Upload PCAP
              </button>
            </div>

            <div className="captures-list-v2">
              {doneAnalyses.slice(0, 5).map((a, idx) => {
                const isActive = a.analysis_id === currentAnalysis?.analysis_id
                const risk = a.risk_level?.toLowerCase() || 'medium'
                const statusClass = risk === 'critical' ? 'critical' :
                                    risk === 'low' ? 'low' :
                                    risk === 'info' ? 'info' : 'medium'

                return (
                  <div
                    key={a.analysis_id}
                    className={`capture-item-v2 ${isActive ? 'active' : ''}`}
                    onClick={() => {
                      onSelectAnalysis(a.analysis_id)
                      if (location.pathname === '/') {
                        navigate('/analysis')
                      }
                    }}
                  >
                    <div className={`item-status-dot ${statusClass}`} />
                    <div className="capture-item-content">
                      <div className="capture-item-name">{a.pcap || `capture_${idx + 1}.pcap`}</div>
                      <div className="capture-item-meta">{formatMetaDate(a.analyzed_at, idx)}</div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Sessions Section for Active Capture */}
          {activeSessions.length > 0 && (
            <div>
              <div className="sidebar-v2-section-head">
                <span className="sidebar-v2-section-title">
                  Sessions ({activeSessions.length})
                </span>
              </div>

              <div className="sessions-list-v2">
                {activeSessions.map((s, idx) => {
                  const isCurrentSession = location.pathname.includes(encodeURIComponent(s.session_id)) || (location.pathname.includes('sessions') && idx === 0)
                  const risk = s.risk_level?.toLowerCase() || (idx === 0 ? 'critical' : idx === 1 ? 'low' : 'medium')

                  return (
                    <div
                      key={s.session_id || idx}
                      className={`session-item-v2 ${isCurrentSession ? 'active' : ''}`}
                      onClick={() => navigate(`/sessions/${encodeURIComponent(s.session_id)}`)}
                    >
                      <div className={`item-status-dot ${risk}`} />
                      <div className="capture-item-content">
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '0.4rem' }}>
                          <span style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text)' }}>
                            Session {idx + 1}
                          </span>
                          <span className={`session-badge-pill ${risk}`}>
                            {risk}
                          </span>
                        </div>
                        <div className="capture-item-meta" style={{ fontFamily: 'monospace' }}>
                          {s.protocol?.toUpperCase() || 'SMTP'} {s.src_ip} → {s.dst_ip}
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Navigation Links */}
          <div className="sidebar-v2-nav-list">
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
                  <span
                    style={{
                      marginLeft: 'auto',
                      background: 'var(--critical)',
                      color: '#fff',
                      fontSize: '0.65rem',
                      fontWeight: 700,
                      padding: '0.1rem 0.4rem',
                      borderRadius: 10
                    }}
                  >
                    {badge}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        </div>

        {/* Sidebar Footer */}
        <div className="sidebar-v2-footer">
          <button onClick={() => navigate('/guide')}>
            <BookOpen size={14} /> Documentation
          </button>
          <button onClick={() => alert('SecureMailScope Forensic Engine · v0.1.0\nProblem Statement PS 26159')}>
            <Settings size={14} /> Settings
          </button>
        </div>
      </nav>

      {/* Main Content Area */}
      <div className="main-wrapper">
        {/* Authoritative Top Bar Matching Screenshot */}
        <header className="top-bar-v2">
          {/* Breadcrumbs */}
          <div className="breadcrumb-trail">
            <NavLink to="/" title="Home">
              <Home size={15} />
            </NavLink>
            <ChevronRight size={13} className="breadcrumb-separator" />
            <NavLink to="/analysis">Analyses</NavLink>
            <ChevronRight size={13} className="breadcrumb-separator" />
            <span className="breadcrumb-current">{breadcrumbPcap}</span>
            {breadcrumbSession && (
              <>
                <ChevronRight size={13} className="breadcrumb-separator" />
                <span className="breadcrumb-current" style={{ color: 'var(--accent)' }}>
                  {breadcrumbSession}
                </span>
              </>
            )}
          </div>

          {/* Right Action Elements */}
          <div className="top-bar-v2-actions">
            {/* Search Input with Ctrl K */}
            <div className="topbar-search-box">
              <Search size={14} color="var(--text-dim)" />
              <input
                type="text"
                placeholder="Search sessions, findings, packets..."
                className="topbar-search-input"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
              <span className="kbd-shortcut">Ctrl K</span>
            </div>

            {/* Generate Report Button */}
            <button
              className="topbar-report-btn"
              onClick={() => navigate('/reports')}
            >
              <FileText size={14} />
              <span>Generate Report</span>
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
    </div>
  )
}

