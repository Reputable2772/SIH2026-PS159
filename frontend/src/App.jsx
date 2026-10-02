import React, { useState, useEffect } from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import { FileText, Upload, Home, AlertTriangle, List, BookOpen } from 'lucide-react'

import Overview from './pages/Overview.jsx'
import Sessions from './pages/Sessions.jsx'
import SessionDetail from './pages/SessionDetail.jsx'
import Findings from './pages/Findings.jsx'
import Reports from './pages/Reports.jsx'
import UploadPage from './pages/Upload.jsx'
import Guide from './pages/Guide.jsx'
import { useApi } from './hooks/useApi.js'

export default function App() {
  const [analyses, setAnalyses] = useState([])
  const [activeAnalysis, setActiveAnalysis] = useState(null)
  const { get } = useApi()

  useEffect(() => {
    let cancelled = false
    const fetchAnalyses = async () => {
      try {
        const data = await get('/api/analyses')
        if (cancelled) return
        if (Array.isArray(data)) {
          setAnalyses(data)
          // Auto-select first done analysis only if no analysis is currently active
          setActiveAnalysis(current => {
            if (current) return current
            const done = data.find(a => a.status === 'done')
            return done ? done.analysis_id : null
          })
        }
      } catch {}
    }
    fetchAnalyses()
    const timer = setInterval(fetchAnalyses, 3000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

  const doneAnalyses = analyses.filter(a => a.status === 'done')
  const criticalCount = doneAnalyses.reduce((sum, a) => sum + (a.risk_level === 'CRITICAL' ? 1 : 0), 0)

  const navItems = [
    { to: '/', icon: Home, label: 'Overview' },
    { to: '/upload', icon: Upload, label: 'Upload PCAP' },
    { to: '/sessions', icon: List, label: 'Sessions' },
    { to: '/findings', icon: AlertTriangle, label: 'Findings',
      badge: criticalCount > 0 ? criticalCount : null },
    { to: '/reports', icon: FileText, label: 'Reports' },
    { to: '/guide', icon: BookOpen, label: 'Capture Guide' },
  ]

  return (
    <div className="app-shell">
      {/* Sidebar */}
      <nav className="sidebar">
        <div className="sidebar-logo">
          <div className="logo-icon">🔒</div>
          <h1>SecureMailScope</h1>
          <p>SIH 2026 · PS 26159</p>
        </div>

        <div className="sidebar-nav">
          <div className="nav-section-label">Navigation</div>
          {navItems.map(({ to, icon: Icon, label, badge }) => (
            <NavLink
              key={to}
              to={to}
              end={to === '/'}
              className={({ isActive }) => `nav-item${isActive ? ' active' : ''}`}
            >
              <Icon size={16} />
              <span>{label}</span>
              {badge && <span className="nav-badge">{badge}</span>}
            </NavLink>
          ))}

          {/* Analysis selector */}
          {doneAnalyses.length > 0 && (
            <>
              <div className="nav-section-label" style={{ marginTop: '1rem' }}>Analyses</div>
              {doneAnalyses.map(a => (
                <div
                  key={a.analysis_id}
                  onClick={() => setActiveAnalysis(a.analysis_id)}
                  className={`nav-item${activeAnalysis === a.analysis_id ? ' active' : ''}`}
                  style={{ fontSize: '0.78rem' }}
                >
                  <div
                    style={{
                      width: 8, height: 8, borderRadius: '50%',
                      background: riskColor(a.risk_level),
                      flexShrink: 0
                    }}
                  />
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.pcap || a.analysis_id.slice(0, 8)}
                  </span>
                </div>
              ))}
            </>
          )}
        </div>

        {/* Status footer */}
        <div style={{ padding: '1rem', borderTop: '1px solid var(--border)', fontSize: '0.72rem', color: 'var(--text-dim)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--info)' }} />
            Backend connected
          </div>
          <div style={{ marginTop: '0.3rem' }}>v0.1.0 · Prototype</div>
        </div>
      </nav>

      {/* Main content */}
      <main className="main-content">
        <Routes>
          <Route path="/" element={<Overview analysisId={activeAnalysis} />} />
          <Route path="/upload" element={<UploadPage onAnalysisCreated={id => setActiveAnalysis(id)} />} />
          <Route path="/sessions" element={<Sessions analysisId={activeAnalysis} />} />
          <Route path="/sessions/:sessionId" element={<SessionDetail analysisId={activeAnalysis} />} />
          <Route path="/findings" element={<Findings analysisId={activeAnalysis} />} />
          <Route path="/reports" element={<Reports analysisId={activeAnalysis} />} />
          <Route path="/guide" element={<Guide />} />
        </Routes>
      </main>
    </div>
  )
}

function riskColor(level) {
  const map = {
    CRITICAL: '#ff6b6b',
    HIGH: '#f5a623',
    MEDIUM: '#ffd700',
    LOW: '#58a6ff',
    MINIMAL: '#3fb950',
  }
  return map[level] || '#8b949e'
}
