import React, { useState, useEffect } from 'react'
import { Routes, Route, useNavigate } from 'react-router-dom'
import { ThemeProvider } from './context/ThemeContext.jsx'
import AppShell from './components/AppShell.jsx'
import Overview from './pages/Overview.jsx'
import AnalysisWorkspace from './pages/AnalysisWorkspace.jsx'
import Sessions from './pages/Sessions.jsx'
import SessionDetail from './pages/SessionDetail.jsx'
import Findings from './pages/Findings.jsx'
import Reports from './pages/Reports.jsx'
import Guide from './pages/Guide.jsx'
import PostureCompare from './components/PostureCompare.jsx'
import { useApi } from './hooks/useApi.js'

export default function App() {
  const [analyses, setAnalyses] = useState([])
  const [activeAnalysis, setActiveAnalysis] = useState(null)
  const { get } = useApi()

  const fetchAnalyses = React.useCallback(async () => {
    try {
      const data = await get('/api/analyses')
      if (Array.isArray(data)) {
        setAnalyses(prev => {
          // Compare content to prevent unnecessary re-render if data is unchanged
          if (
            prev.length === data.length &&
            prev.every((p, i) => p.analysis_id === data[i].analysis_id && p.status === data[i].status)
          ) {
            return prev
          }
          return data
        })

        setActiveAnalysis(current => {
          if (current && data.some(a => a.analysis_id === current)) return current
          const downgrade = data.find(a => a.pcap?.includes('03_starttls_downgrade') && a.status === 'done')
          if (downgrade) return downgrade.analysis_id
          const done = data.find(a => a.status === 'done')
          return done ? done.analysis_id : null
        })
      }
    } catch {}
  }, [])

  useEffect(() => {
    fetchAnalyses()

    // Smart polling: only poll while there are active tasks (pending or running)
    let timer = null
    const hasPending = analyses.some(a => a.status === 'pending' || a.status === 'running')
    if (hasPending) {
      timer = setInterval(fetchAnalyses, 2500)
    }

    const handleFocus = () => { fetchAnalyses() }
    window.addEventListener('focus', handleFocus)
    document.addEventListener('visibilitychange', handleFocus)

    return () => {
      if (timer) clearInterval(timer)
      window.removeEventListener('focus', handleFocus)
      document.removeEventListener('visibilitychange', handleFocus)
    }
  }, [analyses, fetchAnalyses])

  return (
    <ThemeProvider>
      <AppShell
        analyses={analyses}
        activeAnalysisId={activeAnalysis}
        onSelectAnalysis={(id) => setActiveAnalysis(id)}
      >
        <Routes>
          <Route
            path="/"
            element={
              <Overview
                analyses={analyses}
                activeAnalysisId={activeAnalysis}
                onSelectAnalysis={(id) => setActiveAnalysis(id)}
                onRefreshAnalyses={fetchAnalyses}
              />
            }
          />
          <Route
            path="/analysis"
            element={<AnalysisWorkspace analysisId={activeAnalysis} />}
          />
          <Route
            path="/analysis/:id"
            element={<AnalysisWorkspace analysisId={activeAnalysis} />}
          />
          <Route
            path="/sessions"
            element={<Sessions analysisId={activeAnalysis} />}
          />
          <Route
            path="/sessions/:sessionId"
            element={<SessionDetail analysisId={activeAnalysis} />}
          />
          <Route
            path="/findings"
            element={<Findings analysisId={activeAnalysis} />}
          />
          <Route
            path="/compare"
            element={
              <PostureCompare
                analyses={analyses}
                defaultBeforeId={activeAnalysis}
              />
            }
          />
          <Route
            path="/reports"
            element={<Reports analysisId={activeAnalysis} />}
          />
          <Route path="/guide" element={<Guide />} />
        </Routes>
      </AppShell>
    </ThemeProvider>
  )
}
