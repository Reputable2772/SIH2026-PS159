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

  useEffect(() => {
    let cancelled = false
    const fetchAnalyses = async () => {
      try {
        const data = await get('/api/analyses')
        if (cancelled) return
        if (Array.isArray(data)) {
          setAnalyses(data)
          // Default active analysis if none selected yet (prioritize starttls fallback)
          setActiveAnalysis(current => {
            if (current) return current
            const fallback = data.find(a => a.pcap?.includes('starttls_fallback') && a.status === 'done')
            if (fallback) return fallback.analysis_id
            const done = data.find(a => a.status === 'done')
            return done ? done.analysis_id : null
          })
        }
      } catch {}
    }

    fetchAnalyses()
    const timer = setInterval(fetchAnalyses, 4000)
    return () => {
      cancelled = true
      clearInterval(timer)
    }
  }, [])

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
              />
            }
          />
          <Route
            path="/analysis"
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
